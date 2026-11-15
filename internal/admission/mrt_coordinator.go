package admission

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"vansail-ip-atlas/internal/acquire"
	"vansail-ip-atlas/internal/intelligence"
)

type MRTIntakeOptions struct {
	Enabled        bool
	ReplayArchives map[string][]string // optional reviewed same-collector UPDATE URLs, by logical source ID
}

type MRTIntakeResult struct {
	Results              []Result
	CompressedBytes      int64
	CaptureClocks        []intelligence.MRTSnapshotClock
	Mode                 string
	ReplayFallbackReason string
	ReplayUpdates        int
}

type mrtAcquisitionState struct {
	mu      sync.Mutex
	bytes   int64
	sources map[string]bool
	fetch   fetcher
}

func (s *mrtAcquisitionState) chargeFetch(fallback int64) {
	if measured, ok := s.fetch.(interface{ GroupBytesRemaining() (int64, bool) }); ok {
		if remaining, valid := measured.GroupBytesRemaining(); valid && remaining >= 0 && remaining <= 1<<30 {
			s.bytes = 1<<30 - remaining
			return
		}
	}
	s.bytes += fallback
}

// IngestMRT is the sole runtime MRT acquisition entry point. Both independent
// families must pass the real review/certification controls before any fetch.
// The per-Engine source and compressed-byte budgets survive retries and calls;
// a second coordinator cannot reset them. Downloads are always sequential.
func (e *Engine) IngestMRT(ctx context.Context, sources []Source, now time.Time, binding [32]byte, options MRTIntakeOptions) (result MRTIntakeResult, failure error) {
	if e == nil || len(sources) != 2 || now.IsZero() || binding == ([32]byte{}) {
		return result, errors.New("two explicit bounded MRT sources required")
	}
	result.Results = make([]Result, len(sources))
	result.Mode = "cold_rib"
	for i, source := range sources {
		result.Results[i] = Result{Policy: policy(source), Decision: intelligence.SourceDecision{ID: source.ID, State: "quarantined"}}
	}
	deny := func(reason string) (MRTIntakeResult, error) {
		for i := range result.Results {
			result.Results[i].Snapshot = nil
			result.Results[i].Decision.State = "quarantined"
			result.Results[i].Decision.Reason = reason
		}
		if ctx.Err() != nil {
			return result, ctx.Err()
		}
		return result, nil
	}
	if !options.Enabled {
		return deny("mrt_disabled")
	}
	e.lifecycle.RLock()
	defer e.lifecycle.RUnlock()
	if e.closed || e.lock == nil || e.fetch == nil || e.workspace == "" {
		return result, errors.New("owned admission workspace required")
	}
	if sources[0].ID == sources[1].ID || sources[0].Family == sources[1].Family {
		return deny("two_independent_mrt_families_required")
	}
	for i, source := range sources {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		if !validMRTControls(source) {
			return deny("reviewed_mrt_controls_required")
		}
		if source.Rights.Attribution != nil && intelligence.ValidateDatasetLogoFile(e.workspace, source.Rights.Attribution.Logo) != nil {
			return deny("reviewed_dataset_logo_required")
		}
		if err := e.certify(ctx, source, mrtRIB, now); err != nil {
			return deny("reviewed_fixture_certification_required")
		}
		result.Results[i].Policy.FixtureTested = true
		result.Results[i].Policy.RightsReviewed = true
	}
	e.storeMu.Lock()
	if e.mrt == nil {
		group := e.fetch
		if concrete, ok := e.fetch.(*acquire.Fetcher); ok {
			group, failure = concrete.WithByteBudget(1 << 30)
		}
		if failure == nil {
			e.mrt = &mrtAcquisitionState{sources: map[string]bool{}, fetch: group}
		}
	}
	state := e.mrt
	if failure == nil && e.recordStore == nil {
		e.recordStore, failure = intelligence.NewRecordStore(e.workspace, intelligence.DefaultRecordStoreLimits())
	}
	store := e.recordStore
	e.storeMu.Unlock()
	if failure != nil {
		return result, failure
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	selected := len(state.sources)
	for _, source := range sources {
		if !state.sources[source.ID] {
			selected++
		}
	}
	if selected > 2 {
		return deny("mrt_run_source_budget_exceeded")
	}
	for _, source := range sources {
		state.sources[source.ID] = true
	}
	quarantine, err := e.quarantine()
	if err != nil {
		return result, err
	}
	defer func() {
		cleanup := e.cleanup
		if cleanup == nil {
			cleanup = os.RemoveAll
		}
		if cleanup(quarantine) != nil {
			for i := range result.Results {
				result.Results[i].Snapshot = nil
				result.Results[i].Decision.State, result.Results[i].Decision.Reason = "invalid", "private_quarantine_cleanup_failed"
			}
			failure = errors.New("private MRT quarantine cleanup failed")
		}
	}()
	{
		replayed, complete, err := e.tryMRTReplay(ctx, sources, now, binding, options.ReplayArchives, state, store, quarantine, result.Results)
		if err != nil {
			return result, err
		}
		if complete {
			return replayed, nil
		}
		result.ReplayFallbackReason = replayed.ReplayFallbackReason
		result.CompressedBytes += replayed.CompressedBytes
	}
	for i, source := range sources {
		remaining := int64(1<<30) - state.bytes
		if remaining <= 0 {
			return deny("mrt_run_byte_budget_exceeded")
		}
		maximum := min(remaining, source.MaxCompressedBytes)
		payload := filepath.Join(quarantine, []string{"first", "second"}[i])
		fetched, err := state.fetch.Fetch(ctx, source.URL, payload, maximum)
		// A failed transfer may already have consumed its whole bounded body.
		// Reserve the attempted ceiling on failure so retries cannot reset it.
		if err != nil {
			state.chargeFetch(maximum)
			return deny("mrt_asset_unavailable_or_budget_exceeded")
		}
		digest, size, err := hashFile(ctx, payload, maximum)
		if err != nil || size != fetched.Bytes || fetched.SHA256 != hashString(digest) {
			state.chargeFetch(maximum)
			return deny("mrt_payload_integrity_failed")
		}
		state.chargeFetch(size)
		result.CompressedBytes += size
		file, err := os.Open(payload)
		if err != nil {
			return result, err
		}
		writer := store.Writer(ctx)
		clock, err := parseMRTCapturePayload(ctx, file, size, source, now, 100_000_000, writer.Append)
		closeErr := file.Close()
		if err != nil || closeErr != nil {
			_ = writer.Abort()
			return deny("mrt_complete_capture_proof_or_parser_failed")
		}
		published, err := e.retainClock(ctx, digest, clock.First)
		if err != nil || !now.Before(published.Add(source.MaxAge)) {
			_ = writer.Abort()
			return deny("mrt_publication_expired_or_unbound")
		}
		parts, err := writer.Finish()
		_ = writer.Abort()
		if err != nil || len(parts) == 0 {
			return deny("mrt_private_partition_failed")
		}
		result.Results[i].Snapshot = &intelligence.SourceSnapshot{ID: source.ID, PayloadHash: digest, ProofPayloadHash: digest,
			NormalizationPolicyHash: binding, ParserVersion: source.Parser.Version, SchemaVersion: 3, PublishedAt: published,
			ProofKind: "embedded", PayloadVerified: true, SchemaVerified: true, RecordPartitions: parts}
		// Generic reviewed publishers receive complete cold-body proof too.
		// Their source identity never grants provider-specific UPDATE replay.
		collector := sha256.Sum256([]byte("atlas-reviewed-mrt-source-v1\x00" + source.URL))
		if location, err := mrtArchiveURL(source.URL); err == nil && location.rib && !clock.First.Before(location.from) && clock.Last.Before(location.until) {
			collector = location.collector
		}
		result.Results[i].Snapshot.MRTProof = &intelligence.MRTSourceProof{Version: 1, Collector: collector, BasePayloadHash: digest, BaseBytes: size, CapturedAt: clock.First, CaptureUntil: clock.Last, Through: clock.First}
		result.CaptureClocks = append(result.CaptureClocks, clock)
		result.Results[i].Decision.State, result.Results[i].Decision.Reason = "current", ""
	}
	if result.Results[0].Snapshot.PayloadHash == result.Results[1].Snapshot.PayloadHash {
		return deny("identical_payloads_are_not_independent_families")
	}
	return result, nil
}

func validMRTControls(source Source) bool {
	adapter, supported := selectAdapter(source)
	return supported && adapter == mrtRIB && source.Admission == "active" && identity(source.ID) && identity(source.Family) &&
		source.MaxAge > 0 && source.MaxAge <= 720*time.Hour && !math.IsNaN(source.Weight) && !math.IsInf(source.Weight, 0) && source.Weight >= 0 && source.Weight <= 100 && source.MaxCompressedBytes > 0 && source.MaxCompressedBytes <= 1<<30 &&
		safeHTTPS(source.URL) && source.Publication.Kind == "embedded" && source.Publication.Locator == source.URL && source.Publication.Field == "mrt_frame_capture_timestamp" &&
		source.Rights.Status == "reviewed" && permittedDistributionDecision(source.Rights.Distribution) && source.Rights.AttributionRequired != nil && safeHTTPS(source.Rights.EvidenceURL) && strings.TrimSpace(source.Rights.ReviewBasis) != "" &&
		(!*source.Rights.AttributionRequired || source.Rights.Attribution != nil) && (source.Rights.Attribution == nil || source.Rights.Attribution.Validate() == nil)
}

func parseMRTCapturePayload(ctx context.Context, file *os.File, size int64, source Source, now time.Time, maxRecords int, sink func(intelligence.NormalizedRecord) error) (intelligence.MRTSnapshotClock, error) {
	format := "plain"
	if source.Format == "mrt-gz" {
		format = "gzip"
	} else if source.Format == "mrt-bz2" {
		format = "bzip2"
	}
	var proof intelligence.MRTSnapshotClock
	limits := acquire.ArchiveLimits{CompressedBytes: source.MaxCompressedBytes, DecodedBytes: 3 << 30, EntryBytes: 3 << 30, Entries: 1, NameBytes: 4096}
	err := acquire.WalkArchive(ctx, acquire.ArchiveInput{Reader: file, ReaderAt: file, Size: size}, format, limits, func(_ string, input io.Reader) error {
		var err error
		proof, err = intelligence.ParseMRTSnapshot(ctx, input, intelligence.MRTLimits{Bytes: 3 << 30, FrameBytes: 8 << 20, Records: maxRecords / 2, Peers: 65535}, now, source.MaxAge, func(captured intelligence.MRTSnapshotRecord) error {
			value := captured.Record
			if !value.Prefix.IsValid() || value.Prefix.Addr().Is4In6() || value.Prefix.Addr().Zone() != "" || value.ObservedAt.After(captured.CapturedAt.Add(24*time.Hour)) {
				return errors.New("unrepresentable MRT record or future originated time")
			}
			originated := value.ObservedAt
			identity := &intelligence.MRTRouteIdentity{PeerKey: value.PeerKey, PeerIndex: value.PeerIndex, PeerTable: value.PeerTable, PathID: value.PathID, AddPath: value.AddPath, PeerAmbiguous: value.PeerAmbiguous, CapturedAt: captured.CapturedAt}
			origins := []uint32{}
			if intelligence.IsPublicASN(value.Origin) {
				origins = append(origins, value.Origin)
			}
			// A valid observed route with an unsupported scalar origin still
			// shadows broader routes. Do not choose an AS_SET member or drop its
			// prefix: either would invent an origin during longest-prefix lookup.
			if err := sink(intelligence.NormalizedRecord{Version: 3, Kind: intelligence.RecordOrigins, MRTOriginatedAt: &originated, MRT: identity, Origins: &intelligence.OriginMapping{Prefix: value.Prefix, Origins: origins}}); err != nil {
				return err
			}
			if len(origins) == 0 {
				return nil
			}
			return sink(intelligence.NormalizedRecord{Version: 3, Kind: intelligence.RecordPath, MRTOriginatedAt: &originated, MRT: identity, Path: &intelligence.ScopedPath{Prefix: value.Prefix, Observation: intelligence.PathObservation{Origin: value.Origin, Segments: value.Segments, Family: source.Family, Current: true, OriginOutward: false}}})
		})
		return err
	})
	if err != nil {
		return intelligence.MRTSnapshotClock{}, err
	}
	return proof, nil
}
