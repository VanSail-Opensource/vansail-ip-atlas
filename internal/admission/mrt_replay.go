package admission

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"vansail-ip-atlas/internal/intelligence"
)

func (e *Engine) tryMRTReplay(ctx context.Context, sources []Source, now time.Time, binding [32]byte, plans map[string][]string, run *mrtAcquisitionState, store *intelligence.RecordStore, quarantine string, controls []Result) (result MRTIntakeResult, complete bool, failure error) {
	result.Mode = "replayed_updates"
	result.Results = make([]Result, len(controls))
	copy(result.Results, controls)
	cold := func(reason string) (MRTIntakeResult, bool, error) {
		for i := range result.Results {
			result.Results[i].Snapshot = nil
		}
		result.ReplayFallbackReason = reason
		if ctx.Err() != nil {
			return result, false, ctx.Err()
		}
		return result, false, nil
	}
	automatic := len(plans) == 0
	if !automatic && len(plans) != len(sources) {
		return cold("two_source_replay_plan_required")
	}
	for _, source := range sources {
		if !automatic && (len(plans[source.ID]) == 0 || len(plans[source.ID]) > 512) {
			return cold("bounded_source_update_archives_required")
		}
		companion, err := mrtUpdatesSource(source)
		if err != nil {
			return cold("reviewed_update_fixture_required")
		}
		if err = e.certify(ctx, companion, mrtUpdates, now); err != nil {
			return cold("reviewed_update_fixture_certification_required")
		}
	}
	budget := intelligence.NewMRTReplayBudget(ctx)
	defer budget.Close()
	previous, err := intelligence.VerifyPrivateStateSeal(budget.Context(), e.workspace, binding)
	if err != nil {
		return cold("authenticated_replay_base_unavailable")
	}
	selected := make([]intelligence.StoredSource, len(sources))
	locations := make([][]mrtArchiveLocation, len(sources))
	if automatic {
		plans = map[string][]string{}
	}
	for i, source := range sources {
		found := false
		for _, stored := range previous.Sources {
			if stored.ID == source.ID {
				selected[i] = stored
				found = true
				break
			}
		}
		stored := selected[i]
		if !found || stored.Receipt == nil || stored.Receipt.MRTProof == nil || !stored.Receipt.PayloadVerified || !stored.Receipt.SchemaVerified || stored.Receipt.NormalizationPolicyHash != binding || stored.Receipt.ParserVersion != source.Parser.Version || stored.Receipt.SchemaVersion != 3 || stored.Receipt.ProofKind != "embedded" || stored.Receipt.PayloadHash != stored.Receipt.ProofPayloadHash || !now.Before(stored.ExpiresAt) || !now.Before(stored.Receipt.PublishedAt.Add(source.MaxAge)) {
			return cold("current_bound_mrt_base_required")
		}
		proof := stored.Receipt.MRTProof
		content, err := proof.ContentHash()
		if err != nil || content != stored.Receipt.PayloadHash {
			return cold("mrt_base_content_set_mismatch")
		}
		base, err := mrtArchiveURL(source.URL)
		if err != nil || !base.rib || base.collector != proof.Collector {
			return cold("mrt_base_collector_mismatch")
		}
		if automatic {
			cursor := proof.Through
			for n := 0; n < 512; n++ {
				raw, location, err := nextMRTUpdateURL(source.URL, cursor)
				if err != nil {
					return cold("automatic_update_collector_plan_unavailable")
				}
				if location.until.After(now) {
					break
				}
				plans[source.ID] = append(plans[source.ID], raw)
				cursor = location.until
			}
			if raw, location, err := nextMRTUpdateURL(source.URL, cursor); err != nil || raw == "" || !location.until.After(now) {
				return cold("automatic_update_catchup_budget_exceeded")
			}
		}
		for j, raw := range plans[source.ID] {
			location, err := mrtArchiveURL(raw)
			if err != nil || location.rib || location.collector != proof.Collector || location.until.After(now) || j == 0 && (location.from.After(proof.Through) || !location.until.After(proof.Through)) || j > 0 && !location.from.Equal(locations[i][j-1].until) {
				return cold("update_collector_interval_or_gap_invalid")
			}
			locations[i] = append(locations[i], location)
		}
	}
	for i, source := range sources {
		stored := selected[i]
		if len(locations[i]) == 0 {
			r := stored.Receipt
			result.Results[i].Snapshot = &intelligence.SourceSnapshot{ID: source.ID, PayloadHash: r.PayloadHash, ProofPayloadHash: r.ProofPayloadHash, NormalizationPolicyHash: binding, ParserVersion: r.ParserVersion, SchemaVersion: r.SchemaVersion, PublishedAt: r.PublishedAt, ProofKind: r.ProofKind, PayloadVerified: true, SchemaVerified: true, RecordPartitions: append([]intelligence.RecordPartition(nil), stored.RecordPartitions...), MRTProof: r.MRTProof}
			result.Results[i].Decision.State, result.Results[i].Decision.Reason = "current", ""
			continue
		}
		var archives []intelligence.MRTStreamArchive
		clocks := make([]intelligence.MRTSnapshotClock, len(locations[i]))
		published := stored.Receipt.PublishedAt
		for j, location := range locations[i] {
			if budget.Context().Err() != nil {
				return cold("replay_deadline_exceeded")
			}
			remaining := int64(1<<30) - run.bytes
			if remaining <= 0 {
				return cold("replay_shared_run_byte_budget_exceeded")
			}
			maximum := min(remaining, source.MaxCompressedBytes)
			path := filepath.Join(quarantine, "update-"+strconv.Itoa(i)+"-"+strconv.Itoa(j))
			fetched, err := run.fetch.Fetch(budget.Context(), plans[source.ID][j], path, maximum)
			if err != nil {
				run.chargeFetch(maximum)
				return cold("update_archive_unavailable_or_budget")
			}
			digest, size, err := hashFile(budget.Context(), path, maximum)
			if err != nil || size != fetched.Bytes || fetched.SHA256 != hashString(digest) {
				run.chargeFetch(maximum)
				return cold("update_archive_integrity_failed")
			}
			run.chargeFetch(size)
			result.CompressedBytes += size
			archiveSource := source
			if location.format == "gzip" {
				archiveSource.Format = "mrt-gz"
			} else {
				archiveSource.Format = "mrt-bz2"
			}
			archivePath, archiveSize, archiveDigest, archiveIndex := path, size, digest, j
			archives = append(archives, intelligence.MRTStreamArchive{Collector: location.collector, Proof: intelligence.MRTArchiveProof{PayloadHash: digest, From: location.from, Until: location.until}, Scan: func(scanCtx context.Context, limit int, sink func(intelligence.MRTUpdate) error, observe func(intelligence.MRTPeerSession) error) (intelligence.MRTSnapshotClock, error) {
				file, err := os.Open(archivePath)
				if err != nil {
					return intelligence.MRTSnapshotClock{}, err
				}
				clock, parseErr := scanMRTUpdatesFile(scanCtx, file, archiveSize, archiveSource, now, limit, sink, observe)
				closeErr := file.Close()
				if parseErr != nil {
					return intelligence.MRTSnapshotClock{}, parseErr
				}
				if closeErr != nil {
					return intelligence.MRTSnapshotClock{}, closeErr
				}
				actual, n, err := hashFile(scanCtx, archivePath, maximum)
				if err != nil || actual != archiveDigest || n != archiveSize {
					return intelligence.MRTSnapshotClock{}, errors.New("private UPDATE payload changed during replay")
				}
				retained, err := e.retainClock(scanCtx, archiveDigest, clock.First)
				if err != nil {
					return intelligence.MRTSnapshotClock{}, err
				}
				if retained.Before(published) {
					published = retained
				}
				clocks[archiveIndex] = clock
				return clock, nil
			}})
		}
		writer := store.Writer(budget.Context())
		replayed, err := intelligence.StreamMRTReplay(ctx, intelligence.MRTStreamBase{Family: source.Family, Proof: stored.Receipt.MRTProof, Walk: func(walkCtx context.Context, visit func(intelligence.NormalizedRecord) error) error {
			return intelligence.WalkStoredSource(walkCtx, e.workspace, stored, visit)
		}}, archives, now, budget, writer.Append)
		if err != nil || replayed.ColdFallback {
			_ = writer.Abort()
			return cold("streaming_replay_requires_cold_" + replayed.Reason)
		}
		if !now.Before(published.Add(source.MaxAge)) {
			_ = writer.Abort()
			return cold("base_publication_expired_during_replay")
		}
		parts, err := writer.Finish()
		_ = writer.Abort()
		if err != nil || len(parts) == 0 {
			return cold("replay_materialized_partition_failed")
		}
		content, err := replayed.Proof.ContentHash()
		if err != nil {
			return cold("replay_content_set_invalid")
		}
		published, err = e.retainClock(budget.Context(), content, published)
		if err != nil || !now.Before(published.Add(source.MaxAge)) {
			return cold("replay_earliest_content_clock_expired")
		}
		result.Results[i].Snapshot = &intelligence.SourceSnapshot{ID: source.ID, PayloadHash: content, ProofPayloadHash: content, NormalizationPolicyHash: binding, ParserVersion: source.Parser.Version, SchemaVersion: 3, PublishedAt: published, ProofKind: "embedded", PayloadVerified: true, SchemaVerified: true, RecordPartitions: parts, MRTProof: replayed.Proof}
		result.Results[i].Decision.State, result.Results[i].Decision.Reason = "current", ""
		result.ReplayUpdates += replayed.Updates
		result.CaptureClocks = append(result.CaptureClocks, clocks...)
	}
	if result.Results[0].Snapshot.PayloadHash == result.Results[1].Snapshot.PayloadHash {
		return cold("replayed_content_sets_are_correlated")
	}
	if budget.Context().Err() != nil {
		return cold("replay_deadline_exceeded")
	}
	if len(result.CaptureClocks) == 0 {
		result.Mode = "unchanged_mrt"
	}
	return result, true, nil
}
