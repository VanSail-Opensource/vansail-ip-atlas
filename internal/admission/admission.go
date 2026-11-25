// Package admission turns reviewed build-private source controls into freshly
// verified normalized snapshots. It never creates reviews or public provenance.
package admission

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
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

// Source is the typed executable projection of a schema-validated source entry.
// The complete five-file closed schema validation remains a build prerequisite.
// Admission rechecks every control below; an active label alone authorizes no IO.
type Source struct {
	ID, Family, Category, Admission string
	SourceGroup                     string `json:",omitempty"`
	URL, Format                     string
	MRTArchivePolicy                string `json:",omitempty"`
	MaxCompressedBytes              int64
	MaxAge                          time.Duration
	Weight                          float64
	Dependencies                    []string
	Rights                          Rights
	Parser                          Parser
	Fixture                         Fixture
	MRTUpdatesFixture               *Fixture
	Publication                     Publication
	Discovery                       *Discovery
	Coverage                        string
	Scope                           string
	PublicFields                    []string
	Fields                          []string
	FieldMappings                   map[string][]string
	Signals                         []string
}

type Rights struct {
	Status, Distribution, EvidenceURL, ReviewBasis string
	Identifier                                     string
	AttributionRequired                            *bool
	Attribution                                    *intelligence.DatasetAttribution
}

type Parser struct {
	ID, Schema string
	Version    uint32
}

type Fixture struct {
	Status, Path, SHA256, Parser, Schema, TestedAt string
	SchemaObserved                                 bool
	Synthetic                                      *bool
	ContentEncoding                                string
	PayloadFormat                                  string
}

type Publication struct{ Kind, Locator, Field string }

// Result is build-private. Unsuccessful intake always has a nil Snapshot.
// Feed Policies and successful Snapshots into intelligence.Reconcile on every
// build, including no-change builds, to retract withdrawn sources/dependencies.
type Result struct {
	Policy   intelligence.SourcePolicy
	Snapshot *intelligence.SourceSnapshot
	Decision intelligence.SourceDecision
}

type fetcher interface {
	Fetch(context.Context, string, string, int64) (acquire.Result, error)
}

type Engine struct {
	workspace   string
	fetch       fetcher
	cleanup     func(string) error
	clockMu     sync.Mutex
	clocks      map[[32]byte]time.Time
	lifecycle   sync.RWMutex
	closed      bool
	lock        *os.File
	lockInfo    os.FileInfo
	lockPath    string
	storeMu     sync.Mutex
	recordStore *intelligence.RecordStore
	mrt         *mrtAcquisitionState
}

// New creates one bounded acquisition run. Reuse it across sources so retries
// and downloads share acquire's aggregate byte and concurrency budgets.
func New(workspace string) (*Engine, error) {
	root, err := filepath.Abs(workspace)
	if err != nil {
		return nil, errors.New("admission workspace invalid")
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return nil, errors.New("admission workspace invalid")
	}
	transport, err := acquire.NewWithGitHubMetadataToken(os.Getenv("ATLAS_GITHUB_METADATA_TOKEN"))
	if err != nil {
		return nil, errors.New("admission metadata transport invalid")
	}
	engine := &Engine{workspace: root, fetch: transport, cleanup: os.RemoveAll}
	if err := engine.acquireWorkspace(); err != nil {
		return nil, err
	}
	if err := engine.loadClocks(); err != nil {
		_ = engine.Close()
		return nil, err
	}
	return engine, nil
}

func policy(source Source) intelligence.SourcePolicy {
	return intelligence.SourcePolicy{ID: source.ID, Family: source.Family,
		Admission: source.Admission, ProofKind: source.Publication.Kind,
		AttributionRequired: source.Rights.AttributionRequired,
		Attribution:         source.Rights.Attribution,
		ParserVersion:       source.Parser.Version, SchemaVersion: 3, MaxAge: source.MaxAge,
		Subscription: source.Category == "proxy_subscription_ip", CompleteCoverage: source.Coverage == "complete",
		Weight: source.Weight, Dependencies: append([]string(nil), source.Dependencies...)}
}

// Ingest rechecks review/certification before downloading. The only implemented
// publication verifiers require GitHub per-asset SHA-256 metadata or exact
// SHA-256 equality with a separately downloaded immutable commit payload.
// Unsupported clocks, discovery rules and adapters quarantine instead of
// treating fetch times, filenames or repository activity as freshness evidence.
func (e *Engine) Ingest(ctx context.Context, source Source, now time.Time, normalizationPolicyHash [32]byte) (result Result, failure error) {
	return e.ingest(ctx, source, now, normalizationPolicyHash, false)
}

// IngestPartitioned retains the same admission gates while streaming normalized
// rows into bounded immutable private objects instead of a whole-source slice.
func (e *Engine) IngestPartitioned(ctx context.Context, source Source, now time.Time, normalizationPolicyHash [32]byte) (Result, error) {
	return e.ingest(ctx, source, now, normalizationPolicyHash, true)
}

func (e *Engine) ingest(ctx context.Context, source Source, now time.Time, normalizationPolicyHash [32]byte, partitioned bool) (result Result, failure error) {
	result = Result{Policy: policy(source), Decision: intelligence.SourceDecision{ID: source.ID, State: "quarantined"}}
	deny := func(state, reason string) (Result, error) {
		result.Decision.State, result.Decision.Reason = state, reason
		if ctx.Err() != nil {
			return result, ctx.Err()
		}
		return result, nil
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	if e == nil {
		return result, errors.New("admission engine unavailable")
	}
	e.lifecycle.RLock()
	defer e.lifecycle.RUnlock()
	if e.closed || e.lock == nil || e.fetch == nil || e.workspace == "" || now.IsZero() || normalizationPolicyHash == ([32]byte{}) {
		return result, errors.New("admission run requires explicit context and policy")
	}
	if source.Admission != "active" {
		return deny("quarantined", "not_active")
	}
	if !identity(source.ID) || !identity(source.Family) || source.MaxAge <= 0 || source.MaxAge > 720*time.Hour || math.IsNaN(source.Weight) || math.IsInf(source.Weight, 0) || source.Weight < 0 || source.Weight > 100 || source.MaxCompressedBytes <= 0 || source.MaxCompressedBytes > 1<<30 {
		return deny("quarantined", "invalid_source_controls")
	}
	if source.Rights.Status != "reviewed" || !permittedDistributionDecision(source.Rights.Distribution) || source.Rights.AttributionRequired == nil || !safeHTTPS(source.Rights.EvidenceURL) || strings.TrimSpace(source.Rights.ReviewBasis) == "" {
		return deny("quarantined", "reviewed_redistribution_rights_required")
	}
	if *source.Rights.AttributionRequired && source.Rights.Attribution == nil || source.Rights.Attribution != nil && source.Rights.Attribution.Validate() != nil {
		return deny("quarantined", "reviewed_dataset_attribution_required")
	}
	if source.Rights.Attribution != nil && intelligence.ValidateDatasetLogoFile(e.workspace, source.Rights.Attribution.Logo) != nil {
		return deny("quarantined", "reviewed_dataset_logo_required")
	}
	if !safeHTTPS(source.URL) && !dbipProvider(source) && !caidaSource(source) || !publicationSupported(source) {
		return deny("quarantined", "unsupported_or_unbound_publication_verifier")
	}
	adapter, ok := selectAdapter(source)
	if !ok {
		return deny("quarantined", "unsupported_adapter_or_public_field_contract")
	}
	if adapter == mrtRIB || adapter == mrtUpdates {
		// Source milestones do not override the currently disabled global MRT
		// switch. A dedicated cold-build coordinator must enforce two independent
		// families, sequential downloads and their shared 1 GiB budget first.
		return deny("quarantined", "dedicated_mrt_acquisition_required")
	}
	if source.Category == "proxy_subscription_ip" {
		// The syntax decoder deliberately cannot prove individual item clocks.
		// A republished subscription container must not renew old server entries.
		return deny("quarantined", "verified_item_publication_time_required")
	}
	if err := e.certify(ctx, source, adapter, now); err != nil {
		if ctx.Err() != nil {
			return result, ctx.Err()
		}
		return deny("quarantined", "reviewed_fixture_certification_required")
	}
	result.Policy.FixtureTested, result.Policy.RightsReviewed = true, true
	quarantine, err := e.quarantine()
	if err != nil {
		return result, err
	}
	// This path is generated beneath a symlink-checked private directory, never
	// derived from source IDs, download names, archive members or source URLs.
	defer func() {
		cleanup := e.cleanup
		if cleanup == nil {
			cleanup = os.RemoveAll
		}
		if cleanup(quarantine) != nil {
			result.Snapshot = nil
			result.Decision.State, result.Decision.Reason = "invalid", "private_quarantine_cleanup_failed"
			failure = errors.New("private quarantine cleanup failed")
		}
	}()
	payload := filepath.Join(quarantine, "payload")
	assetURL := source.URL
	var dbipPlan dbipMonthlyPlan
	var caidaIndexHash [32]byte
	if caidaSource(source) {
		indexPath := filepath.Join(quarantine, "index")
		if _, err := e.fetch.Fetch(ctx, source.Discovery.IndexURL, indexPath, 1<<20); err != nil {
			return deny("quarantined", "discovery_index_unavailable")
		}
		page, indexErr := boundedFile(ctx, indexPath, 1<<20)
		if indexErr == nil {
			assetURL, indexErr = resolveCAIDASerial2Index(page, now)
		}
		if indexErr != nil {
			return deny("quarantined", "discovery_index_invalid")
		}
		caidaIndexHash = sha256.Sum256(page)
	}
	if dbipProvider(source) {
		metadata := filepath.Join(quarantine, "publication")
		if _, err := e.fetch.Fetch(ctx, source.Publication.Locator, metadata, 4<<20); err != nil {
			return deny("quarantined", "publication_metadata_unavailable")
		}
		page, err := boundedFile(ctx, metadata, 4<<20)
		if err == nil {
			dbipPlan, err = resolveDBIPMonthlyPage(page, now)
		}
		if err != nil {
			return deny("quarantined", "publication_not_payload_bound")
		}
		assetURL = dbipPlan.AssetURL
	}
	var published, contentValidUntil time.Time
	var appleProof *intelligence.AppleRelayProof
	var mullvadProof *intelligence.MullvadRelayProof
	var azureProof *intelligence.AzureServiceProof
	if adapter == appleRelayCSV {
		appleProof, err = e.fetchAppleRelay(ctx, payload, source, now)
		if err != nil {
			if ctx.Err() != nil {
				return result, ctx.Err()
			}
			return deny("quarantined", "publication_not_payload_bound")
		}
		published = appleProof.Edition
		contentValidUntil = appleProof.ContentDeadline(source.MaxAge)
	} else if adapter == mullvadRelaysJSON {
		mullvadProof, published, err = e.fetchMullvad(ctx, payload, source, now)
		if err != nil {
			if ctx.Err() != nil {
				return result, ctx.Err()
			}
			return deny("quarantined", "publication_not_payload_bound")
		}
	} else if adapter == azureAppService {
		azureProof, err = e.fetchAzureService(ctx, payload, source, now)
		if err != nil {
			if ctx.Err() != nil {
				return result, ctx.Err()
			}
			return deny("quarantined", "publication_not_payload_bound")
		}
		published = azureProof.Editions[0].Day
	} else if source.Parser.ID == "tweetfeed-week-csv" {
		published, err = e.fetchTweetFeed(ctx, payload, source, now)
		if err != nil {
			return deny("quarantined", "publication_not_payload_bound")
		}
	} else if _, err := e.fetch.Fetch(ctx, assetURL, payload, source.MaxCompressedBytes); err != nil {
		if ctx.Err() != nil {
			return result, ctx.Err()
		}
		return deny("missing", "asset_unavailable")
	}
	hash, size, err := hashFile(ctx, payload, source.MaxCompressedBytes)
	if err != nil {
		return deny("invalid", "payload_integrity_failed")
	}
	var ripeNames *intelligence.RIPEIPv6NetworkProof
	var googleProof *intelligence.GoogleNetworkProof
	var nroProof *intelligence.NRORegistrationProof
	var geoProof *intelligence.GeoSourceProof
	var vrpProof *intelligence.VRPSourceProof
	var caidaProof *intelligence.CAIDASourceProof
	if appleProof != nil {
		err = appleProof.Validate(now, published, hash)
		if err == nil {
			published, err = e.retainClock(ctx, appleProof.After.PrefixHash, published)
		}
	} else if mullvadProof != nil {
		err = mullvadProof.Validate(now, published, hash)
		if err == nil {
			published, err = e.retainClock(ctx, hash, published)
		}
		if err == nil {
			published, err = e.retainClock(ctx, mullvadProof.Projection, published)
		}
	} else if dbipProvider(source) || adapter == ipapiCityZIP {
		proofFile, openErr := os.Open(payload)
		if openErr != nil {
			return deny("invalid", "payload_read_failed")
		}
		if dbipProvider(source) {
			geoProof, err = verifyDBIPGzip(ctx, proofFile, size, source, dbipPlan)
		} else {
			geoProof, err = verifyIPAPIArchive(ctx, proofFile, size, source, now)
		}
		if closeErr := proofFile.Close(); err == nil {
			err = closeErr
		}
		if err == nil {
			published = geoProof.UpstreamClock
			published, err = e.retainClock(ctx, decodedGeoClockKey(geoProof.DecodedSHA256), published)
		}
	} else if caidaSource(source) {
		caidaProof, err = verifyCAIDAFile(ctx, payload, size, source, assetURL, caidaIndexHash, hash, now)
		if err == nil {
			published = caidaProof.FirstObservedAt
		}
	} else if adapter == ripeNetworkNames {
		ripeNames, err = e.verifyRIPENames(ctx, payload, source, hash, now)
		if err == nil {
			published = ripeNames.PublishedAt
		}
	} else if adapter == googleNetwork {
		googleProof, err = verifyGoogleNetwork(ctx, payload, source, hash, now)
		if err == nil {
			published = googleProof.PublishedAt
		}
	} else if adapter == nroRegistration {
		nroProof, err = e.verifyNRO(ctx, payload, hash, source, now)
		if err == nil {
			published = nroProof.Day
		}
	} else if adapter == rootServiceZone {
		var projection rootZoneProjection
		projection, err = e.verifyRootZone(ctx, payload, hash, size, now)
		if err == nil {
			published, contentValidUntil = projection.day, projection.until
		}
	} else if adapter == torExits {
		published, err = verifyTorExitFile(ctx, payload, source, now)
	} else if adapter == rpkiClientJSON {
		proof, proofErr := verifyRPKIClientFile(ctx, payload, size, source, now)
		err = proofErr
		published = proof.BuiltAt
		if err == nil {
			vrpProof = &intelligence.VRPSourceProof{Version: 2, Rows: uint64(proof.Rows), RetainedRows: uint64(proof.RetainedRows), ObservedAt: proof.BuiltAt, EvaluatedAt: now, CoverageValidUntil: proof.CoverageValidUntil}
		}
	} else if published.IsZero() {
		metadata := filepath.Join(quarantine, "publication")
		if _, err := e.fetch.Fetch(ctx, source.Publication.Locator, metadata, 4<<20); err != nil {
			if ctx.Err() != nil {
				return result, ctx.Err()
			}
			return deny("quarantined", "publication_metadata_unavailable")
		}
		if source.Publication.Kind == "github_commit" {
			published, err = e.verifyCommit(ctx, metadata, quarantine, source, hash, size, now)
		} else {
			published, err = verifyReleaseFile(ctx, metadata, source.URL, hash, size, now)
		}
	}
	if err != nil {
		return deny("quarantined", "publication_not_payload_bound")
	}
	published, err = e.retainClock(ctx, hash, published)
	if err != nil {
		return result, err
	}
	if !now.Before(published.Add(source.MaxAge)) {
		return deny("stale", "publication_expired")
	}
	if !contentValidUntil.IsZero() && !now.Before(contentValidUntil) {
		return deny("stale", "content_expired")
	}
	file, err := os.Open(payload)
	if err != nil {
		return deny("invalid", "payload_read_failed")
	}
	defer func() {
		if file.Close() != nil {
			result.Snapshot = nil
			result.Decision.State, result.Decision.Reason = "invalid", "private_payload_close_failed"
			failure = errors.New("private payload close failed")
		}
	}()
	var asnStats intelligence.ASNIdentityStats
	var records []intelligence.NormalizedRecord
	var partitions []intelligence.RecordPartition
	parserClock := published
	if adapter == rpkiClientJSON || adapter == ripeNetworkNames {
		parserClock = now
	}
	var keepRecord func(intelligence.NormalizedRecord) bool
	if azureProof != nil {
		azureHosts, err := azureProof.Eligible(now, published, hash)
		if err != nil {
			return deny("invalid", "azure_service_selection_invalid")
		}
		keepRecord = func(r intelligence.NormalizedRecord) bool {
			return r.Evidence != nil && azureHosts[r.Evidence.Address]
		}
	}
	if adapter == ipverseUsageJSON {
		cutoff := asnUsageObservedAfter(now, source.MaxAge)
		keepRecord = func(r intelligence.NormalizedRecord) bool {
			return r.Usage != nil && r.Usage.ObservedAt.After(cutoff)
		}
	}
	if partitioned {
		e.storeMu.Lock()
		if e.recordStore == nil {
			e.recordStore, err = intelligence.NewRecordStore(e.workspace, intelligence.DefaultRecordStoreLimits())
		}
		store := e.recordStore
		e.storeMu.Unlock()
		if err != nil {
			return result, err
		}
		writer := store.Writer(ctx)
		defer writer.Abort()
		appendRecord := writer.Append
		if keepRecord != nil {
			appendRecord = func(record intelligence.NormalizedRecord) error {
				if keepRecord(record) {
					return writer.Append(record)
				}
				return nil
			}
		}
		err = parsePayloadTo(ctx, file, size, source, adapter, parserClock, 100_000_000, appendRecord, &asnStats)
		if err == nil {
			partitions, err = writer.Finish()
		}
	} else {
		records, err = parsePayload(ctx, file, size, source, adapter, parserClock, &asnStats)
		if keepRecord != nil && err == nil {
			out := records[:0]
			for _, r := range records {
				if keepRecord(r) {
					out = append(out, r)
				}
			}
			records = out
		}
	}
	if err == nil && (partitioned || adapter == ipverseUsageJSON) && len(records) == 0 && len(partitions) == 0 {
		if adapter == ipverseUsageJSON {
			return deny("quarantined", "no_asn_role_survives_serving_window")
		}
		err = errors.New("source contains no accepted records")
	}
	if err != nil {
		if ctx.Err() != nil {
			return result, ctx.Err()
		}
		return deny("invalid", "schema_or_parser_failed")
	}
	result.Snapshot = &intelligence.SourceSnapshot{ID: source.ID, PayloadHash: hash,
		ProofPayloadHash: hash, NormalizationPolicyHash: normalizationPolicyHash,
		ParserVersion: source.Parser.Version, SchemaVersion: 3, PublishedAt: published, ContentValidUntil: contentValidUntil,
		ProofKind: source.Publication.Kind, PayloadVerified: true, SchemaVerified: true, ImmutableCommitBound: source.Publication.Kind == "github_commit", Records: records, RecordPartitions: partitions}
	result.Snapshot.RIPENetworkProof = ripeNames
	result.Snapshot.GoogleNetworkProof = googleProof
	result.Snapshot.NROProof = nroProof
	result.Snapshot.AzureProof = azureProof
	result.Snapshot.AppleRelayProof = appleProof
	result.Snapshot.MullvadProof = mullvadProof
	result.Snapshot.GeoProof = geoProof
	result.Snapshot.VRPProof = vrpProof
	result.Snapshot.CAIDAProof = caidaProof
	if adapter == asnIdentityCSV {
		result.Snapshot.ASNIdentityStats = &asnStats
	}
	result.Decision.State, result.Decision.Reason = "current", ""
	return result, nil
}

func identity(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for _, c := range value {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

func (e *Engine) quarantine() (string, error) {
	private := filepath.Join(e.workspace, ".atlas-private")
	if err := os.MkdirAll(private, 0700); err != nil {
		return "", errors.New("private quarantine unavailable")
	}
	resolved, err := filepath.EvalSymlinks(private)
	if err != nil || resolved != private {
		return "", errors.New("private quarantine escaped workspace")
	}
	path, err := os.MkdirTemp(private, "intake-")
	if err != nil {
		return "", errors.New("private quarantine unavailable")
	}
	return path, nil
}

func hashFile(ctx context.Context, path string, bound int64) ([32]byte, int64, error) {
	var digest [32]byte
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > bound {
		return digest, 0, errors.New("private payload invalid")
	}
	file, err := os.Open(path)
	if err != nil {
		return digest, 0, errors.New("private payload invalid")
	}
	defer file.Close()
	hash := sha256.New()
	limited := io.LimitReader(contextReader{ctx, file}, bound+1)
	n, err := io.Copy(hash, limited)
	if err != nil || n != info.Size() || n > bound {
		return digest, 0, errors.New("private payload integrity failed")
	}
	copy(digest[:], hash.Sum(nil))
	return digest, n, nil
}

type contextReader struct {
	ctx context.Context
	r   io.Reader
}

func (r contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.r.Read(p)
}

// String intentionally reveals no source identity, locator or raw parser data.
func (r Result) String() string { return fmt.Sprintf("source intake: %s", r.Decision.State) }
