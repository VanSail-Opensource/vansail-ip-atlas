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
	URL, Format                     string
	MaxCompressedBytes              int64
	MaxAge                          time.Duration
	Weight                          float64
	Dependencies                    []string
	Rights                          Rights
	Parser                          Parser
	Fixture                         Fixture
	Publication                     Publication
	Coverage                        string
	Scope                           string
	PublicFields                    []string
	Fields                          []string
	FieldMappings                   map[string][]string
}

type Rights struct {
	Status, Distribution, EvidenceURL, ReviewBasis string
	AttributionRequired                            *bool
}

type Parser struct {
	ID, Schema string
	Version    uint32
}

type Fixture struct {
	Status, Path, SHA256, Parser, Schema, TestedAt string
	SchemaObserved                                 bool
	Synthetic                                      *bool
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
	workspace string
	fetch     fetcher
	cleanup   func(string) error
	clockMu   sync.Mutex
	clocks    map[[32]byte]time.Time
	lifecycle sync.RWMutex
	closed    bool
	lock      *os.File
	lockInfo  os.FileInfo
	lockPath  string
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
	engine := &Engine{workspace: root, fetch: acquire.New(), cleanup: os.RemoveAll}
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
		ParserVersion:       source.Parser.Version, SchemaVersion: 3, MaxAge: source.MaxAge,
		Subscription: source.Category == "proxy_subscription_ip", CompleteCoverage: source.Coverage == "complete",
		Weight: source.Weight, Dependencies: append([]string(nil), source.Dependencies...)}
}

// Ingest rechecks review/certification before downloading. The only implemented
// publication verifier accepts authenticated GitHub per-asset SHA-256 metadata.
// Unsupported clocks, discovery rules and adapters quarantine instead of
// treating fetch times, filenames or repository activity as freshness evidence.
func (e *Engine) Ingest(ctx context.Context, source Source, now time.Time, normalizationPolicyHash [32]byte) (result Result, failure error) {
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
	if source.Rights.Status != "reviewed" || source.Rights.Distribution != "allow" || source.Rights.AttributionRequired == nil || *source.Rights.AttributionRequired || !safeHTTPS(source.Rights.EvidenceURL) || strings.TrimSpace(source.Rights.ReviewBasis) == "" {
		return deny("quarantined", "explicit_no_attribution_rights_required")
	}
	if !safeHTTPS(source.URL) || !validReleaseLocator(source.Publication.Locator, source.URL) || source.Publication.Kind != "github_release" || source.Publication.Field != "published_at" {
		return deny("quarantined", "unsupported_or_unbound_publication_verifier")
	}
	adapter, ok := selectAdapter(source)
	if !ok {
		return deny("quarantined", "unsupported_adapter_or_public_field_contract")
	}
	if adapter == mrtRIB {
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
	if _, err := e.fetch.Fetch(ctx, source.URL, payload, source.MaxCompressedBytes); err != nil {
		if ctx.Err() != nil {
			return result, ctx.Err()
		}
		return deny("missing", "asset_unavailable")
	}
	hash, size, err := hashFile(ctx, payload, source.MaxCompressedBytes)
	if err != nil {
		return deny("invalid", "payload_integrity_failed")
	}
	metadata := filepath.Join(quarantine, "publication")
	if _, err := e.fetch.Fetch(ctx, source.Publication.Locator, metadata, 4<<20); err != nil {
		if ctx.Err() != nil {
			return result, ctx.Err()
		}
		return deny("quarantined", "publication_metadata_unavailable")
	}
	published, err := verifyReleaseFile(ctx, metadata, source.URL, hash, size, now)
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
	records, err := parsePayload(ctx, file, size, source, adapter, published)
	if err != nil {
		if ctx.Err() != nil {
			return result, ctx.Err()
		}
		return deny("invalid", "schema_or_parser_failed")
	}
	result.Snapshot = &intelligence.SourceSnapshot{ID: source.ID, PayloadHash: hash,
		ProofPayloadHash: hash, NormalizationPolicyHash: normalizationPolicyHash,
		ParserVersion: source.Parser.Version, SchemaVersion: 3, PublishedAt: published,
		ProofKind: source.Publication.Kind, PayloadVerified: true, SchemaVerified: true, Records: records}
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
