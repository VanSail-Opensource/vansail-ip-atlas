package admission

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"vansail-ip-atlas/internal/intelligence"
)

// CapabilityReport is private: family labels and source IDs must never be
// copied into a public bundle or hosted evidence. Only its digest may escape.
type CapabilityReport struct {
	Capabilities    []Capability `json:"capabilities"`
	EvaluatedAt     int64        `json:"evaluated_at"`
	IncludedSources int          `json:"included_sources"`
	ReleaseScope    string       `json:"release_scope"`
	SchemaVersion   uint16       `json:"schema_version"`
}
type Capability struct {
	Capability string   `json:"capability"`
	Families   []string `json:"families"`
	Qualified  bool     `json:"qualified"`
	Required   bool     `json:"required"`
}
type SourceStatistics struct {
	ID                                       string
	Records                                  uint64
	Kinds                                    [9]uint64
	Family                                   string
	Country, City, Coordinates, Usage, Exact bool
	VRPComplete                              bool
	Signals                                  map[intelligence.Signal]bool
}

const ProductionReleaseScope = "release-scope-v6"

// Routing observations remain independently derived and recorded even when
// absent. V6 permits that absence; it does not assert routing completeness.
func requiredProductionCapability(name string) (required, known bool) {
	switch name {
	case "country", "region_city", "coordinates", "usage", "risk_reasons", "class_c":
		return true, true
	case "asn_prefix", "rpki", "bgp_origins_paths", "relationships", "tier1":
		return false, true
	default:
		return false, false
	}
}

// ProductionQualification can only be constructed by revalidating a sealed
// intake. Its fields are private so materializers cannot turn a boolean into
// complete VRP or source coverage. Validate binds the exact normalized roots.
type ProductionQualification struct {
	state       intelligence.BuildState
	stateHash   [32]byte
	report      CapabilityReport
	validUntil  time.Time
	vrpComplete bool
}

func QualifyProductionState(ctx context.Context, root string, catalog []Source, now time.Time, binding [32]byte) (*ProductionQualification, error) {
	state, err := intelligence.VerifyPrivateStateSeal(ctx, root, binding)
	if err != nil {
		return nil, err
	}
	return productionFromAuthenticatedState(ctx, root, catalog, state, now, binding)
}

// QualifyProductionStateAtHash selects the exact current or retained generation.
// Retention cannot preserve a withdrawn source, renew a clock, change policy or
// substitute the current state's facts for an older release's receipt.
func QualifyProductionStateAtHash(ctx context.Context, root string, catalog []Source, now time.Time, binding, requested [32]byte) (*ProductionQualification, error) {
	current, err := intelligence.VerifyPrivateStateSeal(ctx, root, binding)
	if err != nil {
		return nil, err
	}
	currentHash, _, err := hashFile(ctx, filepath.Join(root, ".atlas-private", "state-v1.json"), 64<<20)
	if err != nil {
		return nil, err
	}
	currentBytes, err := json.Marshal(current)
	if err != nil || sha256.Sum256(currentBytes) != currentHash {
		return nil, errors.New("authenticated source state changed during selection")
	}
	if requested == currentHash {
		return productionFromAuthenticatedState(ctx, root, catalog, current, now, binding)
	}
	state, err := intelligence.VerifyRetainedPrivateStateSeal(ctx, root, binding, requested)
	if err != nil {
		return nil, err
	}
	if state.EvaluatedAt.After(now) || now.Sub(state.EvaluatedAt) >= 48*time.Hour {
		return nil, errors.New("retained source state exceeds rollback retention")
	}
	currentSources := map[string]intelligence.StoredSource{}
	for _, source := range current.Sources {
		currentSources[source.ID] = source
	}
	for _, source := range state.Sources {
		present, ok := currentSources[source.ID]
		if !ok || !now.Before(present.ExpiresAt) {
			return nil, errors.New("retained source was withdrawn from current intake")
		}
	}
	return productionFromAuthenticatedState(ctx, root, catalog, state, now, binding)
}
func productionFromAuthenticatedState(ctx context.Context, root string, catalog []Source, state intelligence.BuildState, now time.Time, binding [32]byte) (*ProductionQualification, error) {
	report, _, err := RevalidateStoredSources(ctx, root, catalog, state, now, binding)
	if err != nil {
		return nil, err
	}
	if err = report.RequireProduction(); err != nil {
		return nil, err
	}
	data, err := json.Marshal(state)
	if err != nil {
		return nil, err
	}
	q := &ProductionQualification{state: state, stateHash: sha256.Sum256(data), report: report, validUntil: state.EvaluatedAt.Add(720 * time.Hour)}
	for _, s := range state.Sources {
		if s.ExpiresAt.Before(q.validUntil) {
			q.validUntil = s.ExpiresAt
		}
	}
	for _, c := range report.Capabilities {
		if c.Capability == "rpki" {
			q.vrpComplete = c.Qualified
		}
	}
	return q, nil
}
func (q *ProductionQualification) Validate(state intelligence.BuildState, clock time.Time) error {
	if q == nil || q.stateHash == ([32]byte{}) || !clock.Equal(q.state.EvaluatedAt) || !clock.Before(q.validUntil) {
		return errors.New("source qualification does not bind this materialization")
	}
	data, err := json.Marshal(state)
	if err != nil || sha256.Sum256(data) != q.stateHash {
		return errors.New("qualified source state changed")
	}
	return nil
}
func (q *ProductionQualification) VRPComplete() bool {
	return q != nil && q.stateHash != ([32]byte{}) && q.vrpComplete
}
func (q *ProductionQualification) State() intelligence.BuildState {
	if q == nil {
		return intelligence.BuildState{}
	}
	return q.state
}
func (q *ProductionQualification) ValidUntil() time.Time {
	if q == nil {
		return time.Time{}
	}
	return q.validUntil
}
func (q *ProductionQualification) Report() CapabilityReport {
	if q == nil {
		return CapabilityReport{}
	}
	return q.report
}

// ImplementationFingerprint exposes the exact code binding used by the fixture
// ledger; it does not create or renew a certification.
func ImplementationFingerprint(ctx context.Context, root string) ([32]byte, error) {
	return implementationHash(ctx, root)
}

// CanonicalPrivateJSON uses canonical ASCII struct keys and UTF-8 string values.
// Callers must use ordered structs, not arbitrary post-parse maps.
func CanonicalPrivateJSON(value any) ([]byte, error) {
	var b bytes.Buffer
	e := json.NewEncoder(&b)
	e.SetEscapeHTML(false)
	if err := e.Encode(value); err != nil {
		return nil, err
	}
	data := bytes.TrimSuffix(b.Bytes(), []byte{'\n'})
	// encoding/json escapes JavaScript line/paragraph separators even with
	// EscapeHTML disabled. The private canonical contract uses literal UTF-8.
	// Consume escaped backslash pairs first, preserving a literal "\\u2028"
	// instead of confusing it with an actual encoded separator.
	var canonical bytes.Buffer
	for i := 0; i < len(data); {
		if data[i] == '\\' && i+1 < len(data) {
			if data[i+1] == '\\' {
				canonical.Write(data[i : i+2])
				i += 2
				continue
			}
			if i+6 <= len(data) && (string(data[i:i+6]) == `\u2028` || string(data[i:i+6]) == `\u2029`) {
				if data[i+5] == '8' {
					canonical.WriteRune('\u2028')
				} else {
					canonical.WriteRune('\u2029')
				}
				i += 6
				continue
			}
			canonical.Write(data[i : i+2])
			i += 2
			continue
		}
		canonical.WriteByte(data[i])
		i++
	}
	return canonical.Bytes(), nil
}

type canonicalCredit struct {
	LicenseURL string         `json:"license_url,omitempty"`
	Logo       *canonicalLogo `json:"logo,omitempty"`
	Name       string         `json:"name"`
	Text       string         `json:"text"`
	URL        string         `json:"url"`
}
type canonicalLogo struct {
	Alt    string `json:"alt"`
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

func creditCanonical(a *intelligence.DatasetAttribution) *canonicalCredit {
	if a == nil {
		return nil
	}
	result := &canonicalCredit{LicenseURL: a.LicenseURL, Name: a.Name, Text: a.Text, URL: a.URL}
	if a.Logo != nil {
		result.Logo = &canonicalLogo{a.Logo.Alt, a.Logo.Path, a.Logo.SHA256}
	}
	return result
}
func RightsDigests(s Source) (string, *string, error) {
	r := s.Rights
	var identifier *string
	if r.Identifier != "" {
		value := r.Identifier
		identifier = &value
	}
	license := struct {
		Attribution         *canonicalCredit `json:"attribution,omitempty"`
		AttributionRequired *bool            `json:"attribution_required"`
		Distribution        string           `json:"distribution"`
		EvidenceURL         string           `json:"evidence_url"`
		Identifier          *string          `json:"identifier"`
		ReviewBasis         string           `json:"review_basis"`
		Status              string           `json:"status"`
	}{creditCanonical(r.Attribution), r.AttributionRequired, r.Distribution, r.EvidenceURL, identifier, r.ReviewBasis, r.Status}
	data, err := CanonicalPrivateJSON(license)
	if err != nil {
		return "", nil, err
	}
	digest := sha256.Sum256(data)
	var attribution *string
	if r.AttributionRequired != nil && *r.AttributionRequired && r.Attribution != nil {
		data, err = CanonicalPrivateJSON(creditCanonical(r.Attribution))
		if err != nil {
			return "", nil, err
		}
		h := sha256.Sum256(data)
		v := hex.EncodeToString(h[:])
		attribution = &v
	}
	return hex.EncodeToString(digest[:]), attribution, nil
}

// RevalidateStoredSources opens every hashed normalized partition, re-runs the
// exact reviewed fixture against current adapter bytes, checks rights, clocks,
// dependencies and record semantics, then derives source-only capabilities from
// actual records. It accepts neither caller success flags nor a release manifest
// as proof of source coverage. The caller must first verify the private seal.
func RevalidateStoredSources(ctx context.Context, root string, catalog []Source, state intelligence.BuildState, now time.Time, binding [32]byte) (CapabilityReport, []SourceStatistics, error) {
	var report CapabilityReport
	if state.Version != 2 || state.PolicyHash != binding || binding == ([32]byte{}) || now.IsZero() || state.EvaluatedAt.After(now) || len(state.Sources) > 1000 {
		return report, nil, errors.New("production requires current sealed intake")
	}
	byID := make(map[string]Source, len(catalog))
	for _, s := range catalog {
		if _, ok := byID[s.ID]; ok {
			return report, nil, errors.New("duplicate catalog source")
		}
		byID[s.ID] = s
	}
	stored := make(map[string]intelligence.StoredSource, len(state.Sources))
	parents := map[string]string{}
	hashFamily := map[[32]byte]string{}
	var find func(string) string
	find = func(f string) string {
		p, ok := parents[f]
		if !ok {
			parents[f] = f
			return f
		}
		if p != f {
			parents[f] = find(p)
		}
		return parents[f]
	}
	for _, v := range state.Sources {
		s, ok := byID[v.ID]
		r := v.Receipt
		if !ok || s.Admission != "active" || r == nil || !identity(s.Family) || v.Fingerprint == ([32]byte{}) || r.NormalizationPolicyHash != binding || !r.PayloadVerified || !r.SchemaVerified || r.PayloadHash == ([32]byte{}) || r.PayloadHash != r.ProofPayloadHash || r.ParserVersion != s.Parser.Version || r.SchemaVersion != 3 || r.ProofKind != s.Publication.Kind || r.ProofKind == "github_commit" && !r.ImmutableCommitBound || r.Subscription != (s.Category == "proxy_subscription_ip") {
			return report, nil, errors.New("production source receipt does not match current controls")
		}
		if _, ok := stored[v.ID]; ok {
			return report, nil, errors.New("duplicate production source receipt")
		}
		if s.Rights.Status != "reviewed" || s.Rights.Distribution != "allow" || s.Rights.AttributionRequired == nil || !safeHTTPS(s.Rights.EvidenceURL) || strings.TrimSpace(s.Rights.ReviewBasis) == "" || *s.Rights.AttributionRequired && s.Rights.Attribution == nil || s.Rights.Attribution != nil && s.Rights.Attribution.Validate() != nil {
			return report, nil, errors.New("production source rights or credits incomplete")
		}
		if s.Rights.Attribution != nil && intelligence.ValidateDatasetLogoFile(root, s.Rights.Attribution.Logo) != nil {
			return report, nil, errors.New("production source logo missing or changed")
		}
		if s.MaxAge <= 0 || s.MaxAge > 720*time.Hour || r.PublishedAt.IsZero() || r.PublishedAt.After(state.EvaluatedAt.Add(24*time.Hour)) || !now.Before(v.ExpiresAt) || v.ExpiresAt.After(r.PublishedAt.Add(s.MaxAge)) || v.ExpiresAt.After(r.PublishedAt.Add(720*time.Hour)) || r.Subscription && v.ExpiresAt.After(r.PublishedAt.Add(168*time.Hour)) {
			return report, nil, errors.New("production source receipt expired or extended")
		}
		if !r.ContentValidUntil.IsZero() && (v.ExpiresAt.After(r.ContentValidUntil) || !now.Before(r.ContentValidUntil)) {
			return report, nil, errors.New("production content expired or expiry extended")
		}
		if r.MRTProof != nil {
			content, err := r.MRTProof.ContentHash()
			if err != nil || content != r.PayloadHash || r.ProofKind != "embedded" || r.PublishedAt.After(r.MRTProof.CapturedAt) || r.MRTProof.Through.After(state.EvaluatedAt.Add(24*time.Hour)) || r.MRTProof.CaptureEnd().After(state.EvaluatedAt.Add(24*time.Hour)) {
				return report, nil, errors.New("production MRT content-set proof invalid")
			}
		} else if s.Parser.ID == "mrt-table-dump-v2" {
			return report, nil, errors.New("production MRT snapshot proof missing")
		}
		if err := validateStoredGeoSource(s, v, now); err != nil {
			return report, nil, err
		}
		if r.VRPProof != nil {
			if s.Parser.ID != "rpki-client-json" || r.VRPProof.Validate(state.EvaluatedAt, r.PublishedAt, r.ContentValidUntil) != nil {
				return report, nil, errors.New("production complete VRP proof invalid")
			}
		} else if s.Parser.ID == "rpki-client-json" {
			return report, nil, errors.New("production complete VRP proof missing")
		}
		implementation, ok := selectAdapter(s)
		if !ok || !publicationSupported(s) {
			return report, nil, errors.New("production adapter or publication verifier unavailable")
		}
		if err := (&Engine{workspace: root}).certify(ctx, s, implementation, now); err != nil {
			return report, nil, errors.New("production source certification changed")
		}
		stored[v.ID] = v
		aliases := [][32]byte{r.PayloadHash}
		if r.GeoProof != nil {
			decodedHash, err := r.GeoProof.ContentHash()
			if err != nil {
				return report, nil, err
			}
			aliases = append(aliases, decodedHash)
		}
		for _, content := range aliases {
			left := find(s.Family)
			if previous, ok := hashFamily[content]; ok {
				right := find(previous)
				if left < right {
					parents[right] = left
				} else {
					parents[left] = right
				}
			} else {
				hashFamily[content] = s.Family
			}
		}
	}
	var stats []SourceStatistics
	for _, v := range state.Sources {
		s := byID[v.ID]
		for _, id := range s.Dependencies {
			if _, ok := stored[id]; !ok {
				return report, nil, errors.New("production source dependency missing")
			}
		}
		stat := SourceStatistics{ID: s.ID, Family: find(s.Family), Signals: map[intelligence.Signal]bool{}}
		if err := intelligence.WalkStoredSource(ctx, root, v, func(record intelligence.NormalizedRecord) error {
			if err := record.Validate(); err != nil {
				return err
			}
			stat.Records++
			stat.Kinds[record.Kind-1]++
			if stat.Records > 100_000_000 {
				return errors.New("production normalized record budget exceeded")
			}
			family := ""
			switch record.Kind {
			case intelligence.RecordEvidence:
				x := record.Evidence
				family = x.Family
				canonical, ok := intelligence.CanonicalSignal(x.Signal)
				allowed := false
				for _, signal := range s.Signals {
					p, ok := intelligence.CanonicalSignal(intelligence.Signal(signal))
					allowed = allowed || ok && p == canonical
				}
				if !ok || !allowed || !x.Current || !x.SourcePublishedAt.Equal(v.Receipt.PublishedAt) || !contains(s.PublicFields, "reason_flags") {
					return errors.New("production evidence binding invalid")
				}
				itemClock := x.SourcePublishedAt
				if !x.ItemPublishedAt.IsZero() && x.ItemPublishedAt.Before(itemClock) {
					itemClock = x.ItemPublishedAt
				}
				maximum := s.MaxAge
				if x.SubscriptionLiteral && maximum > 168*time.Hour {
					maximum = 168 * time.Hour
				}
				if !now.Before(itemClock.Add(maximum)) || v.ExpiresAt.After(itemClock.Add(maximum)) {
					return errors.New("production dated evidence expiry extended")
				}
				stat.Signals[canonical] = true
				stat.Exact = stat.Exact || x.Scope == intelligence.Exact
			case intelligence.RecordCoverage:
				x := record.Coverage
				family = x.Family
				if !x.Current || x.Complete && s.Coverage != "complete" {
					return errors.New("production coverage binding invalid")
				}
			case intelligence.RecordGeo:
				x := record.Geo
				family = x.Family
				if !x.Current || x.PhysicalCountry != "" && !contains(s.PublicFields, "physical_country") || x.Region != "" && !contains(s.PublicFields, "region") || x.City != "" && !contains(s.PublicFields, "city") || x.Coordinates != nil && (!contains(s.PublicFields, "latitude") || !contains(s.PublicFields, "longitude")) {
					return errors.New("production geographic field binding invalid")
				}
				stat.Country = stat.Country || x.PhysicalCountry != ""
				stat.City = stat.City || x.PhysicalCountry != "" && x.Region != "" && x.City != ""
				stat.Coordinates = stat.Coordinates || x.PhysicalCountry != "" && x.Region != "" && x.City != "" && x.Coordinates != nil
			case intelligence.RecordUsage:
				x := record.Usage.Evidence
				family = x.Family
				if !x.Current || !contains(s.PublicFields, "usage_type") {
					return errors.New("production usage binding invalid")
				}
				if observed := record.Usage.ObservedAt; !observed.IsZero() && (!now.Before(observed.Add(s.MaxAge)) || v.ExpiresAt.After(observed.Add(s.MaxAge))) {
					return errors.New("production usage item expiry extended")
				}
				stat.Usage = stat.Usage || x.Type != "" && x.Type != "unknown"
			case intelligence.RecordOrigins:
				if !contains(s.PublicFields, "origins") && !contains(s.PublicFields, "bgp_origins") {
					return errors.New("production origin binding invalid")
				}
			case intelligence.RecordVRP:
				if !contains(s.PublicFields, "rpki_status") {
					return errors.New("production VRP binding invalid")
				}
				if until := record.VRP.ValidUntil; !until.IsZero() {
					if v.Receipt.ContentValidUntil.IsZero() || until.Before(v.Receipt.ContentValidUntil) || !now.Before(until) {
						return errors.New("production VRP expiry binding invalid")
					}
				} else if s.Parser.ID == "rpki-client-json" {
					return errors.New("production VRP expiry missing")
				}
			case intelligence.RecordPath:
				family = record.Path.Observation.Family
				if !record.Path.Observation.Current || !contains(s.PublicFields, "bgp_paths") {
					return errors.New("production path binding invalid")
				}
			case intelligence.RecordRelationship:
				if !contains(s.PublicFields, "as_relationships") {
					return errors.New("production relationship binding invalid")
				}
			case intelligence.RecordASNIdentity:
				family = record.ASNIdentity.Family
				if !record.ASNIdentity.Current || !contains(s.PublicFields, "asn") {
					return errors.New("production ASN identity binding invalid")
				}
			}
			if family != "" && family != stat.Family {
				return errors.New("production evidence independence changed")
			}
			return nil
		}); err != nil {
			return report, nil, err
		}
		if stat.Records == 0 {
			return report, nil, errors.New("empty production source")
		}
		if proof := v.Receipt.VRPProof; proof != nil {
			if stat.Kinds[intelligence.RecordVRP-1] != proof.AcceptedRows || stat.Records != proof.AcceptedRows {
				return report, nil, errors.New("complete VRP proof differs from retained records")
			}
			stat.VRPComplete = true
		}
		stats = append(stats, stat)
	}
	sort.Slice(stats, func(i, j int) bool { return stats[i].ID < stats[j].ID })
	report = deriveCapabilities(stats, state.EvaluatedAt)
	return report, stats, nil
}
func contains(values []string, value string) bool {
	for _, v := range values {
		if v == value {
			return true
		}
	}
	return false
}
func deriveCapabilities(stats []SourceStatistics, clock time.Time) CapabilityReport {
	families := func(match func(SourceStatistics) bool) []string {
		set := map[string]bool{}
		for _, s := range stats {
			if match(s) {
				set[s.Family] = true
			}
		}
		values := make([]string, 0, len(set))
		for f := range set {
			values = append(values, f)
		}
		sort.Strings(values)
		return values
	}
	report := CapabilityReport{EvaluatedAt: clock.Unix(), IncludedSources: len(stats), ReleaseScope: ProductionReleaseScope, SchemaVersion: 1}
	add := func(name string, minimum int, match func(SourceStatistics) bool) {
		fs := families(match)
		report.Capabilities = append(report.Capabilities, Capability{Capability: name, Families: fs, Qualified: len(fs) >= minimum, Required: true})
	}
	add("country", 1, func(s SourceStatistics) bool { return s.Country })
	add("region_city", 2, func(s SourceStatistics) bool { return s.City })
	add("coordinates", 2, func(s SourceStatistics) bool { return s.Coordinates })
	add("asn_prefix", 1, func(s SourceStatistics) bool { return s.Kinds[intelligence.RecordOrigins-1] > 0 })
	add("usage", 1, func(s SourceStatistics) bool { return s.Usage })
	add("class_c", 1, func(s SourceStatistics) bool { return s.Exact })
	add("rpki", 1, func(s SourceStatistics) bool { return s.VRPComplete })
	originFamilies := families(func(s SourceStatistics) bool { return s.Kinds[intelligence.RecordOrigins-1] > 0 })
	pathFamilies := families(func(s SourceStatistics) bool { return s.Kinds[intelligence.RecordPath-1] > 0 })
	report.Capabilities = append(report.Capabilities, Capability{Capability: "bgp_origins_paths", Families: pathFamilies, Qualified: len(originFamilies) > 0 && len(pathFamilies) >= 2, Required: true})
	add("relationships", 1, func(s SourceStatistics) bool { return s.Kinds[intelligence.RecordRelationship-1] > 0 })
	paths := families(func(s SourceStatistics) bool { return s.Kinds[intelligence.RecordPath-1] > 0 })
	relations := families(func(s SourceStatistics) bool { return s.Kinds[intelligence.RecordRelationship-1] > 0 })
	tier := append(append([]string{}, paths...), relations...)
	sort.Strings(tier)
	tier = uniqueStrings(tier)
	report.Capabilities = append(report.Capabilities, Capability{Capability: "tier1", Families: tier, Qualified: len(paths) >= 2 && len(relations) > 0, Required: true})
	allSignals := map[intelligence.Signal]bool{}
	for _, s := range stats {
		for signal := range s.Signals {
			allSignals[signal] = true
		}
	}
	// Detection support is not a claim that every category is present in every
	// snapshot. One or more actual positive observations establish this release
	// capability; absent categories and unlisted addresses remain unknown.
	risk := len(allSignals) > 0
	report.Capabilities = append(report.Capabilities, Capability{Capability: "risk_reasons", Families: families(func(s SourceStatistics) bool { return len(s.Signals) > 0 }), Qualified: risk, Required: true})
	for i := range report.Capabilities {
		report.Capabilities[i].Required, _ = requiredProductionCapability(report.Capabilities[i].Capability)
	}
	sort.Slice(report.Capabilities, func(i, j int) bool { return report.Capabilities[i].Capability < report.Capabilities[j].Capability })
	return report
}
func uniqueStrings(values []string) []string {
	out := values[:0]
	for _, v := range values {
		if len(out) == 0 || out[len(out)-1] != v {
			out = append(out, v)
		}
	}
	return out
}
func (r CapabilityReport) RequireProduction() error {
	if r.SchemaVersion != 1 || r.ReleaseScope != ProductionReleaseScope || r.IncludedSources <= 0 || len(r.Capabilities) != 11 {
		return errors.New("production_blocked: current nonempty source capability report required")
	}
	var missing []string
	seen := make(map[string]bool, len(r.Capabilities))
	for _, c := range r.Capabilities {
		required, known := requiredProductionCapability(c.Capability)
		if !known || seen[c.Capability] || c.Required != required {
			return errors.New("production_blocked: source capability policy differs")
		}
		seen[c.Capability] = true
		if required && !c.Qualified {
			missing = append(missing, c.Capability)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("production_blocked: unqualified source capabilities: %s", strings.Join(missing, ", "))
	}
	return nil
}
