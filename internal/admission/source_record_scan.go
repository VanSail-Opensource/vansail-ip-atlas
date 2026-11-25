package admission

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"vansail-ip-atlas/internal/intelligence"
)

// sourceRecordScan validates all source-specific predicates against the actual
// typed records. One family can be observed per source. Its final canonical
// family is checked once all receipt payload aliases are known.
type sourceRecordScan struct {
	googleDigest  *intelligence.GoogleNetworkDigest
	nroDigest     *intelligence.NRORegistrationDigest
	rootAddresses rootAddressSet
	azureHosts    map[netip.Addr]bool
	source        Source
	clocks        intelligence.SourceRecordClocks
	now           time.Time
	stat          SourceStatistics
	err           error
}

func newSourceRecordScan(s Source, clocks intelligence.SourceRecordClocks, now time.Time) *sourceRecordScan {
	s.Signals = append([]string(nil), s.Signals...)
	s.PublicFields = append([]string(nil), s.PublicFields...)
	scan := &sourceRecordScan{source: s, clocks: clocks, now: now, stat: SourceStatistics{ID: clocks.ID, Signals: map[intelligence.Signal]bool{}}}
	if googleNetworkSource(s) {
		scan.googleDigest = new(intelligence.GoogleNetworkDigest)
	}
	if nroSource(s) {
		scan.nroDigest = new(intelligence.NRORegistrationDigest)
	}
	if azureServiceSource(s) {
		scan.azureHosts = map[netip.Addr]bool{}
	}
	if rootZoneSource(s) {
		scan.rootAddresses = make(rootAddressSet, 2*rootServerCount)
	}
	return scan
}

func (scan *sourceRecordScan) accept(record intelligence.NormalizedRecord) error {
	s, v, now, stat := &scan.source, &scan.clocks, scan.now, &scan.stat
	if err := record.Validate(); err != nil {
		return err
	}
	if scan.googleDigest != nil {
		if err := scan.googleDigest.Add(record); err != nil {
			return err
		}
	}
	if scan.nroDigest != nil {
		if err := scan.nroDigest.Add(record); err != nil {
			return err
		}
		if record.Geo.Weight != s.Weight {
			return errors.New("NRO registration source weight differs")
		}
	}
	if scan.azureHosts != nil {
		if !intelligence.AzureHostObservation(record) || record.Evidence.Weight != s.Weight || scan.azureHosts[record.Evidence.Address] || len(scan.azureHosts) >= intelligence.MaxAzureServiceHosts {
			return errors.New("unqualified Azure hosting observation")
		}
		scan.azureHosts[record.Evidence.Address] = true
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
		if !ok || !allowed || !x.Current || !x.SourcePublishedAt.Equal(v.PublishedAt) || !contains(s.PublicFields, "reason_flags") {
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
		if !x.Current || x.RegistrationCountry != "" && !contains(s.PublicFields, "registration_country") || x.PhysicalCountry != "" && !contains(s.PublicFields, "physical_country") || x.Region != "" && !contains(s.PublicFields, "region") || x.City != "" && !contains(s.PublicFields, "city") || x.Coordinates != nil && (!contains(s.PublicFields, "latitude") || !contains(s.PublicFields, "longitude")) {
			return errors.New("production geographic field binding invalid")
		}
		stat.Country = stat.Country || x.PhysicalCountry != ""
		stat.City = stat.City || x.PhysicalCountry != "" && x.Region != "" && x.City != ""
		stat.Coordinates = stat.Coordinates || x.PhysicalCountry != "" && x.Region != "" && x.City != "" && x.Coordinates != nil
	case intelligence.RecordUsage:
		x := record.Usage.Evidence
		family = x.Family
		if scan.rootAddresses != nil {
			if !scan.rootAddresses.add(record.Usage, v.PublishedAt) {
				return errors.New("production DNS root service binding invalid")
			}
		} else if !x.Current || !contains(s.PublicFields, "usage_type") {
			return errors.New("production usage binding invalid")
		}
		if observed := record.Usage.ObservedAt; !observed.IsZero() && (!now.Before(observed.Add(s.MaxAge)) || v.ExpiresAt.After(observed.Add(s.MaxAge))) {
			return errors.New("production usage item expiry extended")
		}
		stat.Usage = stat.Usage || x.Type != "" && x.Type != "unknown"
	case intelligence.RecordNetworkOrganization:
		if scan.googleDigest == nil {
			return errors.New("production network organization source binding invalid")
		}
		if record.NetworkOrganization.Prefix.Addr().Is4() {
			stat.googleIPv4++
		}
	case intelligence.RecordOrigins:
		if !contains(s.PublicFields, "origins") && !contains(s.PublicFields, "bgp_origins") {
			return errors.New("production origin binding invalid")
		}
		if len(record.Origins.Origins) > 0 {
			stat.OriginObservations++
		} else {
			stat.UnknownOriginBoundaries++
		}
	case intelligence.RecordVRP:
		if !contains(s.PublicFields, "rpki_status") {
			return errors.New("production VRP binding invalid")
		}
		until := record.VRP.ValidUntil
		if proof := v.VRP; proof.Version == 2 {
			if until.IsZero() || !proof.ObservedAt.Before(until) || until.Before(proof.CoverageValidUntil) {
				return errors.New("production VRP observation expiry binding invalid")
			}
			if stat.VRPCoverageValidUntil.IsZero() || until.Before(stat.VRPCoverageValidUntil) {
				stat.VRPCoverageValidUntil = until
			}
		} else if !until.IsZero() {
			if v.ContentValidUntil.IsZero() || until.Before(v.ContentValidUntil) || !now.Before(until) {
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
	if family != "" && stat.Family != "" && family != stat.Family {
		return errors.New("production evidence independence changed")
	}
	if family != "" {
		stat.Family = family
	}
	return nil
}

// VerifiedSourceRecords binds the source-specific predicates collected during
// structural verification to the exact clock, catalog and verified state. It is
// process-local. Failed predicates do not prevent the separate Tier-1 history
// operation from observing this structurally verified epoch.
type VerifiedSourceRecords struct {
	self        *VerifiedSourceRecords
	verified    *intelligence.VerifiedPrivateState
	catalogHash [32]byte
	now         time.Time
	records     map[string]*sourceRecordScan
}

func VerifySourceRecordsForTier1(ctx context.Context, root string, catalog []Source, now time.Time, binding [32]byte) (*VerifiedSourceRecords, intelligence.BuildState, error) {
	_, catalogHash, catalogErr := sourceValidationIdentity(root, catalog)
	byID := make(map[string]Source)
	if catalogErr == nil {
		for _, s := range catalog {
			byID[s.ID] = s
		}
	}
	// Catalog qualification failures stay behind the authenticated Tier-1 epoch.
	// No records can support qualification through an invalid catalog.
	v := &VerifiedSourceRecords{catalogHash: catalogHash, now: now, records: make(map[string]*sourceRecordScan)}
	visit := func(clocks intelligence.SourceRecordClocks) func(intelligence.NormalizedRecord) {
		s, ok := byID[clocks.ID]
		// Unknown or duplicate receipts are rejected by normal source controls.
		if !ok || v.records[clocks.ID] != nil {
			return nil
		}
		scan := newSourceRecordScan(s, clocks, now)
		v.records[clocks.ID] = scan
		return func(record intelligence.NormalizedRecord) {
			if scan.err == nil {
				scan.err = scan.accept(record)
			}
		}
	}
	verified, state, err := intelligence.VerifyPrivateStateForTier1WithRecords(ctx, root, binding, visit)
	if err != nil {
		return nil, intelligence.BuildState{}, err
	}
	v.self, v.verified = v, verified
	return v, state, nil
}

func (v *VerifiedSourceRecords) PrivateState() *intelligence.VerifiedPrivateState {
	if v == nil || v.self != v {
		return nil
	}
	return v.verified
}

// Qualify performs all normal source control, clock, independence and receipt
// checks. Only the per-record predicates already verified during this exact
// structural traversal are reused. RevalidateFor verifies every current object
// byte plus the state, key and seal at this boundary.
func (v *VerifiedSourceRecords) Qualify(ctx context.Context, root string, catalog []Source, now time.Time, binding [32]byte) (*ProductionQualification, error) {
	if v.PrivateState() == nil {
		return nil, errors.New("verified source record handle required")
	}
	return qualifyValidatedSourceSet(validateVerifiedSourceSet(ctx, root, catalog, now, binding, v.verified, v))
}
