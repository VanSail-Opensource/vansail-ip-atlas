package intelligence

import (
	"crypto/sha256"
	"testing"
	"time"
)

func TestDecodedGeoIdentityDedupeAndReceiptBinding(t *testing.T) {
	p, s, binding := stateFixture()
	s.GeoProof = &GeoSourceProof{Version: 1, AssetURL: "https://publisher.example/month.csv.gz", DecodedSHA256: sha256.Sum256([]byte("same full decoded CSV")), DecodedBytes: 100, UpstreamClock: s.PublishedAt}
	secondPolicy, second := p, s
	secondPolicy.ID = "second-geo"
	secondPolicy.Family = "independent-label"
	second.ID = secondPolicy.ID
	second.PayloadHash = sha256.Sum256([]byte("different archive wrapper"))
	second.ProofPayloadHash = second.PayloadHash
	second.GeoProof = cloneGeoProof(s.GeoProof)
	first, err := Reconcile(BuildState{}, []SourcePolicy{p, secondPolicy}, []SourceSnapshot{s, second}, clock(), binding)
	if err != nil || len(first.State.Sources) != 2 {
		t.Fatal(err)
	}
	if first.State.Sources[0].Records[0].Evidence.Family != first.State.Sources[1].Records[0].Evidence.Family {
		t.Fatal("identical CSV wrappers manufactured independent families")
	}
	saved := first.State.Sources[0].Receipt.GeoProof.DecodedBytes
	s.GeoProof.DecodedBytes++
	if first.State.Sources[0].Receipt.GeoProof.DecodedBytes != saved {
		t.Fatal("source receipt aliases caller proof")
	}
	s.GeoProof.DecodedBytes = saved
	second.GeoProof.PageSHA256 = sha256.Sum256([]byte("changed publisher evidence"))
	changed, err := Reconcile(first.State, []SourcePolicy{p, secondPolicy}, []SourceSnapshot{s, second}, clock(), binding)
	if err != nil || !changed.FullRebuild {
		t.Fatal("publisher proof escaped source fingerprint", err)
	}
	second.GeoProof.UpstreamClock = clock().Add(-time.Hour)
	bad, err := Reconcile(first.State, []SourcePolicy{p, secondPolicy}, []SourceSnapshot{s, second}, clock(), binding)
	if err != nil || len(bad.State.Sources) != 1 {
		t.Fatal("later admitted clock bypassed older decoded proof", err)
	}
}
