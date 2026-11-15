package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"time"

	"vansail-ip-atlas/internal/admission"
	"vansail-ip-atlas/internal/intelligence"
	"vansail-ip-atlas/internal/via3"
)

// All fields are private and canonical ASCII-key ordered. proof_sha256 is the
// payload digest established by publisher proof, not a metadata download hash.
type includedProductionSource struct {
	AttributionSHA256 *string `json:"attribution_sha256"`
	EvidenceFamily    string  `json:"evidence_family"`
	ExpiresAt         int64   `json:"expires_at"`
	Parser            string  `json:"parser"`
	ParserVersion     uint32  `json:"parser_version"`
	PayloadSHA256     string  `json:"payload_sha256"`
	ProofSHA256       string  `json:"proof_sha256"`
	PublishedAt       int64   `json:"published_at"`
	RightsSHA256      string  `json:"rights_sha256"`
	Schema            string  `json:"schema"`
	SourceID          string  `json:"source_id"`
}
type productionReceipt struct {
	CertificationSHA256       string                     `json:"certification_sha256"`
	EvaluatedAt               int64                      `json:"evaluated_at"`
	ImplementationSHA256      string                     `json:"implementation_sha256"`
	IncludedSources           []includedProductionSource `json:"included_sources"`
	Mode                      string                     `json:"mode"`
	NormalizationConfigSHA256 string                     `json:"normalization_config_sha256"`
	NormalizedStateSHA256     string                     `json:"normalized_state_sha256"`
	ReleaseID                 string                     `json:"release_id"`
	ReleaseManifestSHA256     string                     `json:"release_manifest_sha256"`
	ReleaseScope              string                     `json:"release_scope"`
	RightsAuditSHA256         string                     `json:"rights_audit_sha256"`
	SchemaVersion             uint16                     `json:"schema_version"`
	SourceCapabilitiesSHA256  string                     `json:"source_capabilities_sha256"`
	SourceCatalogSHA256       string                     `json:"source_catalog_sha256"`
	ValidUntil                int64                      `json:"valid_until"`
}
type productionBinding struct {
	root                                                                                              string
	catalog                                                                                           []admission.Source
	configHash, certificationHash, stateHash, catalogHash, rightsHash, implementationHash, policyHash [32]byte
	qualification                                                                                     *admission.ProductionQualification
	currentStateHash                                                                                  [32]byte
}

func resolveProductionRoot(workspace string) (string, error) {
	root, err := filepath.Abs(workspace)
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(root)
}
func readPrivateInput(ctx context.Context, path string, maximum int64) ([]byte, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil || resolved != absolute {
		return nil, errors.New("private input cannot traverse links")
	}
	f, err := openRegularInput(absolute, maximum)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(inputContextReader{ctx, f}, maximum+1))
	if err != nil || int64(len(data)) > maximum {
		return nil, errors.New("private input exceeds byte budget")
	}
	return data, nil
}
func loadProductionBinding(ctx context.Context, root string, now time.Time) (productionBinding, error) {
	return loadProductionBindingAtHash(ctx, root, now, nil)
}
func loadProductionBindingAtHash(ctx context.Context, root string, now time.Time, requested *[32]byte) (productionBinding, error) {
	b := productionBinding{root: root}
	var err error
	// Full closed-schema validation is independent of the executable projection.
	// Its stdout is deliberately withheld because source audit details are private.
	command := exec.CommandContext(ctx, "python", filepath.Join(root, "tools", "validate_blueprint.py"), "--now", now.Format(time.RFC3339))
	command.Dir = root
	if command.Run() != nil {
		return b, errors.New("production requires valid closed configuration contracts")
	}
	var sourceBytes []byte
	b.configHash, sourceBytes, err = intakeConfigHash(root)
	if err != nil {
		return b, err
	}
	b.catalogHash = sha256.Sum256(sourceBytes)
	b.catalog, err = admission.DecodeCatalog(bytes.NewReader(sourceBytes))
	if err != nil {
		return b, err
	}
	b.certificationHash, err = admission.CertificationFingerprint(ctx, root, b.catalog)
	if err != nil {
		return b, err
	}
	b.policyHash = sha256.Sum256(append(append([]byte("intake-policy-v1\x00"), b.configHash[:]...), b.certificationHash[:]...))
	b.currentStateHash, err = privateStateHash(ctx, root)
	if err != nil {
		return b, err
	}
	b.stateHash = b.currentStateHash
	if requested == nil {
		b.qualification, err = admission.QualifyProductionState(ctx, root, b.catalog, now, b.policyHash)
	} else {
		b.stateHash = *requested
		b.qualification, err = admission.QualifyProductionStateAtHash(ctx, root, b.catalog, now, b.policyHash, *requested)
	}
	if err != nil {
		return b, err
	}
	stateBytes, err := json.Marshal(b.qualification.State())
	if err != nil || sha256.Sum256(stateBytes) != b.stateHash {
		return b, errors.New("production qualification state identity changed")
	}
	audit, err := readPrivateInput(ctx, filepath.Join(root, "SOURCES_AUDIT.md"), 4<<20)
	if err != nil {
		return b, err
	}
	b.rightsHash = sha256.Sum256(audit)
	b.implementationHash, err = admission.ImplementationFingerprint(ctx, root)
	return b, err
}
func digestString(hash [32]byte) string { return hex.EncodeToString(hash[:]) }
func (b productionBinding) receipt(manifest via3.Manifest, manifestBytes []byte) (productionReceipt, error) {
	q := b.qualification
	state := q.State()
	caps, err := admission.CanonicalPrivateJSON(q.Report())
	if err != nil {
		return productionReceipt{}, err
	}
	capHash := sha256.Sum256(caps)
	r := productionReceipt{CertificationSHA256: digestString(b.certificationHash), EvaluatedAt: state.EvaluatedAt.Unix(), ImplementationSHA256: digestString(b.implementationHash), IncludedSources: []includedProductionSource{}, Mode: "production", NormalizationConfigSHA256: digestString(b.configHash), NormalizedStateSHA256: digestString(b.stateHash), ReleaseID: manifest.ReleaseID, ReleaseManifestSHA256: via3.Hash(manifestBytes), ReleaseScope: "release-scope-v5", RightsAuditSHA256: digestString(b.rightsHash), SchemaVersion: 1, SourceCapabilitiesSHA256: digestString(capHash), SourceCatalogSHA256: digestString(b.catalogHash), ValidUntil: manifest.ValidUntil}
	if manifest.Mode != "production" || manifest.ValidFrom != r.EvaluatedAt || manifest.ValidUntil > q.ValidUntil().Unix() {
		return r, errors.New("production manifest outlives qualified input")
	}
	byID := map[string]admission.Source{}
	for _, s := range b.catalog {
		byID[s.ID] = s
	}
	for _, v := range state.Sources {
		s := byID[v.ID]
		rights, attribution, err := admission.RightsDigests(s)
		if err != nil {
			return r, err
		}
		p := v.Receipt
		r.IncludedSources = append(r.IncludedSources, includedProductionSource{attribution, s.Family, v.ExpiresAt.Unix(), s.Parser.ID, s.Parser.Version, digestString(p.PayloadHash), digestString(p.ProofPayloadHash), p.PublishedAt.Unix(), rights, s.Parser.Schema, s.ID})
	}
	sort.Slice(r.IncludedSources, func(i, j int) bool { return r.IncludedSources[i].SourceID < r.IncludedSources[j].SourceID })
	return r, nil
}
func verifyProduction(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("verify-production", flag.ContinueOnError)
	workspace := fs.String("workspace", ".", "reviewed source workspace")
	receipt := fs.String("receipt", ".atlas-private/production-receipt.json", "private exact-artifact qualification")
	atlas := fs.String("atlas", "build-private/production-atlas", "compiled immutable atlas")
	clock := fs.Int64("clock", time.Now().UTC().Unix(), "current UTC validation clock")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if len(fs.Args()) != 0 || *clock < 0 {
		return errors.New("invalid production verification arguments")
	}
	root, err := resolveProductionRoot(*workspace)
	if err != nil {
		return err
	}
	receiptPath := rooted(root, *receipt)
	atlasPath := rooted(root, *atlas)
	data, err := readPrivateInput(ctx, receiptPath, 2<<20)
	if err != nil {
		return err
	}
	var submitted productionReceipt
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&submitted) != nil || decoder.Decode(new(json.RawMessage)) != io.EOF {
		return errors.New("invalid production receipt")
	}
	if _, err := hex.DecodeString(submitted.ReleaseID); err != nil || len(submitted.ReleaseID) != 64 {
		return errors.New("invalid production release identity")
	}
	stateDigest, err := hex.DecodeString(submitted.NormalizedStateSHA256)
	if err != nil || len(stateDigest) != 32 {
		return errors.New("invalid production state identity")
	}
	var requested [32]byte
	copy(requested[:], stateDigest)
	b, err := loadProductionBindingAtHash(ctx, root, time.Unix(*clock, 0).UTC(), &requested)
	if err != nil {
		return err
	}
	manifestBytes, err := readPrivateInput(ctx, filepath.Join(atlasPath, "releases", submitted.ReleaseID, "manifest.json"), 4<<20)
	if err != nil {
		return err
	}
	var manifest via3.Manifest
	if json.Unmarshal(manifestBytes, &manifest) != nil {
		return errors.New("invalid production manifest")
	}
	expected, err := b.receipt(manifest, manifestBytes)
	if err != nil {
		return err
	}
	canonical, err := admission.CanonicalPrivateJSON(expected)
	if err != nil || !bytes.Equal(data, canonical) {
		return errors.New("production receipt differs from current source qualification")
	}
	if err = intelligence.VerifyProductionReceiptSeal(ctx, root, b.policyHash, data, b.stateHash, sha256.Sum256(manifestBytes), time.Unix(manifest.ValidUntil, 0).UTC()); err != nil {
		return errors.New("production artifact lacks its exact compiler-issued attestation")
	}
	if err = verifyProductionObjects(ctx, atlasPath, manifest, manifestBytes, *clock); err != nil {
		return err
	}
	// Recheck inputs after every object has been decoded. A concurrent intake or
	// review change must not qualify a partially mixed release.
	current, err := privateStateHash(ctx, root)
	if err != nil || current != b.currentStateHash {
		return errors.New("production source state changed during verification")
	}
	config, _, err := intakeConfigHash(root)
	if err != nil || config != b.configHash {
		return errors.New("production configuration changed during verification")
	}
	cert, err := admission.CertificationFingerprint(ctx, root, b.catalog)
	if err != nil || cert != b.certificationHash {
		return errors.New("production certification changed during verification")
	}
	fmt.Println("production source-store and immutable artifact verified")
	return nil
}
func verifyProductionObjects(ctx context.Context, root string, m via3.Manifest, manifest []byte, now int64) error {
	if m.Mode != "production" {
		return errors.New("production objects require production manifest mode")
	}
	p := via3.Pointer{FormatVersion: 3, ManifestPath: "/_atlas/releases/" + m.ReleaseID + "/manifest.json", ManifestSHA256: via3.Hash(manifest), ReleaseID: m.ReleaseID}
	pointer, _ := json.Marshal(p)
	load := func(hash string) ([]byte, error) {
		return readPrivateInput(ctx, filepath.Join(root, "objects", hash+".via3"), via3.MaxFile-1)
	}
	if _, err := via3.NewRelease(pointer, manifest, load, func() int64 { return now }); err != nil {
		return err
	}
	for _, object := range m.Objects {
		if err := ctx.Err(); err != nil {
			return err
		}
		data, err := load(object.SHA256)
		if err != nil || len(data) != object.Bytes || via3.Hash(data) != object.SHA256 {
			return errors.New("production object integrity failed")
		}
		shard, err := via3.Read(ctx, data)
		if err != nil {
			return err
		}
		if err = via3.ValidatePublicProfile(shard); err != nil {
			return err
		}
		if shard.Kind != object.Kind {
			return errors.New("production object kind differs from manifest")
		}
	}
	return nil
}
func rooted(root, path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(root, path)
}
func privateReceiptDestination(root, path string) (string, error) {
	p, err := filepath.Abs(rooted(root, path))
	if err != nil {
		return "", err
	}
	if filepath.Dir(p) != filepath.Join(root, ".atlas-private") {
		return "", errors.New("qualification receipt must stay in the private state directory")
	}
	if info, err := os.Lstat(p); err == nil && !info.Mode().IsRegular() {
		return "", errors.New("qualification receipt must be a regular file")
	}
	return p, nil
}
