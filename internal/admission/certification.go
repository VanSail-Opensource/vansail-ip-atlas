package admission

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

type certification struct {
	SourceID             string `json:"source_id"`
	Parser               string `json:"parser"`
	Schema               string `json:"schema"`
	Version              uint32 `json:"version"`
	FixtureSHA256        string `json:"fixture_sha256"`
	TestedAt             string `json:"tested_at"`
	ImplementationSHA256 string `json:"implementation_sha256"`
}

type ledger struct {
	Version        uint32          `json:"schema_version"`
	Certifications []certification `json:"certifications"`
}

func (e *Engine) certify(ctx context.Context, source Source, adapter adapter, now time.Time) error {
	fixture := source.Fixture
	if fixture.Status != "passed" || !fixture.SchemaObserved || fixture.Synthetic == nil || *fixture.Synthetic || fixture.Parser != source.Parser.ID || fixture.Schema != source.Parser.Schema {
		return errors.New("observed fixture required")
	}
	tested, err := timestamp(fixture.TestedAt)
	if err != nil || tested.After(now.Add(24*time.Hour)) {
		return errors.New("fixture test clock invalid")
	}
	expected, err := decodeHash(fixture.SHA256)
	if err != nil {
		return err
	}
	base := filepath.Join(e.workspace, "fixtures", "source-certification")
	path, err := privateFile(base, filepath.Join(e.workspace, filepath.FromSlash(fixture.Path)))
	if err != nil {
		return err
	}
	actual, size, err := hashFile(ctx, path, 64<<20)
	if err != nil || actual != expected {
		return errors.New("fixture hash mismatch")
	}
	ledgerPath, err := privateFile(base, filepath.Join(base, "adapter-certifications.json"))
	if err != nil {
		return err
	}
	data, err := boundedFile(ctx, ledgerPath, 1<<20)
	if err != nil {
		return err
	}
	var reviews ledger
	if err := strictJSON(data, &reviews); err != nil || reviews.Version != 1 || len(reviews.Certifications) > 1000 {
		return errors.New("review ledger invalid")
	}
	codeHash, err := implementationHash(ctx, e.workspace)
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	matched := false
	for _, review := range reviews.Certifications {
		if !identity(review.SourceID) || seen[review.SourceID] {
			return errors.New("review ledger identity invalid")
		}
		seen[review.SourceID] = true
		if review.SourceID == source.ID {
			matched = review.Parser == source.Parser.ID && review.Schema == source.Parser.Schema && review.Version == source.Parser.Version && review.FixtureSHA256 == fixture.SHA256 && review.TestedAt == fixture.TestedAt && review.ImplementationSHA256 == hex.EncodeToString(codeHash[:])
		}
	}
	if !matched {
		return errors.New("current adapter certification missing")
	}
	file, err := os.Open(path)
	if err != nil {
		return errors.New("fixture unavailable")
	}
	defer file.Close()
	// Review evidence is necessary, but not sufficient: the current adapter must
	// still successfully parse the exact reviewed fixture on this run.
	_, err = parsePayload(ctx, file, size, source, adapter, tested)
	return err
}

func privateFile(base, path string) (string, error) {
	base, err := filepath.Abs(base)
	if err != nil {
		return "", errors.New("private fixture path invalid")
	}
	resolvedBase, err := filepath.EvalSymlinks(base)
	if err != nil || resolvedBase != base {
		return "", errors.New("private fixture root escaped")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", errors.New("private fixture path invalid")
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil || resolved != absolute {
		return "", errors.New("private fixture symlink rejected")
	}
	rel, err := filepath.Rel(base, resolved)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return "", errors.New("private fixture escaped root")
	}
	return resolved, nil
}

// implementationHash is byte-for-byte compatible with the Python admission
// ledger: sorted internal/**/*.go relative names, NUL, content, NUL.
func implementationHash(ctx context.Context, workspace string) ([32]byte, error) {
	value, _, err := implementationHashBudget(ctx, workspace, 64<<20)
	return value, err
}

func implementationHashBudget(ctx context.Context, workspace string, budget int64) ([32]byte, int64, error) {
	var result [32]byte
	base := filepath.Join(workspace, "internal")
	resolved, err := filepath.EvalSymlinks(base)
	if err != nil || resolved != base {
		return result, 0, errors.New("adapter implementation root invalid")
	}
	paths := []string{}
	err = filepath.WalkDir(base, func(path string, entry os.DirEntry, err error) error {
		if err != nil || ctx.Err() != nil {
			return errors.New("adapter implementation unavailable")
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return errors.New("adapter implementation symlink rejected")
		}
		if !entry.IsDir() && strings.HasSuffix(path, ".go") {
			paths = append(paths, path)
			if len(paths) > 10000 {
				return errors.New("adapter implementation file budget exceeded")
			}
		}
		return nil
	})
	if err != nil || len(paths) == 0 {
		return result, 0, errors.New("adapter implementation unavailable")
	}
	sort.Slice(paths, func(i, j int) bool { return filepath.ToSlash(paths[i]) < filepath.ToSlash(paths[j]) })
	hash := sha256.New()
	total := int64(0)
	for _, path := range paths {
		data, err := boundedFile(ctx, path, budget-total)
		if err != nil {
			return result, total, err
		}
		total += int64(len(data))
		name, err := filepath.Rel(workspace, path)
		if err != nil {
			return result, total, errors.New("adapter path invalid")
		}
		hash.Write([]byte(filepath.ToSlash(name)))
		hash.Write([]byte{0})
		hash.Write(data)
		hash.Write([]byte{0})
	}
	copy(result[:], hash.Sum(nil))
	return result, total, nil
}

// CertificationFingerprint binds the review ledger, current internal Go bytes
// and every active source's exact controlled fixture bytes. Build orchestration
// must compare it before and after intake so review withdrawal or implementation
// changes cannot evade the final configuration recheck. The total bytes read
// across the ledger, implementation and fixtures cannot exceed 64 MiB.
func CertificationFingerprint(ctx context.Context, workspace string, sources []Source) (output [32]byte, failure error) {
	defer func() {
		if err := ctx.Err(); err != nil {
			output, failure = [32]byte{}, err
		}
	}()
	if err := ctx.Err(); err != nil {
		return output, err
	}
	root, err := filepath.Abs(workspace)
	if err != nil {
		return output, errors.New("certification workspace invalid")
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil || len(sources) > 1000 {
		return output, errors.New("certification workspace or source count invalid")
	}
	base := filepath.Join(root, "fixtures", "source-certification")
	ledgerPath, err := privateFile(base, filepath.Join(base, "adapter-certifications.json"))
	if err != nil {
		return output, err
	}
	data, err := boundedFile(ctx, ledgerPath, 1<<20)
	if err != nil {
		return output, err
	}
	remaining := int64(64<<20) - int64(len(data))
	implementation, used, err := implementationHashBudget(ctx, root, remaining)
	if err != nil {
		return output, err
	}
	remaining -= used
	hash := sha256.New()
	hash.Write([]byte("admission-certification-fingerprint-v1\x00"))
	hash.Write(data)
	hash.Write([]byte{0})
	hash.Write(implementation[:])
	hash.Write([]byte{0})
	ordered := append([]Source(nil), sources...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].ID < ordered[j].ID })
	for index, source := range ordered {
		if !identity(source.ID) || index > 0 && ordered[index-1].ID == source.ID {
			return output, errors.New("certification source identity invalid")
		}
		if source.Admission != "active" {
			continue
		}
		path, err := privateFile(base, filepath.Join(root, filepath.FromSlash(source.Fixture.Path)))
		if err != nil {
			return output, err
		}
		fixture, size, err := hashFile(ctx, path, remaining)
		if err != nil {
			return output, err
		}
		remaining -= size
		hash.Write([]byte(source.ID + "\x00" + source.Fixture.Path + "\x00"))
		hash.Write(fixture[:])
		hash.Write([]byte{0})
	}
	copy(output[:], hash.Sum(nil))
	return output, nil
}

func decodeHash(value string) ([32]byte, error) {
	var digest [32]byte
	if len(value) != 64 || strings.ToLower(value) != value {
		return digest, errors.New("hash invalid")
	}
	data, err := hex.DecodeString(value)
	if err != nil {
		return digest, errors.New("hash invalid")
	}
	copy(digest[:], data)
	if digest == ([32]byte{}) {
		return digest, errors.New("hash invalid")
	}
	return digest, nil
}

func boundedFile(ctx context.Context, path string, bound int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || bound <= 0 || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > bound {
		return nil, errors.New("bounded private file invalid")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("private file unavailable")
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(contextReader{ctx, file}, bound+1))
	if err != nil || int64(len(data)) > bound || int64(len(data)) != info.Size() {
		return nil, errors.New("private read failed")
	}
	return data, nil
}

// Strict JSON additionally rejects case-insensitive duplicate member names;
// encoding/json otherwise accepts duplicate and folded struct keys silently.
func strictJSON(data []byte, target any) error {
	if err := uniqueJSON(data); err != nil {
		return err
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return errors.New("typed JSON invalid")
	}
	if decoder.Decode(new(json.RawMessage)) != io.EOF {
		return errors.New("JSON trailing data")
	}
	return nil
}

func uniqueJSON(data []byte) error {
	if !utf8.Valid(data) {
		return errors.New("JSON UTF-8 invalid")
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.UseNumber()
	nodes := 0
	var visit func(int) error
	visit = func(depth int) error {
		nodes++
		if depth > 32 || nodes > 100000 {
			return errors.New("JSON structure budget exceeded")
		}
		token, err := decoder.Token()
		if err != nil {
			return errors.New("JSON invalid")
		}
		if delim, ok := token.(json.Delim); ok {
			switch delim {
			case '{':
				keys := map[string]bool{}
				for decoder.More() {
					key, err := decoder.Token()
					name, ok := key.(string)
					if err != nil || !ok || len(name) > 4096 {
						return errors.New("JSON key invalid")
					}
					folded := foldKey(name)
					if keys[folded] {
						return errors.New("duplicate JSON key")
					}
					keys[folded] = true
					if err := visit(depth + 1); err != nil {
						return err
					}
				}
			case '[':
				for decoder.More() {
					if err := visit(depth + 1); err != nil {
						return err
					}
				}
			default:
				return errors.New("JSON delimiter invalid")
			}
			end, err := decoder.Token()
			if err != nil || delim == '{' && end != json.Delim('}') || delim == '[' && end != json.Delim(']') {
				return errors.New("JSON delimiter invalid")
			}
		}
		return nil
	}
	if err := visit(0); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errors.New("JSON trailing data")
	}
	return nil
}

func foldKey(value string) string {
	var output strings.Builder
	for _, r := range value {
		minimum := r
		for next := unicode.SimpleFold(r); next != r; next = unicode.SimpleFold(next) {
			if next < minimum {
				minimum = next
			}
		}
		output.WriteRune(minimum)
	}
	return output.String()
}
