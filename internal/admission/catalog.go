package admission

import (
	"bytes"
	"errors"
	"io"
	"math"
	"strings"
	"time"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

type fieldTargets []string

func (targets *fieldTargets) UnmarshalYAML(node *yaml.Node) error {
	switch {
	case node.Kind == yaml.ScalarNode && node.Tag == "!!null":
		*targets = nil
	case node.Kind == yaml.ScalarNode && node.Tag == "!!str":
		*targets = []string{node.Value}
	case node.Kind == yaml.SequenceNode:
		values := []string{}
		for _, value := range node.Content {
			if value.Kind != yaml.ScalarNode || value.Tag != "!!str" {
				return errors.New("field mapping scalar invalid")
			}
			values = append(values, value.Value)
		}
		*targets = values
	default:
		return errors.New("field mapping shape invalid")
	}
	return nil
}

type catalogSource struct {
	ID       string `yaml:"id"`
	Family   string `yaml:"evidence_family"`
	Category string `yaml:"category"`
	State    string `yaml:"admission"`
	Scope    string `yaml:"scope"`
	Download struct {
		URL     string `yaml:"url"`
		Format  string `yaml:"format"`
		Maximum int64  `yaml:"max_compressed_mib"`
	} `yaml:"download"`
	Refresh struct {
		Maximum string `yaml:"max_stale"`
	} `yaml:"refresh"`
	Trust struct {
		Weight float64 `yaml:"source_weight"`
	} `yaml:"trust"`
	Dependencies []string `yaml:"depends_on"`
	Rights       struct {
		Status       string `yaml:"status"`
		Distribution string `yaml:"distribution"`
		EvidenceURL  string `yaml:"evidence_url"`
		ReviewBasis  string `yaml:"review_basis"`
		Attribution  *bool  `yaml:"attribution_required"`
	} `yaml:"license"`
	Parser struct {
		ID      string `yaml:"id"`
		Schema  string `yaml:"schema"`
		Version uint32 `yaml:"version"`
	} `yaml:"parser"`
	Fixture struct {
		Status    string `yaml:"status"`
		Path      string `yaml:"path"`
		SHA256    string `yaml:"sha256"`
		Parser    string `yaml:"parser"`
		Schema    string `yaml:"schema"`
		TestedAt  string `yaml:"tested_at"`
		Observed  bool   `yaml:"schema_observed"`
		Synthetic *bool  `yaml:"synthetic"`
	} `yaml:"fixture"`
	Publication struct {
		Kind    string `yaml:"kind"`
		Locator string `yaml:"locator"`
		Field   string `yaml:"field"`
	} `yaml:"publication_proof"`
	Coverage struct {
		Kind  string `yaml:"kind"`
		Scope string `yaml:"scope"`
	} `yaml:"coverage"`
	PublicFields  []string                `yaml:"public_fields"`
	Fields        []string                `yaml:"fields"`
	FieldMappings map[string]fieldTargets `yaml:"field_mappings"`
}

// DecodeCatalog projects the already closed-schema-validated sources.yaml into
// executable controls. It is not a replacement for tools/validate_blueprint.py:
// that validator checks global budgets, the other four configs and unused
// catalog fields. Ambiguous YAML and duplicate IDs/dependency cycles are rejected
// here independently. Unsupported discovery/multiple-asset entries retain an
// empty URL and cannot pass Ingest's download/proof contract.
func DecodeCatalog(reader io.Reader) ([]Source, error) {
	data, err := io.ReadAll(io.LimitReader(reader, (2<<20)+1))
	if err != nil || len(data) > 2<<20 || !utf8.Valid(data) {
		return nil, errors.New("bounded UTF-8 source catalog required")
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	var document yaml.Node
	if decoder.Decode(&document) != nil || decoder.Decode(new(yaml.Node)) != io.EOF || validateYAML(&document, 0) != nil {
		return nil, errors.New("unambiguous source YAML required")
	}
	var catalog struct {
		Version uint16          `yaml:"schema_version"`
		Sources []catalogSource `yaml:"sources"`
	}
	if document.Decode(&catalog) != nil || catalog.Version != 3 || len(catalog.Sources) > 1000 {
		return nil, errors.New("source catalog projection invalid")
	}
	output := make([]Source, 0, len(catalog.Sources))
	ids := map[string]int{}
	for _, raw := range catalog.Sources {
		if !identity(raw.ID) || !identity(raw.Family) || raw.Scope != raw.Coverage.Scope || raw.Download.Maximum < 0 || raw.Download.Maximum > 1024 || raw.Download.Maximum == 0 && raw.Download.URL != "" {
			return nil, errors.New("source catalog identity or bounds invalid")
		}
		if _, exists := ids[raw.ID]; exists {
			return nil, errors.New("duplicate source catalog identity")
		}
		age, err := time.ParseDuration(raw.Refresh.Maximum)
		if err != nil || age <= 0 || age > 720*time.Hour {
			return nil, errors.New("source catalog clock invalid")
		}
		mappings := make(map[string][]string, len(raw.FieldMappings))
		for input, outputs := range raw.FieldMappings {
			// Null is an intentional drop, not an executable public mapping.
			if len(outputs) > 0 {
				mappings[input] = append([]string(nil), outputs...)
			}
		}
		output = append(output, Source{ID: raw.ID, Family: raw.Family, Category: raw.Category, Admission: raw.State, URL: raw.Download.URL, Format: raw.Download.Format, MaxCompressedBytes: raw.Download.Maximum << 20,
			MaxAge: age, Weight: raw.Trust.Weight, Dependencies: append([]string(nil), raw.Dependencies...),
			Rights:      Rights{raw.Rights.Status, raw.Rights.Distribution, raw.Rights.EvidenceURL, raw.Rights.ReviewBasis, raw.Rights.Attribution},
			Parser:      Parser{raw.Parser.ID, raw.Parser.Schema, raw.Parser.Version},
			Fixture:     Fixture{raw.Fixture.Status, raw.Fixture.Path, raw.Fixture.SHA256, raw.Fixture.Parser, raw.Fixture.Schema, raw.Fixture.TestedAt, raw.Fixture.Observed, raw.Fixture.Synthetic},
			Publication: Publication{raw.Publication.Kind, raw.Publication.Locator, raw.Publication.Field}, Coverage: raw.Coverage.Kind, Scope: raw.Scope, PublicFields: append([]string(nil), raw.PublicFields...), Fields: append([]string(nil), raw.Fields...), FieldMappings: mappings})
		ids[raw.ID] = len(output) - 1
	}
	state := make([]uint8, len(output))
	var visit func(int) error
	visit = func(index int) error {
		if state[index] == 1 {
			return errors.New("source catalog dependency cycle")
		}
		if state[index] == 2 {
			return nil
		}
		state[index] = 1
		seen := map[string]bool{}
		for _, dependency := range output[index].Dependencies {
			other, exists := ids[dependency]
			if !exists || seen[dependency] {
				return errors.New("source catalog dependency invalid")
			}
			seen[dependency] = true
			if err := visit(other); err != nil {
				return err
			}
		}
		state[index] = 2
		return nil
	}
	for index := range output {
		if err := visit(index); err != nil {
			return nil, err
		}
	}
	return output, nil
}

func validateYAML(node *yaml.Node, depth int) error {
	if depth > 32 || node.Kind == yaml.AliasNode || node.Anchor != "" {
		return errors.New("YAML aliases or depth invalid")
	}
	if node.Kind == yaml.MappingNode {
		seen := map[string]bool{}
		for index := 0; index < len(node.Content); index += 2 {
			key := node.Content[index]
			if key.Kind != yaml.ScalarNode || key.Tag != "!!str" || seen[key.Value] {
				return errors.New("YAML duplicate or non-string key")
			}
			seen[key.Value] = true
		}
	}
	if node.Kind == yaml.ScalarNode && node.Tag == "!!float" {
		var value float64
		if node.Decode(&value) != nil || math.IsNaN(value) || math.IsInf(value, 0) {
			return errors.New("YAML finite scalar required")
		}
	}
	if node.Kind == yaml.ScalarNode && strings.HasPrefix(node.Tag, "!") && !strings.HasPrefix(node.Tag, "!!") {
		return errors.New("YAML custom tags forbidden")
	}
	for _, child := range node.Content {
		if err := validateYAML(child, depth+1); err != nil {
			return err
		}
	}
	return nil
}
