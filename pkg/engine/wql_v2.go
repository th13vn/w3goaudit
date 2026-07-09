package engine

import (
	"fmt"

	"gopkg.in/yaml.v3"
)

// TemplateV2 is the WQL v2 template surface: meta (unchanged from v1) plus
// select/from/where. It is a pure parsing/decoding structure — lowering to
// the existing Rule IR (Template/QueryBlock) is implemented in a later task.
//
// Select accepts either a scalar block kind or a list of block kinds (combo
// select), so it is decoded as a raw yaml.Node and interpreted by lowering.
type TemplateV2 struct {
	Meta   TemplateMeta `yaml:"meta"`
	Select yaml.Node    `yaml:"select"`
	From   string       `yaml:"from"`
	Where  []MatcherV2  `yaml:"where"`
}

// MatcherV2 is a single WQL v2 matcher: a one-key map whose key selects the
// matcher form (block, name, arg.N, has, in, preset, not, any, all, ...) and
// whose value is the matcher's argument (scalar, map, or list).
type MatcherV2 map[string]yaml.Node

// key returns the matcher's single key/value pair. ok is false when the map
// does not contain exactly one key (malformed matcher).
func (m MatcherV2) key() (string, yaml.Node, bool) {
	if len(m) != 1 {
		return "", yaml.Node{}, false
	}
	for k, v := range m {
		return k, v, true
	}
	return "", yaml.Node{}, false
}

// v2Probe is used only for cheap format detection: does the document look
// like a v2 template (select/from present) or a v1 template (query present)?
//
// Select/Query are plain (non-pointer) yaml.Node fields: yaml.v3 fails to
// unmarshal a scalar node into a *yaml.Node field (it only special-cases the
// value type), so presence is instead detected via Kind != 0 (the zero Node
// has Kind 0, which is not a valid yaml.Kind).
type v2Probe struct {
	Select yaml.Node `yaml:"select"`
	From   *string   `yaml:"from"`
	Query  yaml.Node `yaml:"query"`
}

// isV2Source reports whether raw looks like a WQL v2 template document: it
// has a top-level select and/or from key, and no top-level query key. Any
// unmarshal error (malformed/non-template YAML) is treated as "not v2".
func isV2Source(raw []byte) bool {
	var probe v2Probe
	if err := yaml.Unmarshal(raw, &probe); err != nil {
		return false
	}
	return (probe.Select.Kind != 0 || probe.From != nil) && probe.Query.Kind == 0
}

// parseV2 unmarshals raw into a TemplateV2. It returns an error if the
// document has neither select nor from set, since a v2 document needs at
// least one of them to identify what/where to search.
func parseV2(raw []byte) (*TemplateV2, error) {
	var tmpl TemplateV2
	if err := yaml.Unmarshal(raw, &tmpl); err != nil {
		return nil, fmt.Errorf("parseV2: %w", err)
	}

	if tmpl.Select.Kind == 0 && tmpl.From == "" {
		return nil, fmt.Errorf("parseV2: template %q has neither select nor from", tmpl.Meta.ID)
	}

	return &tmpl, nil
}
