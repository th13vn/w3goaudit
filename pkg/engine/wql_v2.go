package engine

import (
	"fmt"
	"reflect"
	"strconv"
	"strings"

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

// ---------------------------------------------------------------------------
// Lowering: TemplateV2 -> *Template (the v1 Rule IR the evaluator runs).
//
// The evaluator (Verify/VerifyAtFunctionWithCallees/VerifyAtContract) is NOT
// changed by v2. lower() only builds a v1 Template value; validation and
// normalization (finalizeTemplate) are applied by the caller (Task A4's
// loader wiring), not here.
// ---------------------------------------------------------------------------

// lower converts a parsed WQL v2 template into the v1 Rule IR. See
// .vscode/plans/2026-07-10-w3goaudit-v0.4-C-wql-v2.md (Task A3) and
// .vscode/specs/2026-07-09-wql-v2-language-spec.md for the algorithm this
// implements.
func (t *TemplateV2) lower() (*Template, error) {
	scope, err := fromToScope(t.From)
	if err != nil {
		return nil, err
	}

	selectKinds, err := decodeSelectKinds(t.Select)
	if err != nil {
		return nil, err
	}
	resolvedSelect := make([]string, 0, len(selectKinds))
	for _, sk := range selectKinds {
		v1, ok := blockKindToV1(sk)
		if !ok {
			return nil, fmt.Errorf("select: unknown block kind %q", sk)
		}
		resolvedSelect = append(resolvedSelect, v1)
	}

	// Lower every `where` matcher and merge its AST-layer and context-layer
	// parts into two running aggregates. astAgg feeds Match; ctxAgg feeds
	// Filter — the same filter/match split the v1 evaluator already expects,
	// just derived here instead of authored directly.
	astAgg := &Rule{}
	ctxAgg := &Rule{}
	for _, m := range t.Where {
		astPart, ctxPart, err := lowerMatcher(m)
		if err != nil {
			return nil, err
		}
		if astPart != nil {
			if err := mergeRuleInto(astAgg, astPart); err != nil {
				return nil, err
			}
		}
		if ctxPart != nil {
			if err := mergeRuleInto(ctxAgg, ctxPart); err != nil {
				return nil, err
			}
		}
	}

	match, err := buildMatch(scope, resolvedSelect, astAgg)
	if err != nil {
		return nil, err
	}

	var filter *Rule
	if !ctxAgg.IsEmpty() {
		filter = ctxAgg
	}

	return &Template{
		Meta: t.Meta,
		Query: QueryBlock{
			Scope:  scope,
			Filter: filter,
			Match:  *match,
		},
	}, nil
}

// fromToScope maps a v2 `from` scope name to the v1 Scope constant (language
// spec §4). An empty from defaults to entry_function, matching v1's default.
func fromToScope(from string) (Scope, error) {
	switch from {
	case "", "entry_function":
		return ScopeEntrypoint, nil
	case "function":
		return ScopeFunction, nil
	case "contract":
		return ScopeContract, nil
	case "library":
		return ScopeLibrary, nil
	case "abstract":
		return ScopeAbstract, nil
	case "main_contract":
		return ScopeMainContract, nil
	case "any_contract":
		return ScopeAllContract, nil
	case "source":
		return ScopeSource, nil
	default:
		return "", fmt.Errorf("from: unknown scope %q", from)
	}
}

// decodeSelectKinds decodes TemplateV2.Select, which is either a scalar
// (single block kind) or a sequence (combo select), into a plain string
// slice of the raw v2 block-kind names (not yet resolved to v1). A zero Node
// (select omitted) returns an empty, non-error result — some scopes (notably
// scope: source) can express a template with no select, relying solely on a
// where: regex matcher.
func decodeSelectKinds(node yaml.Node) ([]string, error) {
	switch node.Kind {
	case 0:
		return nil, nil
	case yaml.ScalarNode:
		var s string
		if err := node.Decode(&s); err != nil {
			return nil, fmt.Errorf("select: %w", err)
		}
		return []string{s}, nil
	case yaml.SequenceNode:
		var list []string
		if err := node.Decode(&list); err != nil {
			return nil, fmt.Errorf("select: %w", err)
		}
		return list, nil
	default:
		return nil, fmt.Errorf("select: expected a scalar block kind or a list, got node kind %v", node.Kind)
	}
}

// buildMatch assembles the v1 Match rule from the resolved select kinds and
// the aggregated AST-layer where matchers, per language spec §3 and Task A3
// step 6:
//
//   - scope: source is regex-only: astAgg must contain nothing but Regex.
//   - a combo select (len>1) becomes Match.All, one branch per select kind;
//     the aggregated where-matchers are merged onto the FIRST branch only
//     (language spec §3: "where matchers constrain the primary selected
//     node"; per-branch constraints belong in labeled all: branches, which
//     lower via the "all" matcher case, not here).
//   - a single select wraps the where-matchers in `contains:` — "found
//     somewhere inside the from-scope" — UNLESS the where-matchers already
//     center on a `sequence:`, which is already a "search within" construct
//     and must stay at the top level of Match instead of being nested inside
//     another contains:.
func buildMatch(scope Scope, selectKinds []string, astAgg *Rule) (*Rule, error) {
	if scope == ScopeSource {
		check := *astAgg
		regex := check.Regex
		check.Regex = ""
		if !check.IsEmpty() {
			return nil, fmt.Errorf("from: source scope supports only a top-level regex: matcher in where")
		}
		if regex == "" {
			return nil, fmt.Errorf("from: source scope requires a regex: matcher in where")
		}
		return &Rule{Regex: regex}, nil
	}

	if len(selectKinds) == 0 {
		// No select: the merged AST where-matchers become the Match directly
		// (no Contains wrap) — e.g. `from: contract` + `where: [regex: ...]`
		// applies the regex at the contract-scope root, matching v1's
		// `scope: contract` pure-regex form, or `where: [any: [...]]` defining
		// the whole match on its own. There must be something to match on.
		if astAgg.IsEmpty() {
			return nil, fmt.Errorf("select: required for scope %q unless where contains AST-level matchers", scope)
		}
		result := *astAgg
		return &result, nil
	}

	if len(selectKinds) > 1 {
		branches := make([]Rule, len(selectKinds))
		for i, k := range selectKinds {
			branches[i] = Rule{Kind: k, Label: fmt.Sprintf("site %d", i+1)}
		}
		if err := mergeRuleInto(&branches[0], astAgg); err != nil {
			return nil, err
		}
		return &Rule{All: branches}, nil
	}

	selKind := selectKinds[0]
	if astAgg.Sequence != nil {
		// A sequence is already a "search within the scope" construct — do
		// not additionally wrap it in contains:. Fill in the select's kind
		// on the last, still-unconstrained sequence element only (keeps the
		// common case — where: already names every step's block: kind, as in
		// the reentrancy worked example — a no-op).
		m := *astAgg
		if n := len(m.Sequence); n > 0 && m.Sequence[n-1].Kind == "" {
			m.Sequence[n-1].Kind = selKind
		}
		return &m, nil
	}

	inner, err := mergeKindInto(astAgg, selKind)
	if err != nil {
		return nil, err
	}
	return &Rule{Contains: inner}, nil
}

// mergeKindInto returns a copy of base with Kind set to kind, erroring if
// base already carries a different Kind (e.g. a `block:` where matcher that
// disagrees with `select:`).
func mergeKindInto(base *Rule, kind string) (*Rule, error) {
	r := *base
	if r.Kind == "" {
		r.Kind = kind
	} else if r.Kind != kind {
		return nil, fmt.Errorf("select: kind %q conflicts with a where block: %q", kind, r.Kind)
	}
	return &r, nil
}

// lowerMatcher lowers one top-level `where` matcher (a single-key MatcherV2)
// into its AST-layer part (feeds Match) and/or context-layer part (feeds
// Filter). Either may be nil. This is the v1 filter/match split, computed
// from the uniform v2 matcher instead of authored directly by the template.
func lowerMatcher(m MatcherV2) (*Rule, *Rule, error) {
	key, val, ok := m.key()
	if !ok {
		return nil, nil, fmt.Errorf("where: malformed matcher (expected exactly one key), got %d", len(m))
	}
	return lowerKeyValue(key, val)
}

// argNPatternV2 matches a `arg.N` matcher key (0-based call-argument index).
var argNPatternV2 = "arg."

// lowerKeyValue lowers a single matcher key/value pair. It is the single
// dispatch point shared by lowerMatcher (top-level `where` items, which are
// always single-key per MatcherV2.key()) and expandMatcherPairs (nested
// matcher maps, which may legally carry several keys ANDed together — see
// the language spec §11.C worked example, where an `all:` branch mixes
// label/block/mutability/has in one map).
func lowerKeyValue(key string, val yaml.Node) (*Rule, *Rule, error) {
	switch key {
	case "block":
		var v string
		if err := val.Decode(&v); err != nil {
			return nil, nil, fmt.Errorf("where.block: %w", err)
		}
		v1, ok := blockKindToV1(v)
		if !ok {
			return nil, nil, fmt.Errorf("where.block: unknown block kind %q", v)
		}
		return &Rule{Kind: v1}, nil, nil

	case "name":
		var v string
		if err := val.Decode(&v); err != nil {
			return nil, nil, fmt.Errorf("where.name: %w", err)
		}
		return &Rule{Name: v}, nil, nil

	case "regex":
		var v string
		if err := val.Decode(&v); err != nil {
			return nil, nil, fmt.Errorf("where.regex: %w", err)
		}
		return &Rule{Regex: v}, nil, nil

	case "tainted":
		var v string
		if err := val.Decode(&v); err != nil {
			return nil, nil, fmt.Errorf("where.tainted: %w", err)
		}
		return &Rule{TaintedFrom: v}, nil, nil

	case "visibility":
		var v string
		if err := val.Decode(&v); err != nil {
			return nil, nil, fmt.Errorf("where.visibility: %w", err)
		}
		return &Rule{Visibility: v}, nil, nil

	case "mutability":
		var v string
		if err := val.Decode(&v); err != nil {
			return nil, nil, fmt.Errorf("where.mutability: %w", err)
		}
		return &Rule{Mutability: v}, nil, nil

	case "operator":
		var v string
		if err := val.Decode(&v); err != nil {
			return nil, nil, fmt.Errorf("where.operator: %w", err)
		}
		return &Rule{Operator: v}, nil, nil

	case "label":
		// `label:` is a sibling key inside an `all:` branch map (§11.C); it
		// carries no matching semantics (Rule.Label is metadata only).
		var v string
		if err := val.Decode(&v); err != nil {
			return nil, nil, fmt.Errorf("where.label: %w", err)
		}
		return &Rule{Label: v}, nil, nil

	case "attr":
		// Wrapped attribute form used by the §11.B worked example:
		// `attr: { has_value: true, ... }`. Each inner key resolves through
		// attrNameToV1 exactly like a bare attribute key would (below).
		var raw map[string]yaml.Node
		if err := val.Decode(&raw); err != nil {
			return nil, nil, fmt.Errorf("where.attr: %w", err)
		}
		ast := &Rule{}
		for ak, av := range raw {
			v1k, ok := attrNameToV1(ak)
			if !ok {
				return nil, nil, fmt.Errorf("where.attr: unknown attribute %q", ak)
			}
			var decoded interface{}
			if err := av.Decode(&decoded); err != nil {
				return nil, nil, fmt.Errorf("where.attr.%s: %w", ak, err)
			}
			if ast.Attr == nil {
				ast.Attr = make(map[string]interface{})
			}
			ast.Attr[v1k] = decoded
		}
		return ast, nil, nil

	case "left":
		sub, err := lowerToRule(val)
		if err != nil {
			return nil, nil, err
		}
		return &Rule{Left: sub}, nil, nil

	case "right":
		sub, err := lowerToRule(val)
		if err != nil {
			return nil, nil, err
		}
		return &Rule{Right: sub}, nil, nil

	case "statement_has":
		sub, err := lowerToRule(val)
		if err != nil {
			return nil, nil, err
		}
		return &Rule{StatementContains: sub}, nil, nil

	case "unchecked_var":
		var v bool
		if err := val.Decode(&v); err != nil {
			return nil, nil, fmt.Errorf("where.unchecked_var: %w", err)
		}
		return &Rule{UncheckedVar: v}, nil, nil

	case "modifier":
		var v string
		if err := val.Decode(&v); err != nil {
			return nil, nil, fmt.Errorf("where.modifier: %w", err)
		}
		return nil, &Rule{Modifier: v}, nil

	case "has":
		sub, err := lowerToRule(val)
		if err != nil {
			return nil, nil, err
		}
		return &Rule{Contains: sub}, nil, nil

	case "in":
		sub, err := lowerToRule(val)
		if err != nil {
			return nil, nil, err
		}
		return &Rule{Inside: sub}, nil, nil

	case "guarded_by":
		sub, err := lowerToRule(val)
		if err != nil {
			return nil, nil, err
		}
		return nil, &Rule{HasGuard: sub}, nil

	case "sequence":
		if val.Kind != yaml.SequenceNode {
			return nil, nil, fmt.Errorf("where.sequence: expected a list of matchers")
		}
		seq := make([]Rule, 0, len(val.Content))
		for _, item := range val.Content {
			r, err := lowerToRule(*item)
			if err != nil {
				return nil, nil, err
			}
			seq = append(seq, *r)
		}
		return &Rule{Sequence: seq}, nil, nil

	case "any":
		if val.Kind != yaml.SequenceNode {
			return nil, nil, fmt.Errorf("where.any: expected a list of matchers")
		}
		branches := make([]Rule, 0, len(val.Content))
		allCtxOnly := true
		for _, item := range val.Content {
			r, err := lowerToRule(*item)
			if err != nil {
				return nil, nil, err
			}
			branches = append(branches, *r)
			if !ruleIsContextOnly(r) {
				allCtxOnly = false
			}
		}
		if allCtxOnly {
			return nil, &Rule{Any: branches}, nil
		}
		return &Rule{Any: branches}, nil, nil

	case "all":
		if val.Kind != yaml.SequenceNode {
			return nil, nil, fmt.Errorf("where.all: expected a list of matchers")
		}
		var astBranches, ctxBranches []Rule
		for _, item := range val.Content {
			r, err := lowerToRule(*item)
			if err != nil {
				return nil, nil, err
			}
			if ruleIsContextOnly(r) {
				ctxBranches = append(ctxBranches, *r)
			} else {
				astBranches = append(astBranches, *r)
			}
		}
		var astPart, ctxPart *Rule
		if len(astBranches) > 0 {
			astPart = &Rule{All: astBranches}
		}
		if len(ctxBranches) > 0 {
			ctxPart = &Rule{All: ctxBranches}
		}
		return astPart, ctxPart, nil

	case "not":
		// Special-case a bare preset: `not: { preset: <renamed property> }`
		// means the safety property is ABSENT, i.e. the underlying v1
		// "vulnerable" preset holds directly (no extra negation) — see
		// presetToV1's doc comment and language spec §8.
		if v1, ok := negatedBarePresetTarget(val); ok {
			return nil, &Rule{Preset: v1}, nil
		}
		if err := rejectMultiKeyNotPreset(val); err != nil {
			return nil, nil, err
		}
		sub, err := lowerToRule(val)
		if err != nil {
			return nil, nil, err
		}
		if ruleIsContextOnly(sub) {
			return nil, &Rule{Not: sub}, nil
		}
		return &Rule{Not: sub}, nil, nil

	case "preset":
		var p string
		if err := val.Decode(&p); err != nil {
			return nil, nil, fmt.Errorf("where.preset: %w", err)
		}
		if v1, negate, ok := presetToV1(p); ok && negate {
			// Bare (no `not:`) assertion that the renamed property holds ->
			// the property is PRESENT -> NOT vulnerable -> ctx.Not wraps the
			// v1 "vulnerable" preset.
			return nil, &Rule{Not: &Rule{Preset: v1}}, nil
		}
		if p == "user_controlled" {
			// Documented approximation (no v1 preset counterpart): treat
			// "reachable from external/tainted input" as tainted-from-parameter
			// on the matched AST node.
			return &Rule{TaintedFrom: "parameter"}, nil, nil
		}
		return nil, nil, fmt.Errorf("where.preset: unknown preset %q", p)

	case "base":
		var v string
		if err := val.Decode(&v); err != nil {
			return nil, nil, fmt.Errorf("where.base: %w", err)
		}
		return nil, &Rule{Extends: v}, nil

	case "func_name":
		var v string
		if err := val.Decode(&v); err != nil {
			return nil, nil, fmt.Errorf("where.func_name: %w", err)
		}
		return nil, &Rule{FuncName: v}, nil

	case "version":
		var v string
		if err := val.Decode(&v); err != nil {
			return nil, nil, fmt.Errorf("where.version: %w", err)
		}
		return nil, &Rule{Version: v}, nil

	case "has_param":
		var v string
		if err := val.Decode(&v); err != nil {
			return nil, nil, fmt.Errorf("where.has_param: %w", err)
		}
		return nil, &Rule{HasParam: v}, nil

	default:
		if strings.HasPrefix(key, argNPatternV2) {
			idx, err := strconv.Atoi(strings.TrimPrefix(key, argNPatternV2))
			if err != nil {
				return nil, nil, fmt.Errorf("where: invalid arg index in %q: %w", key, err)
			}
			sub, err := lowerToRule(val)
			if err != nil {
				return nil, nil, err
			}
			return &Rule{Args: map[int]Rule{idx: *sub}}, nil, nil
		}
		if v1k, ok := attrNameToV1(key); ok {
			var decoded interface{}
			if err := val.Decode(&decoded); err != nil {
				return nil, nil, fmt.Errorf("where.%s: %w", key, err)
			}
			return &Rule{Attr: map[string]interface{}{v1k: decoded}}, nil, nil
		}
		return nil, nil, fmt.Errorf("where: unknown matcher key %q", key)
	}
}

// negatedBarePresetTarget reports whether node is exactly a single-key
// `{preset: <name>}` matcher naming a v2 property preset with the standard
// negate=true polarity (access_controlled/caller_checked/reentrancy_guarded
// today), and if so returns the v1 preset name to assert directly (bare, no
// Not wrapper). ok is false for anything else (not a bare preset matcher, or
// a preset with no negate=true mapping, e.g. user_controlled) — the "not"
// case in lowerKeyValue falls back to generic recursive lowering in that
// case.
func negatedBarePresetTarget(node yaml.Node) (string, bool) {
	if node.Kind != yaml.MappingNode {
		return "", false
	}
	var probe map[string]yaml.Node
	if err := node.Decode(&probe); err != nil || len(probe) != 1 {
		return "", false
	}
	presetNode, ok := probe["preset"]
	if !ok {
		return "", false
	}
	var name string
	if err := presetNode.Decode(&name); err != nil {
		return "", false
	}
	v1, negate, ok := presetToV1(name)
	if !ok || !negate {
		return "", false
	}
	return v1, true
}

// rejectMultiKeyNotPreset returns a clear error when node is a multi-key
// `not:` mapping that includes a `preset:` key alongside other keys (e.g.
// `not: {preset: access_controlled, base: some-other-rule}`). Only a
// single-key `{preset: X}` under `not:` has well-defined bare-negation
// semantics (negatedBarePresetTarget above); a multi-key form falls through
// to the generic recursive path in the "not" case, which wraps the WHOLE
// merged sub-rule (preset's own Not from presetToV1's negate=true handling,
// plus every sibling key) in an outer Not — silently double-negating the
// preset (Not{Not{Preset}} cancels back to the ORIGINAL "vulnerable" preset
// instead of "not vulnerable") while also negating the sibling keys, which
// was never intended. Reject explicitly instead of silently doing the wrong
// thing.
func rejectMultiKeyNotPreset(node yaml.Node) error {
	if node.Kind != yaml.MappingNode {
		return nil
	}
	var probe map[string]yaml.Node
	if err := node.Decode(&probe); err != nil || len(probe) <= 1 {
		return nil
	}
	if _, ok := probe["preset"]; ok {
		return fmt.Errorf("where.not: unsupported: not: with a preset must be the only key (got %d keys)", len(probe))
	}
	return nil
}

// lowerToRule decodes a nested matcher value (a single matcher map, or a list
// of matcher maps to AND) and lowers it to ONE merged Rule. Nested rules
// (inside has:/in:/arg.N:/sequence elements/all:/any: branches) do not split
// into separate AST/context layers the way top-level `where` items do — the
// sub-rule is evaluated as a single Rule value by the v1 evaluator (e.g.
// Rule.Contains, Rule.Args[N]), so its ast and ctx parts are merged together
// here.
func lowerToRule(node yaml.Node) (*Rule, error) {
	pairs, err := expandMatcherPairs(node)
	if err != nil {
		return nil, err
	}
	result := &Rule{}
	for _, kv := range pairs {
		astPart, ctxPart, err := lowerKeyValue(kv.key, kv.val)
		if err != nil {
			return nil, err
		}
		if astPart != nil {
			if err := mergeRuleInto(result, astPart); err != nil {
				return nil, err
			}
		}
		if ctxPart != nil {
			if err := mergeRuleInto(result, ctxPart); err != nil {
				return nil, err
			}
		}
	}
	return result, nil
}

// matcherKV is one exploded key/value pair from a (possibly multi-key)
// matcher map.
type matcherKV struct {
	key string
	val yaml.Node
}

// expandMatcherPairs flattens a matcher value into its constituent key/value
// pairs, implicit-ANDed:
//   - a mapping node contributes one pair per key (a multi-key map, as used
//     by an `all:` branch that mixes label/block/attr/has, means AND of all
//     its keys — see language spec §11.C).
//   - a sequence node recursively flattens every element and concatenates
//     the results (also AND — used by list-valued nested matchers such as
//     `has: [...]`, distinct from `sequence:`, which is ordered/positional
//     and is handled directly in lowerKeyValue's "sequence" case, not here).
func expandMatcherPairs(node yaml.Node) ([]matcherKV, error) {
	switch node.Kind {
	case yaml.MappingNode:
		pairs := make([]matcherKV, 0, len(node.Content)/2)
		for i := 0; i+1 < len(node.Content); i += 2 {
			pairs = append(pairs, matcherKV{key: node.Content[i].Value, val: *node.Content[i+1]})
		}
		return pairs, nil
	case yaml.SequenceNode:
		var all []matcherKV
		for _, item := range node.Content {
			sub, err := expandMatcherPairs(*item)
			if err != nil {
				return nil, err
			}
			all = append(all, sub...)
		}
		return all, nil
	case 0:
		return nil, fmt.Errorf("where: empty matcher node")
	default:
		return nil, fmt.Errorf("where: expected a matcher map or a list of matchers, got node kind %v", node.Kind)
	}
}

// ruleIsContextOnly reports whether r is a context-level matcher (per
// presentRuleFields' classAST/classContext tagging — the same classification
// table validateRulePlacement uses). It backs the "any:"/"all:"/"not:" branch
// routing: a branch lowers into Filter (ctx) only if it is entirely made of
// context-level matchers (e.g. a bare preset, or a `guarded_by:`), otherwise
// it lowers into Match (ast).
//
// This mirrors ruleHasContextFields/ruleHasASTFields (verify.go) exactly,
// reusing them directly: they recurse ONLY through All/Any/Not — never into
// Contains/Inside/HasGuard/Args/Left/Right/Sequence/StatementContains, whose
// bodies are legitimately AST-shaped even though the field itself (e.g.
// HasGuard) is a context field. Walking into those bodies (as a generic
// walkRules-based traversal would) misclassifies a branch like
// `{guarded_by: {block: modifier}}` as "not context-only", because the
// nested `block: modifier` sets Kind (classAST) — even though `guarded_by:`
// itself is the only field present at r's own level and is classContext.
func ruleIsContextOnly(r *Rule) bool {
	if r == nil {
		return true
	}
	return ruleHasContextFields(*r) && !ruleHasASTFields(*r)
}

// mergeRuleInto merges src's fields into dst (both non-nil aggregators; src
// may be nil, in which case this is a no-op). It implements Task A3 step 5
// ("merge all where matchers' ast/ctx parts") and is also used by
// lowerToRule to combine a nested matcher's exploded key/value pairs into one
// Rule.
//
// Scalar fields (Kind, Name, Regex, ...) error on a genuine conflict (two
// matchers setting the same field to different values) — per the plan,
// "that's a template error unless equal". Structural fields accumulate
// instead, since `where` items are implicitly ANDed and a WQL author can
// legitimately narrow the same structural slot from two matchers (e.g. two
// `arg.0:` constraints, or `has:` twice): Attr/Args merge key-by-key
// (recursively for Args, so two constraints on the same argument index AND
// together, which is the correct semantics for "argument N matches both of
// these"); Contains/Inside/Not/HasGuard/Left/Right/StatementContains assign
// on first sight and otherwise recursively merge into the existing sub-rule;
// All simply accumulates (append is safe under AND); Any only accumulates
// directly the first time — a second independent `any:` group is wrapped
// into an All branch instead of concatenated, since concatenating two OR
// groups is NOT equivalent to ANDing them.
func mergeRuleInto(dst, src *Rule) error {
	if src == nil {
		return nil
	}

	type scalarField struct {
		name string
		dst  *string
		src  string
	}
	scalars := []scalarField{
		{"label", &dst.Label, src.Label},
		{"kind", &dst.Kind, src.Kind},
		{"name", &dst.Name, src.Name},
		{"regex", &dst.Regex, src.Regex},
		{"operator", &dst.Operator, src.Operator},
		{"visibility", &dst.Visibility, src.Visibility},
		{"mutability", &dst.Mutability, src.Mutability},
		{"extends", &dst.Extends, src.Extends},
		{"modifier", &dst.Modifier, src.Modifier},
		{"func_name", &dst.FuncName, src.FuncName},
		{"tainted_from", &dst.TaintedFrom, src.TaintedFrom},
		{"version", &dst.Version, src.Version},
		{"preset", &dst.Preset, src.Preset},
		{"has_param", &dst.HasParam, src.HasParam},
	}
	for _, f := range scalars {
		if f.src == "" {
			continue
		}
		if *f.dst == "" {
			*f.dst = f.src
		} else if *f.dst != f.src {
			return fmt.Errorf("where: conflicting %s: %q vs %q", f.name, *f.dst, f.src)
		}
	}

	if src.UncheckedVar {
		dst.UncheckedVar = true
	}
	if src.IsStateVar != nil {
		if dst.IsStateVar == nil {
			dst.IsStateVar = src.IsStateVar
		} else if dst.IsStateVar != src.IsStateVar {
			return fmt.Errorf("where: conflicting is_state_var: %v vs %v", dst.IsStateVar, src.IsStateVar)
		}
	}

	for k, v := range src.Attr {
		if dst.Attr == nil {
			dst.Attr = make(map[string]interface{})
		}
		// reflect.DeepEqual instead of `!=`: an attr value decoded from YAML
		// can be a slice or map (e.g. a list-valued attribute), and comparing
		// uncomparable types with `!=` panics at runtime instead of erroring
		// cleanly.
		if existing, ok := dst.Attr[k]; ok && !reflect.DeepEqual(existing, v) {
			return fmt.Errorf("where: conflicting attr %q: %v vs %v", k, existing, v)
		}
		dst.Attr[k] = v
	}

	for idx, r := range src.Args {
		rCopy := r
		if dst.Args == nil {
			dst.Args = make(map[int]Rule)
		}
		if existing, ok := dst.Args[idx]; ok {
			if err := mergeRuleInto(&existing, &rCopy); err != nil {
				return fmt.Errorf("where: arg.%d: %w", idx, err)
			}
			dst.Args[idx] = existing
		} else {
			dst.Args[idx] = rCopy
		}
	}

	mergePtr := func(dstPtr **Rule, srcPtr *Rule) error {
		if srcPtr == nil {
			return nil
		}
		if *dstPtr == nil {
			cp := *srcPtr
			*dstPtr = &cp
			return nil
		}
		return mergeRuleInto(*dstPtr, srcPtr)
	}
	if err := mergePtr(&dst.Not, src.Not); err != nil {
		return err
	}
	if err := mergePtr(&dst.Contains, src.Contains); err != nil {
		return err
	}
	if err := mergePtr(&dst.Inside, src.Inside); err != nil {
		return err
	}
	if err := mergePtr(&dst.HasGuard, src.HasGuard); err != nil {
		return err
	}
	if err := mergePtr(&dst.StatementContains, src.StatementContains); err != nil {
		return err
	}
	if err := mergePtr(&dst.Left, src.Left); err != nil {
		return err
	}
	if err := mergePtr(&dst.Right, src.Right); err != nil {
		return err
	}

	if len(src.Sequence) > 0 {
		if len(dst.Sequence) > 0 {
			return fmt.Errorf("where: multiple sequence: matchers are not supported in a single rule")
		}
		dst.Sequence = src.Sequence
	}

	dst.All = append(dst.All, src.All...)

	if len(src.Any) > 0 {
		if len(dst.Any) == 0 {
			dst.Any = src.Any
		} else {
			dst.All = append(dst.All, Rule{Any: src.Any})
		}
	}

	return nil
}
