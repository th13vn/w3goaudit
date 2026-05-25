// Package engine provides the WQL (W3GoAudit Query Language) template engine.
package engine

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/th13vn/w3goaudit/pkg/types"
	"gopkg.in/yaml.v3"
)

// Scope defines the context for template matching
type Scope string

const (
	// ScopeAllContract loops over every contract definition
	ScopeAllContract Scope = "all_contract"
	// ScopeMainContract loops only over contracts marked is_main: true
	ScopeMainContract Scope = "main_contract"
	// ScopeFunction loops over all functions
	ScopeFunction Scope = "function"
	// ScopeEntrypoint loops over resolved entry points of main contract
	ScopeEntrypoint Scope = "entrypoint"
	// ScopeContract loops over contract-type definitions only
	ScopeContract Scope = "contract"
	// ScopeLibrary loops over library-type definitions only
	ScopeLibrary Scope = "library"
	// ScopeAbstract loops over abstract contract definitions only
	ScopeAbstract Scope = "abstract"
)

// Template represents a WQL vulnerability detection template
type Template struct {
	Meta  TemplateMeta `yaml:"meta" json:"meta"`
	Query QueryBlock   `yaml:"query" json:"query"`
}

// TemplateMeta contains template metadata
type TemplateMeta struct {
	ID             string   `yaml:"id" json:"id"`
	Title          string   `yaml:"title,omitempty" json:"title,omitempty"`
	Severity       string   `yaml:"severity" json:"severity"`
	Confidence     string   `yaml:"confidence" json:"confidence"`
	Description    string   `yaml:"description,omitempty" json:"description,omitempty"`
	Recommendation string   `yaml:"recommendation,omitempty" json:"recommendation,omitempty"`
	CWE            []int    `yaml:"cwe,omitempty" json:"cwe,omitempty"`
	OWASP          []string `yaml:"owasp,omitempty" json:"owasp,omitempty"`
	References     []string `yaml:"references,omitempty" json:"references,omitempty"`
	Fix            string   `yaml:"fix,omitempty" json:"fix,omitempty"`
}

// QueryBlock defines the query scope, optional filter, and matching rules.
//
// WQL syntax:
//   - filter: function/contract-level preconditions
//   - match:  AST pattern matching rules
type QueryBlock struct {
	Scope  Scope `yaml:"scope" json:"scope"`
	Filter *Rule `yaml:"filter,omitempty" json:"filter,omitempty"`
	Match  Rule  `yaml:"match" json:"match"`
}

// Rule represents a WQL matching rule with recursive structure.
// Default logic: ALL fields must match (AND semantics).
// Aliases are normalized to internal fields during loading.
type Rule struct {
	// ========== LOGIC OPERATORS ==========
	All []Rule `yaml:"all,omitempty" json:"all,omitempty"`
	Any []Rule `yaml:"any,omitempty" json:"any,omitempty"`
	Not *Rule  `yaml:"not,omitempty" json:"not,omitempty"`

	// Sequence: ordered matching of descendants
	Sequence []Rule `yaml:"sequence,omitempty" json:"sequence,omitempty"`

	// ========== ATOMIC MATCHERS ==========
	Kind string `yaml:"kind,omitempty" json:"kind,omitempty"`
	Name string `yaml:"name,omitempty" json:"name,omitempty"`

	// ========== ATTRIBUTES ==========
	Attr map[string]interface{} `yaml:"attr,omitempty" json:"attr,omitempty"`

	// Inline attributes (promoted into Attr during normalization)
	IsStateVar interface{} `yaml:"is_state_var,omitempty" json:"is_state_var,omitempty"`
	Operator   string      `yaml:"operator,omitempty" json:"operator,omitempty"`
	Visibility string      `yaml:"visibility,omitempty" json:"visibility,omitempty"`
	Mutability string      `yaml:"mutability,omitempty" json:"mutability,omitempty"`

	// ========== CONTEXT HELPERS (function-level filters) ==========
	Extends  string `yaml:"extends,omitempty" json:"extends,omitempty"`
	Modifier string `yaml:"modifier,omitempty" json:"modifier,omitempty"`

	// FuncName filters by function name regex (filter-level, not AST name).
	// Use this in filter blocks to restrict which functions are checked.
	// Named FuncName to avoid collision with AST `name`.
	FuncName string `yaml:"func_name,omitempty" json:"func_name,omitempty"`

	// VisibilityFilter restricts matching to functions with the given visibility.
	// Accepted values: public, external, internal, private
	// Supports comma-separated list: "public,external"
	VisibilityFilter string `yaml:"visibility_filter,omitempty" json:"visibility_filter,omitempty"`

	// MutabilityFilter restricts matching to functions with the given mutability.
	// Accepted values: payable, view, pure, nonpayable
	// Supports comma-separated list: "payable,nonpayable"
	MutabilityFilter string `yaml:"mutability_filter,omitempty" json:"mutability_filter,omitempty"`

	// HasGuard checks if the function body contains a require/assert guard
	// with a specific pattern. Used in filter blocks.
	// Example: has_guard: { contains: { pattern: msg.sender } }
	HasGuard *Rule `yaml:"has_guard,omitempty" json:"has_guard,omitempty"`

	// ========== TRAVERSAL ==========
	Contains *Rule `yaml:"contains,omitempty" json:"contains,omitempty"`
	Inside   *Rule `yaml:"inside,omitempty" json:"inside,omitempty"`

	// ========== CALL-SPECIFIC ==========
	// Args matches call arguments by 0-based index.
	// Two equivalent notations are accepted in YAML:
	//   args: { 0: ..., 1: ... }
	//   arg.0: ...
	//   arg.1: ...
	Args map[int]Rule `yaml:"args,omitempty" json:"args,omitempty"`

	// ========== TAINT ANALYSIS ==========
	TaintedFrom string `yaml:"tainted_from,omitempty" json:"tainted_from,omitempty"`

	// ========== VERSION CHECKING ==========
	Version string `yaml:"version,omitempty" json:"version,omitempty"`

	// ========== PRESETS ==========
	Preset string `yaml:"preset,omitempty" json:"preset,omitempty"`

	// ========== LEFT/RIGHT MATCHING ==========
	Left  *Rule `yaml:"left,omitempty" json:"left,omitempty"`
	Right *Rule `yaml:"right,omitempty" json:"right,omitempty"`

	// ========== FILTER-SPECIFIC ==========
	HasParam string `yaml:"has_param,omitempty" json:"has_param,omitempty"` // check function has param named X
}

// LoadTemplate loads a template from a YAML file.
func LoadTemplate(path string) (*Template, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}

	var tmpl Template
	if err := yaml.Unmarshal(data, &tmpl); err != nil {
		return nil, fmt.Errorf("parse YAML: %w", err)
	}

	// Validate that filter/match rules sit at the right layer.
	if err := validateRulePlacement(&tmpl.Query); err != nil {
		return nil, err
	}

	// Promote inline attrs into Attr maps so the matcher can read them uniformly.
	normalizeQueryBlock(&tmpl.Query)

	// Post-process: scan raw YAML for arg.N flat keys.
	if err := normalizeArgNKeys(data, &tmpl); err != nil {
		// Non-fatal: log but don't fail
		VerboseLog("Warning: arg.N normalization failed for %s: %v", path, err)
	}

	// Compile every regex pattern once now so we surface typos as load errors
	// instead of silently rewriting rule semantics at scan time.
	if err := validateRegexes(&tmpl.Query.Match); err != nil {
		return nil, fmt.Errorf("match: %w", err)
	}
	if err := validateRegexes(tmpl.Query.Filter); err != nil {
		return nil, fmt.Errorf("filter: %w", err)
	}

	// Reject unknown preset names so authors see typos immediately.
	if err := validatePresets(&tmpl.Query.Match); err != nil {
		return nil, fmt.Errorf("match: %w", err)
	}
	if err := validatePresets(tmpl.Query.Filter); err != nil {
		return nil, fmt.Errorf("filter: %w", err)
	}

	// Reject unknown `kind:` values (typos, dropped suffixes) so they surface
	// at load instead of silently producing zero findings at scan time.
	if err := validateKinds(&tmpl.Query.Match); err != nil {
		return nil, fmt.Errorf("match: %w", err)
	}
	if err := validateKinds(tmpl.Query.Filter); err != nil {
		return nil, fmt.Errorf("filter: %w", err)
	}

	return &tmpl, nil
}

// normalizeQueryBlock promotes inline attributes (is_state_var, operator,
// etc.) into the Attr map so the matcher can read them uniformly.
func normalizeQueryBlock(q *QueryBlock) {
	normalizeRule(&q.Match)
	if q.Filter != nil {
		normalizeRule(q.Filter)
	}
}

// normalizeRule recursively normalizes a rule:
// - promotes inline attributes (is_state_var, operator, visibility, mutability) into Attr map
// - recurses into sub-rules
func normalizeRule(r *Rule) {
	if r == nil {
		return
	}

	// Promote inline attributes into Attr map (for matchAttributeValue)
	if r.IsStateVar != nil {
		if r.Attr == nil {
			r.Attr = make(map[string]interface{})
		}
		r.Attr["is_state_var"] = r.IsStateVar
		r.IsStateVar = nil
	}
	if r.Operator != "" {
		if r.Attr == nil {
			r.Attr = make(map[string]interface{})
		}
		r.Attr["operator"] = r.Operator
		// Don't clear Operator — it's also used for display/debug
	}

	// Recurse into sub-rules
	for i := range r.All {
		normalizeRule(&r.All[i])
	}
	for i := range r.Any {
		normalizeRule(&r.Any[i])
	}
	normalizeRule(r.Not)
	for i := range r.Sequence {
		normalizeRule(&r.Sequence[i])
	}
	normalizeRule(r.Contains)
	normalizeRule(r.Inside)
	normalizeRule(r.Left)
	normalizeRule(r.Right)
	normalizeRule(r.HasGuard)
	for k, v := range r.Args {
		vCopy := v
		normalizeRule(&vCopy)
		r.Args[k] = vCopy
	}
}

// argNPattern matches the flat key `arg.N` used to constrain a specific
// call argument. Compiled once at package init.
var argNPattern = regexp.MustCompile(`^arg\.(\d+)$`)

// normalizeArgNKeys scans raw YAML for "arg.N" style keys and populates
// the Args map on the matching parsed Rule. Unlike the previous version
// (which only walked the document root and silently lost nested `arg.N`),
// this walks the parsed Rule tree in lockstep with the raw YAML mapping,
// so `arg.N` constraints inside `contains:`, `sequence:`, `all:`, `any:`,
// `not:`, and nested args all get applied.
//
// Example that previously failed silently:
//
//	match:
//	  contains:
//	    kind: call.external
//	    name: transferFrom
//	    arg.0: { tainted_from: parameter }   <-- now correctly applied
func normalizeArgNKeys(data []byte, tmpl *Template) error {
	var rawDoc yaml.Node
	if err := yaml.Unmarshal(data, &rawDoc); err != nil {
		return err
	}
	if rawDoc.Kind != yaml.DocumentNode || len(rawDoc.Content) == 0 {
		return nil
	}
	root := rawDoc.Content[0]
	if root.Kind != yaml.MappingNode {
		return nil
	}

	// Locate the `query:` mapping and walk its `match:` / `filter:` children.
	for i := 0; i+1 < len(root.Content); i += 2 {
		if root.Content[i].Value != "query" {
			continue
		}
		queryNode := root.Content[i+1]
		if queryNode.Kind != yaml.MappingNode {
			continue
		}
		for j := 0; j+1 < len(queryNode.Content); j += 2 {
			key := queryNode.Content[j].Value
			child := queryNode.Content[j+1]
			switch key {
			case "match":
				mergeArgsFromYAML(&tmpl.Query.Match, child)
			case "filter":
				if tmpl.Query.Filter != nil {
					mergeArgsFromYAML(tmpl.Query.Filter, child)
				}
			}
		}
	}
	return nil
}

// mergeArgsFromYAML walks (rule, yamlNode) in lockstep. At each level it
// extracts `arg.N` flat keys into rule.Args, then recurses into every nested
// rule slot the parser exposes (not, contains, inside, left, right,
// has_guard, all/any/sequence list elements, args map values).
func mergeArgsFromYAML(rule *Rule, node *yaml.Node) {
	if rule == nil || node == nil || node.Kind != yaml.MappingNode {
		return
	}

	// 1. Apply arg.N flat keys at THIS level.
	for i := 0; i+1 < len(node.Content); i += 2 {
		key := node.Content[i].Value
		valNode := node.Content[i+1]
		if m := argNPattern.FindStringSubmatch(key); len(m) == 2 {
			idx := 0
			fmt.Sscanf(m[1], "%d", &idx)
			var argRule Rule
			if err := valNode.Decode(&argRule); err != nil {
				continue
			}
			normalizeRule(&argRule)
			if rule.Args == nil {
				rule.Args = make(map[int]Rule)
			}
			rule.Args[idx] = argRule
		}
	}

	// 2. Helper: look up a child node by key name.
	childByKey := func(name string) *yaml.Node {
		for i := 0; i+1 < len(node.Content); i += 2 {
			if node.Content[i].Value == name {
				return node.Content[i+1]
			}
		}
		return nil
	}

	// 3. Recurse into single-rule fields.
	mergeArgsFromYAML(rule.Not, childByKey("not"))
	mergeArgsFromYAML(rule.Contains, childByKey("contains"))
	mergeArgsFromYAML(rule.Inside, childByKey("inside"))
	mergeArgsFromYAML(rule.Left, childByKey("left"))
	mergeArgsFromYAML(rule.Right, childByKey("right"))
	mergeArgsFromYAML(rule.HasGuard, childByKey("has_guard"))

	// 4. Recurse into list-of-rule fields (in source order).
	if n := childByKey("all"); n != nil && n.Kind == yaml.SequenceNode {
		for i, item := range n.Content {
			if i < len(rule.All) {
				mergeArgsFromYAML(&rule.All[i], item)
			}
		}
	}
	if n := childByKey("any"); n != nil && n.Kind == yaml.SequenceNode {
		for i, item := range n.Content {
			if i < len(rule.Any) {
				mergeArgsFromYAML(&rule.Any[i], item)
			}
		}
	}
	if n := childByKey("sequence"); n != nil && n.Kind == yaml.SequenceNode {
		for i, item := range n.Content {
			if i < len(rule.Sequence) {
				mergeArgsFromYAML(&rule.Sequence[i], item)
			}
		}
	}

	// 5. Recurse into the explicit `args:` map (nested form). Also recurse
	// into rules introduced by `arg.N` flat keys so nested arg.N within an
	// argument constraint keeps working.
	if n := childByKey("args"); n != nil && n.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(n.Content); i += 2 {
			idx := 0
			if _, err := fmt.Sscanf(n.Content[i].Value, "%d", &idx); err == nil {
				if argRule, ok := rule.Args[idx]; ok {
					mergeArgsFromYAML(&argRule, n.Content[i+1])
					rule.Args[idx] = argRule
				}
			}
		}
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		key := node.Content[i].Value
		if m := argNPattern.FindStringSubmatch(key); len(m) == 2 {
			idx := 0
			fmt.Sscanf(m[1], "%d", &idx)
			if argRule, ok := rule.Args[idx]; ok {
				mergeArgsFromYAML(&argRule, node.Content[i+1])
				rule.Args[idx] = argRule
			}
		}
	}
}

// validateRulePlacement enforces the WQL contract that filter and match
// blocks operate at different layers:
//
//   - filter:  function/contract-level predicates only (modifier, extends,
//              func_name, visibility_filter, mutability_filter, has_guard,
//              has_param, version, preset).
//   - match:   AST node predicates only (kind, name, contains, sequence,
//              inside, args, tainted_from, left/right, attr, operator,
//              is_state_var, visibility, mutability).
//
// Logical operators (all/any/not) are allowed in both, and recurse.
//
// Returning an error here surfaces classes of mistakes that previously
// silently produced zero matches (e.g. putting `kind: outgoing_call` inside
// `filter:`, or `modifier: onlyOwner` inside `match:`).
func validateRulePlacement(q *QueryBlock) error {
	if q.Filter != nil {
		if err := checkRule(q.Filter, "filter", false); err != nil {
			return err
		}
	}
	if !q.Match.IsEmpty() {
		if err := checkRule(&q.Match, "match", true); err != nil {
			return err
		}
	}
	return nil
}

// checkRule recursively walks a rule tree. inMatch=true means we're inside
// `match:` (AST layer), so context-only fields are forbidden. inMatch=false
// means `filter:` (context layer), so AST-only fields are forbidden.
func checkRule(r *Rule, where string, inMatch bool) error {
	if r == nil {
		return nil
	}

	// AST-only fields — forbidden inside filter:.
	astOnly := map[string]bool{
		"kind":         r.Kind != "",
		"name":         r.Name != "",
		"contains":     r.Contains != nil,
		"inside":       r.Inside != nil,
		"sequence":     len(r.Sequence) > 0,
		"args":         len(r.Args) > 0,
		"tainted_from": r.TaintedFrom != "",
		"left":         r.Left != nil,
		"right":        r.Right != nil,
		"attr":         len(r.Attr) > 0,
		"operator":     r.Operator != "",
		"is_state_var": r.IsStateVar != nil,
	}

	// Context-only fields — forbidden inside match:.
	ctxOnly := map[string]bool{
		"modifier":          r.Modifier != "",
		"extends":           r.Extends != "",
		"func_name":         r.FuncName != "",
		"visibility_filter": r.VisibilityFilter != "",
		"mutability_filter": r.MutabilityFilter != "",
		"has_guard":         r.HasGuard != nil,
		"has_param":         r.HasParam != "",
		"version":           r.Version != "",
		"preset":            r.Preset != "",
	}

	if !inMatch {
		// In filter:, AST-only fields are forbidden.
		for field, present := range astOnly {
			if present {
				return fmt.Errorf("invalid template: `%s` is an AST-level field and cannot appear inside `filter:` — move it under `match:`", field)
			}
		}
	} else {
		// In match:, context-only fields are forbidden.
		for field, present := range ctxOnly {
			if present {
				return fmt.Errorf("invalid template: `%s` is a context-level field and cannot appear inside `match:` — move it under `filter:`", field)
			}
		}
	}

	// Recurse through logical operators (allowed in both layers).
	for i := range r.All {
		if err := checkRule(&r.All[i], where, inMatch); err != nil {
			return err
		}
	}
	for i := range r.Any {
		if err := checkRule(&r.Any[i], where, inMatch); err != nil {
			return err
		}
	}
	if err := checkRule(r.Not, where, inMatch); err != nil {
		return err
	}

	// Recurse into structural traversal — those carry the same layer.
	for i := range r.Sequence {
		if err := checkRule(&r.Sequence[i], where, inMatch); err != nil {
			return err
		}
	}
	if err := checkRule(r.Contains, where, inMatch); err != nil {
		return err
	}
	if err := checkRule(r.Inside, where, inMatch); err != nil {
		return err
	}
	if err := checkRule(r.Left, where, inMatch); err != nil {
		return err
	}
	if err := checkRule(r.Right, where, inMatch); err != nil {
		return err
	}
	// has_guard's body is itself an AST predicate even when it lives in filter:.
	if r.HasGuard != nil {
		if err := checkRule(r.HasGuard, "has_guard", true); err != nil {
			return err
		}
	}
	for k := range r.Args {
		v := r.Args[k]
		if err := checkRule(&v, where, inMatch); err != nil {
			return err
		}
	}
	return nil
}

// LoadTemplates loads all templates from a directory (recursively).
// Invalid templates are skipped with a verbose warning (not silently).
func LoadTemplates(dir string) ([]*Template, error) {
	var templates []*Template

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip directories
		if info.IsDir() {
			return nil
		}

		// Only process YAML files
		name := info.Name()
		if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
			return nil
		}

		// Load template — log errors instead of silently swallowing them
		tmpl, err := LoadTemplate(path)
		if err != nil {
			VerboseLog("⚠️  Skipping invalid template %s: %v", path, err)
			return nil
		}

		// Validate required meta fields
		if tmpl.Meta.ID == "" {
			VerboseLog("⚠️  Skipping template %s: missing meta.id", path)
			return nil
		}
		if tmpl.Meta.Severity == "" {
			VerboseLog("⚠️  Skipping template %s: missing meta.severity", path)
			return nil
		}

		VerboseLog("✓ Loaded template: %s (%s)", tmpl.Meta.ID, path)
		templates = append(templates, tmpl)
		return nil
	})

	if err != nil {
		return nil, err
	}

	return templates, nil
}

// ParseTemplate parses a template from a YAML string. Mirrors LoadTemplate's
// validation pipeline so SDK consumers and the file loader behave identically.
func ParseTemplate(yamlContent string) (*Template, error) {
	data := []byte(yamlContent)

	var tmpl Template
	if err := yaml.Unmarshal(data, &tmpl); err != nil {
		return nil, err
	}

	if err := validateRulePlacement(&tmpl.Query); err != nil {
		return nil, err
	}

	normalizeQueryBlock(&tmpl.Query)

	if err := normalizeArgNKeys(data, &tmpl); err != nil {
		VerboseLog("Warning: arg.N normalization failed: %v", err)
	}

	if err := validateRegexes(&tmpl.Query.Match); err != nil {
		return nil, fmt.Errorf("match: %w", err)
	}
	if err := validateRegexes(tmpl.Query.Filter); err != nil {
		return nil, fmt.Errorf("filter: %w", err)
	}
	if err := validatePresets(&tmpl.Query.Match); err != nil {
		return nil, fmt.Errorf("match: %w", err)
	}
	if err := validatePresets(tmpl.Query.Filter); err != nil {
		return nil, fmt.Errorf("filter: %w", err)
	}
	if err := validateKinds(&tmpl.Query.Match); err != nil {
		return nil, fmt.Errorf("match: %w", err)
	}
	if err := validateKinds(tmpl.Query.Filter); err != nil {
		return nil, fmt.Errorf("filter: %w", err)
	}

	return &tmpl, nil
}

// IsEmpty returns true if the rule has no conditions
func (r *Rule) IsEmpty() bool {
	return len(r.All) == 0 && len(r.Any) == 0 && len(r.Sequence) == 0 &&
		r.Not == nil && r.Contains == nil && r.Inside == nil &&
		r.Kind == "" && r.Name == "" && len(r.Attr) == 0 &&
		r.Extends == "" && r.Modifier == "" && len(r.Args) == 0 &&
		r.TaintedFrom == "" && r.Version == "" && r.Preset == "" &&
		r.Left == nil && r.Right == nil && r.HasParam == "" &&
		r.FuncName == "" && r.VisibilityFilter == "" && r.MutabilityFilter == "" &&
		r.HasGuard == nil && r.IsStateVar == nil
}

// regexCache memoizes compiled regexes so a pattern referenced from N AST
// nodes is compiled once, not N times. sync.Map is safe for concurrent use,
// matching MatchesRegex's threading expectations.
var regexCache sync.Map // map[string]*regexp.Regexp

// compileRegexCached returns a compiled regex for the pattern, using the
// process-wide cache. Returns (nil, nil) on empty pattern and (nil, err) on
// invalid pattern — callers must distinguish "no pattern" from "bad pattern".
func compileRegexCached(pattern string) (*regexp.Regexp, error) {
	if pattern == "" {
		return nil, nil
	}
	if v, ok := regexCache.Load(pattern); ok {
		return v.(*regexp.Regexp), nil
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}
	regexCache.Store(pattern, re)
	return re, nil
}

// MatchesRegex checks if value matches the regex pattern.
//
// Empty pattern matches anything (vacuous true). Invalid patterns return false
// — they are now rejected at template load time by validateRegexes, so this
// path should not be hit in practice. The previous silent fallback to
// substring match was a footgun: a typo in a rule silently changed the
// rule's semantics from "regex" to "case-insensitive contains".
func MatchesRegex(pattern, value string) bool {
	re, err := compileRegexCached(pattern)
	if err != nil || re == nil {
		return err == nil // err == nil && re == nil  -> empty pattern, match
	}
	return re.MatchString(value)
}

// validateKinds walks a rule tree and rejects any `kind:` value that isn't a
// registered exact kind, semantic group, or dotted prefix. Without this, a
// typo like `kind: outgoing_calls` (plural) or `kind: call.lowlevel` (missing
// .call/.delegatecall/.staticcall suffix) silently matched nothing at scan
// time. The error message lists the closest valid examples so the author can
// fix the template without grepping ast.go.
func validateKinds(r *Rule) error {
	if r == nil {
		return nil
	}
	if r.Kind != "" && !types.IsKnownKind(r.Kind) {
		return fmt.Errorf(
			"unknown kind %q — must be one of: a registered AST kind "+
				"(see pkg/types/ast.go), a semantic group "+
				"(outgoing_call, eth_transfer, delegatecall, check, guard, "+
				"token_call, state_write, state_read, any_call, "+
				"selfdestruct), or a known prefix (call, check, stmt, expr, "+
				"decl, asm)",
			r.Kind,
		)
	}
	for i := range r.All {
		if err := validateKinds(&r.All[i]); err != nil {
			return err
		}
	}
	for i := range r.Any {
		if err := validateKinds(&r.Any[i]); err != nil {
			return err
		}
	}
	if err := validateKinds(r.Not); err != nil {
		return err
	}
	for i := range r.Sequence {
		if err := validateKinds(&r.Sequence[i]); err != nil {
			return err
		}
	}
	if err := validateKinds(r.Contains); err != nil {
		return err
	}
	if err := validateKinds(r.Inside); err != nil {
		return err
	}
	if err := validateKinds(r.Left); err != nil {
		return err
	}
	if err := validateKinds(r.Right); err != nil {
		return err
	}
	if err := validateKinds(r.HasGuard); err != nil {
		return err
	}
	for k := range r.Args {
		v := r.Args[k]
		if err := validateKinds(&v); err != nil {
			return err
		}
	}
	return nil
}

// validatePresets walks a rule tree and rejects any preset name that isn't
// registered. Without this, a typo like `preset: unAuthenticatd` previously
// caused checkBuiltinPreset to return true, silently matching every function.
func validatePresets(r *Rule) error {
	if r == nil {
		return nil
	}
	if r.Preset != "" && !IsKnownPreset(r.Preset) {
		return fmt.Errorf("unknown preset %q — known presets: unAuthenticated, unLocked", r.Preset)
	}
	for i := range r.All {
		if err := validatePresets(&r.All[i]); err != nil {
			return err
		}
	}
	for i := range r.Any {
		if err := validatePresets(&r.Any[i]); err != nil {
			return err
		}
	}
	if err := validatePresets(r.Not); err != nil {
		return err
	}
	for i := range r.Sequence {
		if err := validatePresets(&r.Sequence[i]); err != nil {
			return err
		}
	}
	if err := validatePresets(r.Contains); err != nil {
		return err
	}
	if err := validatePresets(r.Inside); err != nil {
		return err
	}
	if err := validatePresets(r.Left); err != nil {
		return err
	}
	if err := validatePresets(r.Right); err != nil {
		return err
	}
	if err := validatePresets(r.HasGuard); err != nil {
		return err
	}
	for k := range r.Args {
		v := r.Args[k]
		if err := validatePresets(&v); err != nil {
			return err
		}
	}
	return nil
}

// validateRegexes walks a rule tree and surfaces any invalid regex pattern as
// an error. Called at template-load time so authors see typos immediately
// instead of getting silently-empty findings.
func validateRegexes(r *Rule) error {
	if r == nil {
		return nil
	}
	checks := []struct {
		field, pattern string
	}{
		{"name", r.Name},
		{"modifier", r.Modifier},
		{"extends", r.Extends},
		{"func_name", r.FuncName},
	}
	for _, c := range checks {
		if c.pattern == "" {
			continue
		}
		if _, err := compileRegexCached(c.pattern); err != nil {
			return fmt.Errorf("invalid regex in %q: %s — %w", c.field, c.pattern, err)
		}
	}
	// Attribute values are matched as regex when they're strings (see verify.go matchAttributeValue).
	for k, v := range r.Attr {
		if s, ok := v.(string); ok && s != "" {
			if _, err := compileRegexCached(s); err != nil {
				return fmt.Errorf("invalid regex in attr.%s: %s — %w", k, s, err)
			}
		}
	}
	// Recurse through sub-rules.
	for i := range r.All {
		if err := validateRegexes(&r.All[i]); err != nil {
			return err
		}
	}
	for i := range r.Any {
		if err := validateRegexes(&r.Any[i]); err != nil {
			return err
		}
	}
	if err := validateRegexes(r.Not); err != nil {
		return err
	}
	for i := range r.Sequence {
		if err := validateRegexes(&r.Sequence[i]); err != nil {
			return err
		}
	}
	if err := validateRegexes(r.Contains); err != nil {
		return err
	}
	if err := validateRegexes(r.Inside); err != nil {
		return err
	}
	if err := validateRegexes(r.Left); err != nil {
		return err
	}
	if err := validateRegexes(r.Right); err != nil {
		return err
	}
	if err := validateRegexes(r.HasGuard); err != nil {
		return err
	}
	for k := range r.Args {
		v := r.Args[k]
		if err := validateRegexes(&v); err != nil {
			return err
		}
	}
	return nil
}
