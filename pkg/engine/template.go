// Package engine provides the WQL (W3GoAudit Query Language) template engine.
package engine

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
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
	// ScopeSource loops over raw source files. Most templates should use an
	// AST scope; regex is also available as a scoped predicate there.
	ScopeSource Scope = "source"
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
	References     []string `yaml:"references,omitempty" json:"references,omitempty"`
	Fix            string   `yaml:"fix,omitempty" json:"fix,omitempty"`
}

// TemplateLoadOptions controls directory template loading.
type TemplateLoadOptions struct {
	// IgnoreInvalid keeps scanning a template directory when one file is
	// malformed or incomplete. The default is fail-closed: any invalid template
	// aborts loading so security scans do not silently run with missing rules.
	IgnoreInvalid bool
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
	// ========== METADATA ==========
	// Label is a human-readable name for this rule branch. It carries no
	// matching semantics; it is surfaced in a finding's related-site list so
	// contract-scope combination rules can name each matched site (e.g.
	// "payable msg.value entrypoint"). Optional.
	Label string `yaml:"label,omitempty" json:"label,omitempty"`

	// ========== LOGIC OPERATORS ==========
	All []Rule `yaml:"all,omitempty" json:"all,omitempty"`
	Any []Rule `yaml:"any,omitempty" json:"any,omitempty"`
	Not *Rule  `yaml:"not,omitempty" json:"not,omitempty"`

	// Sequence: ordered matching of descendants
	Sequence []Rule `yaml:"sequence,omitempty" json:"sequence,omitempty"`

	// ========== ATOMIC MATCHERS ==========
	Kind string `yaml:"kind,omitempty" json:"kind,omitempty"`
	Name string `yaml:"name,omitempty" json:"name,omitempty"`

	// Regex (`regex:`) matches raw source text for the active scope. With
	// query.scope=source it scans the whole file; in contract/function/AST
	// contexts it checks the scoped source snippet.
	Regex string `yaml:"regex,omitempty" json:"regex,omitempty"`

	// StatementContains matches when the node's nearest enclosing statement
	// (the closest `stmt.*` / `check.*` / `decl.variable` ancestor) has a
	// descendant matching this sub-rule. It is a statement-scoped sibling search
	// — narrower than `inside` (any ancestor) and wider than `contains` (this
	// node's own descendants). Combine with `not:` to require the absence of a
	// related node in the same statement, e.g. an exponentiation-typo `^` whose
	// statement holds no other bitwise/shift operator. The operator vocabulary
	// lives in the template, not the engine.
	StatementContains *Rule `yaml:"statement_contains,omitempty" json:"statement_contains,omitempty"`

	// UncheckedVar, on an arithmetic binary_op, matches only when the operation's
	// operands were NOT bounded by a preceding guard (require/assert/if condition
	// that references every operand identifier) earlier in the same function. It
	// separates a deliberate, range-checked `unchecked` block — e.g.
	// `require(a >= b); … a - b;` — from a genuinely unchecked one.
	UncheckedVar bool `yaml:"unchecked_var,omitempty" json:"unchecked_var,omitempty"`

	// ========== ATTRIBUTES ==========
	Attr map[string]interface{} `yaml:"attr,omitempty" json:"attr,omitempty"`

	// Inline attributes (promoted into Attr during normalization)
	IsStateVar interface{} `yaml:"is_state_var,omitempty" json:"is_state_var,omitempty"`
	Operator   string      `yaml:"operator,omitempty" json:"operator,omitempty"`

	// Visibility / Mutability accept a comma-separated "is one of" list
	// (`public,external`, `payable,nonpayable`). In a filter: block they are a
	// function-level precondition; in a match: block they match a node's
	// visibility/mutability attribute (e.g. a `decl.function` at contract scope).
	// One keyword, routed by layer — no `_filter` variant.
	Visibility string `yaml:"visibility,omitempty" json:"visibility,omitempty"`
	Mutability string `yaml:"mutability,omitempty" json:"mutability,omitempty"`

	// ========== CONTEXT HELPERS (function-level filters) ==========
	Extends  string `yaml:"extends,omitempty" json:"extends,omitempty"`
	Modifier string `yaml:"modifier,omitempty" json:"modifier,omitempty"`

	// FuncName filters by function name regex (filter-level, not AST name).
	// Use this in filter blocks to restrict which functions are checked.
	// Named FuncName to avoid collision with AST `name`.
	FuncName string `yaml:"func_name,omitempty" json:"func_name,omitempty"`

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

	if err := finalizeTemplate(&tmpl, data, path); err != nil {
		return nil, err
	}
	return &tmpl, nil
}

// validSeverities is the closed set of finding severities. A typo here used to
// produce findings that appeared on the console but silently vanished from the
// Markdown/HTML reports (which only render the known severity buckets).
var validSeverities = map[string]bool{
	"CRITICAL": true, "HIGH": true, "MEDIUM": true, "LOW": true, "INFO": true,
}

// finalizeTemplate runs the full validate+normalize pipeline shared by the file
// loader (LoadTemplate) and the inline loader (ParseTemplate), so both behave
// identically. `data` is the raw YAML (for arg.N key recovery) and `source`
// names the origin for error messages.
func finalizeTemplate(tmpl *Template, data []byte, source string) error {
	if err := validateTemplateMeta(tmpl, source); err != nil {
		return err
	}
	if !validSeverities[strings.ToUpper(tmpl.Meta.Severity)] {
		return fmt.Errorf("template %s: invalid severity %q — must be one of CRITICAL, HIGH, MEDIUM, LOW, INFO", source, tmpl.Meta.Severity)
	}
	if err := validateScope(tmpl.Query.Scope); err != nil {
		return fmt.Errorf("template %s: %w", source, err)
	}

	// Validate that filter/match rules sit at the right layer.
	if err := validateRulePlacement(&tmpl.Query); err != nil {
		return err
	}

	// Source scope is regex-only and reads only a top-level match.regex;
	// a filter or nested regex would silently do nothing.
	if tmpl.Query.Scope == ScopeSource {
		if tmpl.Query.Filter != nil {
			return fmt.Errorf("template %s: scope: source does not support filter: — use a top-level match.regex", source)
		}
		if tmpl.Query.Match.Regex == "" {
			return fmt.Errorf("template %s: scope: source requires a top-level match.regex", source)
		}
	}

	// Promote inline attrs into Attr maps so the matcher can read them uniformly.
	normalizeQueryBlock(&tmpl.Query)

	// Post-process: scan raw YAML for arg.N flat keys (non-fatal).
	if err := normalizeArgNKeys(data, tmpl); err != nil {
		VerboseLog("Warning: arg.N normalization failed for %s: %v", source, err)
	}

	// Surface bad regexes, presets, kinds, and out-of-vocabulary values as load
	// errors instead of silently rewriting/skipping rule semantics at scan time.
	for label, rule := range map[string]*Rule{"match": &tmpl.Query.Match, "filter": tmpl.Query.Filter} {
		if err := validateRegexes(rule); err != nil {
			return fmt.Errorf("%s: %w", label, err)
		}
		if err := validatePresets(rule); err != nil {
			return fmt.Errorf("%s: %w", label, err)
		}
		if err := validateKinds(rule); err != nil {
			return fmt.Errorf("%s: %w", label, err)
		}
		if err := validateRuleValues(rule); err != nil {
			return fmt.Errorf("%s: %w", label, err)
		}
	}

	return nil
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
	// visibility/mutability are matched directly by matchAtomic (CSV-aware) and
	// by the function-filter path — no attr promotion needed.

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
	normalizeRule(r.StatementContains)
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
//     func_name, visibility_filter, mutability_filter, has_guard,
//     has_param, version, preset).
//   - match:   AST node predicates only (kind, name, contains, sequence,
//     inside, args, tainted_from, left/right, attr, operator,
//     is_state_var, visibility, mutability).
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

// fieldClass tags a Rule field by the layer(s) it is valid in.
type fieldClass uint8

const (
	classAST     fieldClass = iota // AST-level — only valid in match:
	classContext                   // function/contract precondition — only valid in filter:
	classDual                      // valid in both layers
)

// ruleField is one classified field present on a Rule node.
type ruleField struct {
	name  string
	class fieldClass
}

// presentRuleFields is the SINGLE source of truth for classifying Rule fields as
// AST-level, context-level, or dual. It returns the classifiable fields set on r
// (node-local, no recursion). All three consumers read it — checkRule (placement
// validation), ruleHasASTFields, and ruleHasContextFields — so adding a field
// means editing exactly one table. `label` and the logical operators
// (all/any/not/sequence) are not layer-classified and are intentionally omitted.
func presentRuleFields(r *Rule) []ruleField {
	var out []ruleField
	add := func(present bool, name string, class fieldClass) {
		if present {
			out = append(out, ruleField{name, class})
		}
	}
	// AST-level
	add(r.Kind != "", "kind", classAST)
	add(r.Name != "", "name", classAST)
	add(r.Contains != nil, "contains", classAST)
	add(r.Inside != nil, "inside", classAST)
	add(len(r.Sequence) > 0, "sequence", classAST)
	add(len(r.Args) > 0, "args", classAST)
	add(r.TaintedFrom != "", "tainted_from", classAST)
	add(r.Left != nil, "left", classAST)
	add(r.Right != nil, "right", classAST)
	add(len(r.Attr) > 0, "attr", classAST)
	add(r.Operator != "", "operator", classAST)
	add(r.IsStateVar != nil, "is_state_var", classAST)
	add(r.UncheckedVar, "unchecked_var", classAST)
	add(r.StatementContains != nil, "statement_contains", classAST)
	// Context-level
	add(r.Modifier != "", "modifier", classContext)
	add(r.Extends != "", "extends", classContext)
	add(r.FuncName != "", "func_name", classContext)
	add(r.HasGuard != nil, "has_guard", classContext)
	add(r.HasParam != "", "has_param", classContext)
	add(r.Version != "", "version", classContext)
	add(r.Preset != "", "preset", classContext)
	// Dual — valid in both layers (precondition in filter:, attribute/scoped
	// match in match:)
	add(r.Regex != "", "regex", classDual)
	add(r.Visibility != "", "visibility", classDual)
	add(r.Mutability != "", "mutability", classDual)
	return out
}

// checkRule recursively walks a rule tree. inMatch=true means we're inside
// `match:` (AST layer), so context-only fields are forbidden. inMatch=false
// means `filter:` (context layer), so AST-only fields are forbidden. Dual
// fields are allowed in either.
func checkRule(r *Rule, where string, inMatch bool) error {
	if r == nil {
		return nil
	}

	for _, f := range presentRuleFields(r) {
		if inMatch && f.class == classContext {
			return fmt.Errorf("invalid template: `%s` is a context-level field and cannot appear inside `match:` — move it under `filter:`", f.name)
		}
		if !inMatch && f.class == classAST {
			return fmt.Errorf("invalid template: `%s` is an AST-level field and cannot appear inside `filter:` — move it under `match:`", f.name)
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

func validateTemplateMeta(tmpl *Template, path string) error {
	if tmpl == nil {
		return fmt.Errorf("template %s: empty template", path)
	}
	if tmpl.Meta.ID == "" {
		return fmt.Errorf("template %s: missing meta.id", path)
	}
	if tmpl.Meta.Severity == "" {
		return fmt.Errorf("template %s: missing meta.severity", path)
	}
	return nil
}

// LoadTemplates loads all templates from a directory recursively.
//
// The default is fail-closed: malformed templates, missing required metadata,
// or a directory with zero valid templates return an error. Use
// LoadTemplatesWithOptions(..., TemplateLoadOptions{IgnoreInvalid: true}) when
// intentionally running a mixed directory and wanting invalid files skipped.
func LoadTemplates(dir string) ([]*Template, error) {
	return LoadTemplatesWithOptions(dir, TemplateLoadOptions{})
}

// LoadTemplatesLenient preserves the older "skip invalid files" behavior for
// ad-hoc tooling. Production and CI scans should prefer LoadTemplates.
func LoadTemplatesLenient(dir string) ([]*Template, error) {
	return LoadTemplatesWithOptions(dir, TemplateLoadOptions{IgnoreInvalid: true})
}

// LoadTemplatesWithOptions loads all templates from a directory recursively.
func LoadTemplatesWithOptions(dir string, opts TemplateLoadOptions) ([]*Template, error) {
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
			if opts.IgnoreInvalid {
				VerboseLog("⚠️  Skipping invalid template %s: %v", path, err)
				return nil
			}
			return fmt.Errorf("invalid template %s: %w", path, err)
		}

		if err := validateTemplateMeta(tmpl, path); err != nil {
			if opts.IgnoreInvalid {
				VerboseLog("⚠️  Skipping template %s: %v", path, err)
				return nil
			}
			return err
		}

		// LoadTemplate validates required metadata too; keep this second check
		// as a defensive guard for future loader changes.
		if tmpl.Meta.ID == "" || tmpl.Meta.Severity == "" {
			if opts.IgnoreInvalid {
				VerboseLog("⚠️  Skipping incomplete template %s", path)
				return nil
			}
			return fmt.Errorf("template %s: missing required metadata", path)
		}

		VerboseLog("✓ Loaded template: %s (%s)", tmpl.Meta.ID, path)
		templates = append(templates, tmpl)
		return nil
	})

	if err != nil {
		return nil, err
	}
	if len(templates) == 0 {
		return nil, fmt.Errorf("no valid templates found in %s", dir)
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
	if err := finalizeTemplate(&tmpl, data, "<inline>"); err != nil {
		return nil, err
	}
	return &tmpl, nil
}

// LoadTemplatesFromFS loads all .yaml/.yml templates from an fs.FS subtree,
// applying the same fail-closed validation as the path-based loader. This backs
// the embedded default template pack (go:embed) so the binary can scan with a
// sensible default rule set even when no --template directory is given.
func LoadTemplatesFromFS(fsys fs.FS, dir string, opts TemplateLoadOptions) ([]*Template, error) {
	var templates []*Template

	err := fs.WalkDir(fsys, dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		name := d.Name()
		if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
			return nil
		}
		data, readErr := fs.ReadFile(fsys, path)
		if readErr != nil {
			if opts.IgnoreInvalid {
				VerboseLog("⚠️  Skipping unreadable template %s: %v", path, readErr)
				return nil
			}
			return fmt.Errorf("read template %s: %w", path, readErr)
		}
		var tmpl Template
		if uErr := yaml.Unmarshal(data, &tmpl); uErr != nil {
			if opts.IgnoreInvalid {
				VerboseLog("⚠️  Skipping invalid template %s: %v", path, uErr)
				return nil
			}
			return fmt.Errorf("invalid template %s: %w", path, uErr)
		}
		if fErr := finalizeTemplate(&tmpl, data, path); fErr != nil {
			if opts.IgnoreInvalid {
				VerboseLog("⚠️  Skipping invalid template %s: %v", path, fErr)
				return nil
			}
			return fmt.Errorf("invalid template %s: %w", path, fErr)
		}
		VerboseLog("✓ Loaded embedded template: %s (%s)", tmpl.Meta.ID, path)
		templates = append(templates, &tmpl)
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(templates) == 0 {
		return nil, fmt.Errorf("no valid templates found in %s", dir)
	}
	return templates, nil
}

// IsEmpty returns true if the rule has no conditions
func (r *Rule) IsEmpty() bool {
	return len(r.All) == 0 && len(r.Any) == 0 && len(r.Sequence) == 0 &&
		r.Not == nil && r.Contains == nil && r.Inside == nil &&
		r.Kind == "" && r.Name == "" && len(r.Attr) == 0 &&
		r.Regex == "" &&
		r.Extends == "" && r.Modifier == "" && len(r.Args) == 0 &&
		r.TaintedFrom == "" && r.Version == "" && r.Preset == "" &&
		r.Left == nil && r.Right == nil && r.HasParam == "" &&
		r.FuncName == "" &&
		r.HasGuard == nil && r.IsStateVar == nil &&
		r.Operator == "" && r.Visibility == "" && r.Mutability == "" &&
		!r.UncheckedVar && r.StatementContains == nil
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

// matchAnchoredRegex matches value against pattern anchored at both ends, so the
// pattern must describe the WHOLE value. Used for attribute matching, where a
// substring match (`operator: "="` matching `==`) is a footgun. An empty pattern
// matches anything.
func matchAnchoredRegex(pattern, value string) bool {
	if pattern == "" {
		return true
	}
	re, err := compileRegexCached("^(?:" + pattern + ")$")
	if err != nil || re == nil {
		return false
	}
	return re.MatchString(value)
}

// walkRules invokes visit on r and every nested sub-rule (logic operators,
// traversal, left/right, has_guard, args). It is the single source of truth for
// "visit every Rule slot" — validators built on it cannot drift out of sync the
// way the previous hand-rolled recursive walkers did.
func walkRules(r *Rule, visit func(*Rule) error) error {
	if r == nil {
		return nil
	}
	if err := visit(r); err != nil {
		return err
	}
	for i := range r.All {
		if err := walkRules(&r.All[i], visit); err != nil {
			return err
		}
	}
	for i := range r.Any {
		if err := walkRules(&r.Any[i], visit); err != nil {
			return err
		}
	}
	if err := walkRules(r.Not, visit); err != nil {
		return err
	}
	for i := range r.Sequence {
		if err := walkRules(&r.Sequence[i], visit); err != nil {
			return err
		}
	}
	if err := walkRules(r.Contains, visit); err != nil {
		return err
	}
	if err := walkRules(r.Inside, visit); err != nil {
		return err
	}
	if err := walkRules(r.Left, visit); err != nil {
		return err
	}
	if err := walkRules(r.Right, visit); err != nil {
		return err
	}
	if err := walkRules(r.HasGuard, visit); err != nil {
		return err
	}
	if err := walkRules(r.StatementContains, visit); err != nil {
		return err
	}
	// Visit args in sorted key order so error reporting is deterministic.
	if len(r.Args) > 0 {
		keys := make([]int, 0, len(r.Args))
		for k := range r.Args {
			keys = append(keys, k)
		}
		sort.Ints(keys)
		for _, k := range keys {
			v := r.Args[k]
			if err := walkRules(&v, visit); err != nil {
				return err
			}
			r.Args[k] = v
		}
	}
	return nil
}

// validKindsMessage lists the acceptable kind forms; generated from the
// semantic-group registry so it can't drift from matchKind.
func validKindsMessage() string {
	groups := make([]string, 0, len(types.KnownSemanticGroups))
	for g := range types.KnownSemanticGroups {
		groups = append(groups, g)
	}
	sort.Strings(groups)
	return "a registered AST kind (see pkg/types/ast.go), a semantic group (" +
		strings.Join(groups, ", ") + "), or a known prefix (call, check, stmt, expr, decl, asm, call.lowlevel, call.builtin)"
}

// validateKinds rejects any `kind:` value that isn't a registered exact kind,
// semantic group, or known dotted prefix. Without this, a typo like
// `kind: outgoing_calls` (plural) silently matched nothing at scan time.
func validateKinds(r *Rule) error {
	return walkRules(r, func(n *Rule) error {
		if n.Kind != "" && !types.IsKnownKind(n.Kind) {
			return fmt.Errorf("unknown kind %q — must be %s", n.Kind, validKindsMessage())
		}
		return nil
	})
}

// validatePresets rejects any preset name that isn't registered. Without this,
// a typo like `preset: unAuthenticatd` previously caused checkBuiltinPreset to
// return true, silently matching every function.
func validatePresets(r *Rule) error {
	return walkRules(r, func(n *Rule) error {
		if n.Preset != "" && !IsKnownPreset(n.Preset) {
			return fmt.Errorf("unknown preset %q — known presets: unAuthenticated, unLocked", n.Preset)
		}
		return nil
	})
}

// validateRegexes surfaces any invalid regex pattern as a load error so authors
// see typos immediately instead of getting silently-empty findings.
func validateRegexes(r *Rule) error {
	return walkRules(r, func(n *Rule) error {
		checks := []struct{ field, pattern string }{
			{"name", n.Name},
			{"regex", n.Regex},
			{"modifier", n.Modifier},
			{"extends", n.Extends},
			{"func_name", n.FuncName},
		}
		for _, c := range checks {
			if c.pattern == "" {
				continue
			}
			if _, err := compileRegexCached(c.pattern); err != nil {
				return fmt.Errorf("invalid regex in %q: %s — %w", c.field, c.pattern, err)
			}
		}
		// Attribute string values are matched as regex (see matchAttributeValue).
		for k, v := range n.Attr {
			if s, ok := v.(string); ok && s != "" {
				if _, err := compileRegexCached(s); err != nil {
					return fmt.Errorf("invalid regex in attr.%s: %s — %w", k, s, err)
				}
			}
		}
		return nil
	})
}

// Closed sets for value-level validation. A typo in any of these previously
// loaded cleanly and then silently matched nothing (tainted_from) or excluded
// everything (visibility_filter/mutability_filter) at scan time.
var (
	validTaintSources = map[string]bool{
		"parameter": true, "state_var": true, "local_var": true, "sender": true,
	}
	validVisibilities = map[string]bool{
		"public": true, "external": true, "internal": true, "private": true,
	}
	validMutabilities = map[string]bool{
		"payable": true, "view": true, "pure": true, "nonpayable": true,
	}
)

// validateRuleValues rejects out-of-vocabulary values for the closed-set fields
// and malformed version constraints, recursively.
func validateRuleValues(r *Rule) error {
	return walkRules(r, func(n *Rule) error {
		if n.TaintedFrom != "" && !validTaintSources[n.TaintedFrom] {
			return fmt.Errorf("unknown tainted_from %q — must be one of: parameter, state_var, local_var, sender", n.TaintedFrom)
		}
		if err := validateCSVVocabulary("visibility", n.Visibility, validVisibilities); err != nil {
			return err
		}
		if err := validateCSVVocabulary("mutability", n.Mutability, validMutabilities); err != nil {
			return err
		}
		if n.Version != "" {
			if err := validateVersionConstraint(n.Version); err != nil {
				return err
			}
		}
		return nil
	})
}

// validateCSVVocabulary checks each comma-separated token of value against the
// allowed set. Empty value is a no-op.
func validateCSVVocabulary(field, value string, allowed map[string]bool) error {
	if value == "" {
		return nil
	}
	for _, part := range strings.Split(value, ",") {
		token := strings.TrimSpace(strings.ToLower(part))
		if token == "" {
			continue
		}
		if !allowed[token] {
			keys := make([]string, 0, len(allowed))
			for k := range allowed {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			return fmt.Errorf("unknown %s value %q — must be one of: %s", field, token, strings.Join(keys, ", "))
		}
	}
	return nil
}

// versionConstraintPattern accepts an optional comparison operator followed by a
// dotted version (e.g. ">=0.8.0", "0.8", "^0.8.0"). The caret/tilde forms are
// accepted syntactically and treated as equality at scan time.
var versionConstraintPattern = regexp.MustCompile(`^\s*(>=|<=|==|>|<|=|\^|~)?\s*\d+(\.\d+){0,2}\s*$`)

// validateVersionConstraint rejects a version: constraint that the version
// comparator cannot parse, instead of silently degrading to a garbled equality.
func validateVersionConstraint(constraint string) error {
	if !versionConstraintPattern.MatchString(constraint) {
		return fmt.Errorf("invalid version constraint %q — expected e.g. \">=0.8.0\", \"<0.7.0\", or \"0.8.0\"", constraint)
	}
	return nil
}

// validateScope rejects an unknown scope at load. An empty scope is allowed and
// defaults to entrypoint (see Engine.Execute); a non-empty unknown scope used to
// silently fall through to entrypoint, changing what code got scanned.
func validateScope(s Scope) error {
	switch s {
	case "", ScopeAllContract, ScopeMainContract, ScopeFunction, ScopeEntrypoint,
		ScopeContract, ScopeLibrary, ScopeAbstract, ScopeSource:
		return nil
	}
	return fmt.Errorf("unknown scope %q — must be one of: source, function, entrypoint, contract, library, abstract, all_contract, main_contract", s)
}
