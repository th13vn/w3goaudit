// Package engine provides the WQL (W3GoAudit Query Language) template engine.
package engine

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/th13vn/w3goaudit/pkg/logging"
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

// Template is the compiled evaluator IR for one vulnerability detector.
// Public WQL documents are lowered into this structure before validation
// and execution. It is intentionally not a YAML decoding target.
type Template struct {
	Meta  TemplateMeta `json:"meta"`
	Query QueryBlock   `json:"query"`

	// Queries carries every executable block when the template composes
	// multiple queries with a query-level or: (Queries[0] == Query). The
	// engine executes each block and unions the findings under this
	// template's meta. Empty for single-query templates.
	Queries []QueryBlock `json:"queries,omitempty"`
}

// UnmarshalYAML prevents callers from bypassing the WQL loaders by decoding
// the exported evaluator IR directly from YAML. Programmatic IR construction
// and JSON serialization remain supported.
func (*Template) UnmarshalYAML(*yaml.Node) error {
	return fmt.Errorf("the evaluator IR is not a YAML template schema; use ParseTemplate or LoadTemplate")
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

	// Logger receives template-loading diagnostics for this scan. Nil preserves
	// the legacy package-global verbose configuration.
	Logger *logging.Logger
}

func templateLogf(logger *logging.Logger, format string, args ...any) {
	if logger == nil {
		VerboseLog(format, args...)
		return
	}
	logger.Printf(format, args...)
}

// QueryBlock defines the evaluator scope, optional filter, and matching rules.
// Its two rule layers are:
//   - filter: function/contract-level preconditions
//   - match:  AST pattern matching rules
type QueryBlock struct {
	Scope  Scope `json:"scope"`
	Filter *Rule `json:"filter,omitempty"`
	Match  Rule  `json:"match"`
}

// Rule represents one recursive evaluator IR matching rule.
// Default logic: ALL fields must match (AND semantics).
// Aliases are normalized to internal fields during loading.
type Rule struct {
	// ========== METADATA ==========
	// Label is a human-readable name for this rule branch. It carries no
	// matching semantics; it is surfaced in a finding's related-site list so
	// contract-scope combination rules can name each matched site (e.g.
	// "payable msg.value entrypoint"). Optional.
	Label string `json:"label,omitempty"`

	// ========== LOGIC OPERATORS ==========
	All []Rule `json:"all,omitempty"`
	Any []Rule `json:"any,omitempty"`
	Not *Rule  `json:"not,omitempty"`

	// Sequence: ordered matching of descendants
	Sequence []Rule `json:"sequence,omitempty"`

	// ========== ATOMIC MATCHERS ==========
	Kind string `json:"kind,omitempty"`
	Name string `json:"name,omitempty"`

	// Regex (`regex:`) matches raw source text for the active scope. With
	// query.scope=source it scans the whole file; in contract/function/AST
	// contexts it checks the scoped source snippet.
	Regex string `json:"regex,omitempty"`

	// SourceRegex is a deprecated programmatic/JSON alias for Regex. Public
	// WQL accepts only the canonical `regex` matcher.
	SourceRegex string `json:"source_regex,omitempty"`

	// StatementContains matches when the node's nearest enclosing statement
	// (the closest `stmt.*` / `check.*` / `decl.variable` ancestor) has a
	// descendant matching this sub-rule. It is a statement-scoped sibling search
	// — narrower than `inside` (any ancestor) and wider than `contains` (this
	// node's own descendants). Combine with `not:` to require the absence of a
	// related node in the same statement, e.g. an exponentiation-typo `^` whose
	// statement holds no other bitwise/shift operator. The operator vocabulary
	// lives in the template, not the engine.
	StatementContains *Rule `json:"statement_contains,omitempty"`

	// UncheckedVar, on an arithmetic binary_op or assignment, matches only when
	// the operation's operands were NOT bounded by a preceding guard
	// (require/assert/if condition that references every operand identifier)
	// earlier in the same function. It
	// separates deliberate, range-checked subtraction — e.g.
	// `require(a >= b); … a - b;` or `a -= b;` — from genuinely unchecked math.
	UncheckedVar bool `json:"unchecked_var,omitempty"`

	// ========== ATTRIBUTES ==========
	Attr map[string]interface{} `json:"attr,omitempty"`

	// Inline attributes (promoted into Attr during normalization)
	IsStateVar interface{} `json:"is_state_var,omitempty"`
	Operator   string      `json:"operator,omitempty"`

	// Visibility / Mutability accept a comma-separated "is one of" list
	// (`public,external`, `payable,nonpayable`). In a filter: block they are a
	// function-level precondition; in a match: block they match a node's
	// visibility/mutability attribute (e.g. a `decl.function` at contract scope).
	// One keyword, routed by layer — no `_filter` variant.
	Visibility string `json:"visibility,omitempty"`
	Mutability string `json:"mutability,omitempty"`

	// VisibilityFilter and MutabilityFilter are deprecated programmatic/JSON
	// aliases. Public WQL accepts only visibility and mutability.
	VisibilityFilter string `json:"visibility_filter,omitempty"`
	MutabilityFilter string `json:"mutability_filter,omitempty"`

	// ========== CONTEXT HELPERS (function-level filters) ==========
	Extends  string `json:"extends,omitempty"`
	Modifier string `json:"modifier,omitempty"`

	// FuncName filters by function name regex (filter-level, not AST name).
	// Use this in filter blocks to restrict which functions are checked.
	// Named FuncName to avoid collision with AST `name`.
	FuncName string `json:"func_name,omitempty"`

	// HasGuard checks if the function body contains a require/assert guard
	// with a specific pattern. Used in filter blocks.
	// Example: has_guard: { contains: { pattern: msg.sender } }
	HasGuard *Rule `json:"has_guard,omitempty"`

	// ========== TRAVERSAL ==========
	Contains *Rule `json:"contains,omitempty"`
	Inside   *Rule `json:"inside,omitempty"`

	// ========== CALL-SPECIFIC ==========
	// Args matches call arguments by 0-based index.
	// Two equivalent notations are accepted in YAML:
	//   args: { 0: ..., 1: ... }
	//   arg.0: ...
	//   arg.1: ...
	Args map[int]Rule `json:"args,omitempty"`

	// ArgAny (`arg.any:`) matches when SOME positional argument of the call
	// matches the sub-rule. Receivers and call options (value/gas) are not
	// arguments, exactly as with Args.
	ArgAny *Rule `json:"arg_any,omitempty"`

	// ========== TAINT ANALYSIS ==========
	TaintedFrom string `json:"tainted_from,omitempty"`

	// ========== VERSION CHECKING ==========
	Version string `json:"version,omitempty"`

	// ========== PRESETS ==========
	Preset string `json:"preset,omitempty"`

	// ========== LEFT/RIGHT MATCHING ==========
	Left  *Rule `json:"left,omitempty"`
	Right *Rule `json:"right,omitempty"`

	// ========== FILTER-SPECIFIC ==========
	HasParam string `json:"has_param,omitempty"` // check function has param named X
}

// LoadTemplate loads a template from a YAML file.
func LoadTemplate(path string) (*Template, error) {
	return loadTemplateWithLogger(path, nil)
}

func loadTemplateWithLogger(path string, logger *logging.Logger) (*Template, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}
	return parseTemplateDocument(data, path, logger)
}

func parseTemplateDocument(data []byte, source string, logger *logging.Logger) (*Template, error) {
	doc, err := parseWQL(data)
	if err != nil {
		return nil, fmt.Errorf("template %s: %w", source, err)
	}
	tmpl, err := doc.lower()
	if err != nil {
		return nil, fmt.Errorf("template %s: %w", source, err)
	}
	if err := finalizeTemplateWithLogger(tmpl, source, logger); err != nil {
		return nil, err
	}
	return tmpl, nil
}

// validSeverities is the closed set of finding severities. A typo here used to
// produce findings that appeared on the console but silently vanished from the
// Markdown/HTML reports (which only render the known severity buckets).
var validSeverities = map[string]bool{
	"CRITICAL": true, "HIGH": true, "MEDIUM": true, "LOW": true, "INFO": true,
}

// finalizeTemplate runs the full validate+normalize pipeline shared by the file
// loader (LoadTemplate) and the inline loader (ParseTemplate), so both behave
// identically. `source` names the origin for error messages.
func finalizeTemplate(tmpl *Template, source string) error {
	return finalizeTemplateWithLogger(tmpl, source, nil)
}

func finalizeTemplateWithLogger(tmpl *Template, source string, logger *logging.Logger) error {
	if err := validateTemplateMeta(tmpl, source); err != nil {
		return err
	}
	if !validSeverities[strings.ToUpper(tmpl.Meta.Severity)] {
		return fmt.Errorf("template %s: invalid severity %q — must be one of CRITICAL, HIGH, MEDIUM, LOW, INFO", source, tmpl.Meta.Severity)
	}

	// Validate/normalize every executable block: the primary Query plus every
	// or:-composed block in Queries (Queries[0] is kept equal to Query; the
	// normalization pipeline is deterministic, so finalizing both preserves
	// that equality).
	blocks := []*QueryBlock{&tmpl.Query}
	for i := range tmpl.Queries {
		blocks = append(blocks, &tmpl.Queries[i])
	}
	for _, q := range blocks {
		if err := finalizeQueryBlock(q, source); err != nil {
			return err
		}
	}
	return nil
}

// finalizeQueryBlock runs the per-block validate+normalize pipeline: scope,
// rule placement, source-scope shape, inline-attr normalization, and
// regex/preset/kind/value validation.
func finalizeQueryBlock(q *QueryBlock, source string) error {
	if err := normalizeCompatibilityAliases(q); err != nil {
		return fmt.Errorf("template %s: %w", source, err)
	}
	if err := validateScope(q.Scope); err != nil {
		return fmt.Errorf("template %s: %w", source, err)
	}

	// Validate that filter/match rules sit at the right layer.
	if err := validateRulePlacement(q); err != nil {
		return err
	}

	// Source scope is regex-only and reads only a top-level match.regex;
	// a filter or nested regex would silently do nothing.
	if q.Scope == ScopeSource {
		if q.Filter != nil {
			return fmt.Errorf("template %s: scope: source does not support filter: — use a top-level match.regex", source)
		}
		if q.Match.Regex == "" {
			return fmt.Errorf("template %s: scope: source requires a top-level match.regex", source)
		}
	}

	// Promote inline attrs into Attr maps so the matcher can read them uniformly.
	normalizeQueryBlock(q)

	// Surface bad regexes, presets, kinds, and out-of-vocabulary values as load
	// errors instead of silently rewriting/skipping rule semantics at scan time.
	for label, rule := range map[string]*Rule{"match": &q.Match, "filter": q.Filter} {
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

// normalizeCompatibilityAliases preserves the removed evaluator-IR Go/JSON
// fields without exposing them through WQL. Canonical values are populated
// before placement and value validation. Equal duplicate values are accepted;
// conflicting non-empty values fail closed.
func normalizeCompatibilityAliases(q *QueryBlock) error {
	if q == nil {
		return nil
	}
	cloned, err := normalizedQueryBlockCompatibilityCopy(q, "")
	if err != nil {
		return err
	}
	*q = cloned
	return nil
}

func normalizeRuleCompatibilityAliases(rule *Rule, label string) error {
	return walkRules(rule, func(r *Rule) error {
		aliases := []struct {
			canonicalName string
			aliasName     string
			canonical     *string
			alias         string
		}{
			{"regex", "source_regex", &r.Regex, r.SourceRegex},
			{"visibility", "visibility_filter", &r.Visibility, r.VisibilityFilter},
			{"mutability", "mutability_filter", &r.Mutability, r.MutabilityFilter},
		}
		for _, pair := range aliases {
			if pair.alias == "" {
				continue
			}
			if *pair.canonical != "" && *pair.canonical != pair.alias {
				return fmt.Errorf("%s: conflicting %s %q and deprecated %s %q", label, pair.canonicalName, *pair.canonical, pair.aliasName, pair.alias)
			}
			if *pair.canonical == "" {
				*pair.canonical = pair.alias
			}
		}
		return nil
	})
}

func normalizedRuleCompatibilityCopy(rule Rule, label string) (Rule, error) {
	return normalizedRuleCompatibilityCopyFrom(&rule, label)
}

func prepareRuleForEvaluation(rule Rule, label string) (Rule, error) {
	normalized, err := normalizedRuleCompatibilityCopy(rule, label)
	if err != nil {
		return Rule{}, err
	}
	normalizeRule(&normalized)
	for _, validate := range []func(*Rule) error{
		validateRegexes,
		validatePresets,
		validateKinds,
		validateRuleValues,
	} {
		if err := validate(&normalized); err != nil {
			return Rule{}, err
		}
	}
	return normalized, nil
}

func normalizedRuleCompatibilityCopyFrom(rule *Rule, label string) (Rule, error) {
	cloned, err := cloneRuleGraph(rule, label)
	if err != nil {
		return Rule{}, err
	}
	if err := normalizeRuleCompatibilityAliases(&cloned, label); err != nil {
		return Rule{}, err
	}
	return cloned, nil
}

type ruleCloneState struct {
	active           map[*Rule]string
	activeContainers map[ruleContainerIdentity]string
}

type ruleContainerIdentity struct {
	kind reflect.Kind
	ptr  uintptr
}

func cloneRuleGraph(rule *Rule, label string) (Rule, error) {
	if rule == nil {
		return Rule{}, nil
	}
	if label == "" {
		label = "rule"
	}
	state := ruleCloneState{
		active:           make(map[*Rule]string),
		activeContainers: make(map[ruleContainerIdentity]string),
	}
	return state.clone(rule, 1, label)
}

func (state *ruleCloneState) clone(rule *Rule, depth int, path string) (Rule, error) {
	if depth > MaxRuleRecursionDepth {
		return Rule{}, fmt.Errorf("%s: rule nesting depth %d exceeds maximum %d", path, depth, MaxRuleRecursionDepth)
	}
	if ancestor, exists := state.active[rule]; exists {
		return Rule{}, fmt.Errorf("%s: cyclic Rule reference to %s", path, ancestor)
	}
	state.active[rule] = path
	defer delete(state.active, rule)

	cloned := *rule
	var err error
	if cloned.All, err = state.cloneSlice(rule.All, depth+1, path+".all"); err != nil {
		return Rule{}, err
	}
	if cloned.Any, err = state.cloneSlice(rule.Any, depth+1, path+".any"); err != nil {
		return Rule{}, err
	}
	if cloned.Not, err = state.clonePointer(rule.Not, depth+1, path+".not"); err != nil {
		return Rule{}, err
	}
	if cloned.Sequence, err = state.cloneSlice(rule.Sequence, depth+1, path+".sequence"); err != nil {
		return Rule{}, err
	}
	if cloned.Attr, err = state.cloneRuleAttributes(rule.Attr, depth, path+".attr"); err != nil {
		return Rule{}, err
	}
	if cloned.IsStateVar, err = state.cloneRuleAttributeValue(rule.IsStateVar, depth, path+".is_state_var"); err != nil {
		return Rule{}, err
	}
	if cloned.StatementContains, err = state.clonePointer(rule.StatementContains, depth+1, path+".statement_contains"); err != nil {
		return Rule{}, err
	}
	if cloned.HasGuard, err = state.clonePointer(rule.HasGuard, depth+1, path+".has_guard"); err != nil {
		return Rule{}, err
	}
	if cloned.Contains, err = state.clonePointer(rule.Contains, depth+1, path+".contains"); err != nil {
		return Rule{}, err
	}
	if cloned.Inside, err = state.clonePointer(rule.Inside, depth+1, path+".inside"); err != nil {
		return Rule{}, err
	}
	if cloned.Args, err = state.cloneArgs(rule.Args, depth+1, path+".args"); err != nil {
		return Rule{}, err
	}
	if cloned.ArgAny, err = state.clonePointer(rule.ArgAny, depth+1, path+".arg_any"); err != nil {
		return Rule{}, err
	}
	if cloned.Left, err = state.clonePointer(rule.Left, depth+1, path+".left"); err != nil {
		return Rule{}, err
	}
	if cloned.Right, err = state.clonePointer(rule.Right, depth+1, path+".right"); err != nil {
		return Rule{}, err
	}
	return cloned, nil
}

func (state *ruleCloneState) cloneSlice(rules []Rule, depth int, path string) ([]Rule, error) {
	if rules == nil {
		return nil, nil
	}
	cloned := make([]Rule, len(rules))
	for i := range rules {
		var err error
		cloned[i], err = state.clone(&rules[i], depth, fmt.Sprintf("%s[%d]", path, i))
		if err != nil {
			return nil, err
		}
	}
	return cloned, nil
}

func (state *ruleCloneState) clonePointer(rule *Rule, depth int, path string) (*Rule, error) {
	if rule == nil {
		return nil, nil
	}
	cloned, err := state.clone(rule, depth, path)
	if err != nil {
		return nil, err
	}
	return &cloned, nil
}

func (state *ruleCloneState) cloneArgs(args map[int]Rule, depth int, path string) (map[int]Rule, error) {
	if args == nil {
		return nil, nil
	}
	cloned := make(map[int]Rule, len(args))
	keys := make([]int, 0, len(args))
	for index := range args {
		keys = append(keys, index)
	}
	sort.Ints(keys)
	for _, index := range keys {
		rule := args[index]
		clonedRule, err := state.clone(&rule, depth, fmt.Sprintf("%s[%d]", path, index))
		if err != nil {
			return nil, err
		}
		cloned[index] = clonedRule
	}
	return cloned, nil
}

func (state *ruleCloneState) cloneRuleAttributes(attributes map[string]interface{}, depth int, path string) (map[string]interface{}, error) {
	if attributes == nil {
		return nil, nil
	}
	leave, err := state.enterAttributeContainer(attributes, depth, path)
	if err != nil {
		return nil, err
	}
	defer leave()

	cloned := make(map[string]interface{}, len(attributes))
	keys := make([]string, 0, len(attributes))
	for key := range attributes {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		value, err := state.cloneRuleAttributeValue(attributes[key], depth+1, fmt.Sprintf("%s[%q]", path, key))
		if err != nil {
			return nil, err
		}
		cloned[key] = value
	}
	return cloned, nil
}

func (state *ruleCloneState) cloneRuleAttributeValue(value interface{}, depth int, path string) (interface{}, error) {
	switch typed := value.(type) {
	case map[string]interface{}:
		return state.cloneRuleAttributes(typed, depth, path)
	case []interface{}:
		if typed == nil {
			return nil, nil
		}
		leave, err := state.enterAttributeContainer(typed, depth, path)
		if err != nil {
			return nil, err
		}
		defer leave()
		cloned := make([]interface{}, len(typed))
		for i := range typed {
			cloned[i], err = state.cloneRuleAttributeValue(typed[i], depth+1, fmt.Sprintf("%s[%d]", path, i))
			if err != nil {
				return nil, err
			}
		}
		return cloned, nil
	case []string:
		if typed == nil {
			return nil, nil
		}
		leave, err := state.enterAttributeContainer(typed, depth, path)
		if err != nil {
			return nil, err
		}
		defer leave()
		return append([]string(nil), typed...), nil
	default:
		return value, nil
	}
}

func (state *ruleCloneState) enterAttributeContainer(value interface{}, depth int, path string) (func(), error) {
	if depth > MaxRuleRecursionDepth {
		return nil, fmt.Errorf("%s: attribute container nesting depth %d exceeds maximum %d", path, depth, MaxRuleRecursionDepth)
	}
	reflected := reflect.ValueOf(value)
	identity := ruleContainerIdentity{kind: reflected.Kind(), ptr: reflected.Pointer()}
	if ancestor, exists := state.activeContainers[identity]; exists {
		return nil, fmt.Errorf("%s: cyclic attribute container reference to %s", path, ancestor)
	}
	state.activeContainers[identity] = path
	return func() { delete(state.activeContainers, identity) }, nil
}

func normalizedQueryBlockCompatibilityCopy(q *QueryBlock, prefix string) (QueryBlock, error) {
	if q == nil {
		return QueryBlock{}, nil
	}
	label := func(field string) string {
		if prefix == "" {
			return field
		}
		return prefix + "." + field
	}
	cloned := *q
	match, err := normalizedRuleCompatibilityCopyFrom(&q.Match, label("match"))
	if err != nil {
		return QueryBlock{}, err
	}
	cloned.Match = match
	if q.Filter != nil {
		filter, err := normalizedRuleCompatibilityCopyFrom(q.Filter, label("filter"))
		if err != nil {
			return QueryBlock{}, err
		}
		cloned.Filter = &filter
	}
	return cloned, nil
}

func normalizedTemplateCompatibilityCopy(tmpl *Template) (*Template, error) {
	if tmpl == nil {
		return nil, fmt.Errorf("empty template")
	}
	cloned := *tmpl
	query, err := normalizedQueryBlockCompatibilityCopy(&tmpl.Query, "query")
	if err != nil {
		return nil, err
	}
	cloned.Query = query
	cloned.Queries = make([]QueryBlock, len(tmpl.Queries))
	for i := range tmpl.Queries {
		query, err := normalizedQueryBlockCompatibilityCopy(&tmpl.Queries[i], fmt.Sprintf("queries[%d]", i))
		if err != nil {
			return nil, err
		}
		cloned.Queries[i] = query
	}
	return &cloned, nil
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
	normalizeRule(r.ArgAny)
	for k, v := range r.Args {
		vCopy := v
		normalizeRule(&vCopy)
		r.Args[k] = vCopy
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
	add(r.ArgAny != nil, "arg.any", classAST)
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
	if err := checkRule(r.StatementContains, where, inMatch); err != nil {
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
	if err := checkRule(r.ArgAny, where, inMatch); err != nil {
		return err
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
		tmpl, err := loadTemplateWithLogger(path, opts.Logger)
		if err != nil {
			if opts.IgnoreInvalid {
				templateLogf(opts.Logger, "⚠️  Skipping invalid template %s: %v", path, err)
				return nil
			}
			return fmt.Errorf("invalid template %s: %w", path, err)
		}

		if err := validateTemplateMeta(tmpl, path); err != nil {
			if opts.IgnoreInvalid {
				templateLogf(opts.Logger, "⚠️  Skipping template %s: %v", path, err)
				return nil
			}
			return err
		}

		// LoadTemplate validates required metadata too; keep this second check
		// as a defensive guard for future loader changes.
		if tmpl.Meta.ID == "" || tmpl.Meta.Severity == "" {
			if opts.IgnoreInvalid {
				templateLogf(opts.Logger, "⚠️  Skipping incomplete template %s", path)
				return nil
			}
			return fmt.Errorf("template %s: missing required metadata", path)
		}

		templateLogf(opts.Logger, "✓ Loaded template: %s (%s)", tmpl.Meta.ID, path)
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
	return parseTemplateDocument([]byte(yamlContent), "<inline>", nil)
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
				templateLogf(opts.Logger, "⚠️  Skipping unreadable template %s: %v", path, readErr)
				return nil
			}
			return fmt.Errorf("read template %s: %w", path, readErr)
		}
		tmpl, parseErr := parseTemplateDocument(data, path, opts.Logger)
		if parseErr != nil {
			if opts.IgnoreInvalid {
				templateLogf(opts.Logger, "⚠️  Skipping invalid template %s: %v", path, parseErr)
				return nil
			}
			return fmt.Errorf("invalid template %s: %w", path, parseErr)
		}
		templateLogf(opts.Logger, "✓ Loaded embedded template: %s (%s)", tmpl.Meta.ID, path)
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

// IsEmpty returns true if the rule has no conditions
func (r *Rule) IsEmpty() bool {
	return len(r.All) == 0 && len(r.Any) == 0 && len(r.Sequence) == 0 &&
		r.Not == nil && r.Contains == nil && r.Inside == nil &&
		r.Kind == "" && r.Name == "" && len(r.Attr) == 0 &&
		r.Regex == "" && r.SourceRegex == "" && r.ArgAny == nil &&
		r.Extends == "" && r.Modifier == "" && len(r.Args) == 0 &&
		r.TaintedFrom == "" && r.Version == "" && r.Preset == "" &&
		r.Left == nil && r.Right == nil && r.HasParam == "" &&
		r.FuncName == "" &&
		r.HasGuard == nil && r.IsStateVar == nil &&
		r.Operator == "" && r.Visibility == "" && r.Mutability == "" &&
		r.VisibilityFilter == "" && r.MutabilityFilter == "" &&
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
	if err := walkRules(r.ArgAny, visit); err != nil {
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
			return fmt.Errorf("unknown preset %q — known presets: %s", n.Preset, strings.Join(KnownPresetNames(), ", "))
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
		"user_controlled": true,
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
			return fmt.Errorf("unknown tainted_from %q — must be one of: parameter, state_var, local_var, sender, user_controlled", n.TaintedFrom)
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
// allowed set. An empty field is a no-op, while a non-empty field must contain
// at least one non-empty token.
func validateCSVVocabulary(field, value string, allowed map[string]bool) error {
	if value == "" {
		return nil
	}
	seen := 0
	for _, part := range strings.Split(value, ",") {
		token := strings.TrimSpace(strings.ToLower(part))
		if token == "" {
			continue
		}
		seen++
		if !allowed[token] {
			keys := make([]string, 0, len(allowed))
			for key := range allowed {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			return fmt.Errorf("unknown %s value %q: must be one of: %s",
				field, token, strings.Join(keys, ", "))
		}
	}
	if seen == 0 {
		return fmt.Errorf("%s must contain at least one value", field)
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
