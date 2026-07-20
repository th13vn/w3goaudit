package engine

import (
	"bytes"
	"fmt"
	"io"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// TemplateDoc is the top-level WQL YAML document: meta plus one query.
// It is a pure parsing/decoding structure that compiles into the evaluator IR
// represented by Template, QueryBlock, and Rule.
type TemplateDoc struct {
	Meta  TemplateMeta `yaml:"meta"`
	Query *QueryDoc    `yaml:"query"`
}

// QueryDoc is the `query:` container. It is either a single
// select/from/where query, or a one-level composition of branch queries:
//
//   - `and:` — every branch must match in the same instance of the join
//     scope named by the query-level `from:` (one finding per instance;
//     branch sites surface in Finding.Related with their labels).
//   - `or:` — the union of the branches' findings under one meta; each
//     branch is a complete query with its own anchor (`from:` on the query
//     is the branches' default scope).
//
// Exactly one of the three forms may be used; the strict decoder rejects
// unknown keys, and nested composition (and:/or: inside a branch) is
// rejected because QueryBranch has no such fields.
type QueryDoc struct {
	Select string        `yaml:"select"`
	From   string        `yaml:"from"`
	Where  []Matcher     `yaml:"where"`
	And    []QueryBranch `yaml:"and"`
	Or     []QueryBranch `yaml:"or"`

	keys    queryKeyPresence
	andKind yaml.Kind
	orKind  yaml.Kind
}

type queryKeyPresence struct {
	Select bool
	From   bool
	Where  bool
	And    bool
	Or     bool
}

// QueryBranch is one branch of a query-level and:/or: composition. Branches
// are simple queries only — one composition level. `label:` names the
// branch's matched sites in Finding.Related (and: branches only). `from:` is
// only meaningful for or: branches (and: branches share the join scope).
type QueryBranch struct {
	Label  string    `yaml:"label"`
	Select string    `yaml:"select"`
	From   string    `yaml:"from"`
	Where  []Matcher `yaml:"where"`
}

// SimpleQuery is the simple-query lowering unit (select/from/where). Parsed
// documents are decomposed into these before lowering; it is no longer a
// YAML decoding target of its own.
type SimpleQuery struct {
	Meta   TemplateMeta
	Select string
	From   string
	Where  []Matcher
}

// Matcher is a single WQL matcher: a one-key map whose key selects the
// matcher form (block, name, arg.N, has, in, preset, not, any, and, ...) and
// whose value is the matcher's argument (scalar, map, or list).
type Matcher map[string]yaml.Node

// key returns the matcher's single key/value pair. ok is false when the map
// does not contain exactly one key (malformed matcher).
func (m Matcher) key() (string, yaml.Node, bool) {
	if len(m) != 1 {
		return "", yaml.Node{}, false
	}
	for k, v := range m {
		return k, v, true
	}
	return "", yaml.Node{}, false
}

// parseWQL unmarshals raw into a TemplateDoc: strict decoding (unknown keys
// rejected at every struct level), single YAML document, and a present
// `query:`. Shape/semantic validation of the query itself happens in
// TemplateDoc.lower(). Deprecated evaluator-IR JSON aliases are intentionally
// absent here: public WQL accepts only the canonical matcher vocabulary.
func parseWQL(raw []byte) (*TemplateDoc, error) {
	var rawDoc yaml.Node
	rawDecoder := yaml.NewDecoder(bytes.NewReader(raw))
	if err := rawDecoder.Decode(&rawDoc); err != nil {
		return nil, fmt.Errorf("parseWQL: %w", err)
	}
	var rawTrailing yaml.Node
	if err := rawDecoder.Decode(&rawTrailing); err != io.EOF {
		if err != nil {
			return nil, fmt.Errorf("parseWQL: decode trailing YAML document: %w", err)
		}
		return nil, fmt.Errorf("parseWQL: multiple YAML documents are unsupported")
	}
	if err := rejectYAMLMergeKeys(&rawDoc); err != nil {
		return nil, fmt.Errorf("parseWQL: %w", err)
	}
	queryNode, err := queryMappingNode(&rawDoc)
	if err != nil {
		return nil, fmt.Errorf("parseWQL: %w", err)
	}
	if err := validateAuthoredQueryNode(queryNode); err != nil {
		return nil, fmt.Errorf("parseWQL: %w", err)
	}

	var doc TemplateDoc
	decoder := yaml.NewDecoder(bytes.NewReader(raw))
	decoder.KnownFields(true)
	if err := decoder.Decode(&doc); err != nil {
		if hasNonScalarQuerySelect(raw) {
			return nil, fmt.Errorf("parseWQL: select must be a scalar block kind")
		}
		return nil, fmt.Errorf("parseWQL: %w", err)
	}
	var trailing yaml.Node
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err != nil {
			return nil, fmt.Errorf("parseWQL: decode trailing YAML document: %w", err)
		}
		return nil, fmt.Errorf("parseWQL: multiple YAML documents are unsupported")
	}

	if doc.Query == nil {
		return nil, fmt.Errorf("parseWQL: template %q has no query: — templates are meta: plus query: {select, from, where} (or a query-level and:/or: composition)", doc.Meta.ID)
	}
	if err := recordQueryKeyMetadata(queryNode, doc.Query); err != nil {
		return nil, fmt.Errorf("parseWQL: inspect query keys: %w", err)
	}

	return &doc, nil
}

func rejectYAMLMergeKeys(node *yaml.Node) error {
	if node == nil {
		return nil
	}
	if node.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(node.Content); i += 2 {
			key := node.Content[i]
			if key.Value == "<<" {
				return fmt.Errorf("WQL does not support YAML merge keys (<<)")
			}
		}
	}
	for _, child := range node.Content {
		if err := rejectYAMLMergeKeys(child); err != nil {
			return err
		}
	}
	return nil
}

func queryMappingNode(doc *yaml.Node) (*yaml.Node, error) {
	if doc == nil || doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 {
		return nil, fmt.Errorf("expected a YAML document")
	}
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("expected a top-level mapping")
	}
	for i := 0; i+1 < len(root.Content); i += 2 {
		if root.Content[i].Value != "query" {
			continue
		}
		return root.Content[i+1], nil
	}
	return nil, nil
}

func requireAuthoredScalar(node *yaml.Node, path string) error {
	if node == nil || node.Tag == "!!null" || node.Kind != yaml.ScalarNode || strings.TrimSpace(node.Value) == "" {
		if strings.HasSuffix(path, ".select") || path == "query.select" {
			return fmt.Errorf("%s must be a scalar block kind and cannot be null or empty", path)
		}
		return fmt.Errorf("%s must be a non-null, non-empty scalar", path)
	}
	return nil
}

func requireAuthoredMatcherList(node *yaml.Node, path string) error {
	if node == nil || node.Tag == "!!null" || node.Kind != yaml.SequenceNode || len(node.Content) == 0 {
		return fmt.Errorf("%s must be a non-null, non-empty matcher list", path)
	}
	return nil
}

func validateAuthoredQueryNode(queryNode *yaml.Node) error {
	if queryNode == nil || queryNode.Tag == "!!null" {
		return nil
	}
	if queryNode.Kind != yaml.MappingNode {
		return fmt.Errorf("query: must be a mapping")
	}
	for i := 0; i+1 < len(queryNode.Content); i += 2 {
		key := queryNode.Content[i].Value
		value := queryNode.Content[i+1]
		switch key {
		case "select", "from":
			if err := requireAuthoredScalar(value, "query."+key); err != nil {
				return err
			}
		case "where":
			if err := requireAuthoredMatcherList(value, "query.where"); err != nil {
				return err
			}
		case "and", "or":
			if value.Kind != yaml.SequenceNode {
				continue
			}
			for branchIdx, branch := range value.Content {
				if branch == nil || branch.Kind != yaml.MappingNode {
					continue
				}
				path := fmt.Sprintf("query.%s branch %d", key, branchIdx+1)
				for j := 0; j+1 < len(branch.Content); j += 2 {
					branchKey := branch.Content[j].Value
					branchValue := branch.Content[j+1]
					switch branchKey {
					case "label", "select", "from":
						if err := requireAuthoredScalar(branchValue, path+"."+branchKey); err != nil {
							return err
						}
					case "where":
						if err := requireAuthoredMatcherList(branchValue, path+".where"); err != nil {
							return err
						}
					}
				}
			}
		}
	}
	return nil
}

func recordQueryKeyMetadata(queryNode *yaml.Node, query *QueryDoc) error {
	if queryNode == nil || queryNode.Kind != yaml.MappingNode {
		return fmt.Errorf("query: must be a mapping")
	}
	for j := 0; j+1 < len(queryNode.Content); j += 2 {
		key := queryNode.Content[j].Value
		value := queryNode.Content[j+1]
		switch key {
		case "select":
			query.keys.Select = true
		case "from":
			query.keys.From = true
		case "where":
			query.keys.Where = true
		case "and":
			query.keys.And = true
			query.andKind = value.Kind
		case "or":
			query.keys.Or = true
			query.orKind = value.Kind
		}
	}
	return nil
}

// hasNonScalarQuerySelect reports whether raw's query: mapping carries a
// non-scalar select: value (e.g. a list), so the loader can emit a pointed
// "select must be a scalar block kind" error instead of a generic YAML
// type-mismatch message.
func hasNonScalarQuerySelect(raw []byte) bool {
	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil || doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 {
		return false
	}
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode {
		return false
	}
	for i := 0; i+1 < len(root.Content); i += 2 {
		if root.Content[i].Value != "query" {
			continue
		}
		query := root.Content[i+1]
		if query.Kind != yaml.MappingNode {
			return false
		}
		for j := 0; j+1 < len(query.Content); j += 2 {
			if query.Content[j].Value == "select" {
				return query.Content[j+1].Kind != yaml.ScalarNode
			}
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Lowering: SimpleQuery -> *Template (the IR the evaluator runs).
//
// The evaluator (Verify/VerifyAtFunctionWithCallees/VerifyAtContract) is NOT
// changed by WQL lowering. lower() only builds a Template IR value; validation and
// normalization (finalizeTemplate) are applied by the caller, not here.
// ---------------------------------------------------------------------------

// lower converts a parsed WQL document into evaluator IR, dispatching on the
// query's form: a single select/from/where query, an and: join, or an or:
// union. See .vscode/specs/2026-07-17-wql-query-composition.md for the
// composition semantics.
func (t *TemplateDoc) lower() (*Template, error) {
	q := t.Query
	if q == nil {
		return nil, fmt.Errorf("template %q has no query: block", t.Meta.ID)
	}
	hasSimple := q.keys.Select || q.keys.Where

	switch {
	case q.keys.And && q.keys.Or:
		return nil, fmt.Errorf("query: cannot combine and: and or: at the same level")
	case q.keys.And:
		if hasSimple {
			return nil, fmt.Errorf("query: and: cannot be combined with select:/where: at the same level — move them into a branch")
		}
		return t.lowerAnd()
	case q.keys.Or:
		if hasSimple {
			return nil, fmt.Errorf("query: or: cannot be combined with select:/where: at the same level — move them into a branch")
		}
		return t.lowerOr()
	default:
		if q.Select == "" && q.From == "" && !q.keys.Where {
			return nil, fmt.Errorf("template %q has neither select, from, nor where", t.Meta.ID)
		}
		simple := &SimpleQuery{Meta: t.Meta, Select: q.Select, From: q.From, Where: q.Where}
		return simple.lower()
	}
}

// lowerAnd lowers a query-level and: composition. Every branch must match in
// the same instance of the join scope (`from:` on the query), so the result
// is one QueryBlock whose match is a Rule.All of per-branch rules — exactly the
// contract-scope combination shape the evaluator already executes, with each
// branch's label carried into Finding.Related site naming.
func (t *TemplateDoc) lowerAnd() (*Template, error) {
	q := t.Query
	if q.andKind != yaml.SequenceNode {
		return nil, fmt.Errorf("query.and: must be a non-null list")
	}
	if len(q.And) < 2 {
		return nil, fmt.Errorf("query.and: needs at least two branches")
	}
	if q.From == "" {
		return nil, fmt.Errorf("query.and: requires a query-level from: naming the join scope shared by all branches")
	}
	scope, err := fromToScope(q.From)
	if err != nil {
		return nil, err
	}
	if scope == ScopeSource {
		return nil, fmt.Errorf("query.and: from: source is not supported — and: joins structural scopes")
	}
	branches := make([]Rule, 0, len(q.And))
	for i, b := range q.And {
		if b.From != "" {
			return nil, fmt.Errorf("query.and: branch %d: from: is not allowed on and: branches — the query-level from: is the join scope", i+1)
		}
		rule, err := lowerBranchRule(scope, b)
		if err != nil {
			return nil, fmt.Errorf("query.and: branch %d: %w", i+1, err)
		}
		branches = append(branches, *rule)
	}

	return &Template{
		Meta:  t.Meta,
		Query: QueryBlock{Scope: scope, Match: Rule{All: branches}},
	}, nil
}

// lowerBranchRule lowers one and: branch (its own select plus AST-level
// where matchers) into the Rule that becomes one Rule.All conjunct at the join
// scope. Context-level matchers are rejected: a filter applies to the whole
// scope instance in the evaluator IR, so attributing one branch's
// precondition there would silently widen it to every branch.
func lowerBranchRule(scope Scope, b QueryBranch) (*Rule, error) {
	resolvedSelect := ""
	if b.Select != "" {
		irKind, ok := blockKindToIR(b.Select)
		if !ok {
			return nil, fmt.Errorf("select: unknown block kind %q", b.Select)
		}
		resolvedSelect = irKind
	}

	astAgg := &Rule{}
	ctxAgg := &Rule{}
	for _, m := range b.Where {
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
	if !ctxAgg.IsEmpty() {
		return nil, fmt.Errorf("context-level matchers (preset/modifier/func_name/version/base/has_param/guarded_by) are not supported inside and: branches — express the condition with AST-level matchers (e.g. has: {block: function, ...})")
	}

	rule, err := buildMatch(scope, resolvedSelect, astAgg)
	if err != nil {
		return nil, err
	}
	if !ruleGuaranteesReportableAnchor(*rule) {
		return nil, fmt.Errorf("must expose a positive reportable anchor; absence-only matchers such as not: {has: ...} cannot supply primary/related evidence")
	}
	if !ruleGuaranteesTraceableASTEvidence(*rule) {
		return nil, fmt.Errorf("must expose traceable AST evidence; regex may refine an AST-anchored branch but a regex-only branch cannot supply primary/related evidence")
	}
	if b.Label != "" {
		if rule.Label != "" && rule.Label != b.Label {
			return nil, fmt.Errorf("conflicting labels %q vs %q", rule.Label, b.Label)
		}
		rule.Label = b.Label
	}
	return rule, nil
}

// ruleGuaranteesReportableAnchor proves that every successful path through a
// query-level and: branch captures a positive AST/source node. Negation is
// intentionally ignored because absence is not a reportable site. For any:,
// every alternative must be anchored; for all:/args, one anchored conjunct is
// sufficient because it must succeed whenever the branch succeeds.
func ruleGuaranteesReportableAnchor(rule Rule) bool {
	if hasAtomicPredicate(rule) {
		return true
	}
	if rule.Contains != nil && ruleGuaranteesReportableAnchor(*rule.Contains) {
		return true
	}
	if rule.Inside != nil && ruleGuaranteesReportableAnchor(*rule.Inside) {
		return true
	}
	if rule.StatementContains != nil && ruleGuaranteesReportableAnchor(*rule.StatementContains) {
		return true
	}
	if rule.Left != nil && ruleGuaranteesReportableAnchor(*rule.Left) {
		return true
	}
	if rule.Right != nil && ruleGuaranteesReportableAnchor(*rule.Right) {
		return true
	}
	if rule.ArgAny != nil && ruleGuaranteesReportableAnchor(*rule.ArgAny) {
		return true
	}
	for _, arg := range rule.Args {
		if ruleGuaranteesReportableAnchor(arg) {
			return true
		}
	}
	for _, branch := range rule.All {
		if ruleGuaranteesReportableAnchor(branch) {
			return true
		}
	}
	if len(rule.Any) > 0 {
		for _, branch := range rule.Any {
			if !ruleGuaranteesReportableAnchor(branch) {
				return false
			}
		}
		return true
	}
	if len(rule.Sequence) > 0 {
		return ruleGuaranteesReportableAnchor(rule.Sequence[0])
	}
	return false
}

// ruleGuaranteesTraceableASTEvidence proves that every successful branch has
// positive AST evidence independent of raw-source regex matching. Regex can
// refine an AST-anchored branch, but it cannot identify a related AST site by
// itself at function/contract join scopes.
func ruleGuaranteesTraceableASTEvidence(rule Rule) bool {
	if hasTraceableAtomicPredicate(rule) {
		return true
	}
	if rule.Contains != nil && ruleGuaranteesTraceableASTEvidence(*rule.Contains) {
		return true
	}
	if rule.Inside != nil && ruleGuaranteesTraceableASTEvidence(*rule.Inside) {
		return true
	}
	if rule.StatementContains != nil && ruleGuaranteesTraceableASTEvidence(*rule.StatementContains) {
		return true
	}
	if rule.Left != nil && ruleGuaranteesTraceableASTEvidence(*rule.Left) {
		return true
	}
	if rule.Right != nil && ruleGuaranteesTraceableASTEvidence(*rule.Right) {
		return true
	}
	if rule.ArgAny != nil && ruleGuaranteesTraceableASTEvidence(*rule.ArgAny) {
		return true
	}
	for _, arg := range rule.Args {
		if ruleGuaranteesTraceableASTEvidence(arg) {
			return true
		}
	}
	for _, branch := range rule.All {
		if ruleGuaranteesTraceableASTEvidence(branch) {
			return true
		}
	}
	if len(rule.Any) > 0 {
		for _, branch := range rule.Any {
			if !ruleGuaranteesTraceableASTEvidence(branch) {
				return false
			}
		}
		return true
	}
	if len(rule.Sequence) > 0 {
		return ruleGuaranteesTraceableASTEvidence(rule.Sequence[0])
	}
	return false
}

func hasTraceableAtomicPredicate(rule Rule) bool {
	return rule.Kind != "" ||
		rule.Name != "" ||
		len(rule.Attr) > 0 ||
		rule.IsStateVar != nil ||
		rule.Operator != "" ||
		rule.Visibility != "" ||
		rule.Mutability != "" ||
		rule.TaintedFrom != ""
}

// lowerOr lowers a query-level or: composition into one QueryBlock per
// branch (Template.Queries). The engine executes every block and unions the
// findings under this template's meta, deduplicating identical locations.
// Branches may carry their own from:; a query-level from: is the shared
// default.
func (t *TemplateDoc) lowerOr() (*Template, error) {
	q := t.Query
	if q.orKind != yaml.SequenceNode {
		return nil, fmt.Errorf("query.or: must be a non-null list")
	}
	if len(q.Or) < 2 {
		return nil, fmt.Errorf("query.or: needs at least two branches")
	}

	blocks := make([]QueryBlock, 0, len(q.Or))
	for i, b := range q.Or {
		if b.Label != "" {
			return nil, fmt.Errorf("query.or: branch %d: label: is only supported on and: branches", i+1)
		}
		from := b.From
		if from == "" {
			from = q.From
		}
		// Authored where: values are validated as non-empty lists before
		// lowering, so len(b.Where) distinguishes a where-only branch from a
		// truly empty branch without adding a second branch metadata shape.
		if b.Select == "" && from == "" && len(b.Where) == 0 {
			return nil, fmt.Errorf("query.or: branch %d has neither select, from, nor where", i+1)
		}
		simple := &SimpleQuery{Meta: t.Meta, Select: b.Select, From: from, Where: b.Where}
		bt, err := simple.lower()
		if err != nil {
			return nil, fmt.Errorf("query.or: branch %d: %w", i+1, err)
		}
		blocks = append(blocks, bt.Query)
	}

	return &Template{Meta: t.Meta, Query: blocks[0], Queries: blocks}, nil
}

// lower converts one simple select/from/where query into evaluator IR. See
// docs/wql-syntax.md for the canonical authoring rules this implements.
func (t *SimpleQuery) lower() (*Template, error) {
	scope, err := fromToScope(t.From)
	if err != nil {
		return nil, err
	}

	resolvedSelect := ""
	if t.Select != "" {
		irKind, ok := blockKindToIR(t.Select)
		if !ok {
			return nil, fmt.Errorf("select: unknown block kind %q", t.Select)
		}
		resolvedSelect = irKind
	}

	// Lower every `where` matcher and merge its AST-layer and context-layer
	// parts into two running aggregates. astAgg feeds Match; ctxAgg feeds
	// Filter — the same filter/match split the evaluator already expects,
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

// fromToScope maps a WQL `from` scope name to the evaluator Scope constant.
// An empty from defaults to entry_function.
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

// buildMatch assembles the evaluator Match rule from the resolved scalar
// select kind and the aggregated AST-layer where matchers:
//
//   - scope: source is regex-only: astAgg must contain nothing but Regex.
//   - a single select wraps the where-matchers in `contains:` — "found
//     somewhere inside the from-scope" — UNLESS the where-matchers already
//     center on a `sequence:`, which is already a "search within" construct
//     and must stay at the top level. In that case select supplies or must
//     agree with the first sequence step, which is the sequence anchor.
func buildMatch(scope Scope, selectKind string, astAgg *Rule) (*Rule, error) {
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

	if selectKind == "" {
		// No select: the merged AST where-matchers become the Match directly
		// (no Contains wrap) — e.g. `from: contract` + `where: [regex: ...]`
		// applies the regex at the contract-scope root, or
		// `where: [any: [...]]` defines
		// the whole match on its own. There must be something to match on.
		if astAgg.IsEmpty() {
			return nil, fmt.Errorf("select: required for scope %q unless where contains AST-level matchers", scope)
		}
		if err := validatePositiveSequenceAnchors(astAgg, true, "match"); err != nil {
			return nil, err
		}
		result := *astAgg
		return &result, nil
	}

	if astAgg.Sequence != nil {
		m := *astAgg
		if len(m.Sequence) == 0 {
			return nil, fmt.Errorf("select conflicts with sequence: sequence has no anchor step")
		}
		anchor := &m.Sequence[0]
		if anchor.Kind == "" {
			if ruleSpecifiesKind(anchor) {
				return nil, fmt.Errorf("select conflicts with sequence anchor: %q cannot constrain a composite kind anchor", selectKind)
			}
			anchor.Kind = selectKind
		} else if anchor.Kind != selectKind {
			return nil, fmt.Errorf("select conflicts with sequence anchor: %q != %q", selectKind, anchor.Kind)
		}
		return &m, nil
	}

	inner, err := mergeKindInto(astAgg, selectKind)
	if err != nil {
		return nil, err
	}
	return &Rule{Contains: inner}, nil
}

func validatePositiveSequenceAnchors(rule *Rule, positive bool, path string) error {
	if rule == nil {
		return nil
	}
	if positive && len(rule.Sequence) > 0 && !ruleGuaranteesReportableAnchor(rule.Sequence[0]) {
		return fmt.Errorf("select-less sequence first step at %s.sequence must expose a positive actionable anchor", path)
	}
	for i := range rule.All {
		if err := validatePositiveSequenceAnchors(&rule.All[i], positive, fmt.Sprintf("%s.all[%d]", path, i)); err != nil {
			return err
		}
	}
	for i := range rule.Any {
		if err := validatePositiveSequenceAnchors(&rule.Any[i], positive, fmt.Sprintf("%s.any[%d]", path, i)); err != nil {
			return err
		}
	}
	if err := validatePositiveSequenceAnchors(rule.Not, !positive, path+".not"); err != nil {
		return err
	}
	for i := range rule.Sequence {
		if err := validatePositiveSequenceAnchors(&rule.Sequence[i], positive, fmt.Sprintf("%s.sequence[%d]", path, i)); err != nil {
			return err
		}
	}
	children := []struct {
		name string
		rule *Rule
	}{
		{name: "contains", rule: rule.Contains},
		{name: "inside", rule: rule.Inside},
		{name: "statement_contains", rule: rule.StatementContains},
		{name: "left", rule: rule.Left},
		{name: "right", rule: rule.Right},
		{name: "arg_any", rule: rule.ArgAny},
	}
	for _, child := range children {
		if err := validatePositiveSequenceAnchors(child.rule, positive, path+"."+child.name); err != nil {
			return err
		}
	}
	keys := make([]int, 0, len(rule.Args))
	for index := range rule.Args {
		keys = append(keys, index)
	}
	sort.Ints(keys)
	for _, index := range keys {
		child := rule.Args[index]
		if err := validatePositiveSequenceAnchors(&child, positive, fmt.Sprintf("%s.args[%d]", path, index)); err != nil {
			return err
		}
	}
	return nil
}

func ruleSpecifiesKind(rule *Rule) bool {
	found := false
	_ = walkRules(rule, func(current *Rule) error {
		if current.Kind != "" {
			found = true
		}
		return nil
	})
	return found
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

// lowerMatcher lowers one top-level `where` matcher (a single-key Matcher)
// into its AST-layer part (feeds Match) and/or context-layer part (feeds
// Filter). Either may be nil. This is the evaluator's filter/match split, computed
// from the uniform WQL matcher instead of authored directly by the template.
func lowerMatcher(m Matcher) (*Rule, *Rule, error) {
	key, val, ok := m.key()
	if !ok {
		return nil, nil, fmt.Errorf("where: malformed matcher (expected exactly one key), got %d", len(m))
	}
	return lowerKeyValue(key, val)
}

// argMatcherPrefix matches an `arg.N` matcher key (0-based call-argument index).
const argMatcherPrefix = "arg."

// lowerKeyValue lowers a single matcher key/value pair. It is the single
// dispatch point shared by lowerMatcher (top-level `where` items, which are
// always single-key per Matcher.key()) and expandMatcherPairs (nested
// matcher maps, which may legally carry several keys ANDed together — see
// the language spec §11.C worked example, where an `and:` branch mixes
// label/block/mutability/has in one map).
func lowerKeyValue(key string, val yaml.Node) (*Rule, *Rule, error) {
	switch key {
	case "block", "name", "regex", "tainted", "visibility", "mutability",
		"operator", "label", "modifier", "base", "func_name", "version", "has_param":
		return lowerStringMatcher(key, val)
	case "attr":
		return lowerWrappedAttributes(val)
	case "left", "right", "statement_has", "has", "in", "guarded_by":
		return lowerNestedRuleMatcher(key, val)
	case "unchecked_var":
		return lowerUncheckedVar(val)
	case "sequence", "any", "and":
		return lowerListMatcher(key, val)
	case "not":
		return lowerNotMatcher(val)
	case "preset":
		return lowerPresetMatcher(val)
	default:
		return lowerDynamicMatcher(key, val)
	}
}

func lowerStringMatcher(key string, val yaml.Node) (*Rule, *Rule, error) {
	var v string
	if err := val.Decode(&v); err != nil {
		return nil, nil, fmt.Errorf("where.%s: %w", key, err)
	}
	if strings.TrimSpace(v) == "" {
		return nil, nil, fmt.Errorf("where.%s: matcher value must be non-empty", key)
	}

	switch key {
	case "block":
		irKind, ok := blockKindToIR(v)
		if !ok {
			return nil, nil, fmt.Errorf("where.block: unknown block kind %q", v)
		}
		return &Rule{Kind: irKind}, nil, nil
	case "name":
		return &Rule{Name: v}, nil, nil
	case "regex":
		return &Rule{Regex: v}, nil, nil
	case "tainted":
		return &Rule{TaintedFrom: v}, nil, nil
	case "visibility":
		return &Rule{Visibility: v}, nil, nil
	case "mutability":
		return &Rule{Mutability: v}, nil, nil
	case "operator":
		return &Rule{Operator: v}, nil, nil
	case "label":
		return &Rule{Label: v}, nil, nil
	case "modifier":
		return nil, &Rule{Modifier: v}, nil
	case "base":
		return nil, &Rule{Extends: v}, nil
	case "func_name":
		return nil, &Rule{FuncName: v}, nil
	case "version":
		return nil, &Rule{Version: v}, nil
	case "has_param":
		return nil, &Rule{HasParam: v}, nil
	default:
		return nil, nil, fmt.Errorf("where: unknown string matcher key %q", key)
	}
}

func lowerWrappedAttributes(val yaml.Node) (*Rule, *Rule, error) {
	// Wrapped attribute form used by the §11.B worked example:
	// `attr: { has_value: true, ... }`. Each inner key resolves through
	// attrNameToIR exactly like a bare attribute key would.
	var raw map[string]yaml.Node
	if err := val.Decode(&raw); err != nil {
		return nil, nil, fmt.Errorf("where.attr: %w", err)
	}
	if len(raw) == 0 {
		return nil, nil, fmt.Errorf("where.attr: matcher map must not be empty")
	}
	ast := &Rule{}
	for key, value := range raw {
		irKey, ok := attrNameToIR(key)
		if !ok {
			return nil, nil, fmt.Errorf("where.attr: unknown attribute %q", key)
		}
		var decoded interface{}
		if err := value.Decode(&decoded); err != nil {
			return nil, nil, fmt.Errorf("where.attr.%s: %w", key, err)
		}
		if ast.Attr == nil {
			ast.Attr = make(map[string]interface{})
		}
		ast.Attr[irKey] = decoded
	}
	return ast, nil, nil
}

func lowerNestedRuleMatcher(key string, val yaml.Node) (*Rule, *Rule, error) {
	sub, err := lowerToRule(val)
	if err != nil {
		return nil, nil, err
	}
	switch key {
	case "left":
		return &Rule{Left: sub}, nil, nil
	case "right":
		return &Rule{Right: sub}, nil, nil
	case "statement_has":
		return &Rule{StatementContains: sub}, nil, nil
	case "has":
		return &Rule{Contains: sub}, nil, nil
	case "in":
		return &Rule{Inside: sub}, nil, nil
	case "guarded_by":
		return nil, &Rule{HasGuard: sub}, nil
	default:
		return nil, nil, fmt.Errorf("where: unknown nested matcher key %q", key)
	}
}

func lowerUncheckedVar(val yaml.Node) (*Rule, *Rule, error) {
	var v bool
	if err := val.Decode(&v); err != nil {
		return nil, nil, fmt.Errorf("where.unchecked_var: %w", err)
	}
	if !v {
		return nil, nil, fmt.Errorf("where.unchecked_var: only true is meaningful")
	}
	return &Rule{UncheckedVar: true}, nil, nil
}

func lowerListMatcher(key string, val yaml.Node) (*Rule, *Rule, error) {
	if val.Kind != yaml.SequenceNode {
		return nil, nil, fmt.Errorf("where.%s: expected a list of matchers", key)
	}
	if len(val.Content) == 0 {
		return nil, nil, fmt.Errorf("where.%s: matcher list must not be empty", key)
	}
	branches, err := lowerRuleList(val)
	if err != nil {
		return nil, nil, err
	}

	switch key {
	case "sequence":
		return &Rule{Sequence: branches}, nil, nil
	case "any":
		return lowerAnyMatcher(branches)
	case "and":
		return lowerAndMatcher(branches)
	default:
		return nil, nil, fmt.Errorf("where: unknown list matcher key %q", key)
	}
}

func lowerRuleList(val yaml.Node) ([]Rule, error) {
	branches := make([]Rule, 0, len(val.Content))
	for _, item := range val.Content {
		rule, err := lowerToRule(*item)
		if err != nil {
			return nil, err
		}
		branches = append(branches, *rule)
	}
	return branches, nil
}

func lowerAnyMatcher(branches []Rule) (*Rule, *Rule, error) {
	anyContext, anyAST := false, false
	for i := range branches {
		if ruleIsContextOnly(&branches[i]) {
			anyContext = true
		} else {
			anyAST = true
		}
	}
	if anyContext && anyAST {
		return nil, nil, fmt.Errorf("where.any: cannot mix context-level matchers " +
			"(preset/version/modifier/func_name/extends/has_param) with AST-level " +
			"matchers (block/kind/arg/sequence/...) in the same any: — an any: is " +
			"evaluated at a single layer, so the context branches would be silently " +
			"ignored. Split them: put the context condition outside the any:, or use " +
			"separate templates")
	}
	if anyContext {
		return nil, &Rule{Any: branches}, nil
	}
	return &Rule{Any: branches}, nil, nil
}

func lowerAndMatcher(branches []Rule) (*Rule, *Rule, error) {
	var astBranches, contextBranches []Rule
	for i := range branches {
		if ruleIsContextOnly(&branches[i]) {
			contextBranches = append(contextBranches, branches[i])
		} else {
			astBranches = append(astBranches, branches[i])
		}
	}
	var astPart, contextPart *Rule
	if len(astBranches) > 0 {
		astPart = &Rule{All: astBranches}
	}
	if len(contextBranches) > 0 {
		contextPart = &Rule{All: contextBranches}
	}
	return astPart, contextPart, nil
}

func lowerNotMatcher(val yaml.Node) (*Rule, *Rule, error) {
	sub, err := lowerToRule(val)
	if err != nil {
		return nil, nil, err
	}
	if ruleIsContextOnly(sub) {
		return nil, &Rule{Not: sub}, nil
	}
	return &Rule{Not: sub}, nil, nil
}

func lowerPresetMatcher(val yaml.Node) (*Rule, *Rule, error) {
	var preset string
	if err := val.Decode(&preset); err != nil {
		return nil, nil, fmt.Errorf("where.preset: %w", err)
	}
	if !IsKnownPreset(preset) {
		return nil, nil, fmt.Errorf("where.preset: unknown preset %q", preset)
	}
	return nil, &Rule{Preset: preset}, nil
}

func lowerDynamicMatcher(key string, val yaml.Node) (*Rule, *Rule, error) {
	if strings.HasPrefix(key, argMatcherPrefix) {
		rest := strings.TrimPrefix(key, argMatcherPrefix)
		sub, err := lowerToRule(val)
		if err != nil {
			return nil, nil, err
		}
		if rest == "any" {
			return &Rule{ArgAny: sub}, nil, nil
		}
		if rest == "" {
			return nil, nil, fmt.Errorf("where: invalid arg index in %q (use arg.N or arg.any)", key)
		}
		for _, ch := range rest {
			if ch < '0' || ch > '9' {
				return nil, nil, fmt.Errorf("where: invalid arg index in %q (use arg.N or arg.any)", key)
			}
		}
		idx, err := strconv.Atoi(rest)
		if err != nil {
			return nil, nil, fmt.Errorf("where: invalid arg index in %q (use arg.N or arg.any): %w", key, err)
		}
		if idx < 0 {
			return nil, nil, fmt.Errorf("where: invalid arg index in %q (use arg.N or arg.any)", key)
		}
		return &Rule{Args: map[int]Rule{idx: *sub}}, nil, nil
	}
	if irKey, ok := attrNameToIR(key); ok {
		var decoded interface{}
		if err := val.Decode(&decoded); err != nil {
			return nil, nil, fmt.Errorf("where.%s: %w", key, err)
		}
		return &Rule{Attr: map[string]interface{}{irKey: decoded}}, nil, nil
	}
	return nil, nil, fmt.Errorf("where: unknown matcher key %q", key)
}

// lowerToRule decodes a nested matcher value (a single matcher map, or a list
// of matcher maps to AND) and lowers it to ONE merged Rule. Nested rules
// (inside has:/in:/arg.N:/sequence elements/and:/any: branches) do not split
// into separate AST/context layers the way top-level `where` items do — the
// sub-rule is evaluated as a single Rule value by the evaluator (e.g.
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
	if result.IsEmpty() {
		return nil, fmt.Errorf("where: matcher must not be empty")
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
//     by an `and:` branch that mixes label/block/attr/has, means AND of all
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
// table validateRulePlacement uses). It backs the "any:"/"and:"/"not:" branch
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

func mergeArgAnyInto(dst *Rule, src *Rule) {
	if src == nil {
		return
	}
	cp := *src
	if dst.ArgAny == nil {
		dst.ArgAny = &cp
		return
	}
	dst.All = append(dst.All, Rule{ArgAny: &cp})
}

func mergeNotInto(dst *Rule, src *Rule) {
	if src == nil {
		return
	}
	cp := *src
	if dst.Not == nil {
		dst.Not = &cp
		return
	}
	dst.All = append(dst.All, Rule{Not: &cp})
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
// these"); Contains/Inside/HasGuard/Left/Right/StatementContains assign on first
// sight and otherwise recursively merge into the existing sub-rule; repeated
// Not predicates remain independent conjunctions, like repeated ArgAny
// predicates;
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
			return fmt.Errorf("where: conflicting %s: %q vs %q — to require both constraints on the same node, wrap them in and: branches (and: [{%s: %q}, {%s: %q}]) or combine them into one pattern", f.name, *f.dst, f.src, f.name, *f.dst, f.name, f.src)
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
	mergeNotInto(dst, src.Not)
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
	mergeArgAnyInto(dst, src.ArgAny)

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
