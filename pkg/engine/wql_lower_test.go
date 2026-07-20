package engine

import (
	"strings"
	"testing"
)

// These tests assert lower()'s output field-for-field against the evaluator
// IR shape the engine executes for the worked examples in docs/wql-syntax.md.
//
// NOTE on the delegatecall case: blockKindToIR("delegatecall") resolves to
// the "delegatecall" semantic group (pkg/engine/wql_catalog.go), not the
// exact kind string "call.lowlevel.delegatecall" — the semantic group also
// covers the asm.delegatecall sibling (see the catalog's doc comment). Tests
// below assert against the actual catalog mapping, not a literal kind
// string, so they stay correct if the catalog changes.

const delegatecallLowerWQL = `
meta: { id: delegatecall-user-input, severity: CRITICAL, title: Delegatecall to user-controlled target }
query:
  select: delegatecall
  from: entry_function
  where:
    - arg.0: { tainted: parameter }
    - not: { preset: access_controlled }
`

func TestLower_Delegatecall(t *testing.T) {
	doc, err := parseWQL([]byte(delegatecallLowerWQL))
	if err != nil {
		t.Fatalf("parseWQL: %v", err)
	}
	tmpl, err := doc.lower()
	if err != nil {
		t.Fatalf("lower: %v", err)
	}

	if tmpl.Meta.ID != "delegatecall-user-input" {
		t.Errorf("Meta.ID = %q, want %q", tmpl.Meta.ID, "delegatecall-user-input")
	}
	if tmpl.Query.Scope != ScopeEntrypoint {
		t.Errorf("Scope = %q, want %q", tmpl.Query.Scope, ScopeEntrypoint)
	}

	if tmpl.Query.Filter == nil {
		t.Fatalf("Filter is nil, want Not.Preset=access_controlled")
	}
	if tmpl.Query.Filter.Not == nil || tmpl.Query.Filter.Not.Preset != "access_controlled" {
		t.Errorf("Filter = %+v, want Not.Preset=%q", tmpl.Query.Filter, "access_controlled")
	}

	wantKind, ok := blockKindToIR("delegatecall")
	if !ok {
		t.Fatalf("blockKindToIR(delegatecall) ok=false")
	}
	if tmpl.Query.Match.Contains == nil {
		t.Fatalf("Match.Contains is nil")
	}
	if tmpl.Query.Match.Contains.Kind != wantKind {
		t.Errorf("Match.Contains.Kind = %q, want %q", tmpl.Query.Match.Contains.Kind, wantKind)
	}
	arg0, ok := tmpl.Query.Match.Contains.Args[0]
	if !ok {
		t.Fatalf("Match.Contains.Args[0] missing")
	}
	if arg0.TaintedFrom != "parameter" {
		t.Errorf("Match.Contains.Args[0].TaintedFrom = %q, want %q", arg0.TaintedFrom, "parameter")
	}
}

func TestLowerCanonicalPresetWithoutPolarityMapping(t *testing.T) {
	tmpl, err := ParseTemplate(`
meta: {id: T, severity: HIGH}
query:
  select: delegatecall
  where:
    - not: {preset: access_controlled}
`)
	if err != nil {
		t.Fatal(err)
	}
	if tmpl.Query.Filter == nil || tmpl.Query.Filter.Not == nil {
		t.Fatalf("Filter = %+v, want Not preset", tmpl.Query.Filter)
	}
	if got := tmpl.Query.Filter.Not.Preset; got != "access_controlled" {
		t.Fatalf("Preset = %q, want access_controlled", got)
	}
}

func TestWhereOnlyQueryDefaultsToEntryFunction(t *testing.T) {
	tmpl, err := ParseTemplate(`meta: {id: WHERE-ONLY, severity: LOW}
query:
  where:
    - has: {block: delegatecall}`)
	if err != nil {
		t.Fatalf("ParseTemplate: %v", err)
	}
	if tmpl.Query.Scope != ScopeEntrypoint {
		t.Fatalf("scope=%q, want %q", tmpl.Query.Scope, ScopeEntrypoint)
	}
	wantKind, ok := blockKindToIR("delegatecall")
	if !ok {
		t.Fatal("blockKindToIR(delegatecall) ok=false")
	}
	if tmpl.Query.Match.Contains == nil || tmpl.Query.Match.Contains.Kind != wantKind {
		t.Fatalf("match=%#v, want contains kind %q", tmpl.Query.Match, wantKind)
	}
}

func TestWhereOnlyContextPredicateRequiresASTAnchor(t *testing.T) {
	_, err := ParseTemplate(`meta: {id: WHERE-CONTEXT, severity: LOW}
query:
  where:
    - preset: access_controlled`)
	if err == nil {
		t.Fatal("context-only where query loaded")
	}
}

func TestLowerRepeatedSiblingNotPredicatesRemainIndependent(t *testing.T) {
	tmpl, err := ParseTemplate(`
meta: {id: T, severity: HIGH}
query:
  from: entry_function
  where:
    - not: {preset: access_controlled}
    - not: {modifier: '(?i)initializer'}
    - has: {block: state_write}
`)
	if err != nil {
		t.Fatal(err)
	}

	filter := tmpl.Query.Filter
	if filter == nil || filter.Not == nil {
		t.Fatalf("Filter = %+v, want first sibling negation in Filter.Not", filter)
	}
	if filter.Not.Preset != "access_controlled" || filter.Not.Modifier != "" {
		t.Errorf("Filter.Not = %+v, want only Preset=access_controlled", filter.Not)
	}
	if len(filter.All) != 1 || filter.All[0].Not == nil {
		t.Fatalf("Filter.All = %+v, want second sibling negation in Filter.All[0].Not", filter.All)
	}
	if filter.All[0].Not.Modifier != "(?i)initializer" || filter.All[0].Not.Preset != "" {
		t.Errorf("Filter.All[0].Not = %+v, want only Modifier=(?i)initializer", filter.All[0].Not)
	}

	for _, not := range []*Rule{filter.Not, filter.All[0].Not} {
		if not.Preset != "" && not.Modifier != "" {
			t.Errorf("independent sibling negations were merged into one child: %+v", not)
		}
	}
}

func TestLowerRepeatedSiblingNotPredicatesRemainIndependentAtASTLayer(t *testing.T) {
	tmpl, err := ParseTemplate(`
meta: {id: T, severity: HIGH}
query:
  select: external_call
  from: entry_function
  where:
    - not: {name: '^approve$'}
    - not: {block: state_write}
`)
	if err != nil {
		t.Fatal(err)
	}

	match := tmpl.Query.Match.Contains
	if match == nil || match.Not == nil {
		t.Fatalf("Match.Contains = %+v, want first sibling negation in Not", match)
	}
	if match.Not.Name != "^approve$" || match.Not.Kind != "" {
		t.Errorf("Match.Contains.Not = %+v, want only Name=^approve$", match.Not)
	}
	if len(match.All) != 1 || match.All[0].Not == nil {
		t.Fatalf("Match.Contains.All = %+v, want second sibling negation in All[0].Not", match.All)
	}
	wantStateWrite, _ := blockKindToIR("state_write")
	if match.All[0].Not.Kind != wantStateWrite || match.All[0].Not.Name != "" {
		t.Errorf("Match.Contains.All[0].Not = %+v, want only Kind=%s", match.All[0].Not, wantStateWrite)
	}
}

const reentrancyLowerWQL = `
meta: { id: reentrancy-eth, severity: HIGH, title: State write after external call }
query:
  select: external_call
  from: entry_function
  where:
    - not: { preset: reentrancy_guarded }
    - sequence:
        - { block: external_call }
        - { block: state_write }
`

func TestLower_ReentrancySequence(t *testing.T) {
	doc, err := parseWQL([]byte(reentrancyLowerWQL))
	if err != nil {
		t.Fatalf("parseWQL: %v", err)
	}
	tmpl, err := doc.lower()
	if err != nil {
		t.Fatalf("lower: %v", err)
	}

	if tmpl.Query.Filter == nil || tmpl.Query.Filter.Not == nil || tmpl.Query.Filter.Not.Preset != "reentrancy_guarded" {
		t.Fatalf("Filter = %+v, want Not.Preset=reentrancy_guarded", tmpl.Query.Filter)
	}

	if len(tmpl.Query.Match.Sequence) != 2 {
		t.Fatalf("len(Match.Sequence) = %d, want 2", len(tmpl.Query.Match.Sequence))
	}
	// Match must NOT be wrapped in Contains: a sequence is already a
	// "search within scope" construct (Task A3 step 6).
	if tmpl.Query.Match.Contains != nil {
		t.Errorf("Match.Contains = %+v, want nil (sequence stays top-level)", tmpl.Query.Match.Contains)
	}

	wantExternalCall, _ := blockKindToIR("external_call")
	wantStateWrite, _ := blockKindToIR("state_write")
	if tmpl.Query.Match.Sequence[0].Kind != wantExternalCall {
		t.Errorf("Sequence[0].Kind = %q, want %q", tmpl.Query.Match.Sequence[0].Kind, wantExternalCall)
	}
	if tmpl.Query.Match.Sequence[1].Kind != wantStateWrite {
		t.Errorf("Sequence[1].Kind = %q, want %q", tmpl.Query.Match.Sequence[1].Kind, wantStateWrite)
	}
}

func TestSelectlessNestedSequencesRequireActionableFirstStep(t *testing.T) {
	invalid := map[string]string{
		"any": `
    - any:
        - sequence:
            - not: {has: {block: state_write}}
            - block: external_call
        - has: {block: state_write}`,
		"and under has": `
    - has:
        and:
          - sequence:
              - not: {has: {block: state_write}}
              - block: external_call
          - block: state_write`,
		"statement_has": `
    - statement_has:
        sequence:
          - not: {has: {block: state_write}}
          - block: external_call`,
		"left arg.N": `
    - left:
        arg.0:
          sequence:
            - not: {has: {block: state_write}}
            - block: external_call`,
		"right arg.any": `
    - right:
        arg.any:
          sequence:
            - not: {has: {block: state_write}}
            - block: external_call`,
	}
	for name, where := range invalid {
		t.Run(name, func(t *testing.T) {
			_, err := ParseTemplate("meta: {id: nested-sequence, severity: HIGH}\nquery:\n  from: entry_function\n  where:" + where + "\n")
			if err == nil || !strings.Contains(err.Error(), "sequence first step") {
				t.Fatalf("error = %v, want nested sequence first-step rejection", err)
			}
		})
	}

	for _, tc := range []struct {
		name  string
		where string
	}{
		{
			name: "positive nested sequence",
			where: `
    - has:
        arg.any:
          sequence:
            - block: external_call
            - block: state_write`,
		},
		{
			name: "negative-polarity nested sequence",
			where: `
    - has: {block: external_call}
    - not:
        has:
          sequence:
            - not: {has: {block: state_write}}
            - block: external_call`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseTemplate("meta: {id: nested-sequence-control, severity: HIGH}\nquery:\n  from: entry_function\n  where:" + tc.where + "\n"); err != nil {
				t.Fatalf("valid nested sequence control rejected: %v", err)
			}
		})
	}
}

const barePresetLowerWQL = `
meta: { id: bare-preset-assertion, severity: MEDIUM, title: bare preset assertion test }
query:
  select: function
  from: entry_function
  where:
    - preset: reentrancy_guarded
`

func TestLower_BarePresetAssertion(t *testing.T) {
	doc, err := parseWQL([]byte(barePresetLowerWQL))
	if err != nil {
		t.Fatalf("parseWQL: %v", err)
	}
	tmpl, err := doc.lower()
	if err != nil {
		t.Fatalf("lower: %v", err)
	}

	if tmpl.Query.Filter == nil {
		t.Fatalf("Filter is nil, want Preset=reentrancy_guarded")
	}
	if tmpl.Query.Filter.Preset != "reentrancy_guarded" {
		t.Errorf("Filter.Preset = %q, want %q", tmpl.Query.Filter.Preset, "reentrancy_guarded")
	}
	// Bare preset assertion is a pure context (Filter) matcher — Match should
	// carry no leftover AST content from it.
	if tmpl.Query.Filter.Not != nil {
		t.Errorf("Filter.Not = %+v, want nil (assertion lowers directly to Preset)", tmpl.Query.Filter.Not)
	}
}

// Regression test: a `not: { guarded_by: ... }` branch must route entirely
// into Filter (context), not Match (AST) — even though guarded_by's own body
// (`block: modifier`) is AST-shaped. Before the ruleIsContextOnly fix, the
// generic walkRules-based classification recursed INTO HasGuard's sub-rule
// body, saw the nested Kind field, and wrongly concluded the branch was
// AST-bearing, routing it into Match — which finalizeTemplate then rejected
// with "`has_guard` is a context-level field and cannot appear inside
// `match:`".
const notGuardedByLowerWQL = `
meta: { id: not-guarded-by, severity: MEDIUM, title: missing reentrancy guard modifier }
query:
  select: external_call
  from: entry_function
  where:
    - not: { guarded_by: { block: modifier } }
`

func TestLower_NotGuardedByRoutesToFilter(t *testing.T) {
	doc, err := parseWQL([]byte(notGuardedByLowerWQL))
	if err != nil {
		t.Fatalf("parseWQL: %v", err)
	}
	tmpl, err := doc.lower()
	if err != nil {
		t.Fatalf("lower: %v", err)
	}

	if tmpl.Query.Filter == nil {
		t.Fatalf("Filter is nil, want Not.HasGuard")
	}
	if tmpl.Query.Filter.Not == nil || tmpl.Query.Filter.Not.HasGuard == nil {
		t.Fatalf("Filter = %+v, want Not.HasGuard set", tmpl.Query.Filter)
	}
	wantModifierKind, _ := blockKindToIR("modifier")
	if tmpl.Query.Filter.Not.HasGuard.Kind != wantModifierKind {
		t.Errorf("Filter.Not.HasGuard.Kind = %q, want %q", tmpl.Query.Filter.Not.HasGuard.Kind, wantModifierKind)
	}

	// Match must carry no HasGuard anywhere — it's a context-only field.
	if tmpl.Query.Match.HasGuard != nil {
		t.Errorf("Match.HasGuard = %+v, want nil", tmpl.Query.Match.HasGuard)
	}
	if tmpl.Query.Match.Contains != nil && tmpl.Query.Match.Contains.HasGuard != nil {
		t.Errorf("Match.Contains.HasGuard = %+v, want nil", tmpl.Query.Match.Contains.HasGuard)
	}

	// The lowered template must pass finalizeTemplate — this is what would
	// have failed with "`has_guard` is a context-level field and cannot
	// appear inside `match:`" before the fix.
	if err := finalizeTemplate(tmpl, "test"); err != nil {
		t.Fatalf("finalizeTemplate: %v", err)
	}
}

// Companion case: an `any:` branch set mixing `guarded_by:` and `func_name:`
// — both pure context matchers — must route the whole any: into Filter, not
// Match.
const anyGuardedByFuncNameLowerWQL = `
meta: { id: any-guarded-by-func-name, severity: MEDIUM, title: any of guard/func_name test }
query:
  select: external_call
  from: entry_function
  where:
    - any:
        - guarded_by: { block: modifier }
        - func_name: "^admin"
`

func TestLower_AnyGuardedByOrFuncNameRoutesToFilter(t *testing.T) {
	doc, err := parseWQL([]byte(anyGuardedByFuncNameLowerWQL))
	if err != nil {
		t.Fatalf("parseWQL: %v", err)
	}
	tmpl, err := doc.lower()
	if err != nil {
		t.Fatalf("lower: %v", err)
	}

	if tmpl.Query.Filter == nil || len(tmpl.Query.Filter.Any) != 2 {
		t.Fatalf("Filter = %+v, want Any with 2 branches", tmpl.Query.Filter)
	}
	if tmpl.Query.Filter.Any[0].HasGuard == nil {
		t.Errorf("Filter.Any[0].HasGuard is nil, want set")
	}
	if tmpl.Query.Filter.Any[1].FuncName != "^admin" {
		t.Errorf("Filter.Any[1].FuncName = %q, want %q", tmpl.Query.Filter.Any[1].FuncName, "^admin")
	}

	if len(tmpl.Query.Match.Any) != 0 {
		t.Errorf("Match.Any = %+v, want empty (this any: is entirely context-level)", tmpl.Query.Match.Any)
	}

	if err := finalizeTemplate(tmpl, "test"); err != nil {
		t.Fatalf("finalizeTemplate: %v", err)
	}
}

// A multi-key `not:` follows normal logical negation. When every nested field
// is context-level, the complete rule remains a valid context filter.
const notMultiKeyPresetWQL = `
meta: { id: not-multikey-preset, severity: MEDIUM, title: multi-key not with preset test }
query:
  select: external_call
  from: entry_function
  where:
    - not: { preset: access_controlled, base: some-other-rule }
`

func TestLower_NotMultiKeyPresetUsesGenericNegation(t *testing.T) {
	doc, err := parseWQL([]byte(notMultiKeyPresetWQL))
	if err != nil {
		t.Fatalf("parseWQL: %v", err)
	}
	tmpl, err := doc.lower()
	if err != nil {
		t.Fatalf("lower: %v", err)
	}
	if tmpl.Query.Filter == nil || tmpl.Query.Filter.Not == nil {
		t.Fatalf("Filter = %+v, want generic Not rule", tmpl.Query.Filter)
	}
	if got := tmpl.Query.Filter.Not.Preset; got != "access_controlled" {
		t.Errorf("Filter.Not.Preset = %q, want access_controlled", got)
	}
	if got := tmpl.Query.Filter.Not.Extends; got != "some-other-rule" {
		t.Errorf("Filter.Not.Extends = %q, want some-other-rule", got)
	}
}

// --- left / right ------------------------------------------------------

const leftRightLowerWQL = `
meta: { id: left-right, severity: MEDIUM, title: left/right operand test }
query:
  select: binary
  from: entry_function
  where:
    - left: { name: "^msg$" }
    - right: { tainted: parameter }
`

func TestLower_LeftRight(t *testing.T) {
	doc, err := parseWQL([]byte(leftRightLowerWQL))
	if err != nil {
		t.Fatalf("parseWQL: %v", err)
	}
	tmpl, err := doc.lower()
	if err != nil {
		t.Fatalf("lower: %v", err)
	}

	if tmpl.Query.Match.Contains == nil {
		t.Fatalf("Match.Contains is nil")
	}
	if tmpl.Query.Match.Contains.Left == nil || tmpl.Query.Match.Contains.Left.Name != "^msg$" {
		t.Errorf("Match.Contains.Left = %+v, want Name=%q", tmpl.Query.Match.Contains.Left, "^msg$")
	}
	if tmpl.Query.Match.Contains.Right == nil || tmpl.Query.Match.Contains.Right.TaintedFrom != "parameter" {
		t.Errorf("Match.Contains.Right = %+v, want TaintedFrom=%q", tmpl.Query.Match.Contains.Right, "parameter")
	}

	if err := finalizeTemplate(tmpl, "test"); err != nil {
		t.Fatalf("finalizeTemplate: %v", err)
	}
}

// --- statement_has -------------------------------------------------------

const statementHasLowerWQL = `
meta: { id: statement-has, severity: MEDIUM, title: statement_has test }
query:
  select: external_call
  from: entry_function
  where:
    - statement_has: { block: require }
`

func TestLower_StatementHas(t *testing.T) {
	doc, err := parseWQL([]byte(statementHasLowerWQL))
	if err != nil {
		t.Fatalf("parseWQL: %v", err)
	}
	tmpl, err := doc.lower()
	if err != nil {
		t.Fatalf("lower: %v", err)
	}

	wantKind, _ := blockKindToIR("require")
	if tmpl.Query.Match.Contains == nil || tmpl.Query.Match.Contains.StatementContains == nil {
		t.Fatalf("Match.Contains.StatementContains is nil")
	}
	if tmpl.Query.Match.Contains.StatementContains.Kind != wantKind {
		t.Errorf("StatementContains.Kind = %q, want %q", tmpl.Query.Match.Contains.StatementContains.Kind, wantKind)
	}

	if err := finalizeTemplate(tmpl, "test"); err != nil {
		t.Fatalf("finalizeTemplate: %v", err)
	}
}

// --- unchecked_var -------------------------------------------------------

const uncheckedVarLowerWQL = `
meta: { id: unchecked-var, severity: MEDIUM, title: unchecked_var test }
query:
  select: binary
  from: entry_function
  where:
    - unchecked_var: true
`

func TestLower_UncheckedVar(t *testing.T) {
	doc, err := parseWQL([]byte(uncheckedVarLowerWQL))
	if err != nil {
		t.Fatalf("parseWQL: %v", err)
	}
	tmpl, err := doc.lower()
	if err != nil {
		t.Fatalf("lower: %v", err)
	}

	if tmpl.Query.Match.Contains == nil || !tmpl.Query.Match.Contains.UncheckedVar {
		t.Fatalf("Match.Contains.UncheckedVar = %+v, want true", tmpl.Query.Match.Contains)
	}

	if err := finalizeTemplate(tmpl, "test"); err != nil {
		t.Fatalf("finalizeTemplate: %v", err)
	}
}

// --- modifier (context layer, filter-only) -------------------------------

const modifierLowerWQL = `
meta: { id: modifier, severity: MEDIUM, title: modifier filter test }
query:
  select: external_call
  from: entry_function
  where:
    - modifier: "(?i)initializer"
`

func TestLower_ModifierRoutesToFilter(t *testing.T) {
	doc, err := parseWQL([]byte(modifierLowerWQL))
	if err != nil {
		t.Fatalf("parseWQL: %v", err)
	}
	tmpl, err := doc.lower()
	if err != nil {
		t.Fatalf("lower: %v", err)
	}

	if tmpl.Query.Filter == nil || tmpl.Query.Filter.Modifier != "(?i)initializer" {
		t.Fatalf("Filter.Modifier = %+v, want %q", tmpl.Query.Filter, "(?i)initializer")
	}
	// Modifier is context-only: it must not leak into Match anywhere.
	if tmpl.Query.Match.Modifier != "" {
		t.Errorf("Match.Modifier = %q, want empty", tmpl.Query.Match.Modifier)
	}
	if tmpl.Query.Match.Contains != nil && tmpl.Query.Match.Contains.Modifier != "" {
		t.Errorf("Match.Contains.Modifier = %q, want empty", tmpl.Query.Match.Contains.Modifier)
	}

	if err := finalizeTemplate(tmpl, "test"); err != nil {
		t.Fatalf("finalizeTemplate: %v", err)
	}
}

// --- select-absent (structural fix) --------------------------------------

const selectAbsentLowerWQL = `
meta: { id: select-absent, severity: MEDIUM, title: select-absent regex-at-root test }
query:
  from: contract
  where:
    - regex: "slot"
`

func TestLower_SelectAbsentAppliesRegexAtRoot(t *testing.T) {
	doc, err := parseWQL([]byte(selectAbsentLowerWQL))
	if err != nil {
		t.Fatalf("parseWQL: %v", err)
	}
	tmpl, err := doc.lower()
	if err != nil {
		t.Fatalf("lower: %v", err)
	}

	if tmpl.Query.Scope != ScopeContract {
		t.Errorf("Scope = %q, want %q", tmpl.Query.Scope, ScopeContract)
	}
	if tmpl.Query.Match.Regex != "slot" {
		t.Errorf("Match.Regex = %q, want %q", tmpl.Query.Match.Regex, "slot")
	}
	if tmpl.Query.Match.Contains != nil {
		t.Errorf("Match.Contains = %+v, want nil (no select => no Contains wrap)", tmpl.Query.Match.Contains)
	}

	if err := finalizeTemplate(tmpl, "test"); err != nil {
		t.Fatalf("finalizeTemplate: %v", err)
	}
}

// TestLower_SelectAbsentNoASTMattersErrors documents that a select-absent
// template with no AST-level where matchers (and scope != source) is
// rejected — there is nothing to match on.
func TestLower_SelectAbsentNoASTMattersErrors(t *testing.T) {
	const yamlSrc = `
meta: { id: select-absent-empty, severity: MEDIUM, title: select-absent with no AST matcher }
query:
  from: contract
  where:
    - modifier: "(?i)initializer"
`
	doc, err := parseWQL([]byte(yamlSrc))
	if err != nil {
		t.Fatalf("parseWQL: %v", err)
	}
	_, err = doc.lower()
	if err == nil {
		t.Fatalf("lower: expected an error (no select, no AST where-matchers), got nil")
	}
}

func TestLowerRejectsSelectIgnoredBySequence(t *testing.T) {
	doc, err := parseWQL([]byte(`
meta: {id: conflict, severity: HIGH}
query:
  select: state_write
  from: entry_function
  where:
    - sequence:
        - {block: external_call}
        - {block: state_write}
`))
	if err != nil {
		t.Fatal(err)
	}
	_, err = doc.lower()
	if err == nil || !strings.Contains(err.Error(), "select conflicts with sequence") {
		t.Fatalf("error = %v", err)
	}
}

func TestLowerRejectsSelectlessSequenceWithoutActionableFirstStep(t *testing.T) {
	_, err := ParseTemplate(`
meta: {id: absence-first-sequence, severity: HIGH}
query:
  from: entry_function
  where:
    - sequence:
        - not: {has: {block: state_write}}
        - {block: external_call}
`)
	if err == nil || !strings.Contains(err.Error(), "sequence first step") {
		t.Fatalf("error = %v, want select-less sequence first-step anchor rejection", err)
	}
}

func TestLowerAllowsSelectlessSequenceWithActionableFirstStep(t *testing.T) {
	tmpl, err := ParseTemplate(`
meta: {id: positive-first-sequence, severity: HIGH}
query:
  from: entry_function
  where:
    - sequence:
        - {block: external_call}
        - {block: state_write}
`)
	if err != nil {
		t.Fatalf("ParseTemplate rejected actionable first step: %v", err)
	}
	want, _ := blockKindToIR("external_call")
	if got := tmpl.Query.Match.Sequence[0].Kind; got != want {
		t.Fatalf("sequence first-step kind = %q, want %q", got, want)
	}
}

func TestLowerAllowsSelectMatchingSequenceAnchor(t *testing.T) {
	doc, err := parseWQL([]byte(`
meta: {id: matching-anchor, severity: HIGH}
query:
  select: external_call
  from: entry_function
  where:
    - sequence:
        - {block: external_call}
        - {block: state_write}
`))
	if err != nil {
		t.Fatal(err)
	}
	tmpl, err := doc.lower()
	if err != nil {
		t.Fatalf("lower: %v", err)
	}
	want, _ := blockKindToIR("external_call")
	if got := tmpl.Query.Match.Sequence[0].Kind; got != want {
		t.Fatalf("sequence anchor = %q, want %q", got, want)
	}
}

func TestLowerSelectFillsUnkindedSequenceAnchor(t *testing.T) {
	doc, err := parseWQL([]byte(`
meta: {id: filled-anchor, severity: HIGH}
query:
  select: external_call
  from: entry_function
  where:
    - sequence:
        - {name: ^transfer$}
        - {block: state_write}
`))
	if err != nil {
		t.Fatal(err)
	}
	tmpl, err := doc.lower()
	if err != nil {
		t.Fatalf("lower: %v", err)
	}
	wantKind, _ := blockKindToIR("external_call")
	anchor := tmpl.Query.Match.Sequence[0]
	if anchor.Kind != wantKind {
		t.Fatalf("sequence anchor kind = %q, want %q", anchor.Kind, wantKind)
	}
	if anchor.Name != "^transfer$" {
		t.Fatalf("sequence anchor name = %q, want retained predicate %q", anchor.Name, "^transfer$")
	}
}

func TestLowerRejectsSelectWithCompositeSequenceAnchor(t *testing.T) {
	doc, err := parseWQL([]byte(`
meta: {id: composite-anchor, severity: HIGH}
query:
  select: state_write
  from: entry_function
  where:
    - sequence:
        - any:
            - {block: eth_transfer}
            - {block: delegatecall}
        - {block: state_write}
`))
	if err != nil {
		t.Fatal(err)
	}
	_, err = doc.lower()
	if err == nil || !strings.Contains(err.Error(), "select conflicts with sequence") {
		t.Fatalf("error = %v", err)
	}
}
