package engine

import (
	"strings"
	"testing"
)

// These tests assert lower()'s output field-for-field against the v1 Rule IR
// shape a hand-written v1 template would produce, for the worked examples in
// .vscode/specs/2026-07-09-wql-v2-language-spec.md §11.
//
// NOTE on the delegatecall case: blockKindToV1("delegatecall") resolves to
// the "delegatecall" semantic group (pkg/engine/wql_v2_catalog.go), not the
// exact kind string "call.lowlevel.delegatecall" — the semantic group also
// covers the asm.delegatecall sibling (see the catalog's doc comment). Tests
// below assert against the actual catalog mapping, not a literal kind
// string, so they stay correct if the catalog changes.

const v2DelegatecallLowerYAML = `
meta: { id: delegatecall-user-input, severity: CRITICAL, title: Delegatecall to user-controlled target }
select: delegatecall
from: entry_function
where:
  - arg.0: { tainted: parameter }
  - not: { preset: access_controlled }
`

func TestLower_Delegatecall(t *testing.T) {
	tv2, err := parseV2([]byte(v2DelegatecallLowerYAML))
	if err != nil {
		t.Fatalf("parseV2: %v", err)
	}
	tmpl, err := tv2.lower()
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
		t.Fatalf("Filter is nil, want Preset=unAuthenticated")
	}
	if tmpl.Query.Filter.Preset != "unAuthenticated" {
		t.Errorf("Filter.Preset = %q, want %q", tmpl.Query.Filter.Preset, "unAuthenticated")
	}

	wantKind, ok := blockKindToV1("delegatecall")
	if !ok {
		t.Fatalf("blockKindToV1(delegatecall) ok=false")
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

const v2ReentrancyLowerYAML = `
meta: { id: reentrancy-eth, severity: HIGH, title: State write after external call }
select: external_call
from: entry_function
where:
  - not: { preset: reentrancy_guarded }
  - sequence:
      - { block: eth_transfer }
      - { block: state_write }
`

func TestLower_ReentrancySequence(t *testing.T) {
	tv2, err := parseV2([]byte(v2ReentrancyLowerYAML))
	if err != nil {
		t.Fatalf("parseV2: %v", err)
	}
	tmpl, err := tv2.lower()
	if err != nil {
		t.Fatalf("lower: %v", err)
	}

	if tmpl.Query.Filter == nil || tmpl.Query.Filter.Preset != "unLocked" {
		t.Fatalf("Filter.Preset = %+v, want unLocked", tmpl.Query.Filter)
	}

	if len(tmpl.Query.Match.Sequence) != 2 {
		t.Fatalf("len(Match.Sequence) = %d, want 2", len(tmpl.Query.Match.Sequence))
	}
	// Match must NOT be wrapped in Contains: a sequence is already a
	// "search within scope" construct (Task A3 step 6).
	if tmpl.Query.Match.Contains != nil {
		t.Errorf("Match.Contains = %+v, want nil (sequence stays top-level)", tmpl.Query.Match.Contains)
	}

	wantEthTransfer, _ := blockKindToV1("eth_transfer")
	wantStateWrite, _ := blockKindToV1("state_write")
	if tmpl.Query.Match.Sequence[0].Kind != wantEthTransfer {
		t.Errorf("Sequence[0].Kind = %q, want %q", tmpl.Query.Match.Sequence[0].Kind, wantEthTransfer)
	}
	if tmpl.Query.Match.Sequence[1].Kind != wantStateWrite {
		t.Errorf("Sequence[1].Kind = %q, want %q", tmpl.Query.Match.Sequence[1].Kind, wantStateWrite)
	}
}

const v2BarePresetLowerYAML = `
meta: { id: v2-bare-preset-assertion, severity: MEDIUM, title: bare preset assertion test }
select: function
from: entry_function
where:
  - preset: reentrancy_guarded
`

func TestLower_BarePresetAssertion(t *testing.T) {
	tv2, err := parseV2([]byte(v2BarePresetLowerYAML))
	if err != nil {
		t.Fatalf("parseV2: %v", err)
	}
	tmpl, err := tv2.lower()
	if err != nil {
		t.Fatalf("lower: %v", err)
	}

	if tmpl.Query.Filter == nil {
		t.Fatalf("Filter is nil, want Not.Preset=unLocked")
	}
	if tmpl.Query.Filter.Not == nil {
		t.Fatalf("Filter.Not is nil, want Preset=unLocked")
	}
	if tmpl.Query.Filter.Not.Preset != "unLocked" {
		t.Errorf("Filter.Not.Preset = %q, want %q", tmpl.Query.Filter.Not.Preset, "unLocked")
	}
	// Bare preset assertion is a pure context (Filter) matcher — Match should
	// carry no leftover AST content from it.
	if tmpl.Query.Filter.Preset != "" {
		t.Errorf("Filter.Preset = %q, want empty (assertion lowers to Not.Preset only)", tmpl.Query.Filter.Preset)
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
const v2NotGuardedByLowerYAML = `
meta: { id: v2-not-guarded-by, severity: MEDIUM, title: missing reentrancy guard modifier }
select: external_call
from: entry_function
where:
  - not: { guarded_by: { block: modifier } }
`

func TestLower_NotGuardedByRoutesToFilter(t *testing.T) {
	tv2, err := parseV2([]byte(v2NotGuardedByLowerYAML))
	if err != nil {
		t.Fatalf("parseV2: %v", err)
	}
	tmpl, err := tv2.lower()
	if err != nil {
		t.Fatalf("lower: %v", err)
	}

	if tmpl.Query.Filter == nil {
		t.Fatalf("Filter is nil, want Not.HasGuard")
	}
	if tmpl.Query.Filter.Not == nil || tmpl.Query.Filter.Not.HasGuard == nil {
		t.Fatalf("Filter = %+v, want Not.HasGuard set", tmpl.Query.Filter)
	}
	wantModifierKind, _ := blockKindToV1("modifier")
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
	if err := finalizeTemplate(tmpl, []byte(v2NotGuardedByLowerYAML), "test"); err != nil {
		t.Fatalf("finalizeTemplate: %v", err)
	}
}

// Companion case: an `any:` branch set mixing `guarded_by:` and `func_name:`
// — both pure context matchers — must route the whole any: into Filter, not
// Match.
const v2AnyGuardedByFuncNameLowerYAML = `
meta: { id: v2-any-guarded-by-func-name, severity: MEDIUM, title: any of guard/func_name test }
select: external_call
from: entry_function
where:
  - any:
      - guarded_by: { block: modifier }
      - func_name: "^admin"
`

func TestLower_AnyGuardedByOrFuncNameRoutesToFilter(t *testing.T) {
	tv2, err := parseV2([]byte(v2AnyGuardedByFuncNameLowerYAML))
	if err != nil {
		t.Fatalf("parseV2: %v", err)
	}
	tmpl, err := tv2.lower()
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

	if err := finalizeTemplate(tmpl, []byte(v2AnyGuardedByFuncNameLowerYAML), "test"); err != nil {
		t.Fatalf("finalizeTemplate: %v", err)
	}
}

// Fix 3 regression: a multi-key `not:` mapping that includes `preset:`
// alongside another key must be rejected with a clear error instead of
// silently double-negating the preset.
const v2NotMultiKeyPresetYAML = `
meta: { id: v2-not-multikey-preset, severity: MEDIUM, title: multi-key not with preset test }
select: external_call
from: entry_function
where:
  - not: { preset: access_controlled, base: some-other-rule }
`

func TestLower_NotMultiKeyPresetRejected(t *testing.T) {
	tv2, err := parseV2([]byte(v2NotMultiKeyPresetYAML))
	if err != nil {
		t.Fatalf("parseV2: %v", err)
	}
	_, err = tv2.lower()
	if err == nil {
		t.Fatalf("lower: expected an error for multi-key not: with a preset key, got nil")
	}
	if !strings.Contains(err.Error(), "preset") {
		t.Errorf("lower error = %q, want it to mention the preset restriction", err.Error())
	}
}

// --- left / right ------------------------------------------------------

const v2LeftRightLowerYAML = `
meta: { id: v2-left-right, severity: MEDIUM, title: left/right operand test }
select: binary
from: entry_function
where:
  - left: { name: "^msg$" }
  - right: { tainted: parameter }
`

func TestLower_LeftRight(t *testing.T) {
	tv2, err := parseV2([]byte(v2LeftRightLowerYAML))
	if err != nil {
		t.Fatalf("parseV2: %v", err)
	}
	tmpl, err := tv2.lower()
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

	if err := finalizeTemplate(tmpl, []byte(v2LeftRightLowerYAML), "test"); err != nil {
		t.Fatalf("finalizeTemplate: %v", err)
	}
}

// --- statement_has -------------------------------------------------------

const v2StatementHasLowerYAML = `
meta: { id: v2-statement-has, severity: MEDIUM, title: statement_has test }
select: external_call
from: entry_function
where:
  - statement_has: { block: require }
`

func TestLower_StatementHas(t *testing.T) {
	tv2, err := parseV2([]byte(v2StatementHasLowerYAML))
	if err != nil {
		t.Fatalf("parseV2: %v", err)
	}
	tmpl, err := tv2.lower()
	if err != nil {
		t.Fatalf("lower: %v", err)
	}

	wantKind, _ := blockKindToV1("require")
	if tmpl.Query.Match.Contains == nil || tmpl.Query.Match.Contains.StatementContains == nil {
		t.Fatalf("Match.Contains.StatementContains is nil")
	}
	if tmpl.Query.Match.Contains.StatementContains.Kind != wantKind {
		t.Errorf("StatementContains.Kind = %q, want %q", tmpl.Query.Match.Contains.StatementContains.Kind, wantKind)
	}

	if err := finalizeTemplate(tmpl, []byte(v2StatementHasLowerYAML), "test"); err != nil {
		t.Fatalf("finalizeTemplate: %v", err)
	}
}

// --- unchecked_var -------------------------------------------------------

const v2UncheckedVarLowerYAML = `
meta: { id: v2-unchecked-var, severity: MEDIUM, title: unchecked_var test }
select: binary
from: entry_function
where:
  - unchecked_var: true
`

func TestLower_UncheckedVar(t *testing.T) {
	tv2, err := parseV2([]byte(v2UncheckedVarLowerYAML))
	if err != nil {
		t.Fatalf("parseV2: %v", err)
	}
	tmpl, err := tv2.lower()
	if err != nil {
		t.Fatalf("lower: %v", err)
	}

	if tmpl.Query.Match.Contains == nil || !tmpl.Query.Match.Contains.UncheckedVar {
		t.Fatalf("Match.Contains.UncheckedVar = %+v, want true", tmpl.Query.Match.Contains)
	}

	if err := finalizeTemplate(tmpl, []byte(v2UncheckedVarLowerYAML), "test"); err != nil {
		t.Fatalf("finalizeTemplate: %v", err)
	}
}

// --- modifier (context layer, filter-only) -------------------------------

const v2ModifierLowerYAML = `
meta: { id: v2-modifier, severity: MEDIUM, title: modifier filter test }
select: external_call
from: entry_function
where:
  - modifier: "(?i)initializer"
`

func TestLower_ModifierRoutesToFilter(t *testing.T) {
	tv2, err := parseV2([]byte(v2ModifierLowerYAML))
	if err != nil {
		t.Fatalf("parseV2: %v", err)
	}
	tmpl, err := tv2.lower()
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

	if err := finalizeTemplate(tmpl, []byte(v2ModifierLowerYAML), "test"); err != nil {
		t.Fatalf("finalizeTemplate: %v", err)
	}
}

// --- select-absent (structural fix) --------------------------------------

const v2SelectAbsentLowerYAML = `
meta: { id: v2-select-absent, severity: MEDIUM, title: select-absent regex-at-root test }
from: contract
where:
  - regex: "slot"
`

func TestLower_SelectAbsentAppliesRegexAtRoot(t *testing.T) {
	tv2, err := parseV2([]byte(v2SelectAbsentLowerYAML))
	if err != nil {
		t.Fatalf("parseV2: %v", err)
	}
	tmpl, err := tv2.lower()
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

	if err := finalizeTemplate(tmpl, []byte(v2SelectAbsentLowerYAML), "test"); err != nil {
		t.Fatalf("finalizeTemplate: %v", err)
	}
}

// TestLower_SelectAbsentNoASTMattersErrors documents that a select-absent
// template with no AST-level where matchers (and scope != source) is
// rejected — there is nothing to match on.
func TestLower_SelectAbsentNoASTMattersErrors(t *testing.T) {
	const yamlSrc = `
meta: { id: v2-select-absent-empty, severity: MEDIUM, title: select-absent with no AST matcher }
from: contract
where:
  - modifier: "(?i)initializer"
`
	tv2, err := parseV2([]byte(yamlSrc))
	if err != nil {
		t.Fatalf("parseV2: %v", err)
	}
	_, err = tv2.lower()
	if err == nil {
		t.Fatalf("lower: expected an error (no select, no AST where-matchers), got nil")
	}
}
