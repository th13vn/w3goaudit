package engine

import "testing"

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
