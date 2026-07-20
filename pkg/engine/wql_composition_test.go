package engine

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/th13vn/w3goaudit/pkg/builder"
	"github.com/th13vn/w3goaudit/pkg/reader"
	"github.com/th13vn/w3goaudit/pkg/types"
)

// ---------------------------------------------------------------------------
// Shape validation: query:-level and:/or: composition.
// ---------------------------------------------------------------------------

func TestCompositionShapeRejections(t *testing.T) {
	cases := []struct {
		name string
		yaml string
		want string
	}{
		{
			name: "and and or together",
			yaml: `
meta: {id: T, severity: HIGH}
query:
  from: main_contract
  and: [{select: external_call}, {select: state_write}]
  or: [{select: external_call}, {select: state_write}]
`,
			want: "cannot combine and: and or:",
		},
		{
			name: "and with sibling select",
			yaml: `
meta: {id: T, severity: HIGH}
query:
  from: main_contract
  select: external_call
  and: [{select: external_call}, {select: state_write}]
`,
			want: "and: cannot be combined with select:/where:",
		},
		{
			name: "or with sibling where",
			yaml: `
meta: {id: T, severity: HIGH}
query:
  where: [{name: transfer}]
  or: [{select: external_call, from: entry_function}, {select: state_write, from: entry_function}]
`,
			want: "or: cannot be combined with select:/where:",
		},
		{
			name: "empty or with simple select",
			yaml: `
meta: {id: T, severity: HIGH}
query:
  select: external_call
  or: []
`,
			want: "or: cannot be combined with select:/where:",
		},
		{
			name: "null and",
			yaml: `
meta: {id: T, severity: HIGH}
query:
  from: main_contract
  and: null
`,
			want: "query.and: must be a non-null list",
		},
		{
			name: "null or",
			yaml: `
meta: {id: T, severity: HIGH}
query:
  or: null
`,
			want: "query.or: must be a non-null list",
		},
		{
			name: "merged composition",
			yaml: `
meta: {id: T, severity: HIGH}
query:
  <<: {or: []}
  select: external_call
`,
			want: "WQL does not support YAML merge keys (<<)",
		},
		{
			name: "merged simple fields",
			yaml: `
meta: {id: T, severity: HIGH}
query:
  <<: {select: external_call}
  or: [{select: external_call}, {select: state_write}]
`,
			want: "WQL does not support YAML merge keys (<<)",
		},
		{
			name: "empty and and populated or",
			yaml: `
meta: {id: T, severity: HIGH}
query:
  from: main_contract
  and: []
  or: [{select: external_call}, {select: state_write}]
`,
			want: "cannot combine and: and or:",
		},
		{
			name: "empty or",
			yaml: `
meta: {id: T, severity: HIGH}
query:
  or: []
`,
			want: "query.or: needs at least two branches",
		},
		{
			name: "empty and",
			yaml: `
meta: {id: T, severity: HIGH}
query:
  and: []
`,
			want: "query.and: needs at least two branches",
		},
		{
			name: "and without from",
			yaml: `
meta: {id: T, severity: HIGH}
query:
  and: [{select: external_call}, {select: state_write}]
`,
			want: "requires a query-level from:",
		},
		{
			name: "and from source",
			yaml: `
meta: {id: T, severity: HIGH}
query:
  from: source
  and: [{select: external_call}, {select: state_write}]
`,
			want: "from: source is not supported",
		},
		{
			name: "and single branch",
			yaml: `
meta: {id: T, severity: HIGH}
query:
  from: main_contract
  and: [{select: external_call}]
`,
			want: "at least two branches",
		},
		{
			name: "and branch with from",
			yaml: `
meta: {id: T, severity: HIGH}
query:
  from: main_contract
  and:
    - {select: external_call, from: entry_function}
    - {select: state_write}
`,
			want: "from: is not allowed on and: branches",
		},
		{
			name: "and branch with context matcher",
			yaml: `
meta: {id: T, severity: HIGH}
query:
  from: main_contract
  and:
    - {select: external_call, where: [{preset: access_controlled}]}
    - {select: state_write}
`,
			want: "context-level matchers",
		},
		{
			name: "and branch without positive anchor",
			yaml: `
meta: {id: T, severity: HIGH}
query:
  from: function
  and:
    - label: absence only
      where: [{not: {has: {block: state_write}}}]
    - label: call site
      select: external_call
`,
			want: "positive reportable anchor",
		},
		{
			name: "and branch with regex only",
			yaml: `
meta: {id: T, severity: HIGH}
query:
  from: function
  and:
    - label: source text only
      where: [{regex: "delegatecall\\("}]
    - label: call site
      select: external_call
`,
			want: "traceable AST evidence",
		},
		{
			name: "and branches all regex only",
			yaml: `
meta: {id: T, severity: HIGH}
query:
  from: function
  and:
    - {where: [{regex: "delegatecall\\("}]}
    - {where: [{regex: "msg\\.sender"}]}
`,
			want: "traceable AST evidence",
		},
		{
			name: "or single branch",
			yaml: `
meta: {id: T, severity: HIGH}
query:
  or: [{select: external_call, from: entry_function}]
`,
			want: "at least two branches",
		},
		{
			name: "or branch with label",
			yaml: `
meta: {id: T, severity: HIGH}
query:
  or:
    - {select: external_call, from: entry_function, label: first}
    - {select: state_write, from: entry_function}
`,
			want: "label: is only supported on and: branches",
		},
		{
			name: "or branch with context-only where",
			yaml: `
meta: {id: T, severity: HIGH}
query:
  or:
    - {where: [{preset: access_controlled}]}
    - {select: state_write, from: entry_function}
`,
			want: "select: required",
		},
		{
			name: "empty or branch",
			yaml: `
meta: {id: T, severity: HIGH}
query:
  or:
    - {}
    - {select: state_write, from: entry_function}
`,
			want: "neither select, from, nor where",
		},
		{
			name: "nested composition rejected",
			yaml: `
meta: {id: T, severity: HIGH}
query:
  from: main_contract
  and:
    - {and: [{select: external_call}, {select: state_write}]}
    - {select: state_write}
`,
			want: "field and not found",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseTemplate(tc.yaml)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want substring %q", err, tc.want)
			}
		})
	}
}

func TestCompositionAllowsRegexRefinementWithASTEvidence(t *testing.T) {
	_, err := ParseTemplate(`
meta: {id: ast-anchored-regex-join, severity: HIGH}
query:
  from: function
  and:
    - label: refined call
      where:
        - {regex: "delegatecall\\("}
        - {has: {block: external_call}}
    - label: state update
      select: state_write
`)
	if err != nil {
		t.Fatalf("AST-anchored regex branch rejected: %v", err)
	}
}

func TestCompositionAllowsSimpleRegexQueryOutsideAnd(t *testing.T) {
	_, err := ParseTemplate(`
meta: {id: simple-regex-query, severity: HIGH}
query:
  from: function
  where: [{regex: "delegatecall\\("}]
`)
	if err != nil {
		t.Fatalf("simple regex query rejected: %v", err)
	}
}

func TestSimpleQueryNegationWithPositiveSelectRemainsValid(t *testing.T) {
	if _, err := ParseTemplate(`
meta: {id: simple-positive-with-negation, severity: HIGH}
query:
  from: entry_function
  select: external_call
  where: [{not: {has: {block: state_write}}}]
`); err != nil {
		t.Fatalf("simple query with a positive select and negation must remain valid: %v", err)
	}
}

// ---------------------------------------------------------------------------
// and: lowering — one QueryBlock with Rule.All labeled branches at the join scope.
// ---------------------------------------------------------------------------

func TestLowerAndComposition(t *testing.T) {
	tmpl, err := ParseTemplate(`
meta: {id: and-composed, severity: HIGH}
query:
  from: main_contract
  and:
    - label: value accounting
      select: identifier
      where: [{name: "msg\\.value"}]
    - label: batch entry
      select: function
      where: [{name: ^multicall$}]
`)
	if err != nil {
		t.Fatalf("ParseTemplate: %v", err)
	}

	if len(tmpl.Queries) != 0 {
		t.Fatalf("Queries = %d blocks, want 0 (and: is a single block)", len(tmpl.Queries))
	}
	if tmpl.Query.Scope != ScopeMainContract {
		t.Fatalf("Scope = %q, want %q", tmpl.Query.Scope, ScopeMainContract)
	}
	if len(tmpl.Query.Match.All) != 2 {
		t.Fatalf("Match.All = %d branches, want 2", len(tmpl.Query.Match.All))
	}

	first, second := tmpl.Query.Match.All[0], tmpl.Query.Match.All[1]
	if first.Label != "value accounting" || second.Label != "batch entry" {
		t.Errorf("labels = %q, %q — want branch labels preserved", first.Label, second.Label)
	}
	wantIdent, _ := blockKindToIR("identifier")
	wantFunc, _ := blockKindToIR("function")
	if first.Contains == nil || first.Contains.Kind != wantIdent {
		t.Errorf("branch 1 = %+v, want Contains.Kind=%q", first.Contains, wantIdent)
	}
	if second.Contains == nil || second.Contains.Kind != wantFunc {
		t.Errorf("branch 2 = %+v, want Contains.Kind=%q", second.Contains, wantFunc)
	}
}

// ---------------------------------------------------------------------------
// or: lowering — one QueryBlock per branch under one meta.
// ---------------------------------------------------------------------------

func TestLowerOrComposition(t *testing.T) {
	tmpl, err := ParseTemplate(`
meta: {id: or-composed, severity: HIGH}
query:
  from: entry_function
  or:
    - select: selfdestruct
      where: [{not: {preset: access_controlled}}]
    - select: delegatecall
      where: [{arg.0: {tainted: parameter}}]
`)
	if err != nil {
		t.Fatalf("ParseTemplate: %v", err)
	}

	if len(tmpl.Queries) != 2 {
		t.Fatalf("Queries = %d blocks, want 2", len(tmpl.Queries))
	}
	if tmpl.Query.Scope != tmpl.Queries[0].Scope || tmpl.Query.Match.Contains == nil {
		t.Fatalf("Query should equal Queries[0]; Query = %+v", tmpl.Query)
	}
	wantSelfdestruct, _ := blockKindToIR("selfdestruct")
	wantDelegatecall, _ := blockKindToIR("delegatecall")
	if tmpl.Queries[0].Match.Contains.Kind != wantSelfdestruct {
		t.Errorf("Queries[0] kind = %q, want %q", tmpl.Queries[0].Match.Contains.Kind, wantSelfdestruct)
	}
	if tmpl.Queries[1].Match.Contains.Kind != wantDelegatecall {
		t.Errorf("Queries[1] kind = %q, want %q", tmpl.Queries[1].Match.Contains.Kind, wantDelegatecall)
	}
	// Branch 1 carries its own context filter; branch 2 has none. Per-branch
	// filters are the reason or: lowers to separate blocks.
	if tmpl.Queries[0].Filter == nil || tmpl.Queries[0].Filter.Not == nil ||
		tmpl.Queries[0].Filter.Not.Preset != "access_controlled" {
		t.Errorf("Queries[0].Filter = %+v, want Not.Preset=access_controlled", tmpl.Queries[0].Filter)
	}
	if tmpl.Queries[1].Filter != nil {
		t.Errorf("Queries[1].Filter = %+v, want nil", tmpl.Queries[1].Filter)
	}
}

func TestLowerOrCompositionCrossScope(t *testing.T) {
	tmpl, err := ParseTemplate(`
meta: {id: or-cross-scope, severity: MEDIUM}
query:
  or:
    - select: external_call
      from: entry_function
    - from: source
      where: [{regex: "tx\\.origin"}]
`)
	if err != nil {
		t.Fatalf("ParseTemplate: %v", err)
	}
	if len(tmpl.Queries) != 2 {
		t.Fatalf("Queries = %d blocks, want 2", len(tmpl.Queries))
	}
	if tmpl.Queries[0].Scope != ScopeEntrypoint || tmpl.Queries[1].Scope != ScopeSource {
		t.Fatalf("scopes = %q, %q — want entrypoint + source", tmpl.Queries[0].Scope, tmpl.Queries[1].Scope)
	}
}

// ---------------------------------------------------------------------------
// End-to-end execution.
// ---------------------------------------------------------------------------

const orExecutionFixture = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Vulnerable_KillOrDelegate {
    function kill() external {
        selfdestruct(payable(msg.sender));
    }

    function execute(address target, bytes calldata data) external {
        (bool ok, ) = target.delegatecall(data);
        require(ok, "delegatecall failed");
    }
}
`

func TestOrCompositionExecutesUnion(t *testing.T) {
	tmpl, err := ParseTemplate(`
meta: {id: or-union, severity: CRITICAL}
query:
  from: entry_function
  or:
    - select: selfdestruct
    - select: delegatecall
`)
	if err != nil {
		t.Fatalf("ParseTemplate: %v", err)
	}
	db := buildDBFromSource(t, orExecutionFixture).GetDatabase()
	findings := New(db).Execute(tmpl)

	matched := make(map[string]bool, len(findings))
	for _, f := range findings {
		matched[f.Location.Function] = true
	}
	if !matched["kill"] || !matched["execute"] {
		t.Fatalf("or: union should find both kill (selfdestruct) and execute (delegatecall); findings = %+v", findings)
	}
}

func TestOrWhereOnlyBranchDefaultsToEntrypointAndExecutes(t *testing.T) {
	tmpl, err := ParseTemplate(`
meta: {id: or-where-only-default, severity: CRITICAL}
query:
  or:
    - where:
        - has: {block: delegatecall}
    - select: selfdestruct
      from: entry_function
`)
	if err != nil {
		t.Fatalf("ParseTemplate: %v", err)
	}
	if len(tmpl.Queries) != 2 {
		t.Fatalf("Queries = %d blocks, want 2", len(tmpl.Queries))
	}
	wantDelegatecall, ok := blockKindToIR("delegatecall")
	if !ok {
		t.Fatal("blockKindToIR(delegatecall) ok=false")
	}
	whereOnly := tmpl.Queries[0]
	if whereOnly.Scope != ScopeEntrypoint {
		t.Fatalf("where-only branch scope = %q, want %q", whereOnly.Scope, ScopeEntrypoint)
	}
	if whereOnly.Match.Contains == nil || whereOnly.Match.Contains.Kind != wantDelegatecall {
		t.Fatalf("where-only branch match = %#v, want contains kind %q", whereOnly.Match, wantDelegatecall)
	}

	db := buildDBFromSource(t, orExecutionFixture).GetDatabase()
	findings := New(db).Execute(tmpl)
	matched := make(map[string]bool, len(findings))
	for _, finding := range findings {
		matched[finding.Location.Function] = true
	}
	if !matched["execute"] || !matched["kill"] {
		t.Fatalf("where-only/default branch and explicit branch must both execute; findings = %+v", findings)
	}
}

func TestOrCompositionDeduplicatesSameSite(t *testing.T) {
	// Both branches anchor on the same delegatecall node; the union must
	// carry it once.
	tmpl, err := ParseTemplate(`
meta: {id: or-dedupe, severity: CRITICAL}
query:
  from: entry_function
  or:
    - select: delegatecall
    - select: delegatecall
      where: [{arg.0: {tainted: parameter}}]
`)
	if err != nil {
		t.Fatalf("ParseTemplate: %v", err)
	}
	db := buildDBFromSource(t, orExecutionFixture).GetDatabase()
	findings := New(db).Execute(tmpl)

	count := 0
	for _, f := range findings {
		if f.Location.Function == "execute" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("delegatecall in execute reported %d times, want 1 (deduped); findings = %+v", count, findings)
	}
}

const andExecutionFixture = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Vulnerable_PayableMulticall {
    uint256 public total;

    function deposit() external payable {
        total += msg.value;
    }

    function multicall(bytes[] calldata calls) external payable {
        for (uint256 i = 0; i < calls.length; i++) {
            (bool ok, ) = address(this).delegatecall(calls[i]);
            require(ok, "call failed");
        }
    }
}

contract Safe_PayableOnly {
    uint256 public total;

    function deposit() external payable {
        total += msg.value;
    }
}
`

func TestAndCompositionJoinsOnContract(t *testing.T) {
	tmpl, err := ParseTemplate(`
meta: {id: and-join, severity: HIGH}
query:
  from: main_contract
  and:
    - label: msg.value accounting
      select: member
      where:
        - name: ^value$
        - parent: ^msg$
    - label: batch entry
      select: function
      where: [{name: ^multicall$}]
`)
	if err != nil {
		t.Fatalf("ParseTemplate: %v", err)
	}
	db := buildDBFromSource(t, andExecutionFixture).GetDatabase()
	findings := New(db).Execute(tmpl)

	byContract := make(map[string]*Finding, len(findings))
	for _, f := range findings {
		byContract[f.Location.Contract] = f
	}
	if byContract["Vulnerable_PayableMulticall"] == nil {
		t.Fatalf("contract with BOTH msg.value use and multicall must match; findings = %+v", findings)
	}
	if byContract["Safe_PayableOnly"] != nil {
		t.Fatalf("contract with only one branch matching must NOT match; findings = %+v", findings)
	}

	f := byContract["Vulnerable_PayableMulticall"]
	labels := make(map[string]bool, len(f.Related))
	for _, site := range f.Related {
		labels[site.Label] = true
	}
	if !labels["msg.value accounting"] || !labels["batch entry"] {
		t.Fatalf("Related labels = %v, want both branch labels", labels)
	}
}

// ---------------------------------------------------------------------------
// Companion matchers: where and: alias, arg.any:.
// ---------------------------------------------------------------------------

func TestWhereAndLowersToRuleAll(t *testing.T) {
	tmpl, err := ParseTemplate(`
meta: {id: T, severity: HIGH}
query:
  select: external_call
  from: entry_function
  where:
    - and: [{name: transfer}, {arg.0: {tainted: parameter}}]
`)
	if err != nil {
		t.Fatalf("ParseTemplate(and:): %v", err)
	}
	if got := len(tmpl.Query.Match.Contains.All); got != 2 {
		t.Fatalf("len(Rule.All) = %d, want 2: %+v", got, tmpl.Query.Match)
	}
}

const argAnyFixture = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Vulnerable_ArgAny {
    event Done(address who);

    function forward(address a, address b) external {
        helper(address(this), b);
    }

    function helper(address x, address y) public {
        emit Done(y);
    }
}
`

func TestArgAnyMatchesSomeArgument(t *testing.T) {
	// arg.0 of helper(address(this), b) is NOT parameter-tainted, but arg.1
	// is — arg.any must match while arg.0 must not.
	byIndex, err := ParseTemplate(`
meta: {id: arg-0, severity: LOW}
query:
  select: internal_call
  from: entry_function
  where:
    - name: ^helper$
    - arg.0: {tainted: parameter}
`)
	if err != nil {
		t.Fatalf("ParseTemplate(arg.0): %v", err)
	}
	byAny, err := ParseTemplate(`
meta: {id: arg-any, severity: LOW}
query:
  select: internal_call
  from: entry_function
  where:
    - name: ^helper$
    - arg.any: {tainted: parameter}
`)
	if err != nil {
		t.Fatalf("ParseTemplate(arg.any): %v", err)
	}

	db := buildDBFromSource(t, argAnyFixture).GetDatabase()

	if findings := New(db).Execute(byIndex); len(findings) != 0 {
		t.Fatalf("arg.0 tainted must not match (first arg is address(this)); findings = %+v", findings)
	}
	findings := New(db).Execute(byAny)
	found := false
	for _, f := range findings {
		if f.Location.Function == "forward" {
			found = true
		}
	}
	if !found {
		t.Fatalf("arg.any tainted must match the helper call in forward; findings = %+v", findings)
	}
}

const repeatedArgAnyFixture = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract RepeatedArgAny {
    address private recipient;
    address private last;

    function entry(address payload) external {
        helper(recipient, payload);
    }

    function helper(address first, address second) internal {
        last = second;
    }
}
`

func TestRepeatedArgAnyUsesIndependentWitnesses(t *testing.T) {
	tmpl, err := ParseTemplate(`
meta: {id: T, severity: HIGH}
query:
  select: internal_call
  from: entry_function
  where:
    - arg.any: {name: ^recipient$}
    - arg.any: {tainted: user_controlled}
`)
	if err != nil {
		t.Fatalf("ParseTemplate: %v", err)
	}

	db := buildDBFromSource(t, repeatedArgAnyFixture).GetDatabase()
	findings := New(db).Execute(tmpl)
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1 with independent arg.any witnesses: %+v", len(findings), findings)
	}
}

// ---------------------------------------------------------------------------
// Variant coverage: function-scope joins, cross-scope unions, wide unions,
// IR serialization, and degenerate query shapes.
// ---------------------------------------------------------------------------

func TestCompositionDegenerateQueryShapes(t *testing.T) {
	cases := []struct {
		name string
		yaml string
		want string
	}{
		{
			name: "null query",
			yaml: "meta: {id: T, severity: HIGH}\nquery:\n",
			want: "no query:",
		},
		{
			name: "empty query map",
			yaml: "meta: {id: T, severity: HIGH}\nquery: {}\n",
			want: "neither select, from, nor where",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseTemplate(tc.yaml)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want substring %q", err, tc.want)
			}
		})
	}
}

func TestOrBranchRejectsListSelect(t *testing.T) {
	_, err := ParseTemplate(`
meta: {id: T, severity: HIGH}
query:
  from: entry_function
  or:
    - select: [selfdestruct, delegatecall]
    - select: state_write
`)
	if err == nil {
		t.Fatalf("a list select on an or: branch must fail to load")
	}
}

func TestLowerAndBranchWithSequence(t *testing.T) {
	tmpl, err := ParseTemplate(`
meta: {id: and-seq, severity: HIGH}
query:
  from: entry_function
  and:
    - label: CEI violation
      where:
        - sequence:
            - block: external_call
            - block: state_write
    - select: member
      where:
        - name: ^value$
        - parent: ^msg$
`)
	if err != nil {
		t.Fatalf("ParseTemplate: %v", err)
	}
	if len(tmpl.Query.Match.All) != 2 {
		t.Fatalf("Match.All = %d branches, want 2", len(tmpl.Query.Match.All))
	}
	seqBranch := tmpl.Query.Match.All[0]
	if seqBranch.Label != "CEI violation" || len(seqBranch.Sequence) != 2 {
		t.Fatalf("branch 1 = %+v, want labeled 2-step sequence at branch root", seqBranch)
	}
	if seqBranch.Contains != nil {
		t.Fatalf("branch 1 sequence must stay at the branch root, got Contains wrap: %+v", seqBranch.Contains)
	}
}

const functionJoinFixture = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract JoinTargets {
    uint256 public balance;

    function both(address payable to) external {
        to.transfer(1 ether);
        balance = 0;
    }

    function onlyTransfer(address payable to) external {
        to.transfer(1 ether);
    }

    function onlyWrite() external {
        balance = 0;
    }
}
`

func TestAndCompositionJoinsOnFunction(t *testing.T) {
	tmpl, err := ParseTemplate(`
meta: {id: and-function-join, severity: MEDIUM}
query:
  from: entry_function
  and:
    - select: eth_transfer
    - select: state_write
`)
	if err != nil {
		t.Fatalf("ParseTemplate: %v", err)
	}
	db := buildDBFromSource(t, functionJoinFixture).GetDatabase()
	findings := New(db).Execute(tmpl)

	matched := make(map[string]bool, len(findings))
	for _, f := range findings {
		matched[f.Location.Function] = true
	}
	if !matched["both"] {
		t.Fatalf("function with BOTH sites must match; findings = %+v", findings)
	}
	if matched["onlyTransfer"] || matched["onlyWrite"] {
		t.Fatalf("functions with only one site must NOT match; findings = %+v", findings)
	}
}

const crossScopeFixture = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract CrossScope {
    address public owner;

    function auth() external {
        require(tx.origin == owner, "no");
        selfdestruct(payable(msg.sender));
    }
}
`

func TestOrCompositionExecutesAcrossScopes(t *testing.T) {
	tmpl, err := ParseTemplate(`
meta: {id: or-cross-scope-exec, severity: MEDIUM}
query:
  or:
    - select: selfdestruct
      from: entry_function
    - from: source
      where: [{regex: "tx\\.origin"}]
`)
	if err != nil {
		t.Fatalf("ParseTemplate: %v", err)
	}
	db := buildDBFromSource(t, crossScopeFixture).GetDatabase()
	findings := New(db).Execute(tmpl)

	// The union must carry BOTH branch matches: the tx.origin require line
	// (source regex) and the selfdestruct line (entrypoint scope) are distinct
	// source lines in the fixture.
	lines := make(map[int]bool, len(findings))
	for _, f := range findings {
		lines[f.Location.Line] = true
	}
	if len(findings) != 2 || len(lines) != 2 {
		t.Fatalf("cross-scope union must include the source-regex match and the entrypoint match on their two distinct lines; findings = %d on lines %v", len(findings), lines)
	}
}

func TestOrCompositionThreeBranches(t *testing.T) {
	tmpl, err := ParseTemplate(`
meta: {id: or-three, severity: MEDIUM}
query:
  from: entry_function
  or:
    - select: selfdestruct
    - select: eth_transfer
    - select: state_write
`)
	if err != nil {
		t.Fatalf("ParseTemplate: %v", err)
	}
	if len(tmpl.Queries) != 3 {
		t.Fatalf("Queries = %d blocks, want 3", len(tmpl.Queries))
	}
	db := buildDBFromSource(t, functionJoinFixture).GetDatabase()
	findings := New(db).Execute(tmpl)
	matched := make(map[string]bool, len(findings))
	for _, f := range findings {
		matched[f.Location.Function] = true
	}
	for _, fn := range []string{"both", "onlyTransfer", "onlyWrite"} {
		if !matched[fn] {
			t.Fatalf("3-branch union must cover %s; findings = %+v", fn, findings)
		}
	}
}

func TestOrCompositionSurvivesJSONRoundTrip(t *testing.T) {
	tmpl, err := ParseTemplate(`
meta: {id: or-roundtrip, severity: MEDIUM}
query:
  from: entry_function
  or:
    - select: selfdestruct
    - select: delegatecall
`)
	if err != nil {
		t.Fatalf("ParseTemplate: %v", err)
	}
	data, err := json.Marshal(tmpl)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	var restored Template
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if len(restored.Queries) != 2 {
		t.Fatalf("restored Queries = %d blocks, want 2", len(restored.Queries))
	}

	db := buildDBFromSource(t, orExecutionFixture).GetDatabase()
	before := New(db).Execute(tmpl)
	after := New(db).Execute(&restored)
	if len(before) != len(after) || len(before) == 0 {
		t.Fatalf("round-tripped or: template found %d findings, original %d (want equal, nonzero)", len(after), len(before))
	}
}

const orIdentityFixture = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract IdentityTarget {
    function run(address target, bytes calldata data) external {
        target.delegatecall(data);
        selfdestruct(payable(msg.sender));
    }
}
`

func TestOrCompositionDistinctNodesSameFunctionIdentity(t *testing.T) {
	tmpl, err := ParseTemplate(`
meta: {id: or-distinct-identity, severity: HIGH}
query:
  from: function
  or:
    - select: delegatecall
    - select: selfdestruct
`)
	if err != nil {
		t.Fatalf("ParseTemplate: %v", err)
	}
	db := buildDBFromSource(t, orIdentityFixture).GetDatabase()
	contract := mustContractByName(t, db, "IdentityTarget")
	fn := mustFunctionByName(t, contract, "run")
	wantDelegate := mustASTNode(t, fn.AST, types.KindCallLowlevelDelegate)
	wantDestroy := mustASTNode(t, fn.AST, types.KindCallBuiltinSelfdestruct)

	findings := New(db).Execute(tmpl)
	if len(findings) != 2 {
		t.Fatalf("findings = %d, want two distinct nodes in run: %+v", len(findings), findings)
	}
	assertFindingMatchesOneOfNodes(t, findings[0], wantDelegate, wantDestroy)
	assertFindingMatchesOneOfNodes(t, findings[1], wantDelegate, wantDestroy)
	if findings[0].PrimaryAST.StartByte == findings[1].PrimaryAST.StartByte {
		t.Fatalf("distinct findings share primary byte %d: %+v", findings[0].PrimaryAST.StartByte, findings)
	}
}

func TestOrCompositionSameNodeIdentity(t *testing.T) {
	tmpl, err := ParseTemplate(`
meta: {id: or-same-identity, severity: HIGH}
query:
  from: function
  or:
    - select: delegatecall
    - select: delegatecall
      where: [{arg.0: {tainted: parameter}}]
`)
	if err != nil {
		t.Fatalf("ParseTemplate: %v", err)
	}
	db := buildDBFromSource(t, orIdentityFixture).GetDatabase()
	fn := mustFunctionByName(t, mustContractByName(t, db, "IdentityTarget"), "run")
	want := mustASTNode(t, fn.AST, types.KindCallLowlevelDelegate)

	findings := New(db).Execute(tmpl)
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want one canonical node: %+v", len(findings), findings)
	}
	assertFindingMatchesNode(t, findings[0], want)
}

func TestOrCompositionSameNodeAcrossScopesIdentity(t *testing.T) {
	tmpl, err := ParseTemplate(`
meta: {id: or-across-scopes-identity, severity: HIGH}
query:
  or:
    - select: delegatecall
      from: entry_function
    - select: delegatecall
      from: function
`)
	if err != nil {
		t.Fatalf("ParseTemplate: %v", err)
	}
	db := buildDBFromSource(t, orIdentityFixture).GetDatabase()
	fn := mustFunctionByName(t, mustContractByName(t, db, "IdentityTarget"), "run")
	want := mustASTNode(t, fn.AST, types.KindCallLowlevelDelegate)

	findings := New(db).Execute(tmpl)
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want one node across entry_function and function: %+v", len(findings), findings)
	}
	assertFindingMatchesNode(t, findings[0], want)
}

func TestOrCompositionInheritedContractContractIdentity(t *testing.T) {
	tmpl, err := ParseTemplate(`
meta: {id: or-inherited-contract-contract-identity, severity: HIGH}
query:
  or:
    - select: delegatecall
      from: main_contract
    - select: delegatecall
      from: main_contract
`)
	if err != nil {
		t.Fatalf("ParseTemplate: %v", err)
	}
	db, paths := buildInheritedIdentityDatabase(t)
	base := mustContractByExactFile(t, db, paths["base"], "RepeatedBase")
	want := mustASTNode(t, mustFunctionByName(t, base, "inheritedRun").AST, types.KindCallLowlevelDelegate)

	findings := New(db).Execute(tmpl)
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want one inherited node across contract branches: %+v", len(findings), findings)
	}
	assertFindingExactOwnedNode(t, findings[0], paths["base"], base.Name, "inheritedRun", want)
}

func TestOrCompositionInheritedContractFunctionIdentity(t *testing.T) {
	tmpl, err := ParseTemplate(`
meta: {id: or-inherited-contract-function-identity, severity: HIGH}
query:
  or:
    - select: delegatecall
      from: main_contract
    - select: delegatecall
      from: function
`)
	if err != nil {
		t.Fatalf("ParseTemplate: %v", err)
	}
	db, paths := buildInheritedIdentityDatabase(t)
	base := mustContractByExactFile(t, db, paths["base"], "RepeatedBase")
	want := mustASTNode(t, mustFunctionByName(t, base, "inheritedRun").AST, types.KindCallLowlevelDelegate)

	findings := New(db).Execute(tmpl)
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want one inherited node across contract and function branches: %+v", len(findings), findings)
	}
	assertFindingExactOwnedNode(t, findings[0], paths["base"], base.Name, "inheritedRun", want)
}

func TestOrCompositionInheritedEntryFunctionOwningFileIdentity(t *testing.T) {
	db, paths := buildInheritedIdentityDatabase(t)
	base := mustContractByExactFile(t, db, paths["base"], "RepeatedBase")
	want := mustASTNode(t, mustFunctionByName(t, base, "inheritedRun").AST, types.KindCallLowlevelDelegate)

	entryTemplate, err := ParseTemplate(`
meta: {id: inherited-entry-owning-file, severity: HIGH}
query:
  select: delegatecall
  from: entry_function
`)
	if err != nil {
		t.Fatalf("ParseTemplate entry template: %v", err)
	}
	entryFindings := New(db).Execute(entryTemplate)
	if len(entryFindings) != 1 {
		t.Fatalf("entry findings = %d, want one inherited entry node: %+v", len(entryFindings), entryFindings)
	}
	entryFinding := entryFindings[0]
	assertFindingExactOwnedNode(t, entryFinding, paths["base"], base.Name, "inheritedRun", want)
	if entryFinding.Reachability == nil || len(entryFinding.Reachability.Steps) == 0 {
		t.Fatalf("missing inherited entry reachability: %+v", entryFinding)
	}
	host := entryFinding.Reachability.Steps[len(entryFinding.Reachability.Steps)-1]
	if host.File != paths["base"] || host.Contract != base.Name || host.Function != "inheritedRun" {
		t.Fatalf("inherited entry host = %+v, want %s %s.inheritedRun", host, paths["base"], base.Name)
	}
	if host.File == paths["duplicate"] || host.File == paths["derived"] {
		t.Fatalf("inherited entry host used non-owning duplicate/deployment file: %+v", host)
	}

	orTemplate, err := ParseTemplate(`
meta: {id: or-inherited-entry-function-identity, severity: HIGH}
query:
  or:
    - select: delegatecall
      from: entry_function
    - select: delegatecall
      from: function
`)
	if err != nil {
		t.Fatalf("ParseTemplate or template: %v", err)
	}
	findings := New(db).Execute(orTemplate)
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want inherited entry/function node deduplicated: %+v", len(findings), findings)
	}
	assertFindingExactOwnedNode(t, findings[0], paths["base"], base.Name, "inheritedRun", want)
}

func TestOrCompositionSourceSpanIdentity(t *testing.T) {
	const source = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
// π FLAG gap FLAG
contract SourceSpan {}
`
	tmpl, err := ParseTemplate(`
meta: {id: or-source-span, severity: LOW}
query:
  or:
    - from: source
      where: [{regex: "FLAG"}]
    - select: selfdestruct
      from: function
`)
	if err != nil {
		t.Fatalf("ParseTemplate: %v", err)
	}
	db := buildDBFromSource(t, source).GetDatabase()
	findings := New(db).Execute(tmpl)
	if len(findings) != 2 {
		t.Fatalf("findings = %d, want two same-line regex occurrences: %+v", len(findings), findings)
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].Location.StartByte < findings[j].Location.StartByte })
	first := strings.Index(source, "FLAG")
	second := strings.LastIndex(source, "FLAG")
	for i, wantStart := range []int{first, second} {
		f := findings[i]
		if f.Location.StartByte != wantStart || f.Location.EndByte != wantStart+len("FLAG") {
			t.Fatalf("finding %d byte span = [%d,%d), want [%d,%d)", i, f.Location.StartByte, f.Location.EndByte, wantStart, wantStart+len("FLAG"))
		}
		lineStart := strings.LastIndex(source[:wantStart], "\n") + 1
		wantCol := utf8.RuneCountInString(source[lineStart:wantStart]) + 1
		if f.Location.Line != 3 || f.Location.EndLine != 3 || f.Location.Col != wantCol || f.Location.EndCol != wantCol+4 {
			t.Fatalf("finding %d source span = %+v, want line 3 cols [%d,%d)", i, f.Location, wantCol, wantCol+4)
		}
	}
}

func TestOrCompositionMultilineUnicodeSourceSpanIdentity(t *testing.T) {
	const source = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
// π START
// 中 END
contract MultilineSourceSpan {}
`
	tmpl, err := ParseTemplate(`
meta: {id: multiline-unicode-source-span, severity: LOW}
query:
  from: source
  where: [{regex: "START\\n// 中 END"}]
`)
	if err != nil {
		t.Fatalf("ParseTemplate: %v", err)
	}
	findings := New(buildDBFromSource(t, source).GetDatabase()).Execute(tmpl)
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want one multiline source match: %+v", len(findings), findings)
	}
	wantText := "START\n// 中 END"
	wantStart := strings.Index(source, wantText)
	wantEnd := wantStart + len(wantText)
	loc := findings[0].Location
	if loc.Line != 3 || loc.Col != 6 || loc.EndLine != 4 || loc.EndCol != 9 ||
		loc.StartByte != wantStart || loc.EndByte != wantEnd {
		t.Fatalf("multiline Unicode span = %+v, want line 3 col 6 to line 4 col 9 bytes [%d,%d)", loc, wantStart, wantEnd)
	}
}

func TestOrCompositionPreciseContractFindingsDeduplicate(t *testing.T) {
	tmpl, err := ParseTemplate(`
meta: {id: or-precise-contract, severity: LOW}
query:
  from: contract
  or:
    - where: [{name: "^IdentityTarget$"}]
    - where: [{name: "^IdentityTarget$"}]
`)
	if err != nil {
		t.Fatalf("ParseTemplate: %v", err)
	}
	db := buildDBFromSource(t, orIdentityFixture).GetDatabase()
	findings := New(db).Execute(tmpl)
	if len(findings) != 1 {
		t.Fatalf("precise contract findings = %d, want identical branches deduplicated: %+v", len(findings), findings)
	}
	contract := db.GetContractByName("IdentityTarget")
	f := findings[0]
	if f.PrimaryAST == nil || f.PrimaryAST.Kind != types.KindDeclContract {
		t.Fatalf("primary AST = %+v, want exact decl.contract", f.PrimaryAST)
	}
	if f.PrimaryAST.Start != contract.StartLine || f.PrimaryAST.End != contract.EndLine ||
		f.PrimaryAST.StartCol != contract.StartCol || f.PrimaryAST.EndCol != contract.EndCol ||
		f.PrimaryAST.StartByte != contract.StartByte || f.PrimaryAST.EndByte != contract.EndByte {
		t.Fatalf("primary AST span = %+v, want contract span %+v", f.PrimaryAST, contract)
	}
	if f.Location.Line != contract.StartLine || f.Location.EndLine != contract.EndLine ||
		f.Location.Col != contract.StartCol || f.Location.EndCol != contract.EndCol ||
		f.Location.StartByte != contract.StartByte || f.Location.EndByte != contract.EndByte {
		t.Fatalf("location = %+v, want exact contract declaration span", f.Location)
	}
}

func TestOrCompositionIdentityPreservesIntraBranchDuplicates(t *testing.T) {
	tmpl, err := ParseTemplate(`
meta: {id: or-intra-branch-duplicates, severity: HIGH}
query:
  or:
    - select: delegatecall
      from: entry_function
    - select: require
      from: entry_function
`)
	if err != nil {
		t.Fatalf("ParseTemplate: %v", err)
	}
	db := buildDBFromSource(t, orIdentityFixture).GetDatabase()
	for _, entry := range db.MainContracts {
		if len(entry.EntryFunctions) == 0 {
			continue
		}
		entry.EntryFunctions = append(entry.EntryFunctions, entry.EntryFunctions[0])
	}
	fn := mustFunctionByName(t, mustContractByName(t, db, "IdentityTarget"), "run")
	want := mustASTNode(t, fn.AST, types.KindCallLowlevelDelegate)

	findings := New(db).Execute(tmpl)
	if len(findings) != 2 {
		t.Fatalf("intra-branch duplicate findings = %d, want both retained: %+v", len(findings), findings)
	}
	for _, f := range findings {
		assertFindingMatchesNode(t, f, want)
	}
}

const functionScopeProvenanceFixture = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract FunctionScopeJoin {
    uint256 public balance;

    function entry(address target, bytes calldata data) external {
        joined(target, data);
    }

    function joined(address target, bytes memory data) public {
        target.delegatecall(data);
        balance = 1;
    }

    function onlyCall(address target, bytes calldata data) external {
        callOnly(target, data);
    }

    function callOnly(address target, bytes memory data) internal {
        target.delegatecall(data);
    }

    function onlyWrite() external {
        balance = 2;
    }
}
`

func TestAndCompositionFunctionScopeProvenance(t *testing.T) {
	db := buildDBFromSource(t, functionScopeProvenanceFixture).GetDatabase()
	contract := mustContractByName(t, db, "FunctionScopeJoin")
	joined := mustFunctionByName(t, contract, "joined")
	wantFirst := mustASTNode(t, joined.AST, types.KindCallLowlevelDelegate)
	wantSecond := mustASTNode(t, joined.AST, types.KindStmtAssign)

	for _, tc := range []struct {
		name           string
		scope          string
		entryPointName string
	}{
		{name: "entry_function", scope: "entry_function", entryPointName: "entry"},
		{name: "function", scope: "function", entryPointName: "joined"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tmpl := mustParseAndProvenanceTemplate(t, tc.scope)
			findings := New(db).Execute(tmpl)
			finding := findingByEntryPoint(t, findings, tc.entryPointName)
			assertFindingMatchesNode(t, finding, wantFirst)
			assertJoinFindingProvenance(t, finding, []expectedRelatedNode{
				{label: "first site", file: contract.SourceFile, contract: contract.Name, function: joined.Name, node: wantFirst},
				{label: "second site", file: contract.SourceFile, contract: contract.Name, function: joined.Name, node: wantSecond},
			})
			for _, f := range findings {
				if f.Location.Function == "onlyCall" || f.Location.Function == "onlyWrite" || f.Location.Function == "callOnly" {
					t.Fatalf("safe one-branch function produced a join: %+v", f)
				}
			}
		})
	}
}

func TestRegexRefinementDefersPrimaryToTraceableASTEvidence(t *testing.T) {
	const source = `pragma solidity ^0.8.20;
contract RegexRefinement {
    uint256 private stored;
    function run(address target) external {
        target.call("");
        stored = 1;
    }
}`
	db := buildDBFromSource(t, source).GetDatabase()
	contract := mustContractByName(t, db, "RegexRefinement")
	fn := mustFunctionByName(t, contract, "run")
	call := mustASTNode(t, fn.AST, types.KindCallLowlevelCall)
	write := mustASTNode(t, fn.AST, types.KindStmtAssign)

	for _, scope := range []string{"entry_function", "function", "main_contract", "contract"} {
		t.Run(scope, func(t *testing.T) {
			tmpl, err := ParseTemplate(fmt.Sprintf(`
meta: {id: regex-refinement, severity: HIGH}
query:
  from: %s
  and:
    - label: first site
      where:
        - regex: 'target\.call'
        - has: {block: lowlevel_call}
    - label: second site
      select: state_write
`, scope))
			if err != nil {
				t.Fatalf("ParseTemplate: %v", err)
			}
			findings := New(db).Execute(tmpl)
			if len(findings) != 1 {
				t.Fatalf("findings = %d, want one regex-refined join: %+v", len(findings), findings)
			}
			finding := findings[0]
			assertFindingMatchesNode(t, finding, call)
			assertJoinFindingProvenance(t, finding, []expectedRelatedNode{
				{label: "first site", file: contract.SourceFile, contract: contract.Name, function: fn.Name, node: call},
				{label: "second site", file: contract.SourceFile, contract: contract.Name, function: fn.Name, node: write},
			})
		})
	}

	for _, scope := range []string{"function", "contract"} {
		t.Run("simple regex "+scope, func(t *testing.T) {
			tmpl, err := ParseTemplate(fmt.Sprintf(`
meta: {id: simple-regex, severity: LOW}
query:
  from: %s
  where: [{regex: 'target\.call'}]
`, scope))
			if err != nil {
				t.Fatalf("ParseTemplate: %v", err)
			}
			findings := New(db).Execute(tmpl)
			if len(findings) != 1 {
				t.Fatalf("simple regex findings = %d, want one: %+v", len(findings), findings)
			}
			if findings[0].PrimaryAST != nil {
				t.Fatalf("simple regex unexpectedly gained AST provenance: %+v", findings[0].PrimaryAST)
			}
			wantFunction := "run"
			if scope == "contract" {
				wantFunction = ""
			}
			if findings[0].Location.Contract != contract.Name || findings[0].Location.Function != wantFunction {
				t.Fatalf("simple regex location = %+v, want coarse %s.%s context", findings[0].Location, contract.Name, wantFunction)
			}
		})
	}
}

func TestAndCompositionContractRootBranchContributesRelatedSite(t *testing.T) {
	db, paths := buildCompositionScopeDatabase(t)
	tests := []struct {
		name           string
		scope          string
		contractFile   string
		contractName   string
		secondFunction string
	}{
		{name: "main_contract", scope: "main_contract", contractFile: paths["derived"], contractName: "DerivedJoin", secondFunction: "secondSite"},
		{name: "any_contract", scope: "any_contract", contractFile: paths["derived"], contractName: "DerivedJoin", secondFunction: "secondSite"},
		{name: "contract", scope: "contract", contractFile: paths["contract"], contractName: "PlainJoin", secondFunction: "secondSite"},
		{name: "library", scope: "library", contractFile: paths["library"], contractName: "LibraryJoin", secondFunction: "secondSite"},
		{name: "abstract", scope: "abstract", contractFile: paths["abstract"], contractName: "AbstractJoin", secondFunction: "secondSite"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tmpl, err := ParseTemplate(fmt.Sprintf(`
meta: {id: and-contract-root-provenance, severity: HIGH}
query:
  from: %s
  and:
    - label: contract declaration
      where: [{name: "^%s$"}]
    - label: call site
      select: lowlevel_call
`, tc.scope, tc.contractName))
			if err != nil {
				t.Fatalf("ParseTemplate: %v", err)
			}
			findings := New(db).Execute(tmpl)
			finding := findingByExactContractFile(t, findings, tc.contractFile, tc.contractName)
			contract := mustContractByExactFile(t, db, tc.contractFile, tc.contractName)
			assertContractRootPrimary(t, finding, contract)
			assertContractRootLocation(t, finding.Location, contract)

			var rootSite, callSite *RelatedLocation
			for i := range finding.Related {
				site := &finding.Related[i]
				switch site.Label {
				case "contract declaration":
					rootSite = site
				case "call site":
					callSite = site
				}
			}
			assertContractRootRelated(t, rootSite, contract, finding.Related)
			secondFn := mustFunctionByName(t, contract, tc.secondFunction)
			secondNode := mustASTNode(t, secondFn.AST, types.KindCallLowlevelCall)
			if callSite == nil || callSite.File != tc.contractFile || callSite.Contract != tc.contractName || callSite.Function != tc.secondFunction {
				t.Fatalf("call related site = %+v, want %s.%s; all=%+v", callSite, tc.contractName, tc.secondFunction, finding.Related)
			}
			assertRelatedJSONSpan(t, *callSite, secondNode)
		})
	}
}

func assertContractRootPrimary(t *testing.T, finding *Finding, contract *types.Contract) {
	t.Helper()
	primary := finding.PrimaryAST
	if primary == nil || primary.Kind != types.KindDeclContract || primary.Name != contract.Name {
		t.Fatalf("PrimaryAST = %+v, want first branch contract declaration %s", primary, contract.Name)
	}
	if primary.Start != contract.StartLine || primary.End != contract.EndLine ||
		primary.StartCol != contract.StartCol || primary.EndCol != contract.EndCol ||
		primary.StartByte != contract.StartByte || primary.EndByte != contract.EndByte {
		t.Fatalf("PrimaryAST span = %+v, want exact contract span", primary)
	}
}

func assertContractRootLocation(t *testing.T, location Location, contract *types.Contract) {
	t.Helper()
	if location.File != contract.SourceFile || location.Contract != contract.Name || location.Function != "" ||
		location.Line != contract.StartLine || location.EndLine != contract.EndLine ||
		location.Col != contract.StartCol || location.EndCol != contract.EndCol ||
		location.StartByte != contract.StartByte || location.EndByte != contract.EndByte {
		t.Fatalf("Location = %+v, want exact contract declaration for %s", location, contract.Name)
	}
}

func assertContractRootRelated(t *testing.T, site *RelatedLocation, contract *types.Contract, all []RelatedLocation) {
	t.Helper()
	if site == nil || site.File != contract.SourceFile || site.Contract != contract.Name || site.Function != "" ||
		site.Kind != types.KindDeclContract || site.Name != contract.Name ||
		site.Line != contract.StartLine || site.EndLine != contract.EndLine ||
		site.Col != contract.StartCol || site.EndCol != contract.EndCol ||
		site.StartByte != contract.StartByte || site.EndByte != contract.EndByte {
		t.Fatalf("contract-root related site = %+v, want exact contract declaration; all=%+v", site, all)
	}
}

func TestAndCompositionContractScopeProvenance(t *testing.T) {
	db, paths := buildCompositionScopeDatabase(t)
	correctBase := mustContractByExactFile(t, db, paths["correct"], "RepeatedBase")
	baseFirstFn := mustFunctionByName(t, correctBase, "firstSite")
	baseFirst := mustASTNode(t, baseFirstFn.AST, types.KindCheckRequire)

	tests := []struct {
		name           string
		scope          string
		contractFile   string
		contractName   string
		firstContract  string
		firstFunction  string
		firstNode      *types.ASTNode
		secondFunction string
	}{
		{name: "main_contract", scope: "main_contract", contractFile: paths["derived"], contractName: "DerivedJoin", firstContract: "RepeatedBase", firstFunction: "firstSite", firstNode: baseFirst, secondFunction: "secondSite"},
		{name: "any_contract", scope: "any_contract", contractFile: paths["derived"], contractName: "DerivedJoin", firstContract: "RepeatedBase", firstFunction: "firstSite", firstNode: baseFirst, secondFunction: "secondSite"},
		{name: "contract", scope: "contract", contractFile: paths["contract"], contractName: "PlainJoin", firstContract: "PlainJoin", firstFunction: "firstSite", secondFunction: "secondSite"},
		{name: "library", scope: "library", contractFile: paths["library"], contractName: "LibraryJoin", firstContract: "LibraryJoin", firstFunction: "firstSite", secondFunction: "secondSite"},
		{name: "abstract", scope: "abstract", contractFile: paths["abstract"], contractName: "AbstractJoin", firstContract: "AbstractJoin", firstFunction: "firstSite", secondFunction: "secondSite"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tmpl := mustParseContractAndProvenanceTemplate(t, tc.scope)
			findings := New(db).Execute(tmpl)
			var finding *Finding
			if tc.contractName == "DerivedJoin" {
				finding = findingByRelatedExactSite(t, findings, tc.contractFile, tc.secondFunction)
			} else {
				finding = findingByExactContractFile(t, findings, tc.contractFile, tc.contractName)
			}
			firstNode := tc.firstNode
			firstFile := tc.contractFile
			if firstNode == nil {
				firstFn := mustFunctionByName(t, mustContractByExactFile(t, db, tc.contractFile, tc.contractName), tc.firstFunction)
				firstNode = mustASTNode(t, firstFn.AST, types.KindCheckRequire)
			} else {
				firstFile = paths["correct"]
			}
			contract := mustContractByExactFile(t, db, tc.contractFile, tc.contractName)
			secondFn := mustFunctionByName(t, contract, tc.secondFunction)
			secondNode := mustASTNode(t, secondFn.AST, types.KindCallLowlevelCall)
			assertJoinFindingProvenance(t, finding, []expectedRelatedNode{
				{label: "first site", file: firstFile, contract: tc.firstContract, function: tc.firstFunction, node: firstNode},
				{label: "second site", file: tc.contractFile, contract: tc.contractName, function: tc.secondFunction, node: secondNode},
			})
			if tc.contractName == "DerivedJoin" {
				for _, related := range finding.Related {
					if related.Label == "first site" && related.File == paths["wrong"] {
						t.Fatalf("inherited site resolved to duplicate-name wrong file: %+v", related)
					}
				}
			}
			for _, f := range findings {
				if strings.HasPrefix(f.Location.Contract, "Safe") {
					t.Fatalf("safe one-branch contract produced a join: %+v", f)
				}
			}
		})
	}
}

type expectedRelatedNode struct {
	label    string
	file     string
	contract string
	function string
	node     *types.ASTNode
}

func mustParseAndProvenanceTemplate(t *testing.T, scope string) *Template {
	t.Helper()
	tmpl, err := ParseTemplate(`
meta: {id: and-function-provenance, severity: HIGH}
query:
  from: ` + scope + `
  and:
    - label: first site
      select: delegatecall
      where: [{arg.0: {tainted: parameter}}]
    - label: second site
      select: state_write
`)
	if err != nil {
		t.Fatalf("ParseTemplate: %v", err)
	}
	return tmpl
}

func mustParseContractAndProvenanceTemplate(t *testing.T, scope string) *Template {
	t.Helper()
	tmpl, err := ParseTemplate(`
meta: {id: and-contract-provenance, severity: HIGH}
query:
  from: ` + scope + `
  and:
    - label: first site
      select: require
    - label: second site
      select: lowlevel_call
`)
	if err != nil {
		t.Fatalf("ParseTemplate: %v", err)
	}
	return tmpl
}

func buildCompositionScopeDatabase(t *testing.T) (*types.Database, map[string]string) {
	t.Helper()
	dir := t.TempDir()
	canonicalDir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatalf("canonicalize fixture directory: %v", err)
	}
	dir = canonicalDir
	files := map[string]string{
		"base/Correct.sol": `pragma solidity ^0.8.0;
contract RepeatedBase {
	function firstSite(uint256 value) public { require(value > 0, "first"); }
}
`,
		"duplicate/Wrong.sol": `pragma solidity ^0.8.0;
contract RepeatedBase {
    function wrongSite(uint256 value) public { require(value == 0, "wrong"); }
}
`,
		"Derived.sol": `pragma solidity ^0.8.0;
import {RepeatedBase} from "./base/Correct.sol";
contract DerivedJoin is RepeatedBase {
    function secondSite(address target) public { target.call(""); }
}
contract SafeMain is RepeatedBase {}
`,
		"Plain.sol": `pragma solidity ^0.8.0;
contract PlainJoin {
    function firstSite(uint256 value) public { require(value > 0, "first"); }
    function secondSite(address target) public { target.call(""); }
}
contract SafeContract {
    function firstSite(uint256 value) public { require(value > 0, "first"); }
}
`,
		"Library.sol": `pragma solidity ^0.8.0;
library LibraryJoin {
    function firstSite(uint256 value) public { require(value > 0, "first"); }
    function secondSite(address target) public { target.call(""); }
}
library SafeLibrary {
    function firstSite(uint256 value) public { require(value > 0, "first"); }
}
`,
		"Abstract.sol": `pragma solidity ^0.8.0;
abstract contract AbstractJoin {
    function firstSite(uint256 value) public { require(value > 0, "first"); }
    function secondSite(address target) public { target.call(""); }
}
abstract contract SafeAbstract {
    function firstSite(uint256 value) public { require(value > 0, "first"); }
}
`,
	}
	for name, content := range files {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", name, err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	rdr := reader.New()
	sources, err := rdr.Read(dir)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	db, err := builder.New().Build(sources)
	if err != nil {
		t.Fatalf("build fixture: %v", err)
	}
	paths := map[string]string{
		"correct":  filepath.Join(dir, "base/Correct.sol"),
		"wrong":    filepath.Join(dir, "duplicate/Wrong.sol"),
		"derived":  filepath.Join(dir, "Derived.sol"),
		"contract": filepath.Join(dir, "Plain.sol"),
		"library":  filepath.Join(dir, "Library.sol"),
		"abstract": filepath.Join(dir, "Abstract.sol"),
	}
	return db, paths
}

func buildInheritedIdentityDatabase(t *testing.T) (*types.Database, map[string]string) {
	t.Helper()
	dir := t.TempDir()
	canonicalDir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatalf("canonicalize fixture directory: %v", err)
	}
	dir = canonicalDir
	files := map[string]string{
		"base/Correct.sol": `pragma solidity ^0.8.0;
contract RepeatedBase {
    function inheritedRun(address target, bytes memory data) public {
        target.delegatecall(data);
    }
}
`,
		"duplicate/Wrong.sol": `pragma solidity ^0.8.0;
contract RepeatedBase {
    function inheritedRun(address target, bytes memory data) public pure returns (bytes memory) {
        target;
        return data;
    }
}
`,
		"Derived.sol": `pragma solidity ^0.8.0;
import {RepeatedBase} from "./base/Correct.sol";
contract DerivedIdentity is RepeatedBase {}
`,
	}
	for name, content := range files {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", name, err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	rdr := reader.New()
	sources, err := rdr.Read(dir)
	if err != nil {
		t.Fatalf("read inherited identity fixture: %v", err)
	}
	db, err := builder.New().Build(sources)
	if err != nil {
		t.Fatalf("build inherited identity fixture: %v", err)
	}
	return db, map[string]string{
		"base":      filepath.Join(dir, "base/Correct.sol"),
		"duplicate": filepath.Join(dir, "duplicate/Wrong.sol"),
		"derived":   filepath.Join(dir, "Derived.sol"),
	}
}

func mustContractByName(t *testing.T, db *types.Database, name string) *types.Contract {
	t.Helper()
	var found *types.Contract
	for _, contract := range db.Contracts {
		if contract != nil && contract.Name == name {
			if found != nil {
				t.Fatalf("contract name %q is ambiguous", name)
			}
			found = contract
		}
	}
	if found == nil {
		t.Fatalf("contract %q not found", name)
	}
	return found
}

func mustContractByExactFile(t *testing.T, db *types.Database, file, name string) *types.Contract {
	t.Helper()
	contract := db.GetContractByID(types.MakeContractID(file, name))
	if contract == nil {
		t.Fatalf("contract %s#%s not found", file, name)
	}
	return contract
}

func mustFunctionByName(t *testing.T, contract *types.Contract, name string) *types.Function {
	t.Helper()
	for _, fn := range contract.Functions {
		if fn != nil && fn.Name == name {
			return fn
		}
	}
	t.Fatalf("function %s.%s not found", contract.Name, name)
	return nil
}

func mustASTNode(t *testing.T, root *types.ASTNode, kind string) *types.ASTNode {
	t.Helper()
	var found *types.ASTNode
	if root != nil && root.Kind == kind {
		found = root
	}
	if root != nil && found == nil {
		root.WalkDescendants(func(node *types.ASTNode) bool {
			if node.Kind == kind {
				found = node
				return false
			}
			return true
		})
	}
	if found == nil {
		t.Fatalf("AST node kind %q not found", kind)
	}
	return found
}

func assertFindingMatchesOneOfNodes(t *testing.T, finding *Finding, nodes ...*types.ASTNode) {
	t.Helper()
	for _, node := range nodes {
		if finding.PrimaryAST != nil && finding.PrimaryAST.StartByte == node.StartByte {
			assertFindingMatchesNode(t, finding, node)
			return
		}
	}
	t.Fatalf("finding primary = %+v, want one of %+v", finding.PrimaryAST, nodes)
}

func assertFindingMatchesNode(t *testing.T, finding *Finding, node *types.ASTNode) {
	t.Helper()
	if finding.PrimaryAST == nil {
		t.Fatal("missing primary AST")
	}
	if finding.PrimaryAST.Kind != node.Kind || finding.PrimaryAST.Name != node.Name ||
		finding.PrimaryAST.StartByte != node.StartByte || finding.PrimaryAST.EndByte != node.EndByte {
		t.Fatalf("PrimaryAST = %+v, want %s %q bytes [%d,%d)", finding.PrimaryAST, node.Kind, node.Name, node.StartByte, node.EndByte)
	}
	if finding.Location.StartByte != node.StartByte || finding.Location.EndByte != node.EndByte {
		t.Fatalf("Location = %+v, want bytes [%d,%d)", finding.Location, node.StartByte, node.EndByte)
	}
}

func assertFindingExactOwnedNode(t *testing.T, finding *Finding, file, contract, function string, node *types.ASTNode) {
	t.Helper()
	assertFindingMatchesNode(t, finding, node)
	if finding.Location.File != file || finding.Location.Contract != contract || finding.Location.Function != function {
		t.Fatalf("Location owner = %+v, want %s %s.%s", finding.Location, file, contract, function)
	}
}

func findingByEntryPoint(t *testing.T, findings []*Finding, entryPoint string) *Finding {
	t.Helper()
	for _, finding := range findings {
		if finding.EntryPoint != nil && finding.EntryPoint.Function == entryPoint {
			return finding
		}
	}
	t.Fatalf("finding with entry point %q not found: %+v", entryPoint, findings)
	return nil
}

func findingByExactContractFile(t *testing.T, findings []*Finding, file, contract string) *Finding {
	t.Helper()
	for _, finding := range findings {
		if finding.Location.File == file && finding.Location.Contract == contract {
			return finding
		}
	}
	t.Fatalf("finding for %s#%s not found: %+v", file, contract, findings)
	return nil
}

func findingByRelatedExactSite(t *testing.T, findings []*Finding, file, function string) *Finding {
	t.Helper()
	for _, finding := range findings {
		for _, related := range finding.Related {
			if related.File == file && related.Function == function {
				return finding
			}
		}
	}
	t.Fatalf("finding with related site %s:%s not found: %+v", file, function, findings)
	return nil
}

func assertJoinFindingProvenance(t *testing.T, finding *Finding, expected []expectedRelatedNode) {
	t.Helper()
	if finding.PrimaryAST == nil {
		t.Fatal("missing primary AST")
	}
	labels := make(map[string]bool, len(finding.Related))
	for _, related := range finding.Related {
		labels[related.Label] = true
	}
	if !labels["first site"] || !labels["second site"] {
		t.Fatalf("Related = %+v", finding.Related)
	}
	for _, want := range expected {
		var got *RelatedLocation
		for i := range finding.Related {
			candidate := &finding.Related[i]
			if candidate.Label == want.label && candidate.File == want.file && candidate.Function == want.function {
				got = candidate
				break
			}
		}
		if got == nil {
			t.Fatalf("related site %q at %s %s.%s missing: %+v", want.label, want.file, want.contract, want.function, finding.Related)
		}
		if got.Contract != want.contract || got.Kind != want.node.Kind || got.Name != want.node.Name || got.Line != want.node.StartLine {
			t.Fatalf("related site = %+v, want %s %s.%s %s %q line %d", *got, want.file, want.contract, want.function, want.node.Kind, want.node.Name, want.node.StartLine)
		}
		assertRelatedJSONSpan(t, *got, want.node)
	}
}

func assertRelatedJSONSpan(t *testing.T, related RelatedLocation, node *types.ASTNode) {
	t.Helper()
	data, err := json.Marshal(related)
	if err != nil {
		t.Fatalf("marshal related: %v", err)
	}
	var fields map[string]any
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Fatalf("unmarshal related: %v", err)
	}
	wants := map[string]int{
		"col":       node.StartCol,
		"endLine":   node.EndLine,
		"endCol":    node.EndCol,
		"startByte": node.StartByte,
		"endByte":   node.EndByte,
	}
	for key, want := range wants {
		got, ok := fields[key].(float64)
		if !ok || int(got) != want {
			t.Fatalf("related JSON %s = %v, want %d; related = %s", key, fields[key], want, data)
		}
	}
}
