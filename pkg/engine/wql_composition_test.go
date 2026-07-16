package engine

import (
	"encoding/json"
	"strings"
	"testing"
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
			name: "or branch without select or from",
			yaml: `
meta: {id: T, severity: HIGH}
query:
  or:
    - {where: [{name: transfer}]}
    - {select: state_write, from: entry_function}
`,
			want: "neither select nor from",
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

// ---------------------------------------------------------------------------
// and: lowering — one QueryBlock, all: of labeled branches at the join scope.
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
	if tmpl.Queries[0].Filter == nil || tmpl.Queries[0].Filter.Preset != "unAuthenticated" {
		t.Errorf("Queries[0].Filter = %+v, want Preset=unAuthenticated", tmpl.Queries[0].Filter)
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

func TestWhereAndAliasLowersLikeAll(t *testing.T) {
	viaAnd, err := ParseTemplate(`
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
	viaAll, err := ParseTemplate(`
meta: {id: T, severity: HIGH}
query:
  select: external_call
  from: entry_function
  where:
    - all: [{name: transfer}, {arg.0: {tainted: parameter}}]
`)
	if err != nil {
		t.Fatalf("ParseTemplate(all:): %v", err)
	}
	if len(viaAnd.Query.Match.Contains.All) != len(viaAll.Query.Match.Contains.All) {
		t.Fatalf("and: alias lowered differently: %+v vs %+v", viaAnd.Query.Match, viaAll.Query.Match)
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
			want: "neither select nor from",
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
