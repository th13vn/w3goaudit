package engine

import (
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/th13vn/w3goaudit/pkg/builder"
	"github.com/th13vn/w3goaudit/pkg/reader"
	"github.com/th13vn/w3goaudit/pkg/types"
)

func TestInterproceduralTaintForInternalTransferFrom(t *testing.T) {
	root := repoRoot(t)
	rdr := reader.New()
	sources, err := rdr.Read(filepath.Join(root, "test-data/security/arbitrary-transferfrom.sol"))
	if err != nil {
		t.Fatalf("read sources: %v", err)
	}
	db, err := builder.New().Build(sources)
	if err != nil {
		t.Fatalf("build db: %v", err)
	}
	tmpl, err := LoadTemplate(filepath.Join(root, "templates/official/high/arbitrary-transferfrom.yaml"))
	if err != nil {
		t.Fatalf("load template: %v", err)
	}

	findings := New(db).Execute(tmpl)
	got := make([]string, 0, len(findings))
	for _, finding := range findings {
		got = append(got, finding.Location.Contract+"."+finding.Location.Function)
	}
	sort.Strings(got)

	want := []string{
		"VulnerableAliasForward.depositFrom",
		"VulnerableAliasReassignmentForward.depositFrom",
		"VulnerableArrayElementForward.deposit",
		"VulnerableBatchDeposit.batchDeposit",
		"VulnerableConditionalForward.depositFrom",
		"VulnerableDeposit.deposit",
		"VulnerableInternalForward.depositFrom",
		"VulnerableNestedForward.depositFrom",
		"VulnerableNoAuth.withdrawFrom",
		"VulnerableReturnHelperForward.depositFrom",
		"VulnerableShadowedAliasForward.deposit",
		"VulnerableStructForward.deposit",
		"VulnerableStaking.stake",
		"VulnerableStructArrayForward.depositBatch",
		"VulnerableSwap.swap",
		"VulnerableSwappedArgsForward.depositFrom",
	}
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected findings:\n got: %v\nwant: %v", got, want)
	}
}

func TestFindingLocationsUseExactFunctionIDSourceFile(t *testing.T) {
	root := repoRoot(t)
	rdr := reader.New()
	// pkg-a/ and pkg-b/ each ship a tx-origin.sol whose basename collides but
	// whose full path differs, and both define a contract literally named
	// Vulnerable_TxOrigin. Read both explicitly so the test exercises the
	// colliding-basename case.
	sources, err := rdr.ReadFiles([]string{
		filepath.Join(root, "test-data/core/engine-features/path-collision/pkg-a/tx-origin.sol"),
		filepath.Join(root, "test-data/core/engine-features/path-collision/pkg-b/tx-origin.sol"),
	})
	if err != nil {
		t.Fatalf("read sources: %v", err)
	}
	db, err := builder.New().Build(sources)
	if err != nil {
		t.Fatalf("build db: %v", err)
	}
	tmpl, err := LoadTemplate(filepath.Join(root, "templates/official/medium/tx-origin-auth.yaml"))
	if err != nil {
		t.Fatalf("load template: %v", err)
	}

	// Two findings should come back, each with a *distinct full path* so
	// downstream consumers can tell them apart even though the basenames
	// collide. Indexing the seen set by directory (pkg-a vs pkg-b) verifies
	// that both fixtures were reached AND that the Location.File carries the
	// real path, not just the basename.
	seen := make(map[string]bool)
	for _, finding := range New(db).Execute(tmpl) {
		if finding.Location.Contract != "Vulnerable_TxOrigin" {
			continue
		}
		if !strings.HasSuffix(finding.Location.File, ".sol") {
			t.Fatalf("expected Solidity source file location, got %q", finding.Location.File)
		}
		dir := filepath.Base(filepath.Dir(finding.Location.File))
		seen[dir] = true
	}

	want := map[string]bool{
		"pkg-a": true,
		"pkg-b": true,
	}
	if !reflect.DeepEqual(seen, want) {
		t.Fatalf("expected Vulnerable_TxOrigin findings from both subdirs (distinct full paths)\n got: %v\nwant: %v", seen, want)
	}
}

func TestTypeCastsDoNotCreateReentrancyFindings(t *testing.T) {
	root := repoRoot(t)
	rdr := reader.New()
	// The fixture pairs the two safe guards (address-zero and mint/burn-zero)
	// whose `require(x != address(0))` casts previously tripped a false
	// reentrancy match.
	sources, err := rdr.Read(filepath.Join(root, "test-data/core/engine-features/type-cast-guards.sol"))
	if err != nil {
		t.Fatalf("read sources: %v", err)
	}
	db, err := builder.New().Build(sources)
	if err != nil {
		t.Fatalf("build db: %v", err)
	}
	tmpl, err := LoadTemplate(filepath.Join(root, "templates/official/high/reentrancy-pattern.yaml"))
	if err != nil {
		t.Fatalf("load template: %v", err)
	}

	for _, finding := range New(db).Execute(tmpl) {
		switch finding.Location.Contract {
		case "Safe_AddressZeroCheck", "Safe_MintBurnZero":
			t.Fatalf("type casts in guards must not be treated as outgoing calls: %+v", finding.Location)
		}
	}
}

func TestInterproceduralSequenceFindsCallsInsideInternalHelpers(t *testing.T) {
	root := repoRoot(t)
	rdr := reader.New()
	sources, err := rdr.Read(filepath.Join(root, "test-data/security/reentrancy-simple.sol"))
	if err != nil {
		t.Fatalf("read sources: %v", err)
	}
	db, err := builder.New().Build(sources)
	if err != nil {
		t.Fatalf("build db: %v", err)
	}
	tmpl, err := LoadTemplate(filepath.Join(root, "templates/official/high/reentrancy-pattern.yaml"))
	if err != nil {
		t.Fatalf("load template: %v", err)
	}

	findings := New(db).Execute(tmpl)
	got := make([]string, 0, len(findings))
	for _, finding := range findings {
		got = append(got, finding.Location.Contract+"."+finding.Location.Function)
	}
	sort.Strings(got)

	want := []string{
		"DeepRecursive.withdraw",
		"DirectCall.withdraw",
		"NestedBlock.withdraw",
		"RecursiveCall.withdraw",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected reentrancy findings:\n got: %v\nwant: %v", got, want)
	}
}

func TestInterproceduralSequenceExecutionOrder(t *testing.T) {
	src := `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface ISequenceInputs {
    function optionValue() external returns (uint256);
    function argumentValue() external returns (uint256);
}

contract InterproceduralOrder {
    uint256 private stored;
    ISequenceInputs private inputs;

    function run() external {
        this.helper{value: inputs.optionValue()}(inputs.argumentValue());
    }

    function helper(uint256 value) external payable {
        stored = value;
    }
}
`
	db := buildDBFromSource(t, src).GetDatabase()
	contract := db.GetContractByName("InterproceduralOrder")
	if contract == nil {
		t.Fatal("InterproceduralOrder not found")
	}
	var run *types.Function
	for _, fn := range contract.Functions {
		if fn.Name == "run" {
			run = fn
			break
		}
	}
	if run == nil {
		t.Fatal("run function not found")
	}

	call := func(name string) Rule {
		return Rule{Kind: types.KindCallExternal, Name: "^" + name + "$"}
	}
	write := Rule{Kind: "state_write"}
	cases := []struct {
		name  string
		rules []Rule
		want  bool
	}{
		{
			name:  "option before outer call and callee write",
			rules: []Rule{call("optionValue"), call("helper"), write},
			want:  true,
		},
		{
			name:  "argument before outer call and callee write",
			rules: []Rule{call("argumentValue"), call("helper"), write},
			want:  true,
		},
		{
			name:  "pre-call siblings may execute option then argument",
			rules: []Rule{call("optionValue"), call("argumentValue"), call("helper"), write},
			want:  true,
		},
		{
			name:  "pre-call siblings may execute argument then option",
			rules: []Rule{call("argumentValue"), call("optionValue"), call("helper"), write},
			want:  true,
		},
		{
			name:  "outer call cannot precede option",
			rules: []Rule{call("helper"), call("optionValue")},
			want:  false,
		},
		{
			name:  "callee write cannot precede argument",
			rules: []Rule{write, call("argumentValue")},
			want:  false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := New(db).VerifyAtFunctionWithCallees(run, Rule{Sequence: tc.rules}, contract)
			if got != tc.want {
				t.Fatalf("VerifyAtFunctionWithCallees(sequence) = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestArgAnyInterproceduralSequenceUsesContextSensitiveRouting(t *testing.T) {
	src := `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract ArgAnySequence {
    address private last;

    function safe() external {
        helper(address(this));
    }

    function vulnerable(address recipient) external {
        helper(recipient);
    }

    function helper(address recipient) internal {
        sink(recipient);
        last = recipient;
    }

    function sink(address) internal pure {}
}
`
	tmpl, err := ParseTemplate(`
meta: {id: T, severity: HIGH}
query:
  from: entry_function
  where:
    - sequence:
        - block: internal_call
          name: ^sink$
          arg.any: {tainted: user_controlled}
        - block: state_write
`)
	if err != nil {
		t.Fatalf("ParseTemplate: %v", err)
	}

	db := buildDBFromSource(t, src).GetDatabase()
	findings := New(db).Execute(tmpl)
	got := make([]string, 0, len(findings))
	for _, finding := range findings {
		got = append(got, finding.Location.Function)
	}
	sort.Strings(got)
	want := []string{"vulnerable"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("entrypoint findings = %v, want %v", got, want)
	}
}

func TestUncheckedArithmeticTemplateSeesUncheckedBlocks(t *testing.T) {
	root := repoRoot(t)
	rdr := reader.New()
	sources, err := rdr.Read(filepath.Join(root, "test-data/security/unchecked-arithmetic.sol"))
	if err != nil {
		t.Fatalf("read sources: %v", err)
	}
	db, err := builder.New().Build(sources)
	if err != nil {
		t.Fatalf("build db: %v", err)
	}
	tmpl, err := LoadTemplate(filepath.Join(root, "templates/official/medium/unchecked-arithmetic.yaml"))
	if err != nil {
		t.Fatalf("load template: %v", err)
	}

	findings := New(db).Execute(tmpl)
	got := make([]string, 0, len(findings))
	for _, finding := range findings {
		got = append(got, finding.Location.Contract+"."+finding.Location.Function)
	}
	sort.Strings(got)

	// Safe_GuardedUncheckedSub.withdrawAll is intentionally ABSENT: its
	// `require(bal >= amount)` is an ordering bound over both operands of
	// `bal - amount`, so the `unchecked_var:` predicate excludes it.
	// Vulnerable_NonOrderingGuard.pay IS flagged: `require(bal != amount)`
	// references both operands but is not an ordering bound. incrementSmall stays
	// flagged because its `require(amount <= 100)` bounds only one operand of
	// `balances[user] + amount`.
	want := []string{
		"Safe_BoundedUncheckedArithmetic.incrementSmall",
		"UncheckedSubtractionGuardMatrix.dominatedArmEffectfulSibling",
		"UncheckedSubtractionGuardMatrix.dominatedArmExternalEffectfulSibling",
		"UncheckedSubtractionGuardMatrix.requireEffectfulSibling",
		"UncheckedSubtractionGuardMatrix.reversedRequire",
		"UncheckedSubtractionGuardMatrix.unrelatedOrdering",
		"Vulnerable_NonOrderingGuard.pay",
		"Vulnerable_UncheckedArithmetic.credit",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected unchecked arithmetic findings:\n got: %v\nwant: %v", got, want)
	}
}

// TestTaintFixpointPropagatesLoopCarriedAlias proves the dataflow fixpoint.
// `a = b` is written before `b = from`, so a single forward pass leaves `a`
// untainted by the parameter. Because the assignments sit in a loop, b's
// parameter taint reaches a on the next iteration — the bounded fixpoint in
// buildFunctionTaintEnv must converge to env[a] carrying "parameter".
func TestTaintFixpointPropagatesLoopCarriedAlias(t *testing.T) {
	src := `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract LoopCarried {
    function f(address from) public pure returns (address) {
        address a;
        address b;
        for (uint256 i = 0; i < 2; i++) {
            a = b;
            b = from;
        }
        return a;
    }
}
`
	dir := t.TempDir()
	path := filepath.Join(dir, "loop_carried.sol")
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	sources, err := reader.New().Read(path)
	if err != nil {
		t.Fatalf("read sources: %v", err)
	}
	db, err := builder.New().Build(sources)
	if err != nil {
		t.Fatalf("build db: %v", err)
	}
	c := db.GetContractByName("LoopCarried")
	if c == nil {
		t.Fatal("LoopCarried not found")
	}
	var env map[string][]string
	for _, fn := range c.Functions {
		if fn.Name == "f" {
			env = New(db).buildFunctionTaintEnv(fn, nil)
		}
	}
	if env == nil {
		t.Fatal("function f not found")
	}
	found := false
	for _, s := range env["a"] {
		if s == "parameter" {
			found = true
		}
	}
	if !found {
		t.Fatalf("fixpoint should taint `a` from the parameter via the loop-carried alias; env[a] = %v", env["a"])
	}
}

// TestSequenceRespectsTryCatchArms proves the try/catch CFG-awareness upgrade.
// The body of a try and a catch clause can never both execute, so a
// `sequence: [state_write, outgoing_call]` must NOT match when the write is in
// the body and the call is in the catch (function f) — but MUST match when both
// land in the same arm (function g). The sequence starts with state_write so the
// always-executing try expression (an outgoing_call positioned before the body)
// cannot mask the arm check.
func TestSequenceRespectsTryCatchArms(t *testing.T) {
	src := `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IExt { function a() external; function b() external; }

contract TryCatchSeq {
    uint256 public state;
    IExt ext;

    // write in body, external call in catch -> mutually exclusive arms.
    function f() public {
        try ext.a() {
            state = 1;
        } catch {
            ext.b();
        }
    }

    // write then external call both in the body -> same arm.
    function g() public {
        try ext.a() {
            state = 1;
            ext.b();
        } catch {}
    }
}
`
	dir := t.TempDir()
	solPath := filepath.Join(dir, "trycatch_seq.sol")
	if err := os.WriteFile(solPath, []byte(src), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	sources, err := reader.New().Read(solPath)
	if err != nil {
		t.Fatalf("read sources: %v", err)
	}
	db, err := builder.New().Build(sources)
	if err != nil {
		t.Fatalf("build db: %v", err)
	}
	loaded := &Template{
		Meta: TemplateMeta{
			ID:         "TEST-TRYCATCH-SEQ",
			Title:      "try/catch sequence arm test",
			Severity:   "LOW",
			Confidence: "LOW",
		},
		Query: QueryBlock{
			Scope: ScopeFunction,
			Match: Rule{Sequence: []Rule{
				{Kind: "state_write"},
				{Kind: "outgoing_call"},
			}},
		},
	}
	if err := finalizeTemplate(loaded, "try/catch evaluator IR test"); err != nil {
		t.Fatalf("finalize evaluator IR: %v", err)
	}
	findings := New(db).Execute(loaded)
	hit := map[string]bool{}
	for _, f := range findings {
		hit[f.Location.Function] = true
	}
	if hit["f"] {
		t.Errorf("f must NOT match: state_write (body) and outgoing_call (catch) are mutually exclusive arms")
	}
	if !hit["g"] {
		t.Errorf("g must match: state_write and outgoing_call are in the same try body")
	}
}

func TestResolveInternalCalleeUsesExactRecordedSelectorForResolvedCallTypes(t *testing.T) {
	db := types.NewDatabase()
	wrong := &types.Function{Name: "helper", Selector: "helper(address)", Parameters: []*types.Parameter{{TypeName: "address"}}}
	want := &types.Function{Name: "helper", Selector: "helper(uint256)", Parameters: []*types.Parameter{{TypeName: "uint256"}}}
	base := &types.Contract{Name: "Base", SourceFile: "/repo/Base.sol", Functions: []*types.Function{wrong, want}}
	derived := &types.Contract{Name: "Derived", SourceFile: "/repo/Derived.sol"}
	db.AddContract(base)
	db.AddContract(derived)
	derived.LinearizedBaseIDs = []string{derived.ID, base.ID}

	callTypes := []types.CallType{
		types.CallTypeInternal,
		types.CallTypeInherited,
		types.CallTypeSelf,
		types.CallTypeSuper,
		types.CallTypeLibrary,
	}
	for i, callType := range callTypes {
		t.Run(string(callType), func(t *testing.T) {
			byteOffset := 100 + i*20
			call := &types.FunctionCall{
				Target:             "helper",
				ResolvedContract:   base.Name,
				ResolvedContractID: base.ID,
				ResolvedFunction:   want.Selector,
				CallType:           callType,
				Line:               8,
				Col:                9 + i,
				Byte:               byteOffset,
				Resolved:           true,
				ArgCount:           1,
			}
			node := locatedNode(types.KindCallInternal, "helper", 8, 9+i, 8, 20+i, byteOffset, byteOffset+6)
			node.AddChild(types.NewASTNode(types.KindExprLiteral))
			e := New(db)
			e.currentFunction = &types.Function{Name: "run", Calls: []*types.FunctionCall{call}}
			got, owner := e.resolveInternalCallee(derived, node)
			if got != want || owner != base {
				t.Fatalf("resolved %s call = (%p, %p), want exact selector (%p, %p)", callType, got, owner, want, base)
			}
		})
	}

	t.Run("resolved internal target outside runtime MRO fails closed", func(t *testing.T) {
		unrelated := &types.Contract{Name: "Unrelated", SourceFile: "/repo/Unrelated.sol", Functions: []*types.Function{want}}
		db.AddContract(unrelated)
		call := &types.FunctionCall{
			Target:             "helper",
			ResolvedContractID: unrelated.ID,
			ResolvedFunction:   want.Selector,
			CallType:           types.CallTypeInternal,
			Line:               20,
			Col:                4,
			Byte:               240,
			Resolved:           true,
			ArgCount:           1,
		}
		node := locatedNode(types.KindCallInternal, "helper", 20, 4, 20, 12, 240, 248)
		node.AddChild(types.NewASTNode(types.KindExprLiteral))
		e := New(db)
		e.currentFunction = &types.Function{Calls: []*types.FunctionCall{call}}
		if got, owner := e.resolveInternalCallee(derived, node); got != nil || owner != nil {
			t.Fatalf("resolved out-of-MRO call = (%p, %p), want nil", got, owner)
		}
	})

	t.Run("ambiguous super metadata without exact host fails closed", func(t *testing.T) {
		db := types.NewDatabase()
		baseFn := &types.Function{Name: "helper", Selector: "helper(uint256)", Parameters: []*types.Parameter{{TypeName: "uint256"}}}
		grandFn := &types.Function{Name: "helper", Selector: "helper(uint256)", Parameters: []*types.Parameter{{TypeName: "uint256"}}}
		grand := &types.Contract{Name: "Grand", SourceFile: "/repo/Grand.sol", Functions: []*types.Function{grandFn}}
		base := &types.Contract{Name: "Base", SourceFile: "/repo/Base.sol", Functions: []*types.Function{baseFn}}
		derived := &types.Contract{Name: "Derived", SourceFile: "/repo/Derived.sol"}
		db.AddContract(grand)
		db.AddContract(base)
		db.AddContract(derived)
		derived.LinearizedBaseIDs = []string{derived.ID, base.ID, grand.ID}
		calls := []*types.FunctionCall{
			{Target: "helper", ResolvedContractID: base.ID, ResolvedFunction: baseFn.Selector, CallType: types.CallTypeSuper, Line: 30, Col: 5, Byte: 300, Resolved: true, ArgCount: 1},
			{Target: "helper", ResolvedContractID: grand.ID, ResolvedFunction: grandFn.Selector, CallType: types.CallTypeSuper, Line: 30, Col: 5, Byte: 300, Resolved: true, ArgCount: 1},
		}
		node := locatedNode(types.KindCallInternal, "helper", 30, 5, 30, 12, 300, 307)
		node.AddChild(types.NewASTNode(types.KindExprLiteral))
		e := New(db)
		e.currentFunction = &types.Function{Name: "run", Calls: calls}
		if got, owner := e.resolveInternalCallee(derived, node); got != nil || owner != nil {
			t.Fatalf("ambiguous host-less super metadata = (%p, %p), want nil", got, owner)
		}
	})
}

func TestResolveInternalCalleeLegacyFallbackRequiresUniqueSelectorAndArity(t *testing.T) {
	newCall := func(argCount int) *types.ASTNode {
		node := types.NewASTNode(types.KindCallInternal)
		node.Name = "helper"
		for i := 0; i < argCount; i++ {
			node.AddChild(types.NewASTNode(types.KindExprLiteral))
		}
		return node
	}

	t.Run("same-arity overload ambiguity", func(t *testing.T) {
		db := types.NewDatabase()
		contract := &types.Contract{Name: "C", SourceFile: "/repo/C.sol", Functions: []*types.Function{
			{Name: "helper", Selector: "helper(address)", Parameters: []*types.Parameter{{TypeName: "address"}}},
			{Name: "helper", Selector: "helper(uint256)", Parameters: []*types.Parameter{{TypeName: "uint256"}}},
		}}
		db.AddContract(contract)
		contract.LinearizedBaseIDs = []string{contract.ID}
		if got, owner := New(db).resolveInternalCallee(contract, newCall(1)); got != nil || owner != nil {
			t.Fatalf("ambiguous fallback = (%p, %p), want nil", got, owner)
		}
	})

	t.Run("arity mismatch", func(t *testing.T) {
		db := types.NewDatabase()
		contract := &types.Contract{Name: "C", SourceFile: "/repo/C.sol", Functions: []*types.Function{
			{Name: "helper", Selector: "helper(address)", Parameters: []*types.Parameter{{TypeName: "address"}}},
		}}
		db.AddContract(contract)
		contract.LinearizedBaseIDs = []string{contract.ID}
		if got, owner := New(db).resolveInternalCallee(contract, newCall(2)); got != nil || owner != nil {
			t.Fatalf("arity-mismatch fallback = (%p, %p), want nil", got, owner)
		}
	})

	t.Run("missing exact metadata uses unique compatibility fallback", func(t *testing.T) {
		db := types.NewDatabase()
		fn := &types.Function{Name: "helper", Selector: "helper(address)", Parameters: []*types.Parameter{{TypeName: "address"}}}
		contract := &types.Contract{Name: "C", SourceFile: "/repo/C.sol", Functions: []*types.Function{fn}}
		db.AddContract(contract)
		contract.LinearizedBaseIDs = []string{contract.ID}
		call := &types.FunctionCall{Target: "helper", CallType: types.CallTypeInternal, Line: 4, Col: 3, Byte: 40, Resolved: true, ArgCount: 1}
		node := newCall(1)
		node.StartLine, node.StartCol, node.StartByte = 4, 3, 40
		e := New(db)
		e.currentFunction = &types.Function{Calls: []*types.FunctionCall{call}}
		if got, owner := e.resolveInternalCallee(contract, node); got != fn || owner != contract {
			t.Fatalf("incomplete resolved metadata fallback = (%p, %p), want unique candidate (%p, %p)", got, owner, fn, contract)
		}
	})

	t.Run("override selector is one runtime candidate", func(t *testing.T) {
		db := types.NewDatabase()
		baseFn := &types.Function{Name: "helper", Selector: "helper(address)", Parameters: []*types.Parameter{{TypeName: "address"}}}
		derivedFn := &types.Function{Name: "helper", Selector: "helper(address)", Parameters: []*types.Parameter{{TypeName: "address"}}}
		base := &types.Contract{Name: "Base", SourceFile: "/repo/Base.sol", Functions: []*types.Function{baseFn}}
		derived := &types.Contract{Name: "Derived", SourceFile: "/repo/Derived.sol", Functions: []*types.Function{derivedFn}}
		db.AddContract(base)
		db.AddContract(derived)
		derived.LinearizedBaseIDs = []string{derived.ID, base.ID}
		if got, owner := New(db).resolveInternalCallee(derived, newCall(1)); got != derivedFn || owner != derived {
			t.Fatalf("override fallback = (%p, %p), want derived implementation (%p, %p)", got, owner, derivedFn, derived)
		}
	})
}

func TestNestedSameArityOverloadTraversalUsesExactCallerMetadata(t *testing.T) {
	const src = `pragma solidity ^0.8.20;
contract NestedOverloadTraversal {
    uint256 private state;

    function entry(address target, bytes memory data) external {
        dispatch(target, data);
    }

    function dispatch(address target, bytes memory data) internal {
        helper(target, data);
    }

    function helper(address target, bytes memory data) internal {
        target.call(data);
        state = 1;
    }

    function helper(uint256 amount, bytes memory data) internal {
        state = amount;
        data;
    }
}`
	db := buildDBFromSource(t, src).GetDatabase()
	contract := mustContractByName(t, db, "NestedOverloadTraversal")
	entry := mustFunctionByName(t, contract, "entry")

	taintRule := Rule{Contains: &Rule{
		Kind:     types.KindCallLowlevelCall,
		Contains: &Rule{TaintedFrom: "parameter"},
	}}
	if !New(db).VerifyAtFunctionWithCallees(entry, taintRule, contract) {
		t.Fatal("VerifyAtFunctionWithCallees did not follow the exact nested helper(address,bytes) overload")
	}

	sequenceRule := Rule{Sequence: []Rule{
		{Kind: types.KindCallLowlevelCall},
		{Kind: "state_write"},
	}}
	if !New(db).VerifyAtFunction(entry, sequenceRule, contract) {
		t.Fatal("nested interprocedural sequence did not follow exact same-arity overload metadata")
	}

	tmpl := &Template{
		Meta:  TemplateMeta{ID: "nested-overload", Severity: "HIGH"},
		Query: QueryBlock{Scope: ScopeEntrypoint, Match: taintRule},
	}
	findings := New(db).Execute(tmpl)
	var finding *Finding
	for _, candidate := range findings {
		if candidate.Location.Function == "entry" {
			finding = candidate
			break
		}
	}
	if finding == nil {
		t.Fatalf("entry finding missing: %+v", findings)
	}
	if finding.Reachability == nil || len(finding.Reachability.Steps) != 3 {
		t.Fatalf("reachability = %+v, want entry -> dispatch -> helper", finding.Reachability)
	}
}

func TestRealMemberCallTraversalUsesRecordedCallTypesAndSolidityArguments(t *testing.T) {
	const src = `pragma solidity ^0.8.20;
library TraverseLib {
    function libraryHop(address target, bytes memory data) internal {
        target.call(data);
    }
}

contract MemberBase {
    function inheritedHop(address target, bytes memory data) internal {
        target.call(data);
    }

    function superHop(address target, bytes memory data) internal virtual {
        target.call(data);
    }
}

contract MemberMid is MemberBase {
    function superHop(address target, bytes memory data) internal virtual override {
        super.superHop(target, data);
    }

    function selfHop(address target, bytes memory data) external {
        target.call(data);
    }
}

contract MemberLeaf is MemberMid {
    function viaInherited(address target, bytes memory data) external {
        inheritedHop(target, data);
    }

    function viaSelf(address target, bytes memory data) external {
        this.selfHop(target, data);
    }

    function viaSuper(address target, bytes memory data) external {
        superHop(target, data);
    }

    function viaLibrary(address target, bytes memory data) external {
        TraverseLib.libraryHop(target, data);
    }
}`
	db := buildDBFromSource(t, src).GetDatabase()
	leaf := mustContractByName(t, db, "MemberLeaf")
	rule := Rule{Contains: &Rule{
		Kind:     types.KindCallLowlevelCall,
		Contains: &Rule{TaintedFrom: "parameter"},
	}}

	wantDepth := map[string]int{
		"viaInherited": 2,
		"viaSelf":      2,
		"viaSuper":     3,
		"viaLibrary":   2,
	}
	for name := range wantDepth {
		fn := mustFunctionByName(t, leaf, name)
		if !New(db).VerifyAtFunctionWithCallees(fn, rule, leaf) {
			t.Errorf("VerifyAtFunctionWithCallees did not follow %s", name)
		}
	}

	tmpl := &Template{
		Meta:  TemplateMeta{ID: "member-traversal", Severity: "HIGH"},
		Query: QueryBlock{Scope: ScopeEntrypoint, Match: rule},
	}
	findings := New(db).Execute(tmpl)
	seen := make(map[string]*Finding)
	for _, finding := range findings {
		seen[finding.Location.Function] = finding
	}
	for name, depth := range wantDepth {
		finding := seen[name]
		if finding == nil {
			t.Errorf("missing end-to-end finding for %s; findings=%+v", name, findings)
			continue
		}
		if finding.Reachability == nil || len(finding.Reachability.Steps) != depth {
			t.Errorf("%s reachability = %+v, want %d steps", name, finding.Reachability, depth)
		}
	}
}

func TestInterproceduralSequenceInlinesReceiverAndOptionHelpersBeforeOuterCall(t *testing.T) {
	const source = `pragma solidity ^0.8.20;
interface PreludeSink { function ping() external; }
contract PreludeCalls {
    uint256 private stored;
    function receiverHelper(address target) internal returns (PreludeSink) { stored = 1; return PreludeSink(target); }
    function receiverHelper(uint160 target) internal returns (PreludeSink) { stored = 9; return PreludeSink(address(target)); }
    function optionHelper(address value) internal returns (uint256) { stored = 2; value; return gasleft(); }
    function optionHelper(uint160 value) internal returns (uint256) { stored = 8; value; return gasleft(); }
    function viaReceiver(address target) external { receiverHelper(target).ping(); }
    function viaOption(address target) external { PreludeSink(target).ping{gas: optionHelper(address(this))}(); }
}`
	db := buildDBFromSource(t, source).GetDatabase()
	contract := mustContractByName(t, db, "PreludeCalls")
	forward := Rule{Sequence: []Rule{
		{Kind: "state_write"},
		{Kind: types.KindCallExternal, Name: "^ping$"},
	}}
	reverse := Rule{Sequence: []Rule{
		{Kind: types.KindCallExternal, Name: "^ping$"},
		{Kind: "state_write"},
	}}
	for _, name := range []string{"viaReceiver", "viaOption"} {
		t.Run(name, func(t *testing.T) {
			fn := mustFunctionByName(t, contract, name)
			if !New(db).VerifyAtFunction(fn, forward, contract) {
				t.Fatalf("%s did not inline its nested helper operation before the outer ping call", name)
			}
			if New(db).VerifyAtFunction(fn, reverse, contract) {
				t.Fatalf("%s allowed the outer ping call before its nested helper operation", name)
			}
		})
	}
}

func TestInterproceduralSequencePreservesSelectedInlineOccurrenceReachability(t *testing.T) {
	const source = `pragma solidity ^0.8.20;
contract ReusedLeafSequence {
    uint256 private stored;

    function entry(address target) external {
        firstHop(target);
        stored = 1;
        secondHop(target);
    }

    function firstHop(address target) internal {
        leaf(target);
    }

    function secondHop(address target) internal {
        leaf(target);
    }

    function leaf(address target) internal {
        target.call("");
    }
}`
	db := buildDBFromSource(t, source).GetDatabase()
	tmpl := &Template{
		Meta: TemplateMeta{ID: "reused-leaf-sequence", Severity: "HIGH"},
		Query: QueryBlock{Scope: ScopeEntrypoint, Match: Rule{Sequence: []Rule{
			{Kind: "outgoing_call"},
			{Kind: "state_write"},
		}}},
	}
	if err := finalizeTemplate(tmpl, "reused leaf sequence test"); err != nil {
		t.Fatalf("finalizeTemplate: %v", err)
	}

	findings := New(db).Execute(tmpl)
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
	if findings[0].Reachability == nil {
		t.Fatal("reachability missing")
	}
	got := make([]string, 0, len(findings[0].Reachability.Steps))
	for _, step := range findings[0].Reachability.Steps {
		got = append(got, step.Function)
	}
	want := []string{"entry", "firstHop", "leaf"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("reachability = %v, want selected occurrence %v", got, want)
	}
}

func TestInterproceduralSequenceMatchesRepeatedInlineOutgoingCalls(t *testing.T) {
	const source = `pragma solidity ^0.8.20;
contract RepeatedInlineLeaf {
    function entry(address target) external {
        leaf(target);
        leaf(target);
    }

    function leaf(address target) internal {
        target.call("");
    }
}`
	db := buildDBFromSource(t, source).GetDatabase()
	tmpl, err := ParseTemplate(`
meta: {id: repeated-inline-outgoing, severity: HIGH}
query:
  from: entry_function
  where:
    - sequence:
        - {block: outgoing_call}
        - {block: outgoing_call}
`)
	if err != nil {
		t.Fatalf("ParseTemplate: %v", err)
	}

	findings := New(db).Execute(tmpl)
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1 from the first and second leaf invocations", len(findings))
	}
	if findings[0].PrimaryAST == nil || findings[0].PrimaryAST.Kind != types.KindCallLowlevelCall {
		t.Fatalf("primary AST = %+v, want the first inline low-level call occurrence", findings[0].PrimaryAST)
	}
	if findings[0].Reachability == nil {
		t.Fatal("reachability missing")
	}
	got := make([]string, 0, len(findings[0].Reachability.Steps))
	for _, step := range findings[0].Reachability.Steps {
		got = append(got, step.Function)
	}
	want := []string{"entry", "leaf"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("reachability = %v, want first selected occurrence %v", got, want)
	}
}

func TestInterproceduralSequenceAllowsOppositeArmsAcrossInlineOccurrences(t *testing.T) {
	const source = `pragma solidity ^0.8.20;
contract RepeatedConditionalHelper {
    uint256 private stored;

    function entry(address target) external {
        helper(target, true);
        helper(target, false);
    }

    function helper(address target, bool flag) internal {
        if (flag) {
            target.call("");
        } else {
            stored = 1;
        }
    }
}`
	db := buildDBFromSource(t, source).GetDatabase()
	tmpl, err := ParseTemplate(`
meta: {id: repeated-inline-opposite-arms, severity: HIGH}
query:
  from: entry_function
  where:
    - sequence:
        - {block: outgoing_call}
        - {block: state_write}
`)
	if err != nil {
		t.Fatalf("ParseTemplate: %v", err)
	}

	findings := New(db).Execute(tmpl)
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1 from the first call arm and second write arm", len(findings))
	}
	finding := findings[0]
	if finding.PrimaryAST == nil || finding.PrimaryAST.Kind != types.KindCallLowlevelCall {
		t.Fatalf("primary AST = %+v, want the selected outgoing-call occurrence", finding.PrimaryAST)
	}
	if finding.Reachability == nil {
		t.Fatal("reachability missing")
	}
	got := make([]string, 0, len(finding.Reachability.Steps))
	for _, step := range finding.Reachability.Steps {
		got = append(got, step.Function)
	}
	want := []string{"entry", "helper"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("reachability = %v, want selected first helper occurrence %v", got, want)
	}
}

func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "../.."))
}

// benchmarkHarnessAvailable reports whether the competitive benchmark harness
// (scripts/benchmark/) is present on disk. The harness is dev-only tooling that
// is intentionally git-ignored, so it is absent on a fresh clone / CI checkout.
//
// It probes concrete harness files, not just a parent directory: a partial tree
// (e.g. empty subdirectories left behind by `git clean`) must read as absent so
// the dependent tests skip rather than fail on missing fixtures/templates.
func benchmarkHarnessAvailable(root string) bool {
	base := filepath.Join(root, "scripts", "benchmark")
	for _, sentinel := range []string{
		"run_benchmark.py",
		filepath.Join("templates", "slither-inspired", "unprotected-upgrade.yaml"),
		filepath.Join("fixtures", "slither-detectors", "unprotected-upgrade.sol"),
	} {
		if info, err := os.Stat(filepath.Join(base, sentinel)); err != nil || info.IsDir() {
			return false
		}
	}
	return true
}

// skipWithoutBenchmarkHarness skips a benchmark-dependent regression test when
// the git-ignored scripts/benchmark/ harness is not checked out.
func skipWithoutBenchmarkHarness(t *testing.T, root string) {
	t.Helper()
	if !benchmarkHarnessAvailable(root) {
		t.Skip("scripts/benchmark harness not present (dev-only, git-ignored); skipping benchmark-dependent test")
	}
}
