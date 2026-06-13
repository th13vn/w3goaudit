package builder

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/th13vn/w3goaudit/pkg/reader"
	"github.com/th13vn/w3goaudit/pkg/types"
)

// buildFixture reads a fixture file under test-data/core/build-database and runs the
// full builder pipeline, returning the resulting database. The path is given
// relative to this package; reader.Read canonicalizes it to an absolute path,
// so contract/function IDs are in absolute-path#Name form.
func buildFixture(t *testing.T, rel string) *types.Database {
	t.Helper()
	r := reader.New()
	sources, err := r.Read(rel)
	if err != nil {
		t.Fatalf("reader.Read(%q): %v", rel, err)
	}
	if len(sources) == 0 {
		t.Fatalf("reader.Read(%q): no sources", rel)
	}
	db, err := New().Build(sources)
	if err != nil {
		t.Fatalf("Build(%q): %v", rel, err)
	}
	return db
}

// fixtureAbs returns the absolute path of a fixture, matching the canonical
// path the reader produces for the source file (used to build expected IDs).
func fixtureAbs(t *testing.T, rel string) string {
	t.Helper()
	abs, err := filepath.Abs(rel)
	if err != nil {
		t.Fatalf("filepath.Abs(%q): %v", rel, err)
	}
	return abs
}

const (
	basicFixture       = "../../test-data/core/build-database/01-basic-contracts.sol"
	inheritanceFixture = "../../test-data/core/build-database/02-inheritance.sol"
	callsFixture       = "../../test-data/core/build-database/03-function-calls.sol"
	diamondFixture     = "../../test-data/core/build-database/07-diamond.sol"
	semanticFixture    = "../../test-data/core/build-database/08-semantic-types.sol"
	overrideFixture    = "../../test-data/core/build-database/10-override-state-order.sol"
)

// TestBuildBasicContracts verifies that Build extracts the expected contracts
// with the correct kinds and absPath#Name IDs.
func TestBuildBasicContracts(t *testing.T) {
	db := buildFixture(t, basicFixture)
	abs := fixtureAbs(t, basicFixture)

	wantKinds := map[string]types.ContractKind{
		"IToken":     types.ContractKindInterface,
		"MathLib":    types.ContractKindLibrary,
		"Ownable":    types.ContractKindAbstract,
		"BasicToken": types.ContractKindContract,
	}

	if len(db.Contracts) != len(wantKinds) {
		t.Fatalf("contract count = %d, want %d (%v)", len(db.Contracts), len(wantKinds), contractNames(db))
	}

	for name, kind := range wantKinds {
		wantID := abs + "#" + name
		c := db.GetContract(wantID)
		if c == nil {
			t.Fatalf("contract %s not found by ID %q; have %v", name, wantID, contractIDs(db))
		}
		if c.ID != wantID {
			t.Errorf("%s.ID = %q, want %q", name, c.ID, wantID)
		}
		if c.Name != name {
			t.Errorf("contract Name = %q, want %q", c.Name, name)
		}
		if c.Kind != kind {
			t.Errorf("%s.Kind = %q, want %q", name, c.Kind, kind)
		}
	}
}

// TestDeployableAndMainCandidate captures IsDeployable / IsMainCandidate per
// contract kind, and that only the concrete leaf contract becomes a main contract.
func TestDeployableAndMainCandidate(t *testing.T) {
	db := buildFixture(t, basicFixture)

	tests := []struct {
		name           string
		wantDeployable bool
		wantMainCand   bool
	}{
		{"IToken", false, false},   // interface
		{"MathLib", false, false},  // library
		{"Ownable", false, false},  // abstract
		{"BasicToken", true, true}, // concrete
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := db.GetContractByName(tt.name)
			if c == nil {
				t.Fatalf("contract %s not found", tt.name)
			}
			if got := c.IsDeployable(); got != tt.wantDeployable {
				t.Errorf("IsDeployable() = %v, want %v", got, tt.wantDeployable)
			}
			if got := c.IsMainCandidate(); got != tt.wantMainCand {
				t.Errorf("IsMainCandidate() = %v, want %v", got, tt.wantMainCand)
			}
		})
	}

	// Only BasicToken is a main contract (Ownable is abstract & inherited).
	if len(db.MainContracts) != 1 {
		t.Fatalf("MainContracts count = %d, want 1 (%v)", len(db.MainContracts), db.MainContracts)
	}
	abs := fixtureAbs(t, basicFixture)
	wantMain := abs + "#BasicToken"
	if _, ok := db.MainContracts[wantMain]; !ok {
		var got []string
		for id := range db.MainContracts {
			got = append(got, id)
		}
		t.Fatalf("MainContracts missing %q; have %v", wantMain, got)
	}
}

// TestFunctionSelectorsAndSignatures verifies canonical selectors and the
// 4-byte keccak256 signatures for known functions (compared against the
// well-known ERC20 selectors).
func TestFunctionSelectorsAndSignatures(t *testing.T) {
	db := buildFixture(t, basicFixture)
	bt := db.GetContractByName("BasicToken")
	if bt == nil {
		t.Fatal("BasicToken not found")
	}

	type want struct {
		selector  string
		signature string
		entry     bool
	}
	wants := map[string]want{
		// transfer(address,uint256) -> a9059cbb is the canonical ERC20 selector.
		"transfer": {"transfer(address,uint256)", "a9059cbb", true},
		"mint":     {"mint(address,uint256)", "40c10f19", true},
		// balanceOf(address) -> 70a08231 (ERC20). view => not an entrypoint.
		"balanceOf": {"balanceOf(address)", "70a08231", false},
	}

	byName := make(map[string]*types.Function)
	for _, fn := range bt.Functions {
		byName[fn.Name] = fn
	}

	for name, w := range wants {
		t.Run(name, func(t *testing.T) {
			fn := byName[name]
			if fn == nil {
				t.Fatalf("function %s not found", name)
			}
			if fn.Selector != w.selector {
				t.Errorf("Selector = %q, want %q", fn.Selector, w.selector)
			}
			if fn.Signature != w.signature {
				t.Errorf("Signature = %q, want %q", fn.Signature, w.signature)
			}
			if len(fn.Signature) != 8 {
				t.Errorf("Signature %q is not 8 hex chars (4 bytes)", fn.Signature)
			}
			if got := fn.IsEntrypoint(); got != w.entry {
				t.Errorf("IsEntrypoint() = %v, want %v", got, w.entry)
			}
		})
	}
}

// TestC3Linearization captures the C3 method-resolution order for the diamond
// inheritance pattern in 02-inheritance.sol.
func TestC3Linearization(t *testing.T) {
	db := buildFixture(t, inheritanceFixture)
	myt := db.GetContractByName("MyToken")
	if myt == nil {
		t.Fatal("MyToken not found")
	}

	// Direct (declared) base contracts, in declaration order.
	wantBases := []string{"Pausable", "Ownable", "IERC20", "IOwnable"}
	if !equalStrings(myt.BaseContracts, wantBases) {
		t.Errorf("BaseContracts = %v, want %v", myt.BaseContracts, wantBases)
	}

	// C3 linearization is derived-first, most-base last. This is the canonical
	// Solidity order (last-listed base is most-derived), verified against
	// solc 0.8.20 for: contract MyToken is Pausable, Ownable, IERC20, IOwnable.
	wantLin := []string{"MyToken", "IOwnable", "IERC20", "Ownable", "Pausable", "Context"}
	if !equalStrings(myt.LinearizedBases, wantLin) {
		t.Errorf("LinearizedBases = %v, want %v", myt.LinearizedBases, wantLin)
	}

	// Structural invariants independent of the exact ordering choice:
	if len(myt.LinearizedBases) == 0 || myt.LinearizedBases[0] != "MyToken" {
		t.Errorf("linearization must start with the contract itself, got %v", myt.LinearizedBases)
	}
	if last := myt.LinearizedBases[len(myt.LinearizedBases)-1]; last != "Context" {
		t.Errorf("most-base contract should be Context (last), got %q", last)
	}
	// Context is the shared diamond root; both Pausable and Ownable must
	// precede it in the MRO.
	assertBefore(t, myt.LinearizedBases, "Pausable", "Context")
	assertBefore(t, myt.LinearizedBases, "Ownable", "Context")

	// The single deployable leaf becomes the main contract and propagates its MRO.
	abs := fixtureAbs(t, inheritanceFixture)
	entry := db.MainContracts[abs+"#MyToken"]
	if entry == nil {
		t.Fatalf("MyToken should be a main contract; have %v", db.MainContracts)
	}
	if !equalStrings(entry.LinearizedBases, wantLin) {
		t.Errorf("MainContractEntry.LinearizedBases = %v, want %v", entry.LinearizedBases, wantLin)
	}
}

// TestC3DiamondMatchesSolc pins the classic A/B/C/D diamond to the exact order
// solc 0.8.20 produces: `contract D is B, C` linearizes to [D, C, B, A] (C
// before B because the last-listed base is most-derived). This guards the
// chain-draining c3Merge against divergence from canonical C3 on a diamond.
func TestC3DiamondMatchesSolc(t *testing.T) {
	db := buildFixture(t, diamondFixture)
	d := db.GetContractByName("D")
	if d == nil {
		t.Fatal("D not found")
	}
	want := []string{"D", "C", "B", "A"}
	if !equalStrings(d.LinearizedBases, want) {
		t.Errorf("D LinearizedBases = %v, want %v (solc 0.8.20 order)", d.LinearizedBases, want)
	}
}

// TestComplexDiamondOverrideAndStateOrder pins three solc-0.8.20 inheritance
// properties on the asymmetric Base/Left/Right/Middle/Derived diamond
// (Middle is Left, Right; Derived is Middle):
//
//  1. C3 linearization (derived-first): Derived → Middle → Right → Left → Base.
//  2. State-variable storage order: most-base contract first, declaration order
//     within each — Base.{baseVar,baseFlag}, Left.leftVar, Right.rightVar,
//     Middle.middleVar, Derived.derivedVar.
//  3. Override binding along the MRO: super.foo() → Middle.foo (next contract in
//     the MRO that defines foo); bar() → Right.bar (overridden only on the Right
//     branch); baz() → Base.baz (never overridden).
func TestComplexDiamondOverrideAndStateOrder(t *testing.T) {
	db := buildFixture(t, overrideFixture)
	abs := fixtureAbs(t, overrideFixture)
	db.CallGraph.EnsureIndex()

	derived := db.GetContractByName("Derived")
	if derived == nil {
		t.Fatal("Derived not found")
	}

	// 1. C3 linearization.
	wantMRO := []string{"Derived", "Middle", "Right", "Left", "Base"}
	if !equalStrings(derived.LinearizedBases, wantMRO) {
		t.Errorf("Derived MRO = %v, want %v (solc 0.8.20 order)", derived.LinearizedBases, wantMRO)
	}

	// 2. State-variable storage order (walk the MRO in reverse = most-base first).
	var layout []string
	for i := len(derived.LinearizedBases) - 1; i >= 0; i-- {
		base := db.GetContractByName(derived.LinearizedBases[i])
		if base == nil {
			continue
		}
		for _, sv := range base.StateVariables {
			layout = append(layout, base.Name+"."+sv.Name)
		}
	}
	wantLayout := []string{
		"Base.baseVar", "Base.baseFlag",
		"Left.leftVar", "Right.rightVar",
		"Middle.middleVar", "Derived.derivedVar",
	}
	if !equalStrings(layout, wantLayout) {
		t.Errorf("storage layout = %v, want %v", layout, wantLayout)
	}

	// 3. Override binding along the MRO.
	bindings := []struct {
		from, wantToContains string
	}{
		{abs + "#Derived.foo()", "#Middle.foo"},
		{abs + "#Derived.callsBar()", "#Right.bar"},
		{abs + "#Derived.callsBaz()", "#Base.baz"},
	}
	for _, b := range bindings {
		callees := db.CallGraph.GetCallees(b.from)
		found := false
		for _, e := range callees {
			if strings.Contains(e.To, b.wantToContains) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("%s: no callee edge to %q; got %v", b.from, b.wantToContains, edgeTargets(callees))
		}
	}
}

// TestC3MergeCanonicalClassicExample pins the c3Merge step against the canonical
// C3 example from the original Dylan/CPython papers — the case that DISTINGUISHES
// true C3 from the old reverse-order chain-draining heuristic. With
//
//	class K1(A, B, C); class K2(D, B, E); class K3(D, A); class Z(K1, K2, K3)
//
// canonical C3 yields Z's MRO as [Z, K1, K2, K3, D, A, B, C, E, O]. The merge
// below feeds the parents' linearizations plus the direct-base list (forward
// order, no Solidity reversal — this tests the merge primitive in isolation) and
// asserts the textbook result.
func TestC3MergeCanonicalClassicExample(t *testing.T) {
	ib := NewInheritanceBuilder(nil) // c3Merge does not touch the database
	lists := [][]string{
		{"K1", "A", "B", "C", "O"}, // L[K1]
		{"K2", "D", "B", "E", "O"}, // L[K2]
		{"K3", "D", "A", "O"},      // L[K3]
		{"K1", "K2", "K3"},         // direct bases
	}
	got := ib.c3Merge(lists)
	want := []string{"K1", "K2", "K3", "D", "A", "B", "C", "E", "O"}
	if !equalStrings(got, want) {
		t.Errorf("c3Merge classic example = %v, want %v", got, want)
	}
}

// TestC3MergeInputUnmutated guards that c3Merge works on copies and does not
// drain the caller's slices (the old implementation mutated in place).
func TestC3MergeInputUnmutated(t *testing.T) {
	ib := NewInheritanceBuilder(nil)
	first := []string{"B", "A"}
	lists := [][]string{first, {"C", "A"}, {"B", "C"}}
	_ = ib.c3Merge(lists)
	if !equalStrings(first, []string{"B", "A"}) {
		t.Errorf("c3Merge mutated caller slice: got %v, want [B A]", first)
	}
}

// TestEntryFunctionsResolved verifies the main contract's resolved entry
// functions: only state-mutating public/external functions, by ID.
func TestEntryFunctionsResolved(t *testing.T) {
	db := buildFixture(t, inheritanceFixture)
	abs := fixtureAbs(t, inheritanceFixture)
	entry := db.MainContracts[abs+"#MyToken"]
	if entry == nil {
		t.Fatal("MyToken main entry missing")
	}

	prefix := abs + "#MyToken."
	wantSuffixes := []string{
		"mint(address,uint256)",
		"pause()",
		"unpause()",
	}
	got := append([]string(nil), entry.EntryFunctions...)
	if len(got) != len(wantSuffixes) {
		t.Fatalf("EntryFunctions count = %d (%v), want %d", len(got), got, len(wantSuffixes))
	}
	for _, suffix := range wantSuffixes {
		wantID := prefix + suffix
		if !containsString(got, wantID) {
			t.Errorf("EntryFunctions missing %q; have %v", wantID, got)
		}
	}
	// totalSupply is view => must NOT appear as an entry function.
	for _, id := range got {
		if strings.Contains(id, "totalSupply") {
			t.Errorf("view function totalSupply should not be an entry function, got %q", id)
		}
	}
}

// TestCallGraphEdges verifies that the call graph captures caller->callee edges
// and classifies the various call types (internal, library, external, self,
// low-level call/delegatecall/staticcall).
func TestCallGraphEdges(t *testing.T) {
	db := buildFixture(t, callsFixture)
	abs := fixtureAbs(t, callsFixture)
	db.CallGraph.EnsureIndex()

	if len(db.CallGraph.Edges) == 0 {
		t.Fatal("call graph has no edges")
	}

	processDeposit := abs + "#CallTest.processDeposit(uint256)"
	callees := db.CallGraph.GetCallees(processDeposit)
	if len(callees) != 3 {
		t.Fatalf("processDeposit callees = %d, want 3 (%v)", len(callees), edgeTargets(callees))
	}
	for _, want := range []string{"_validateAmount", "_transferToVault", "_updateState"} {
		if !hasEdgeToName(callees, want) {
			t.Errorf("processDeposit should call %s; got %v", want, edgeCalledNames(callees))
		}
	}
	for _, e := range callees {
		if e.Type != types.CallTypeInternal {
			t.Errorf("edge %s->%s type = %q, want internal", e.From, e.CalledName, e.Type)
		}
	}

	// Reverse lookup: processDeposit is called by selfCall (this.processDeposit).
	callers := db.CallGraph.GetCallers(processDeposit)
	if !hasEdgeFromContains(callers, "selfCall") {
		t.Errorf("processDeposit should have caller selfCall; got %v", edgeFroms(callers))
	}

	// Verify call-type classification across the contract via CalledName.
	wantTypeByName := map[string]types.CallType{
		"add":            types.CallTypeLibrary,      // MathLib.add
		"deposit":        types.CallTypeExternal,     // vault.deposit (interface)
		"call":           types.CallTypeLowLevelCall, // target.call
		"delegatecall":   types.CallTypeLowLevelDelegate,
		"staticcall":     types.CallTypeLowLevelStatic,
		"processDeposit": types.CallTypeSelf, // this.processDeposit
	}
	gotTypeByName := make(map[string]types.CallType)
	for _, e := range db.CallGraph.Edges {
		if _, interesting := wantTypeByName[e.CalledName]; interesting {
			gotTypeByName[e.CalledName] = e.Type
		}
	}
	for name, want := range wantTypeByName {
		if got := gotTypeByName[name]; got != want {
			t.Errorf("call %q classified as %q, want %q", name, got, want)
		}
	}
}

// TestFunctionASTCallClassification verifies that the per-function AST tags
// external and low-level calls with the expected node kinds.
func TestFunctionASTCallClassification(t *testing.T) {
	db := buildFixture(t, callsFixture)
	ct := db.GetContractByName("CallTest")
	if ct == nil {
		t.Fatal("CallTest not found")
	}
	byName := make(map[string]*types.Function)
	for _, fn := range ct.Functions {
		byName[fn.Name] = fn
	}

	tests := []struct {
		fn       string
		wantKind string
	}{
		{"_transferToVault", types.KindCallExternal},        // vault.deposit(...)
		{"callContract", types.KindCallLowlevelCall},        // target.call(data)
		{"delegateToLogic", types.KindCallLowlevelDelegate}, // logic.delegatecall(data)
		{"readContract", types.KindCallLowlevelStatic},      // target.staticcall(data)
		{"selfCall", types.KindCallExternal},                // this.processDeposit(...)
	}

	for _, tt := range tests {
		t.Run(tt.fn, func(t *testing.T) {
			fn := byName[tt.fn]
			if fn == nil {
				t.Fatalf("function %s not found", tt.fn)
			}
			if fn.AST == nil {
				t.Fatalf("function %s has nil AST", tt.fn)
			}
			if !astHasKind(fn.AST, tt.wantKind) {
				t.Errorf("function %s AST missing node kind %q; kinds present: %v",
					tt.fn, tt.wantKind, astKinds(fn.AST))
			}
		})
	}

	// _validateAmount: require(amount > 0) => a check node with a binary op.
	va := byName["_validateAmount"]
	if va == nil || va.AST == nil {
		t.Fatal("_validateAmount missing or has nil AST")
	}
	if !astHasKind(va.AST, types.KindExprBinaryOp) {
		t.Errorf("_validateAmount should contain a binary op; kinds: %v", astKinds(va.AST))
	}
}

func TestSemanticTypeFactsAndCallClassification(t *testing.T) {
	db := buildFixture(t, semanticFixture)
	abs := fixtureAbs(t, semanticFixture)
	contract := db.GetContractByName("SemanticTypeFacts")
	if contract == nil {
		t.Fatal("SemanticTypeFacts not found")
	}
	if db.Semantics == nil {
		t.Fatal("db.Semantics is nil")
	}

	stateSym := db.Semantics.GetSymbol(abs + "#SemanticTypeFacts.oneArgToken")
	if stateSym == nil {
		t.Fatalf("missing semantic symbol for oneArgToken")
	}
	if stateSym.Type.Name != "IOneArgToken" || stateSym.Type.Kind != string(types.ContractKindInterface) {
		t.Fatalf("oneArgToken type = %#v; want IOneArgToken interface", stateSym.Type)
	}

	byName := make(map[string]*types.Function)
	for _, fn := range contract.Functions {
		byName[fn.Name] = fn
	}

	tests := []struct {
		fn                 string
		callName           string
		wantKind           string
		wantReceiverType   string
		wantReceiverKind   string
		wantReceiverIsAddr bool
	}{
		{
			fn:               "interfaceTransfer",
			callName:         "transfer",
			wantKind:         types.KindCallExternal,
			wantReceiverType: "IOneArgToken",
			wantReceiverKind: string(types.ContractKindInterface),
		},
		{
			fn:               "localCastTransfer",
			callName:         "transfer",
			wantKind:         types.KindCallExternal,
			wantReceiverType: "IOneArgToken",
			wantReceiverKind: string(types.ContractKindInterface),
		},
		{
			fn:                 "payableTransfer",
			callName:           "transfer",
			wantKind:           types.KindCallBuiltinTransfer,
			wantReceiverType:   "address",
			wantReceiverKind:   types.TypeKindPrimitive,
			wantReceiverIsAddr: true,
		},
		{
			fn:                 "payableCastTransfer",
			callName:           "transfer",
			wantKind:           types.KindCallBuiltinTransfer,
			wantReceiverType:   "address",
			wantReceiverKind:   types.TypeKindPrimitive,
			wantReceiverIsAddr: true,
		},
		{
			fn:               "interfaceSend",
			callName:         "send",
			wantKind:         types.KindCallExternal,
			wantReceiverType: "IOneArgToken",
			wantReceiverKind: string(types.ContractKindInterface),
		},
	}

	for _, tt := range tests {
		t.Run(tt.fn, func(t *testing.T) {
			fn := byName[tt.fn]
			if fn == nil || fn.AST == nil {
				t.Fatalf("function %s missing or has nil AST", tt.fn)
			}
			call := findCallByName(fn.AST, tt.callName)
			if call == nil {
				t.Fatalf("%s missing call %q; kinds present: %v", tt.fn, tt.callName, astKinds(fn.AST))
			}
			if call.Kind != tt.wantKind {
				t.Fatalf("%s.%s kind = %q; want %q (attrs: %#v)", tt.fn, tt.callName, call.Kind, tt.wantKind, call.Attributes)
			}
			if got := call.GetAttributeString("receiver_type"); got != tt.wantReceiverType {
				t.Errorf("receiver_type = %q; want %q", got, tt.wantReceiverType)
			}
			if got := call.GetAttributeString("receiver_type_kind"); got != tt.wantReceiverKind {
				t.Errorf("receiver_type_kind = %q; want %q", got, tt.wantReceiverKind)
			}
			if got := call.GetAttributeBool("receiver_type_is_address"); got != tt.wantReceiverIsAddr {
				t.Errorf("receiver_type_is_address = %v; want %v", got, tt.wantReceiverIsAddr)
			}
			if got := call.GetAttributeString("call_classification"); got != "semantic" {
				t.Errorf("call_classification = %q; want semantic", got)
			}
		})
	}

	callGraphTests := []struct {
		fn               string
		calledName       string
		wantType         types.CallType
		wantResolved     bool
		wantResolvedName string
	}{
		{"interfaceTransfer", "transfer", types.CallTypeExternal, true, "IOneArgToken"},
		{"localCastTransfer", "transfer", types.CallTypeExternal, true, "IOneArgToken"},
		{"payableTransfer", "transfer", types.CallTypeTransferETH, false, ""},
		{"payableCastTransfer", "transfer", types.CallTypeTransferETH, false, ""},
		{"interfaceSend", "send", types.CallTypeExternal, true, "IOneArgToken"},
	}
	for _, tt := range callGraphTests {
		t.Run("callgraph_"+tt.fn, func(t *testing.T) {
			fn := byName[tt.fn]
			if fn == nil {
				t.Fatalf("function %s not found", tt.fn)
			}
			edge := findEdgeFromFunction(db, "SemanticTypeFacts", fn, tt.calledName)
			if edge == nil {
				t.Fatalf("missing callgraph edge from %s to %s", tt.fn, tt.calledName)
			}
			if edge.Type != tt.wantType {
				t.Errorf("edge.Type = %q; want %q (edge: %#v)", edge.Type, tt.wantType, edge)
			}
			if edge.Resolved != tt.wantResolved {
				t.Errorf("edge.Resolved = %v; want %v (edge: %#v)", edge.Resolved, tt.wantResolved, edge)
			}
			if edge.ResolvedContract != tt.wantResolvedName {
				t.Errorf("edge.ResolvedContract = %q; want %q (edge: %#v)", edge.ResolvedContract, tt.wantResolvedName, edge)
			}
		})
	}
}

// --- helpers ---

func astHasKind(root *types.ASTNode, kind string) bool {
	found := false
	root.WalkDescendants(func(n *types.ASTNode) bool {
		if n.Kind == kind {
			found = true
			return false
		}
		return true
	})
	return found
}

func astKinds(root *types.ASTNode) []string {
	seen := map[string]bool{}
	root.WalkDescendants(func(n *types.ASTNode) bool {
		seen[n.Kind] = true
		return true
	})
	var out []string
	for k := range seen {
		out = append(out, k)
	}
	return out
}

func findCallByName(root *types.ASTNode, name string) *types.ASTNode {
	var found *types.ASTNode
	root.WalkDescendants(func(n *types.ASTNode) bool {
		if strings.HasPrefix(n.Kind, "call.") && n.Name == name {
			found = n
			return false
		}
		return true
	})
	return found
}

func findEdgeFromFunction(db *types.Database, contractName string, fn *types.Function, calledName string) *types.CallEdge {
	if db == nil || db.CallGraph == nil || fn == nil {
		return nil
	}
	fnKey := fn.Selector
	if fnKey == "" {
		fnKey = fn.Name
	}
	fromSuffix := "#" + contractName + "." + fnKey
	for _, edge := range db.CallGraph.Edges {
		if strings.HasSuffix(edge.From, fromSuffix) && edge.CalledName == calledName {
			return edge
		}
	}
	return nil
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func containsString(s []string, want string) bool {
	for _, v := range s {
		if v == want {
			return true
		}
	}
	return false
}

func assertBefore(t *testing.T, order []string, earlier, later string) {
	t.Helper()
	ei, li := -1, -1
	for i, v := range order {
		if v == earlier {
			ei = i
		}
		if v == later {
			li = i
		}
	}
	if ei == -1 || li == -1 {
		t.Errorf("expected both %q and %q in %v", earlier, later, order)
		return
	}
	if ei >= li {
		t.Errorf("expected %q before %q in %v", earlier, later, order)
	}
}

func contractNames(db *types.Database) []string {
	var out []string
	for _, c := range db.Contracts {
		out = append(out, c.Name)
	}
	return out
}

func contractIDs(db *types.Database) []string {
	var out []string
	for id := range db.Contracts {
		out = append(out, id)
	}
	return out
}

func edgeTargets(edges []*types.CallEdge) []string {
	var out []string
	for _, e := range edges {
		out = append(out, e.To)
	}
	return out
}

func edgeCalledNames(edges []*types.CallEdge) []string {
	var out []string
	for _, e := range edges {
		out = append(out, e.CalledName)
	}
	return out
}

func edgeFroms(edges []*types.CallEdge) []string {
	var out []string
	for _, e := range edges {
		out = append(out, e.From)
	}
	return out
}

func hasEdgeToName(edges []*types.CallEdge, name string) bool {
	for _, e := range edges {
		if e.CalledName == name {
			return true
		}
	}
	return false
}

func hasEdgeFromContains(edges []*types.CallEdge, sub string) bool {
	for _, e := range edges {
		if strings.Contains(e.From, sub) {
			return true
		}
	}
	return false
}
