package builder

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/th13vn/w3goaudit/pkg/reader"
	"github.com/th13vn/w3goaudit/pkg/types"
)

const identityCollisionFixture = "../../test-data/core/identity-collision"

func TestCallGraphKeepsDuplicateContractIdentity(t *testing.T) {
	db := buildFixture(t, identityCollisionFixture)
	root := fixtureAbs(t, identityCollisionFixture)
	aFile := filepath.Join(root, "a", "Token.sol")
	zFile := filepath.Join(root, "z", "Token.sol")

	aContractID := types.MakeContractID(aFile, "Token")
	zContractID := types.MakeContractID(zFile, "Token")
	aContract := db.GetContractByID(aContractID)
	zContract := db.GetContractByID(zContractID)
	if aContract == nil || zContract == nil {
		t.Fatalf("duplicate contracts missing: a=%v z=%v", aContract != nil, zContract != nil)
	}
	if got := db.LinearizedContracts(aContract); len(got) != 1 || got[0] != aContract {
		t.Fatalf("a Token exact MRO = %#v, want self", exactContractIDs(got))
	}
	if got := db.LinearizedContracts(zContract); len(got) != 1 || got[0] != zContract {
		t.Fatalf("z Token exact MRO = %#v, want self", exactContractIDs(got))
	}
	for _, contractID := range []string{aContractID, zContractID} {
		entry := db.MainContracts[contractID]
		if entry == nil {
			t.Fatalf("main-contract entry %q missing", contractID)
		}
		if len(entry.LinearizedBaseIDs) != 1 || entry.LinearizedBaseIDs[0] != contractID {
			t.Fatalf("main-contract exact MRO for %q = %v, want self", contractID, entry.LinearizedBaseIDs)
		}
	}

	aRun := types.MakeFunctionID(aFile, "Token", "run()")
	zRun := types.MakeFunctionID(zFile, "Token", "run()")
	aHelper := types.MakeFunctionID(aFile, "Token", "helper()")
	zDanger := types.MakeFunctionID(zFile, "Token", "danger()")
	aGate := types.MakeModifierID(aFile, "Token", "gate")
	zGate := types.MakeModifierID(zFile, "Token", "gate")

	assertExactTargets(t, db.CallGraph.GetCallees(aRun), aHelper, aGate)
	assertExactTargets(t, db.CallGraph.GetCallees(zRun), zDanger, zGate)
	assertExactTargets(t, db.CallGraph.GetCallees(aGate), aHelper)
	assertExactTargets(t, db.CallGraph.GetCallees(zGate), zDanger)

	for _, edge := range db.CallGraph.Edges {
		if strings.HasPrefix(edge.From, zFile+"#") && strings.HasPrefix(edge.To, aFile+"#") {
			t.Fatalf("cross-file corruption from z to a: %#v", edge)
		}
		if strings.HasPrefix(edge.From, aFile+"#") && strings.HasPrefix(edge.To, zFile+"#") {
			t.Fatalf("cross-file corruption from a to z: %#v", edge)
		}
		if edge.Resolved && edge.ResolvedContractID == "" {
			t.Fatalf("resolved edge lacks exact contract ID: %#v", edge)
		}
	}

	assertFunctionCallsResolveTo(t, findFunction(t, aContract, "run"), aContractID)
	assertFunctionCallsResolveTo(t, findFunction(t, zContract, "run"), zContractID)
	assertModifierCallsResolveTo(t, findModifier(t, aContract, "gate"), aContractID)
	assertModifierCallsResolveTo(t, findModifier(t, zContract, "gate"), zContractID)

	for _, diagnostic := range db.Diagnostics {
		if diagnostic.Code == types.DiagnosticIdentity {
			t.Fatalf("fully resolvable duplicate fixture emitted identity diagnostic: %#v", diagnostic)
		}
	}
}

func TestLinearizedContractsLegacyNameFallbackKeepsExactSelf(t *testing.T) {
	db := buildFixture(t, identityCollisionFixture)
	root := fixtureAbs(t, identityCollisionFixture)
	zContract := db.GetContractByID(types.MakeContractID(filepath.Join(root, "z", "Token.sol"), "Token"))
	if zContract == nil {
		t.Fatal("z Token missing")
	}

	ids := append([]string(nil), zContract.LinearizedBaseIDs...)
	zContract.LinearizedBaseIDs = nil // simulate schema-2.0.0 cache written before exact IDs
	got := db.LinearizedContracts(zContract)
	zContract.LinearizedBaseIDs = ids
	if len(got) != 1 || got[0] != zContract {
		t.Fatalf("legacy MRO fallback = %#v, want exact z Token self", exactContractIDs(got))
	}
}

func TestLinearizedContractsLegacyFallbackOmitsAmbiguousBase(t *testing.T) {
	db := buildFixture(t, identityCollisionFixture)
	derivedFile := filepath.Join(fixtureAbs(t, identityCollisionFixture), "unrelated", "Derived.sol")
	derived := &types.Contract{
		Name:            "Derived",
		SourceFile:      derivedFile,
		LinearizedBases: []string{"Derived", "Token"},
	}
	db.AddSourceFile(&types.SourceFile{Path: derivedFile})
	db.AddContract(derived)
	db.NormalizeDiagnostics()
	diagnosticsBefore := len(db.Diagnostics)

	got := db.LinearizedContracts(derived)
	if len(got) != 1 || got[0] != derived {
		t.Fatalf("legacy ambiguous MRO = %v, want exact self only", exactContractIDs(got))
	}
	if len(db.Diagnostics) != diagnosticsBefore {
		t.Fatalf("LinearizedContracts mutated diagnostics: before=%d after=%d", diagnosticsBefore, len(db.Diagnostics))
	}
	found := false
	for _, diagnostic := range db.Diagnostics {
		if diagnostic.Code == types.DiagnosticIdentity && diagnostic.File == derivedFile && diagnostic.Symbol == "Token" {
			found = true
		}
	}
	if !found {
		t.Fatalf("diagnostics = %#v, want ambiguous legacy Token identity", db.Diagnostics)
	}
}

func TestCallGraphAttachesSameLineOverloadsByExactDeclarationAndType(t *testing.T) {
	db, file := buildSourceText(t, "pragma solidity ^0.8.20;\ncontract Overloads { function onlyUint() internal {} function onlyAddress() internal {} function hit(uint256 x) internal { onlyUint(); } function hit(address x) internal { onlyAddress(); } function callTyped(uint256 x, address y) external { hit(x); hit(y); } function pick(uint128 x) internal {} function pick(uint256 x) internal {} function callAmbiguous() external { pick(1); } }\n")
	contract := db.GetContractByID(types.MakeContractID(file, "Overloads"))
	if contract == nil {
		t.Fatal("Overloads missing")
	}

	uintHit := findFunctionBySelector(t, contract, "hit(uint256)")
	addressHit := findFunctionBySelector(t, contract, "hit(address)")
	assertCallNames(t, uintHit.Calls, "onlyUint")
	assertCallNames(t, addressHit.Calls, "onlyAddress")

	typedID := types.MakeFunctionID(file, "Overloads", "callTyped(uint256,address)")
	assertExactTargets(t, db.CallGraph.GetCallees(typedID),
		types.MakeFunctionID(file, "Overloads", "hit(uint256)"),
		types.MakeFunctionID(file, "Overloads", "hit(address)"),
	)

	ambiguousID := types.MakeFunctionID(file, "Overloads", "callAmbiguous()")
	edges := db.CallGraph.GetCallees(ambiguousID)
	if len(edges) != 1 || edges[0].CalledName != "pick" || edges[0].Resolved {
		t.Fatalf("ambiguous same-arity call edges = %#v, want one unresolved pick", edges)
	}
	if edges[0].ResolvedContractID != contract.ID {
		t.Fatalf("ambiguous call exact contract = %q, want %q", edges[0].ResolvedContractID, contract.ID)
	}
}

func TestKnownArityMismatchRemainsUnresolvedWithDiagnostic(t *testing.T) {
	db, file := buildSourceText(t, `pragma solidity ^0.8.20;
contract KnownArity {
    function target(uint256 value) internal pure returns (uint256) { return value; }
    function mismatch() external { target(); }
    function exact() external { target(1); }
}
`)
	contract := db.GetContractByID(types.MakeContractID(file, "KnownArity"))
	if contract == nil {
		t.Fatal("KnownArity missing")
	}

	mismatch := findFunction(t, contract, "mismatch")
	if len(mismatch.Calls) != 1 {
		t.Fatalf("mismatch calls = %#v, want one", mismatch.Calls)
	}
	call := mismatch.Calls[0]
	if call.Resolved || call.ResolvedFunction != "" || call.ResolvedContractID != "" {
		t.Fatalf("known arity mismatch resolved unexpectedly: %#v", call)
	}
	edges := db.CallGraph.GetCallees(types.MakeFunctionID(file, "KnownArity", "mismatch()"))
	if len(edges) != 1 || edges[0].Resolved || edges[0].ResolvedFunction != "" || edges[0].ResolvedContractID != "" {
		t.Fatalf("known arity mismatch edges = %#v, want one unresolved edge without exact target", edges)
	}

	exactEdges := db.CallGraph.GetCallees(types.MakeFunctionID(file, "KnownArity", "exact()"))
	wantTarget := types.MakeFunctionID(file, "KnownArity", "target(uint256)")
	if len(exactEdges) != 1 || !exactEdges[0].Resolved || exactEdges[0].To != wantTarget {
		t.Fatalf("exact-arity edge = %#v, want resolved %s", exactEdges, wantTarget)
	}

	var matching []types.Diagnostic
	for _, diagnostic := range db.Diagnostics {
		if diagnostic.Code == types.DiagnosticIdentity && diagnostic.File == file && diagnostic.Symbol == "target" {
			matching = append(matching, diagnostic)
		}
	}
	if len(matching) != 1 || matching[0].Line != call.Line || !strings.Contains(matching[0].Message, "arity 0") {
		t.Fatalf("known-arity diagnostics = %#v, want one durable target/arity diagnostic", matching)
	}
}

func TestCallGraphRecordsNestedReceiverAndOptionCallsExactlyOnce(t *testing.T) {
	db, file := buildSourceText(t, `pragma solidity ^0.8.20;
interface PreludeSink { function ping() external; }
contract PreludeCalls {
    uint256 private stored;
    function receiverHelper(address target) internal returns (PreludeSink) { stored = 1; return PreludeSink(target); }
    function receiverHelper(uint160 target) internal returns (PreludeSink) { stored = 9; return PreludeSink(address(target)); }
    function optionHelper(address value) internal returns (uint256) { stored = 2; value; return gasleft(); }
    function optionHelper(uint160 value) internal returns (uint256) { stored = 8; value; return gasleft(); }
    function viaReceiver(address target) external { receiverHelper(target).ping(); }
    function viaOption(address target) external { PreludeSink(target).ping{gas: optionHelper(address(this))}(); }
}`)

	cases := []struct {
		caller string
		helper string
	}{
		{caller: "viaReceiver(address)", helper: "receiverHelper(address)"},
		{caller: "viaOption(address)", helper: "optionHelper(address)"},
	}
	for _, tc := range cases {
		edges := db.CallGraph.GetCallees(types.MakeFunctionID(file, "PreludeCalls", tc.caller))
		counts := make(map[string]int)
		for _, edge := range edges {
			counts[edge.CalledName]++
		}
		if counts["ping"] != 1 {
			t.Errorf("%s ping edges = %d, want exactly one; edges=%#v", tc.caller, counts["ping"], edges)
		}
		helperName := strings.SplitN(tc.helper, "(", 2)[0]
		if counts[helperName] != 1 {
			t.Errorf("%s %s edges = %d, want exactly one; edges=%#v", tc.caller, helperName, counts[helperName], edges)
		}
		wantHelper := types.MakeFunctionID(file, "PreludeCalls", tc.helper)
		resolved := false
		for _, edge := range edges {
			if edge.To == wantHelper && edge.Resolved {
				resolved = true
			}
		}
		if !resolved {
			t.Errorf("%s missing exact nested helper target %s; edges=%#v", tc.caller, wantHelper, edges)
		}
		if len(edges) != 2 {
			t.Errorf("%s edges = %d, want helper plus outer ping only: %#v", tc.caller, len(edges), edges)
		}
	}
}

func TestImportedAliasesResolveInheritanceTypesCallsAndLibraries(t *testing.T) {
	cases := []struct {
		name             string
		importStatement  string
		baseReference    string
		libraryReference string
		targetReference  string
	}{
		{
			name:             "named aliases",
			importStatement:  `import {Base as Parent, Helpers as AliasLib, TypedTarget as AliasTarget} from "./Vendor.sol";`,
			baseReference:    "Parent",
			libraryReference: "AliasLib",
			targetReference:  "AliasTarget",
		},
		{
			name:             "namespace alias",
			importStatement:  `import * as V from "./Vendor.sol";`,
			baseReference:    "V.Base",
			libraryReference: "V.Helpers",
			targetReference:  "V.TypedTarget",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db, childFile, vendorFile := buildImportedAliasProject(t, tc.importStatement, tc.baseReference, tc.libraryReference, tc.targetReference)
			assertImportedAliasProject(t, db, childFile, vendorFile, tc.baseReference)

			raw, err := json.MarshalIndent(db, "", "  ")
			if err != nil {
				t.Fatalf("marshal database: %v", err)
			}
			if !strings.Contains(string(raw), `"importBindings"`) {
				t.Fatalf("database JSON lacks serialized structured import bindings:\n%s", raw)
			}
			cachePath := filepath.Join(t.TempDir(), "database.json")
			if err := os.WriteFile(cachePath, raw, 0o644); err != nil {
				t.Fatalf("write database cache: %v", err)
			}
			loaded, err := types.LoadFromJSON(cachePath)
			if err != nil {
				t.Fatalf("LoadFromJSON: %v", err)
			}
			assertImportedAliasProject(t, loaded, childFile, vendorFile, tc.baseReference)
		})
	}
}

func TestImportedAliasAmbiguityAndMissingBindingsFailClosed(t *testing.T) {
	cases := []struct {
		name   string
		files  map[string]string
		child  string
		symbol string
	}{
		{
			name: "ambiguous namespace binding",
			files: map[string]string{
				"A.sol": `contract Base {}`,
				"B.sol": `contract Base {}`,
			},
			child: `pragma solidity ^0.8.20;
import * as V from "./A.sol";
import * as V from "./B.sol";
contract Child is V.Base {}`,
			symbol: "V.Base",
		},
		{
			name: "missing named binding",
			files: map[string]string{
				"Vendor.sol": `contract Other {}`,
			},
			child: `pragma solidity ^0.8.20;
import {Missing as Parent} from "./Vendor.sol";
contract Child is Parent {}`,
			symbol: "Parent",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			for name, source := range tc.files {
				if err := os.WriteFile(filepath.Join(root, name), []byte(source), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			childPath := filepath.Join(root, "Child.sol")
			if err := os.WriteFile(childPath, []byte(tc.child), 0o644); err != nil {
				t.Fatal(err)
			}
			r := reader.New()
			sources, err := r.Read(childPath)
			if err != nil {
				t.Fatal(err)
			}
			childPath = sources[0].Path
			if err := r.ResolveImports(root); err != nil {
				t.Fatal(err)
			}
			db, err := New().Build(r.GetAllSources())
			if err != nil {
				t.Fatal(err)
			}
			child := db.GetContractByID(types.MakeContractID(childPath, "Child"))
			if child == nil || len(child.LinearizedBaseIDs) != 1 || child.LinearizedBaseIDs[0] != child.ID {
				t.Fatalf("ambiguous/missing alias exact MRO = %#v", child)
			}
			found := false
			for _, diagnostic := range db.Diagnostics {
				if diagnostic.Code == types.DiagnosticIdentity && diagnostic.File == childPath && diagnostic.Symbol == tc.symbol {
					found = true
				}
			}
			if !found {
				t.Fatalf("diagnostics = %#v, want durable identity diagnostic for %s", db.Diagnostics, tc.symbol)
			}
		})
	}
}

func buildImportedAliasProject(t *testing.T, importStatement, baseReference, libraryReference, targetReference string) (*types.Database, string, string) {
	t.Helper()
	root := t.TempDir()
	vendorPath := filepath.Join(root, "Vendor.sol")
	childPath := filepath.Join(root, "Child.sol")
	vendorSource := `pragma solidity ^0.8.20;
contract Base {
    uint256 internal inheritedState;
    modifier onlyBase() { _; }
    function inheritedFn() internal {}
}
library Helpers {
    function bump(uint256 self) internal pure returns (uint256) { return self + 1; }
}
contract TypedTarget {
    function ping() external {}
}
`
	childSource := "pragma solidity ^0.8.20;\n" + importStatement + "\n" +
		"contract Child is " + baseReference + " {\n" +
		"    using " + libraryReference + " for uint256;\n" +
		"    " + targetReference + " private target;\n" +
		"    function run(uint256 value) external onlyBase {\n" +
		"        inheritedFn();\n" +
		"        value.bump();\n" +
		"        target.ping();\n" +
		"    }\n" +
		"}\n"
	if err := os.WriteFile(vendorPath, []byte(vendorSource), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(childPath, []byte(childSource), 0o644); err != nil {
		t.Fatal(err)
	}

	r := reader.New()
	if _, err := r.Read(childPath); err != nil {
		t.Fatalf("Read child: %v", err)
	}
	if err := r.ResolveImports(root); err != nil {
		t.Fatalf("ResolveImports: %v", err)
	}
	sources := r.GetAllSources()
	for _, source := range sources {
		switch filepath.Base(source.Path) {
		case "Child.sol":
			childPath = source.Path
		case "Vendor.sol":
			vendorPath = source.Path
		}
	}
	db, err := New().Build(sources)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	return db, childPath, vendorPath
}

func assertImportedAliasProject(t *testing.T, db *types.Database, childFile, vendorFile, baseReference string) {
	t.Helper()
	child := db.GetContractByID(types.MakeContractID(childFile, "Child"))
	base := db.GetContractByID(types.MakeContractID(vendorFile, "Base"))
	helpers := db.GetContractByID(types.MakeContractID(vendorFile, "Helpers"))
	target := db.GetContractByID(types.MakeContractID(vendorFile, "TypedTarget"))
	if child == nil || base == nil || helpers == nil || target == nil {
		t.Fatalf("alias project contracts missing: child=%v base=%v helpers=%v target=%v", child != nil, base != nil, helpers != nil, target != nil)
	}
	if got := child.LinearizedBaseIDs; len(got) != 2 || got[0] != child.ID || got[1] != base.ID {
		t.Fatalf("Child exact MRO = %v, want [%s %s]", got, child.ID, base.ID)
	}
	if resolved, exact := db.ResolveContractNameExact(baseReference, childFile); !exact || resolved != base {
		t.Fatalf("ResolveContractNameExact(%q) = %#v/%v, want %s", baseReference, resolved, exact, base.ID)
	}
	if baseReference != "Base" {
		if resolved, exact := db.ResolveContractNameExact("Base", childFile); exact || resolved != nil {
			t.Fatalf("bare Base escaped structured alias scope: %#v/%v", resolved, exact)
		}
	}
	if len(base.StateVariables) == 0 || findFunction(t, base, "inheritedFn") == nil || findModifier(t, base, "onlyBase") == nil {
		t.Fatalf("base inherited members missing: %#v", base)
	}

	run := findFunction(t, child, "run")
	wantCalls := map[string]string{
		"inheritedFn": base.ID,
		"bump":        helpers.ID,
		"ping":        target.ID,
		"onlyBase":    base.ID,
	}
	for _, call := range run.Calls {
		if wantID, ok := wantCalls[call.Target]; ok && call.Resolved && call.ResolvedContractID == wantID {
			delete(wantCalls, call.Target)
		}
	}
	if len(wantCalls) != 0 {
		t.Fatalf("run unresolved alias-derived calls = %v; calls=%#v", wantCalls, run.Calls)
	}

	semanticTarget := false
	for _, symbol := range db.Semantics.Symbols {
		if symbol != nil && symbol.Name == "target" && symbol.Type.ContractID == target.ID {
			semanticTarget = true
			break
		}
	}
	if !semanticTarget {
		t.Fatalf("semantic facts do not resolve target to %s: %#v", target.ID, db.Semantics.Symbols)
	}
	entry := db.MainContracts[child.ID]
	runID := types.MakeFunctionID(childFile, "Child", "run(uint256)")
	if entry == nil || !containsString(entry.EntryFunctions, runID) {
		t.Fatalf("Child entry functions = %#v, want %s", entry, runID)
	}
	for _, diagnostic := range db.Diagnostics {
		if diagnostic.Code == types.DiagnosticIdentity || diagnostic.Code == types.DiagnosticUnresolvedBase {
			t.Fatalf("fully resolved alias project emitted diagnostic: %#v", diagnostic)
		}
	}
}

func TestUsingForResolutionHonorsReceiverTypeArityAndAmbiguity(t *testing.T) {
	db, file := buildSourceText(t, "pragma solidity ^0.8.20;\nlibrary UintLib { function plus(uint256 self, uint256 x) internal pure returns (uint256) { return self + x; } }\nlibrary AddressLib { function plus(address self, uint256 x) internal pure returns (address) { self; x; return self; } }\ncontract Uses { using UintLib for uint256; using AddressLib for address; function run(uint256 x, address a) external { x.plus(1); a.plus(1); } }\n")
	runID := types.MakeFunctionID(file, "Uses", "run(uint256,address)")
	assertExactTargets(t, db.CallGraph.GetCallees(runID),
		types.MakeFunctionID(file, "UintLib", "plus(uint256,uint256)"),
		types.MakeFunctionID(file, "AddressLib", "plus(address,uint256)"),
	)

	ambiguousDB, ambiguousFile := buildSourceText(t, "pragma solidity ^0.8.20;\nlibrary A { function ext(uint256 self, uint256 x) internal pure returns (uint256) { return self + x; } }\nlibrary B { function ext(uint256 self, uint256 x) internal pure returns (uint256) { return self + x; } }\ncontract Uses { using A for uint256; using B for uint256; function run(uint256 x) external { x.ext(1); } }\n")
	ambiguousEdges := ambiguousDB.CallGraph.GetCallees(types.MakeFunctionID(ambiguousFile, "Uses", "run(uint256)"))
	if len(ambiguousEdges) != 1 || ambiguousEdges[0].CalledName != "ext" || ambiguousEdges[0].Resolved || ambiguousEdges[0].Type != types.CallTypeLibrary {
		t.Fatalf("ambiguous using-for edge = %#v, want one unresolved library ext", ambiguousEdges)
	}
}

func assertExactTargets(t *testing.T, edges []*types.CallEdge, want ...string) {
	t.Helper()
	got := make(map[string]bool, len(edges))
	for _, edge := range edges {
		got[edge.To] = true
	}
	for _, target := range want {
		if !got[target] {
			t.Errorf("missing target %q; got %v", target, edgeTargets(edges))
		}
	}
	if len(edges) != len(want) {
		t.Errorf("targets = %v, want exactly %v", edgeTargets(edges), want)
	}
}

func exactContractIDs(contracts []*types.Contract) []string {
	ids := make([]string, 0, len(contracts))
	for _, contract := range contracts {
		if contract != nil {
			ids = append(ids, contract.ID)
		}
	}
	return ids
}

func buildSourceText(t *testing.T, source string) (*types.Database, string) {
	t.Helper()
	file := filepath.Join(t.TempDir(), "Fixture.sol")
	if err := os.WriteFile(file, []byte(source), 0o644); err != nil {
		t.Fatal(err)
	}
	r := reader.New()
	sources, err := r.Read(file)
	if err != nil {
		t.Fatal(err)
	}
	file = sources[0].Path
	db, err := New().Build(sources)
	if err != nil {
		t.Fatal(err)
	}
	return db, file
}

func findFunctionBySelector(t *testing.T, contract *types.Contract, selector string) *types.Function {
	t.Helper()
	for _, fn := range contract.Functions {
		if fn.Selector == selector {
			return fn
		}
	}
	t.Fatalf("function %s.%s missing", contract.Name, selector)
	return nil
}

func assertCallNames(t *testing.T, calls []*types.FunctionCall, want ...string) {
	t.Helper()
	got := make([]string, 0, len(calls))
	for _, call := range calls {
		got = append(got, call.Target)
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("call names = %v, want %v", got, want)
	}
}

func findFunction(t *testing.T, contract *types.Contract, name string) *types.Function {
	t.Helper()
	for _, fn := range contract.Functions {
		if fn.Name == name {
			return fn
		}
	}
	t.Fatalf("function %s.%s missing", contract.Name, name)
	return nil
}

func findModifier(t *testing.T, contract *types.Contract, name string) *types.Modifier {
	t.Helper()
	for _, modifier := range contract.Modifiers {
		if modifier.Name == name {
			return modifier
		}
	}
	t.Fatalf("modifier %s.%s missing", contract.Name, name)
	return nil
}

func assertFunctionCallsResolveTo(t *testing.T, fn *types.Function, contractID string) {
	t.Helper()
	if len(fn.Calls) == 0 {
		t.Fatalf("%s has no calls", fn.Name)
	}
	for _, call := range fn.Calls {
		if call.ResolvedContractID != contractID {
			t.Errorf("%s call %s resolvedContractId = %q, want %q", fn.Name, call.Target, call.ResolvedContractID, contractID)
		}
	}
}

func assertModifierCallsResolveTo(t *testing.T, modifier *types.Modifier, contractID string) {
	t.Helper()
	if len(modifier.Calls) == 0 {
		t.Fatalf("modifier %s has no calls", modifier.Name)
	}
	for _, call := range modifier.Calls {
		if call.ResolvedContractID != contractID {
			t.Errorf("modifier %s call %s resolvedContractId = %q, want %q", modifier.Name, call.Target, call.ResolvedContractID, contractID)
		}
	}
}
