package builder

import (
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
