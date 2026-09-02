package builder

import (
	"encoding/json"
	"reflect"
	"sort"
	"strconv"
	"testing"

	"github.com/th13vn/w3goaudit/pkg/types"
)

const externalBoundariesFixture = "../../test-data/core/semantic-hardening/external-boundaries.sol"

func TestBuildExternalBoundariesClassifiesTargetsAndValues(t *testing.T) {
	db := buildFixture(t, externalBoundariesFixture)
	abs := fixtureAbs(t, externalBoundariesFixture)
	contractID := types.MakeContractID(abs, "ExternalBoundaryMatrix")

	controlled := boundaryFact(t, db, contractID, "callerControlled(address[],uint256,uint256,bytes)", types.KindCallLowlevelCall)
	if controlled.Receiver == nil || controlled.Receiver.Control != types.BoundaryValueCallerControlled {
		t.Fatalf("controlled receiver = %+v", controlled.Receiver)
	}
	if controlled.Value == nil || controlled.Value.Control != types.BoundaryValueCallerControlled {
		t.Fatalf("call value = %+v", controlled.Value)
	}
	if controlled.Gas == nil || controlled.Gas.Control != types.BoundaryValueFixed {
		t.Fatalf("call gas = %+v", controlled.Gas)
	}
	if len(controlled.Arguments) != 1 || controlled.Arguments[0].Index != 0 || controlled.Arguments[0].Control != types.BoundaryValueCallerControlled {
		t.Fatalf("call arguments = %+v", controlled.Arguments)
	}

	state := boundaryFact(t, db, contractID, "stateDerived(uint256,bytes)", types.KindCallLowlevelCall)
	if state.Receiver == nil || state.Receiver.Control != types.BoundaryValueStateDerived {
		t.Fatalf("state-derived receiver = %+v", state.Receiver)
	}

	exact := boundaryFact(t, db, contractID, "exactTarget(IBoundaryTarget,bytes)", types.KindCallExternal)
	wantTarget := types.MakeContractID(abs, "IBoundaryTarget")
	if exact.Target.Resolution != types.BoundaryTargetResolved || exact.Target.ContractID != wantTarget || exact.Target.FunctionSelector != "ping(bytes)" {
		t.Fatalf("exact target = %+v", exact.Target)
	}
	if controlled.Target.Resolution != types.BoundaryTargetUnresolved || controlled.Target.ContractID != "" {
		t.Fatalf("dynamic target guessed: %+v", controlled.Target)
	}
}

func TestBuildExternalBoundariesCoversSolidityAndYulKinds(t *testing.T) {
	db := buildFixture(t, externalBoundariesFixture)
	got := map[string]bool{}
	for _, fact := range db.Semantics.ExternalBoundaries {
		got[fact.Kind] = true
	}
	want := []string{
		types.KindCallExternal, types.KindCallLowlevelCall, types.KindCallLowlevelDelegate,
		types.KindCallLowlevelStatic, types.KindCallBuiltinTransfer, types.KindCallBuiltinSend,
		types.KindCallCreate, types.KindAsmCall, types.KindAsmDelegatecall,
		types.KindAsmStaticcall, types.KindAsmCreate, types.KindAsmCreate2,
	}
	for _, kind := range want {
		if !got[kind] {
			t.Errorf("boundary kind %s not indexed; got=%v", kind, got)
		}
	}
	create := boundaryFact(t, db, types.MakeContractID(fixtureAbs(t, externalBoundariesFixture), "ExternalBoundaryMatrix"), "createKinds(uint256)", types.KindCallCreate)
	if create.Target.Resolution != types.BoundaryTargetResolved || create.Target.ContractID != types.MakeContractID(fixtureAbs(t, externalBoundariesFixture), "BoundaryChild") {
		t.Fatalf("create target = %+v", create.Target)
	}
	if db.Semantics.ExternalBoundaryVersion != types.ExternalBoundaryFactsVersion {
		t.Fatalf("facts version = %q", db.Semantics.ExternalBoundaryVersion)
	}
}

func TestBuildExternalBoundariesAnnotatesProtocolNeutralWQLAttributes(t *testing.T) {
	db := buildFixture(t, externalBoundariesFixture)
	abs := fixtureAbs(t, externalBoundariesFixture)
	fact := boundaryFact(t, db, types.MakeContractID(abs, "ExternalBoundaryMatrix"), "callerControlled(address[],uint256,uint256,bytes)", types.KindCallLowlevelCall)
	fn, ok := db.GetFunctionByID(fact.FunctionID)
	if !ok {
		t.Fatalf("function %s missing", fact.FunctionID)
	}
	node := findASTNodeByPath(fn.AST, fact.ASTPath)
	if node == nil {
		t.Fatalf("AST path %s missing", fact.ASTPath)
	}
	checks := map[string]string{
		"external_boundary_id":       fact.ID,
		"boundary_target_resolution": types.BoundaryTargetUnresolved,
		"boundary_receiver_control":  string(types.BoundaryValueCallerControlled),
		"boundary_value_control":     string(types.BoundaryValueCallerControlled),
	}
	for key, want := range checks {
		if got := node.GetAttributeString(key); got != want {
			t.Errorf("%s = %q, want %q", key, got, want)
		}
	}
	if !node.GetAttributeBool("boundary_arguments_controlled") {
		t.Error("boundary_arguments_controlled is false")
	}
}

func TestBuildExternalBoundariesDeterministicAcrossBuilds(t *testing.T) {
	first := buildFixture(t, externalBoundariesFixture)
	second := buildFixture(t, externalBoundariesFixture)
	firstJSON, err := json.Marshal(first.Semantics.ExternalBoundaries)
	if err != nil {
		t.Fatal(err)
	}
	secondJSON, err := json.Marshal(second.Semantics.ExternalBoundaries)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(firstJSON, secondJSON) {
		t.Fatalf("boundary facts differ across builds\nfirst: %s\nsecond: %s", firstJSON, secondJSON)
	}
	ids := make([]string, 0, len(first.Semantics.ExternalBoundaries))
	for _, fact := range first.Semantics.ExternalBoundaries {
		ids = append(ids, fact.ID)
	}
	if !sort.StringsAreSorted(ids) {
		t.Fatalf("fact IDs not sorted: %v", ids)
	}
}

func boundaryFact(t *testing.T, db *types.Database, contractID, selector, kind string) *types.ExternalBoundaryFact {
	t.Helper()
	functionID := types.MakeFunctionID(db.Contracts[contractID].SourceFile, db.Contracts[contractID].Name, selector)
	var matches []*types.ExternalBoundaryFact
	for _, fact := range db.Semantics.ExternalBoundaries {
		if fact.ContractID == contractID && fact.FunctionID == functionID && fact.Kind == kind {
			matches = append(matches, fact)
		}
	}
	if len(matches) != 1 {
		t.Fatalf("facts for %s %s = %d, want 1: %+v", selector, kind, len(matches), matches)
	}
	return matches[0]
}

func findASTNodeByPath(root *types.ASTNode, path string) *types.ASTNode {
	if root == nil || path == "" {
		return nil
	}
	var found *types.ASTNode
	var walk func(*types.ASTNode, string)
	walk = func(node *types.ASTNode, current string) {
		if node == nil || found != nil {
			return
		}
		if current == path {
			found = node
			return
		}
		for index, child := range node.Children {
			walk(child, current+"."+strconv.Itoa(index))
		}
	}
	walk(root, "0")
	return found
}
