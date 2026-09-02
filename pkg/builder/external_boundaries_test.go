package builder

import (
	"bytes"
	"encoding/json"
	"os"
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

func TestBuildExternalBoundariesClassifiesResultUseAndChecks(t *testing.T) {
	db := buildFixture(t, externalBoundariesFixture)
	contractID := types.MakeContractID(fixtureAbs(t, externalBoundariesFixture), "ExternalBoundaryMatrix")
	cases := []struct {
		selector     string
		kind         string
		availability string
		disposition  string
		directCheck  string
	}{
		{"capturedChecked(address,bytes)", types.KindCallLowlevelCall, types.BoundaryResultYes, types.BoundaryResultCaptured, types.BoundaryResultYes},
		{"capturedUnchecked(address,bytes)", types.KindCallLowlevelCall, types.BoundaryResultYes, types.BoundaryResultCaptured, types.BoundaryResultNo},
		{"discarded(address,bytes)", types.KindCallLowlevelCall, types.BoundaryResultYes, types.BoundaryResultDiscarded, types.BoundaryResultNo},
		{"returned(address,bytes)", types.KindCallLowlevelCall, types.BoundaryResultYes, types.BoundaryResultReturned, types.BoundaryResultNo},
		{"directCondition(address,uint256)", types.KindCallBuiltinSend, types.BoundaryResultYes, types.BoundaryResultCondition, types.BoundaryResultYes},
		{"consumed(address,uint256)", types.KindCallBuiltinSend, types.BoundaryResultYes, types.BoundaryResultConsumed, types.BoundaryResultNo},
		{"etherKinds(address,uint256)", types.KindCallBuiltinTransfer, types.BoundaryResultNo, types.BoundaryResultNone, types.BoundaryResultNo},
	}
	for _, tc := range cases {
		t.Run(tc.selector, func(t *testing.T) {
			fact := boundaryFact(t, db, contractID, tc.selector, tc.kind)
			if fact.Result.Availability != tc.availability || fact.Result.Disposition != tc.disposition || fact.Result.DirectCheck != tc.directCheck {
				t.Fatalf("result = %+v, want availability=%s disposition=%s directCheck=%s", fact.Result, tc.availability, tc.disposition, tc.directCheck)
			}
			if tc.directCheck == types.BoundaryResultYes && len(fact.Result.CheckSites) == 0 {
				t.Fatal("checked result has no enforcing site")
			}
		})
	}
	unchecked := boundaryFact(t, db, contractID, "capturedUnchecked(address,bytes)", types.KindCallLowlevelCall)
	if len(unchecked.Result.Targets) != 1 || unchecked.Result.Targets[0].Expression != "looksChecked" {
		t.Fatalf("captured result targets = %+v", unchecked.Result.Targets)
	}
}

func TestBuildExternalBoundariesRelatesDirectStateEffects(t *testing.T) {
	db := buildFixture(t, externalBoundariesFixture)
	contractID := types.MakeContractID(fixtureAbs(t, externalBoundariesFixture), "ExternalBoundaryMatrix")
	cases := []struct {
		selector string
		want     string
	}{
		{"stateBefore(address,bytes)", types.BoundaryStateBefore},
		{"stateAfter(address,bytes)", types.BoundaryStateAfter},
		{"incompatible(address,bytes,bool)", types.BoundaryStateIncompatible},
		{"unordered(address,uint256)", types.BoundaryStateUnordered},
		{"loopUnknown(address,uint256)", types.BoundaryStateUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.selector, func(t *testing.T) {
			kind := types.KindCallLowlevelCall
			if tc.selector == "unordered(address,uint256)" || tc.selector == "loopUnknown(address,uint256)" {
				kind = types.KindCallBuiltinSend
			}
			fact := boundaryFact(t, db, contractID, tc.selector, kind)
			if len(fact.StateEffects) != 1 || fact.StateEffects[0].Name != "total" || fact.StateEffects[0].Relation != tc.want {
				t.Fatalf("state effects = %+v, want one total/%s", fact.StateEffects, tc.want)
			}
		})
	}
}

func TestBuildExternalBoundariesClassifiesReentryAndLimitations(t *testing.T) {
	db := buildFixture(t, externalBoundariesFixture)
	contractID := types.MakeContractID(fixtureAbs(t, externalBoundariesFixture), "ExternalBoundaryMatrix")
	cases := []struct {
		selector string
		kind     string
		want     string
	}{
		{"callerControlled(address[],uint256,uint256,bytes)", types.KindCallLowlevelCall, types.BoundaryReentryPossible},
		{"lowLevelKinds(address,bytes)", types.KindCallLowlevelDelegate, types.BoundaryReentryDelegateContext},
		{"lowLevelKinds(address,bytes)", types.KindCallLowlevelStatic, types.BoundaryReentryReadOnlyPossible},
		{"etherKinds(address,uint256)", types.KindCallBuiltinSend, types.BoundaryReentryStipendLimited},
		{"selfTarget(bytes)", types.KindCallExternal, types.BoundaryReentrySameContract},
		{"createKinds(uint256)", types.KindCallCreate, types.BoundaryReentryConstructorPossible},
	}
	for _, tc := range cases {
		fact := boundaryFact(t, db, contractID, tc.selector, tc.kind)
		if fact.ReentryClass != tc.want {
			t.Errorf("%s %s reentry = %q, want %q", tc.selector, tc.kind, fact.ReentryClass, tc.want)
		}
		if len(fact.Limitations) == 0 {
			t.Errorf("%s %s has no explicit limitations", tc.selector, tc.kind)
		}
	}

	stateAfter := boundaryFact(t, db, contractID, "stateAfter(address,bytes)", types.KindCallLowlevelCall)
	fn, _ := db.GetFunctionByID(stateAfter.FunctionID)
	node := findASTNodeByPath(fn.AST, stateAfter.ASTPath)
	if node.GetAttributeString("boundary_result_disposition") != types.BoundaryResultDiscarded ||
		node.GetAttributeString("boundary_result_checked") != types.BoundaryResultNo ||
		!node.GetAttributeBool("boundary_has_state_after") {
		t.Fatalf("completed WQL bridge attrs = %+v", node.Attributes)
	}
}

func TestBuildExternalBoundariesRecordsExactEntryReachability(t *testing.T) {
	db := buildFixture(t, externalBoundariesFixture)
	abs := fixtureAbs(t, externalBoundariesFixture)
	contractID := types.MakeContractID(abs, "ExternalBoundaryMatrix")
	direct := boundaryFact(t, db, contractID, "callerControlled(address[],uint256,uint256,bytes)", types.KindCallLowlevelCall)
	wantDirect := types.MakeFunctionID(abs, "ExternalBoundaryMatrix", "callerControlled(address[],uint256,uint256,bytes)")
	if !reflect.DeepEqual(direct.ReachableFrom, []string{wantDirect}) {
		t.Fatalf("direct reachability = %v, want %v", direct.ReachableFrom, []string{wantDirect})
	}

	helper := boundaryFact(t, db, contractID, "_helper(address,bytes)", types.KindCallLowlevelCall)
	wantHelper := types.MakeFunctionID(abs, "ExternalBoundaryMatrix", "helperEntry(address,bytes)")
	if !reflect.DeepEqual(helper.ReachableFrom, []string{wantHelper}) {
		t.Fatalf("helper reachability = %v, want %v", helper.ReachableFrom, []string{wantHelper})
	}

	libraryContractID := types.MakeContractID(abs, "BoundaryLibrary")
	library := boundaryFact(t, db, libraryContractID, "forward(address,bytes)", types.KindCallLowlevelCall)
	wantLibrary := types.MakeFunctionID(abs, "ExternalBoundaryMatrix", "libraryEntry(address,bytes)")
	if !reflect.DeepEqual(library.ReachableFrom, []string{wantLibrary}) {
		t.Fatalf("library reachability = %v, want %v", library.ReachableFrom, []string{wantLibrary})
	}

	orphan := boundaryFact(t, db, contractID, "_orphan(address,bytes)", types.KindCallLowlevelCall)
	if len(orphan.ReachableFrom) != 0 {
		t.Fatalf("internal-only boundary reachability = %v, want none", orphan.ReachableFrom)
	}

	fn, _ := db.GetFunctionByID(helper.FunctionID)
	node := findASTNodeByPath(fn.AST, helper.ASTPath)
	if !node.GetAttributeBool("boundary_reachable_from_entry") {
		t.Fatalf("reachable boundary AST attributes = %+v", node.Attributes)
	}
}

func TestBuildExternalBoundariesIndexesModifierHostedBoundary(t *testing.T) {
	db := buildFixture(t, externalBoundariesFixture)
	abs := fixtureAbs(t, externalBoundariesFixture)
	contractID := types.MakeContractID(abs, "ExternalBoundaryMatrix")
	scopeID := types.MakeModifierID(abs, "ExternalBoundaryMatrix", "boundaryCall")
	entryID := types.MakeFunctionID(abs, "ExternalBoundaryMatrix", "modifierEntry(address,bytes)")

	fact := boundaryScopeFact(t, db, contractID, scopeID, types.KindCallLowlevelCall)
	if fact.ScopeKind != types.ExternalBoundaryScopeModifier || fact.FunctionID != "" {
		t.Fatalf("modifier scope identity = kind %q function %q", fact.ScopeKind, fact.FunctionID)
	}
	if !reflect.DeepEqual(fact.ReachableFrom, []string{entryID}) {
		t.Fatalf("modifier reachability = %v, want %v", fact.ReachableFrom, []string{entryID})
	}
	if fact.Receiver == nil || fact.Receiver.Control != types.BoundaryValueCallerControlled {
		t.Fatalf("modifier receiver = %+v", fact.Receiver)
	}
	if fact.Result.Disposition != types.BoundaryResultCaptured || fact.Result.DirectCheck != types.BoundaryResultYes {
		t.Fatalf("modifier result evidence = %+v", fact.Result)
	}

	contract := db.GetContractByID(contractID)
	if contract == nil {
		t.Fatal("modifier contract missing")
	}
	var modifier *types.Modifier
	for _, candidate := range contract.Modifiers {
		if candidate != nil && candidate.Name == "boundaryCall" {
			modifier = candidate
			break
		}
	}
	if modifier == nil {
		t.Fatal("modifier missing")
	}
	node := findASTNodeByPath(modifier.AST, fact.ASTPath)
	if node == nil || node.GetAttributeString("external_boundary_id") != fact.ID {
		t.Fatalf("modifier boundary AST attributes = %+v", node)
	}
}

func TestBuildExternalBoundariesIndexesQueryableConstructorBoundary(t *testing.T) {
	db := buildFixture(t, externalBoundariesFixture)
	abs := fixtureAbs(t, externalBoundariesFixture)
	contractID := types.MakeContractID(abs, "ExternalBoundaryMatrix")
	scopeID := types.MakeFunctionID(abs, "ExternalBoundaryMatrix", "constructor")

	fact := boundaryScopeFact(t, db, contractID, scopeID, types.KindCallLowlevelCall)
	if fact.ScopeKind != types.ExternalBoundaryScopeFunction || fact.FunctionID != scopeID {
		t.Fatalf("constructor scope identity = kind %q function %q", fact.ScopeKind, fact.FunctionID)
	}
	if len(fact.ReachableFrom) != 0 {
		t.Fatalf("constructor reachability = %v, want no runtime entry", fact.ReachableFrom)
	}

	page, err := db.QueryExternalBoundaries(types.ExternalBoundaryQuery{ScopeID: scopeID, Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if page.Total != 1 || len(page.Items) != 1 || page.Items[0].ID != fact.ID {
		t.Fatalf("constructor scope page = %+v", page)
	}
}

func TestExternalBoundaryFactsSourceCacheParity(t *testing.T) {
	db := buildFixture(t, externalBoundariesFixture)
	raw, err := json.Marshal(db)
	if err != nil {
		t.Fatal(err)
	}
	cache := t.TempDir() + "/database.json"
	if err := os.WriteFile(cache, raw, 0600); err != nil {
		t.Fatal(err)
	}
	loaded, err := types.LoadFromJSON(cache)
	if err != nil {
		t.Fatal(err)
	}
	freshFacts, _ := json.Marshal(db.Semantics.ExternalBoundaries)
	cachedFacts, _ := json.Marshal(loaded.Semantics.ExternalBoundaries)
	if !bytes.Equal(freshFacts, cachedFacts) {
		t.Fatalf("source/cache facts differ\nfresh: %s\ncached: %s", freshFacts, cachedFacts)
	}
	for _, fact := range loaded.Semantics.ExternalBoundaries {
		node := findBoundaryScopeAST(loaded, fact)
		if node == nil || node.GetAttributeString("external_boundary_id") != fact.ID || node.GetAttributeString("boundary_result_disposition") != fact.Result.Disposition {
			t.Fatalf("cached fact-backed attributes differ for %s: %+v", fact.ID, node)
		}
	}
}

func boundaryFact(t *testing.T, db *types.Database, contractID, selector, kind string) *types.ExternalBoundaryFact {
	t.Helper()
	functionID := types.MakeFunctionID(db.Contracts[contractID].SourceFile, db.Contracts[contractID].Name, selector)
	return boundaryScopeFact(t, db, contractID, functionID, kind)
}

func boundaryScopeFact(t *testing.T, db *types.Database, contractID, scopeID, kind string) *types.ExternalBoundaryFact {
	t.Helper()
	var matches []*types.ExternalBoundaryFact
	for _, fact := range db.Semantics.ExternalBoundaries {
		if fact.ContractID == contractID && fact.ScopeID == scopeID && fact.Kind == kind {
			matches = append(matches, fact)
		}
	}
	if len(matches) != 1 {
		t.Fatalf("facts for %s %s = %d, want 1: %+v", scopeID, kind, len(matches), matches)
	}
	return matches[0]
}

func findBoundaryScopeAST(db *types.Database, fact *types.ExternalBoundaryFact) *types.ASTNode {
	if db == nil || fact == nil {
		return nil
	}
	if fact.ScopeKind == types.ExternalBoundaryScopeFunction {
		fn, ok := db.GetFunctionByID(fact.ScopeID)
		if !ok {
			return nil
		}
		return findASTNodeByPath(fn.AST, fact.ASTPath)
	}
	if fact.ScopeKind == types.ExternalBoundaryScopeModifier {
		contract := db.GetContractByID(fact.ContractID)
		if contract == nil {
			return nil
		}
		for _, modifier := range contract.Modifiers {
			if modifier != nil && types.MakeModifierID(contract.SourceFile, contract.Name, modifier.Name) == fact.ScopeID {
				return findASTNodeByPath(modifier.AST, fact.ASTPath)
			}
		}
	}
	return nil
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
