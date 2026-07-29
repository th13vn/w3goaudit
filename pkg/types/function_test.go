package types

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIsAccessControlledDoesNotTrustRoleModifierNames(t *testing.T) {
	tests := []struct {
		name     string
		modifier string
	}{
		{name: "operator", modifier: "onlyOperator"},
		{name: "governance", modifier: "onlyGovernance"},
		{name: "guardian", modifier: "onlyGuardian"},
		{name: "manager", modifier: "onlyManager"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fn := &Function{
				Name:      "guarded",
				Modifiers: []string{tt.modifier},
			}

			if fn.IsAccessControlled(NewDatabase()) {
				t.Fatalf("modifier name %s must not prove access control", tt.modifier)
			}
		})
	}
}

func TestFunctionCallArgCountJSONPresence(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want int
	}{
		{name: "missing is unknown", raw: `{"target":"helper","callType":"internal"}`, want: -1},
		{name: "explicit zero", raw: `{"target":"helper","callType":"internal","argCount":0}`, want: 0},
		{name: "positive", raw: `{"target":"helper","callType":"internal","argCount":2}`, want: 2},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var call FunctionCall
			if err := json.Unmarshal([]byte(tc.raw), &call); err != nil {
				t.Fatalf("json.Unmarshal: %v", err)
			}
			if call.ArgCount != tc.want {
				t.Fatalf("ArgCount = %d, want %d", call.ArgCount, tc.want)
			}
		})
	}

	call := FunctionCall{Target: "helper", CallType: CallTypeInternal, ArgCount: 0}
	first, err := json.Marshal(&call)
	if err != nil {
		t.Fatalf("first marshal: %v", err)
	}
	if !bytes.Contains(first, []byte(`"argCount":0`)) {
		t.Fatalf("zero argCount omitted from JSON: %s", first)
	}
	var roundTripped FunctionCall
	if err := json.Unmarshal(first, &roundTripped); err != nil {
		t.Fatalf("round-trip unmarshal: %v", err)
	}
	if roundTripped.ArgCount != 0 {
		t.Fatalf("round-trip ArgCount = %d, want 0", roundTripped.ArgCount)
	}
	second, err := json.Marshal(&roundTripped)
	if err != nil {
		t.Fatalf("second marshal: %v", err)
	}
	if !bytes.Contains(second, []byte(`"argCount":0`)) {
		t.Fatalf("zero argCount omitted after second marshal: %s", second)
	}
}

func TestLoadFromJSONMissingFunctionCallArgCountIsUnknown(t *testing.T) {
	db := NewDatabase()
	contract := &Contract{
		Name:       "C",
		SourceFile: "/repo/C.sol",
		Functions: []*Function{{
			Name:         "run",
			ContractName: "C",
			Calls: []*FunctionCall{{
				Target:   "helper",
				CallType: CallTypeInternal,
				ArgCount: 0,
			}},
		}},
	}
	db.AddContract(contract)
	raw, err := json.Marshal(db)
	if err != nil {
		t.Fatalf("marshal database: %v", err)
	}
	var legacy map[string]any
	if err := json.Unmarshal(raw, &legacy); err != nil {
		t.Fatalf("decode database JSON: %v", err)
	}
	contracts := legacy["contracts"].(map[string]any)
	contractJSON := contracts[contract.ID].(map[string]any)
	functions := contractJSON["functions"].([]any)
	calls := functions[0].(map[string]any)["calls"].([]any)
	delete(calls[0].(map[string]any), "argCount")
	legacyRaw, err := json.Marshal(legacy)
	if err != nil {
		t.Fatalf("marshal legacy database: %v", err)
	}
	path := filepath.Join(t.TempDir(), "legacy.json")
	if err := os.WriteFile(path, legacyRaw, 0o644); err != nil {
		t.Fatalf("write legacy database: %v", err)
	}

	loaded, err := LoadFromJSON(path)
	if err != nil {
		t.Fatalf("LoadFromJSON: %v", err)
	}
	got := loaded.GetContractByID(contract.ID).Functions[0].Calls[0].ArgCount
	if got != -1 {
		t.Fatalf("legacy missing ArgCount = %d, want -1", got)
	}
}

// TestEntryFunctionsPreferDerivedOverrideOverBase pins that the most-derived
// declaration of a selector claims it, even when that override is NOT itself an
// entry point.
//
// The bug this covers produced 7 false positives on Uniswap v4 IHooks in a real
// scan. `IsEntrypoint()` was checked before the override dedup, so a derived
// override that is `view`/`pure` never occupied its signature slot and the
// inherited INTERFACE declaration — nonpayable, hence an entry point — was
// admitted in its place. Every access-control detector then fired on a bodyless
// interface stub, where there is nothing to fix.
//
// The correct model is the documented one: the most-derived override wins. If that
// override is not externally callable in a state-changing way, the selector simply
// has no entry function.
func TestEntryFunctionsPreferDerivedOverrideOverBase(t *testing.T) {
	db := NewDatabase()

	// Interface declares a nonpayable external function (an entry point shape).
	iface := &Contract{
		Name: "IHooks", Kind: ContractKindInterface, SourceFile: "/src/IHooks.sol",
		Functions: []*Function{{
			Name: "afterInitialize", ContractName: "IHooks", SourceFile: "/src/IHooks.sol",
			Visibility: "external", Selector: "afterInitialize(address)",
		}},
	}
	// The implementation overrides it as `pure`, so it is not an entry point.
	impl := &Contract{
		Name: "Hook", Kind: ContractKindContract, SourceFile: "/src/Hook.sol",
		BaseContracts: []string{"IHooks"},
		Functions: []*Function{{
			Name: "afterInitialize", ContractName: "Hook", SourceFile: "/src/Hook.sol",
			Visibility: "external", StateMutability: "pure", Selector: "afterInitialize(address)",
		}},
	}
	for _, contract := range []*Contract{iface, impl} {
		db.AddContract(contract)
		db.SourceFiles[contract.SourceFile] = &SourceFile{Path: contract.SourceFile}
	}
	impl.LinearizedBaseIDs = []string{impl.ID, iface.ID}

	entries := db.buildEntryFunctionsForContract(impl)
	for _, id := range entries {
		if strings.Contains(id, "#IHooks.") {
			t.Errorf("inherited interface declaration selected as an entry function: %s\n"+
				"the derived `pure` override must claim the selector and yield no entry point", id)
		}
	}
	if len(entries) != 0 {
		t.Errorf("entry functions = %v, want none (the only override is pure)", entries)
	}
}

// TestEntryFunctionsKeepDerivedEntrypointOverride is the positive control: when the
// derived override IS an entry point, it — and not the base — is selected.
func TestEntryFunctionsKeepDerivedEntrypointOverride(t *testing.T) {
	db := NewDatabase()
	base := &Contract{
		Name: "Base", Kind: ContractKindAbstract, SourceFile: "/src/Base.sol",
		Functions: []*Function{{
			Name: "act", ContractName: "Base", SourceFile: "/src/Base.sol",
			Visibility: "external", Selector: "act()",
		}},
	}
	derived := &Contract{
		Name: "Derived", Kind: ContractKindContract, SourceFile: "/src/Derived.sol",
		BaseContracts: []string{"Base"},
		Functions: []*Function{{
			Name: "act", ContractName: "Derived", SourceFile: "/src/Derived.sol",
			Visibility: "external", Selector: "act()",
		}},
	}
	for _, contract := range []*Contract{base, derived} {
		db.AddContract(contract)
		db.SourceFiles[contract.SourceFile] = &SourceFile{Path: contract.SourceFile}
	}
	derived.LinearizedBaseIDs = []string{derived.ID, base.ID}

	entries := db.buildEntryFunctionsForContract(derived)
	if len(entries) != 1 || !strings.Contains(entries[0], "#Derived.") {
		t.Errorf("entry functions = %v, want the derived override only", entries)
	}
}

// TestEntryFunctionsKeepInheritedImplementationWhenNotOverridden keeps the ordinary
// inheritance case working: a base implementation that the derived contract does not
// override remains an entry function, attributed to the base that declares it.
func TestEntryFunctionsKeepInheritedImplementationWhenNotOverridden(t *testing.T) {
	db := NewDatabase()
	base := &Contract{
		Name: "Base", Kind: ContractKindContract, SourceFile: "/src/Base.sol",
		Functions: []*Function{{
			Name: "act", ContractName: "Base", SourceFile: "/src/Base.sol",
			Visibility: "external", Selector: "act()",
		}},
	}
	derived := &Contract{
		Name: "Derived", Kind: ContractKindContract, SourceFile: "/src/Derived.sol",
		BaseContracts: []string{"Base"},
	}
	for _, contract := range []*Contract{base, derived} {
		db.AddContract(contract)
		db.SourceFiles[contract.SourceFile] = &SourceFile{Path: contract.SourceFile}
	}
	derived.LinearizedBaseIDs = []string{derived.ID, base.ID}

	entries := db.buildEntryFunctionsForContract(derived)
	if len(entries) != 1 || !strings.Contains(entries[0], "#Base.act") {
		t.Errorf("entry functions = %v, want the inherited Base implementation", entries)
	}
}

// TestAccessControlResolvesVirtualHookOverride covers the OpenZeppelin UUPS
// pattern that produced CRITICAL false positives in a real scan.
//
// `UUPSUpgradeable.upgradeTo` calls `_authorizeUpgrade(newImplementation)`, which
// the base declares as `internal virtual;` with NO body. The concrete
// `onlyOwner` implementation is supplied by the deriving contract — that is the
// whole point of the hook. Resolving the call to the bodyless base declaration
// found no authorization and reported an unprotected upgrade on the most
// standard upgrade guard in the ecosystem.
//
// Solidity dispatches `virtual` internal calls through the RUNTIME contract's MRO,
// so the override must be resolved from the contract being analyzed, not from the
// contract that declares the hook.
func TestAccessControlResolvesVirtualHookOverride(t *testing.T) {
	db := NewDatabase()

	authorizeSelector := "_authorizeUpgrade(address)"

	// Base: declares the hook with no body, and calls it from upgradeTo.
	// Non-nil AST with no body statements, matching `internal virtual;` as the
	// builder records it. The override below is likewise empty-bodied, so body
	// presence cannot tell them apart — only MRO position can.
	baseHook := &Function{
		Name: "_authorizeUpgrade", ContractName: "UUPSUpgradeable",
		SourceFile: "/src/UUPS.sol", Visibility: "internal", Selector: authorizeSelector,
		AST: NewASTNode(KindDeclFunction),
	}
	upgradeTo := &Function{
		Name: "upgradeTo", ContractName: "UUPSUpgradeable", SourceFile: "/src/UUPS.sol",
		Visibility: "public", Selector: "upgradeTo(address)",
		Parameters: []*Parameter{{Name: "newImplementation", TypeName: "address"}},
		AST:        NewASTNode(KindDeclFunction),
		Calls: []*FunctionCall{{
			Target: "_authorizeUpgrade", CallType: CallTypeInternal, Resolved: true,
			ResolvedContractID: "/src/UUPS.sol#UUPSUpgradeable",
			ResolvedFunction:   authorizeSelector,
		}},
	}
	base := &Contract{
		Name: "UUPSUpgradeable", Kind: ContractKindAbstract, SourceFile: "/src/UUPS.sol",
		Functions: []*Function{upgradeTo, baseHook},
	}

	// Derived: supplies the real hook body, gated on an owner comparison.
	guard := NewASTNode(KindCheckRequire)
	comparison := NewASTNode(KindExprBinaryOp)
	comparison.SetAttribute("operator", "==")
	sender := NewASTNode(KindExprMemberAccess)
	sender.Name = "sender"
	senderBase := NewASTNode(KindExprIdentifier)
	senderBase.Name = "msg"
	sender.AddChild(senderBase)
	owner := NewASTNode(KindExprIdentifier)
	owner.Name = "_owner"
	owner.RefKind = "state_var"
	comparison.AddChild(sender)
	comparison.AddChild(owner)
	guard.AddChild(comparison)
	derivedHookAST := NewASTNode(KindDeclFunction)
	derivedHookAST.AddChild(guard)

	derivedHook := &Function{
		Name: "_authorizeUpgrade", ContractName: "Impl", SourceFile: "/src/Impl.sol",
		Visibility: "internal", Selector: authorizeSelector, AST: derivedHookAST,
	}
	derived := &Contract{
		Name: "Impl", Kind: ContractKindContract, SourceFile: "/src/Impl.sol",
		BaseContracts:  []string{"UUPSUpgradeable"},
		Functions:      []*Function{derivedHook},
		StateVariables: []*StateVariable{{Name: "_owner"}},
	}

	for _, contract := range []*Contract{base, derived} {
		db.AddContract(contract)
		db.SourceFiles[contract.SourceFile] = &SourceFile{Path: contract.SourceFile}
	}
	derived.LinearizedBaseIDs = []string{derived.ID, base.ID}
	base.LinearizedBaseIDs = []string{base.ID}

	if !upgradeTo.IsAccessControlledIn(db, derived) {
		t.Error("virtual hook override in the deriving contract must prove access control")
	}
}

// TestAccessControlVirtualHookWithoutOverrideStaysUnproven is the control: when no
// contract in the runtime MRO supplies an authorizing body, nothing is proven.
func TestAccessControlVirtualHookWithoutOverrideStaysUnproven(t *testing.T) {
	db := NewDatabase()
	authorizeSelector := "_authorizeUpgrade(address)"
	hook := &Function{
		Name: "_authorizeUpgrade", ContractName: "UUPSUpgradeable",
		SourceFile: "/src/UUPS.sol", Visibility: "internal", Selector: authorizeSelector,
	}
	upgradeTo := &Function{
		Name: "upgradeTo", ContractName: "UUPSUpgradeable", SourceFile: "/src/UUPS.sol",
		Visibility: "public", Selector: "upgradeTo(address)",
		AST: NewASTNode(KindDeclFunction),
		Calls: []*FunctionCall{{
			Target: "_authorizeUpgrade", CallType: CallTypeInternal, Resolved: true,
			ResolvedContractID: "/src/UUPS.sol#UUPSUpgradeable",
			ResolvedFunction:   authorizeSelector,
		}},
	}
	base := &Contract{
		Name: "UUPSUpgradeable", Kind: ContractKindAbstract, SourceFile: "/src/UUPS.sol",
		Functions: []*Function{upgradeTo, hook},
	}
	// A deriving contract that does NOT override the hook.
	derived := &Contract{
		Name: "Impl", Kind: ContractKindContract, SourceFile: "/src/Impl.sol",
		BaseContracts: []string{"UUPSUpgradeable"},
	}
	for _, contract := range []*Contract{base, derived} {
		db.AddContract(contract)
		db.SourceFiles[contract.SourceFile] = &SourceFile{Path: contract.SourceFile}
	}
	derived.LinearizedBaseIDs = []string{derived.ID, base.ID}

	if upgradeTo.IsAccessControlledIn(db, derived) {
		t.Error("an unoverridden bodyless hook proves nothing")
	}
}

// TestAccessControlSuperCallIsNotRedirected pins that virtual dispatch leaves
// `super.f()` alone.
//
// `super` targets the next contract after the caller in the MRO, so redirecting it
// to the most-derived declaration points it back at the caller and loses whatever
// the base proves. Euler's `EVault.transferFrom` is literally
// `return super.transferFrom(...)`, and redirecting it hid the base module's
// allowance check.
func TestAccessControlSuperCallIsNotRedirected(t *testing.T) {
	db := NewDatabase()
	selector := "act()"

	// Base supplies the authorizing body.
	guard := NewASTNode(KindCheckRequire)
	comparison := NewASTNode(KindExprBinaryOp)
	comparison.SetAttribute("operator", "==")
	sender := NewASTNode(KindExprMemberAccess)
	sender.Name = "sender"
	senderBase := NewASTNode(KindExprIdentifier)
	senderBase.Name = "msg"
	sender.AddChild(senderBase)
	owner := NewASTNode(KindExprIdentifier)
	owner.Name = "_owner"
	owner.RefKind = "state_var"
	comparison.AddChild(sender)
	comparison.AddChild(owner)
	guard.AddChild(comparison)
	baseAST := NewASTNode(KindDeclFunction)
	baseAST.AddChild(guard)

	baseAct := &Function{
		Name: "act", ContractName: "Base", SourceFile: "/src/Base.sol",
		Visibility: "public", Selector: selector, AST: baseAST,
	}
	base := &Contract{
		Name: "Base", Kind: ContractKindAbstract, SourceFile: "/src/Base.sol",
		Functions:      []*Function{baseAct},
		StateVariables: []*StateVariable{{Name: "_owner"}},
	}

	// Derived forwards to the base via `super` and proves nothing itself.
	derivedAct := &Function{
		Name: "act", ContractName: "Derived", SourceFile: "/src/Derived.sol",
		Visibility: "public", Selector: selector, AST: NewASTNode(KindDeclFunction),
		Calls: []*FunctionCall{{
			Target: "act", CallType: CallTypeSuper, Resolved: true,
			ResolvedContractID: "/src/Base.sol#Base", ResolvedFunction: selector,
		}},
	}
	derived := &Contract{
		Name: "Derived", Kind: ContractKindContract, SourceFile: "/src/Derived.sol",
		BaseContracts: []string{"Base"}, Functions: []*Function{derivedAct},
	}
	for _, contract := range []*Contract{base, derived} {
		db.AddContract(contract)
		db.SourceFiles[contract.SourceFile] = &SourceFile{Path: contract.SourceFile}
	}
	derived.LinearizedBaseIDs = []string{derived.ID, base.ID}

	if !derivedAct.IsAccessControlledIn(db, derived) {
		t.Error("super.act() must keep resolving to the base body that proves authorization")
	}
}

// TestUnresolvableAppliedModifierIsUndetermined covers the last false-positive
// class from the real scan.
//
// Axelar's `InterchainToken.burn` is `external onlyRole(uint8(Roles.MINTER))`, but
// some `@axelar-network/…` imports do not resolve, so `RolesBase` has no exact
// contract in the MRO and the applied modifier resolves to nothing. The analyzer
// then had NO information about the gate, yet concluded "not access controlled" and
// reported a role-gated burn as a public burn.
//
// A recorded-but-unresolvable modifier application is undetermined, not absent. The
// scan already reports the unresolved imports loudly (and `--strict-imports` fails
// on them), so the analyzer should not additionally manufacture a security finding
// out of its own incomplete view.
//
// This is deliberately narrower than trusting names: a modifier listed only in
// `Function.Modifiers`, with no recorded application, still proves nothing — that is
// what TestIsAccessControlledDoesNotTrustRoleModifierNames pins.
func TestUnresolvableAppliedModifierIsUndetermined(t *testing.T) {
	fn := &Function{
		Name:      "burn",
		Modifiers: []string{"onlyRole"},
		AST:       NewASTNode(KindDeclFunction),
		Calls: []*FunctionCall{{
			Target: "onlyRole", CallType: CallTypeModifier,
			// Unresolved: no ResolvedContractID / ResolvedFunction, exactly as the
			// builder records it when the declaring base is missing from the MRO.
			Resolved: false,
		}},
	}
	// A populated database whose MRO simply lacks the declaring base. An absent or
	// empty database is a different situation — "no context at all" — and still
	// proves nothing, which TestEffectsRequireExactSemanticAuthorization pins via
	// IsAccessControlled(nil).
	db := NewDatabase()
	host := &Contract{Name: "InterchainToken", Kind: ContractKindContract, SourceFile: "/src/T.sol"}
	db.AddContract(host)
	db.SourceFiles[host.SourceFile] = &SourceFile{Path: host.SourceFile}

	if !fn.IsAccessControlled(db) {
		t.Error("an applied modifier the analyzer cannot resolve is undetermined; " +
			"concluding 'unprotected' from an incomplete view is a false positive")
	}
	if fn.IsAccessControlled(nil) {
		t.Error("with no database at all there is no evidence of anything")
	}
}

// TestResolvableNonAuthorizingModifierStaysUnprotected is the control: when the
// modifier body IS visible and proves nothing, the function is still unprotected.
func TestResolvableNonAuthorizingModifierStaysUnprotected(t *testing.T) {
	db := NewDatabase()
	body := NewASTNode(KindDeclModifier)
	emit := NewASTNode(KindStmtEmit)
	body.AddChild(emit)

	contract := &Contract{
		Name: "C", Kind: ContractKindContract, SourceFile: "/src/C.sol",
		Modifiers: []*Modifier{{Name: "decorative", AST: body}},
	}
	db.AddContract(contract)
	db.SourceFiles[contract.SourceFile] = &SourceFile{Path: contract.SourceFile}

	fn := &Function{
		Name: "act", ContractName: "C", SourceFile: "/src/C.sol",
		Modifiers: []string{"decorative"},
		AST:       NewASTNode(KindDeclFunction),
		Calls: []*FunctionCall{{
			Target: "decorative", CallType: CallTypeModifier, Resolved: true,
			ResolvedContractID: contract.ID, ResolvedFunction: "decorative",
		}},
	}
	if fn.IsAccessControlled(db) {
		t.Error("a resolvable modifier that only emits an event must not prove access control")
	}
}
