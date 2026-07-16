package engine

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/th13vn/w3goaudit/pkg/types"
)

// ─── Token Call & Guard Alias ────────────────────────────────────────────────

func TestMatchKindGuardAlias(t *testing.T) {
	db := types.NewDatabase()
	e := New(db)

	tests := []struct {
		name      string
		nodeKind  string
		queryKind string
		expected  bool
	}{
		// guard = alias for check (semantic group)
		{"guard matches check.require", types.KindCheckRequire, "guard", true},
		{"guard matches check.assert", types.KindCheckAssert, "guard", true},
		{"guard matches check.revert", types.KindCheckRevert, "guard", true},
		{"guard does NOT match call.external", types.KindCallExternal, "guard", false},

		// guard.require = alias for check.require
		{"guard.require matches check.require", types.KindCheckRequire, "guard.require", true},
		{"guard.assert matches check.assert", types.KindCheckAssert, "guard.assert", true},
		{"guard.revert matches check.revert", types.KindCheckRevert, "guard.revert", true},
		{"guard.require does NOT match check.assert", types.KindCheckAssert, "guard.require", false},

		// check still works as before
		{"check still matches check.require", types.KindCheckRequire, "check", true},
		{"check.require still matches check.require", types.KindCheckRequire, "check.require", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			node := &types.ASTNode{Kind: tt.nodeKind}
			result := e.matchKind(node, tt.queryKind)
			if result != tt.expected {
				t.Errorf("matchKind(%q, %q) = %v, want %v", tt.nodeKind, tt.queryKind, result, tt.expected)
			}
		})
	}
}

func TestMatchKindTokenCall(t *testing.T) {
	db := types.NewDatabase()
	e := New(db)

	tests := []struct {
		name     string
		nodeKind string
		expected bool
	}{
		{"token_call matches call.external", types.KindCallExternal, true},
		{"token_call does NOT match call.internal", types.KindCallInternal, false},
		{"token_call does NOT match call.lowlevel.call", types.KindCallLowlevelCall, false},
		{"token_call does NOT match check.require", types.KindCheckRequire, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			node := &types.ASTNode{Kind: tt.nodeKind}
			result := e.matchKind(node, "token_call")
			if result != tt.expected {
				t.Errorf("matchKind(%q, 'token_call') = %v, want %v", tt.nodeKind, result, tt.expected)
			}
		})
	}
}

// ─── Canonical syntax ─────────────────────────────────────────────────────────

func TestCanonicalSyntaxAccepted(t *testing.T) {
	yamlCanonical := `
meta:
  id: TEST-SYNTAX-001
  title: "canonical syntax"
  severity: HIGH
  confidence: MEDIUM

query:
  from: entry_function
  where:
    - not:
        modifier: nonReentrant
    - sequence:
        - block: outgoing_call
        - block: state_write
`
	tmpl, err := ParseTemplate(yamlCanonical)
	if err != nil {
		t.Fatalf("ParseTemplate failed on canonical syntax: %v", err)
	}

	if tmpl.Query.Filter == nil {
		t.Error("Expected filter to be set")
	}
	if tmpl.Query.Match.IsEmpty() {
		t.Error("Expected match to be set")
	}
	if len(tmpl.Query.Match.Sequence) != 2 {
		t.Errorf("Expected 2 sequence items, got %d", len(tmpl.Query.Match.Sequence))
	}
}

func TestEvaluatorIRAcceptsRegexInFilterAndMatch(t *testing.T) {
	tmpl := &Template{
		Meta: TemplateMeta{
			ID:         "TEST-SOURCE-REGEX-SCOPE",
			Title:      "source regex scope",
			Severity:   "LOW",
			Confidence: "HIGH",
		},
		Query: QueryBlock{
			Scope:  ScopeFunction,
			Filter: &Rule{Regex: "onlyFunctionBody"},
			Match:  Rule{Regex: "rawSnippetPredicate"},
		},
	}
	if err := finalizeTemplate(tmpl, "filter/match regex evaluator IR test"); err != nil {
		t.Fatalf("finalizeTemplate should accept regex in filter and match: %v", err)
	}
	if tmpl.Query.Filter == nil || tmpl.Query.Filter.Regex == "" {
		t.Fatal("expected filter.regex to be preserved")
	}
	if tmpl.Query.Match.Regex == "" {
		t.Fatal("expected match.regex to be preserved")
	}
}

// ─── Filter-level checks ──────────────────────────────────────────────────────

func TestContextFuncNameFilter(t *testing.T) {
	db := types.NewDatabase()
	e := New(db)

	fn := &types.Function{
		Name:       "withdraw",
		Visibility: types.VisibilityPublic,
	}
	fn.AST = types.NewASTNode(types.KindDeclFunction)
	contract := &types.Contract{Name: "Vault"}

	tests := []struct {
		name     string
		funcName string
		expected bool
	}{
		{"exact match", "^withdraw$", true},
		{"regex match", "^(withdraw|deposit)$", true},
		{"no match", "^transfer$", false},
		{"case sensitive - no match", "^Withdraw$", false},
		{"case insensitive", "(?i)^withdraw$", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := Rule{FuncName: tt.funcName}
			result := e.VerifyAtFunction(fn, rule, contract)
			if result != tt.expected {
				t.Errorf("FuncName %q on fn %q = %v, want %v", tt.funcName, fn.Name, result, tt.expected)
			}
		})
	}
}

func TestContextVisibility(t *testing.T) {
	db := types.NewDatabase()
	e := New(db)

	contract := &types.Contract{Name: "Test"}
	mkFn := func(vis types.Visibility) *types.Function {
		fn := &types.Function{Name: "foo", Visibility: vis}
		fn.AST = types.NewASTNode(types.KindDeclFunction)
		return fn
	}

	tests := []struct {
		name             string
		fn               *types.Function
		visibilityFilter string
		expected         bool
	}{
		{"public matches public", mkFn(types.VisibilityPublic), "public", true},
		{"external matches external", mkFn(types.VisibilityExternal), "external", true},
		{"public does not match external", mkFn(types.VisibilityPublic), "external", false},
		{"multi: public,external matches public", mkFn(types.VisibilityPublic), "public,external", true},
		{"multi: public,external matches external", mkFn(types.VisibilityExternal), "public,external", true},
		{"multi: public,external does not match internal", mkFn(types.VisibilityInternal), "public,external", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := Rule{Visibility: tt.visibilityFilter}
			result := e.VerifyAtFunction(tt.fn, rule, contract)
			if result != tt.expected {
				t.Errorf("Visibility %q = %v, want %v", tt.visibilityFilter, result, tt.expected)
			}
		})
	}
}

func TestContextMutability(t *testing.T) {
	db := types.NewDatabase()
	e := New(db)

	contract := &types.Contract{Name: "Test"}
	mkFn := func(mut types.StateMutability) *types.Function {
		fn := &types.Function{Name: "foo", Visibility: types.VisibilityPublic, StateMutability: mut}
		fn.AST = types.NewASTNode(types.KindDeclFunction)
		return fn
	}

	tests := []struct {
		name             string
		fn               *types.Function
		mutabilityFilter string
		expected         bool
	}{
		{"payable matches payable", mkFn(types.StateMutabilityPayable), "payable", true},
		{"view does not match payable", mkFn(types.StateMutabilityView), "payable", false},
		{"multi: payable,nonpayable matches payable", mkFn(types.StateMutabilityPayable), "payable,nonpayable", true},
		{"multi: payable,nonpayable matches nonpayable", mkFn(types.StateMutabilityNonPayable), "payable,nonpayable", true},
		{"multi: payable,nonpayable does not match view", mkFn(types.StateMutabilityView), "payable,nonpayable", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := Rule{Mutability: tt.mutabilityFilter}
			result := e.VerifyAtFunction(tt.fn, rule, contract)
			if result != tt.expected {
				t.Errorf("Mutability %q = %v, want %v", tt.mutabilityFilter, result, tt.expected)
			}
		})
	}
}

func TestRegexScopedFunctionAndFilter(t *testing.T) {
	db := types.NewDatabase()
	e := New(db)

	path := "/virtual/Scoped.sol"
	content := `contract Scoped {
    function foo() external {
        emit Flagged();
    }
}
`
	db.AddSourceFile(&types.SourceFile{Path: path, Content: content})

	fnAST := types.NewASTNode(types.KindDeclFunction)
	fnAST.Name = "foo"
	fnAST.StartLine = 2
	fnAST.EndLine = 4
	fn := &types.Function{
		Name:         "foo",
		ContractName: "Scoped",
		Visibility:   types.VisibilityExternal,
		StartLine:    2,
		EndLine:      4,
		AST:          fnAST,
	}
	contract := &types.Contract{
		Name:       "Scoped",
		SourceFile: path,
		Kind:       types.ContractKindContract,
		Functions:  []*types.Function{fn},
	}
	db.AddContract(contract)

	t.Run("regex matches current function source", func(t *testing.T) {
		result := e.VerifyAtFunction(fn, Rule{Regex: `emit\s+Flagged`}, contract)
		if !result {
			t.Fatal("expected regex to match function source")
		}
	})

	t.Run("regex can compose with function filters", func(t *testing.T) {
		rule := Rule{All: []Rule{
			{Regex: `emit\s+Flagged`},
			{Visibility: "external"},
		}}
		result := e.VerifyAtFunction(fn, rule, contract)
		if !result {
			t.Fatal("expected regex and visibility to match together")
		}
	})

	t.Run("regex rejects non-matching scoped source", func(t *testing.T) {
		result := e.VerifyAtFunction(fn, Rule{Regex: `NotHere`}, contract)
		if result {
			t.Fatal("expected regex to reject non-matching function source")
		}
	})
}

func TestContractContextAllExtends(t *testing.T) {
	db := types.NewDatabase()
	e := New(db)

	contract := &types.Contract{
		Name:            "VulnerableThirdwebCombination",
		Kind:            types.ContractKindContract,
		LinearizedBases: []string{"VulnerableThirdwebCombination", "ERC2771Context", "Multicall"},
	}

	rule := Rule{All: []Rule{
		{Extends: `^ERC2771Context$`},
		{Extends: `^Multicall$`},
	}}
	if !e.VerifyAtContract(contract, rule) {
		t.Fatal("expected contract to match both inherited bases")
	}

	missingBase := Rule{All: []Rule{
		{Extends: `^ERC2771Context$`},
		{Extends: `^Ownable$`},
	}}
	if e.VerifyAtContract(contract, missingBase) {
		t.Fatal("expected contract to reject missing inherited base")
	}
}

func TestContractScopeASTMatchesInheritedAndLocalFunctions(t *testing.T) {
	db := types.NewDatabase()

	main := &types.Contract{
		ID:              types.MakeContractID("Vault.sol", "Vault"),
		Name:            "Vault",
		SourceFile:      "Vault.sol",
		Kind:            types.ContractKindContract,
		LinearizedBases: []string{"Vault", "Multicall"},
	}
	depositRoot := types.NewASTNode(types.KindDeclFunction)
	depositRoot.Name = "depositETH"
	depositRoot.StartLine = 10
	depositRoot.EndLine = 20
	depositRoot.SetAttribute("visibility", "external")
	depositRoot.SetAttribute("mutability", "payable")
	msgValue := types.NewASTNode(types.KindExprMemberAccess)
	msgValue.Name = "value"
	msgValue.StartLine = 12
	msgValue.EndLine = 12
	msgValue.SetAttribute("parent", "msg")
	depositRoot.AddChild(msgValue)
	mintRoot := types.NewASTNode(types.KindDeclFunction)
	mintRoot.Name = "mintETH"
	mintRoot.StartLine = 22
	mintRoot.EndLine = 35
	mintRoot.SetAttribute("visibility", "external")
	mintRoot.SetAttribute("mutability", "payable")
	mintMsgValue := types.NewASTNode(types.KindExprMemberAccess)
	mintMsgValue.Name = "value"
	mintMsgValue.StartLine = 24
	mintMsgValue.EndLine = 24
	mintMsgValue.SetAttribute("parent", "msg")
	mintRoot.AddChild(mintMsgValue)
	main.Functions = []*types.Function{{
		Name:            "depositETH",
		ContractName:    "Vault",
		Visibility:      types.VisibilityExternal,
		StateMutability: types.StateMutabilityPayable,
		StartLine:       10,
		EndLine:         20,
		AST:             depositRoot,
	}, {
		Name:            "mintETH",
		ContractName:    "Vault",
		Visibility:      types.VisibilityExternal,
		StateMutability: types.StateMutabilityPayable,
		StartLine:       22,
		EndLine:         35,
		AST:             mintRoot,
	}}

	multicall := &types.Contract{
		ID:         types.MakeContractID("Multicall.sol", "Multicall"),
		Name:       "Multicall",
		SourceFile: "Multicall.sol",
		Kind:       types.ContractKindAbstract,
	}
	multicallRoot := types.NewASTNode(types.KindDeclFunction)
	multicallRoot.Name = "multicall"
	multicallRoot.StartLine = 30
	multicallRoot.EndLine = 40
	multicallRoot.SetAttribute("visibility", "external")
	loop := types.NewASTNode(types.KindStmtLoop)
	loop.SetAttribute("loop_type", "for")
	delegate := types.NewASTNode(types.KindCallExternal)
	delegate.Name = "functionDelegateCall"
	loop.AddChild(delegate)
	multicallRoot.AddChild(loop)
	multicall.Functions = []*types.Function{{
		Name:         "multicall",
		ContractName: "Multicall",
		Visibility:   types.VisibilityExternal,
		StartLine:    30,
		EndLine:      40,
		AST:          multicallRoot,
	}}

	db.AddContract(main)
	db.AddContract(multicall)
	db.MainContracts[main.ID] = &types.MainContractEntry{}
	e := New(db)

	rule := Rule{All: []Rule{
		{Label: "payable msg.value entrypoint", Contains: &Rule{
			Kind:       types.KindDeclFunction,
			Mutability: "payable",
			Contains: &Rule{
				Kind: types.KindExprMemberAccess,
				Name: "^value$",
				Left: &Rule{Name: "^msg$"},
			},
		}},
		{Label: "batch delegatecall entrypoint", Contains: &Rule{
			Kind: types.KindDeclFunction,
			Name: "(?i)multicall",
			Contains: &Rule{
				Kind: types.KindStmtLoop,
				Contains: &Rule{Any: []Rule{
					{Kind: "delegatecall"},
					{Kind: types.KindCallExternal, Name: "functionDelegateCall"},
				}},
			},
		}},
	}}

	if !e.VerifyAtContract(main, rule) {
		t.Fatal("expected contract-scope AST rule to match local payable msg.value and inherited multicall")
	}

	tmpl := &Template{
		Meta: TemplateMeta{ID: "T", Severity: "HIGH", Confidence: "HIGH"},
		Query: QueryBlock{
			Scope: ScopeMainContract,
			Match: rule,
		},
	}
	findings := e.Execute(tmpl)
	if len(findings) != 1 {
		t.Fatalf("Execute() findings = %d, want 1", len(findings))
	}
	if findings[0].Location.Line == 0 || findings[0].Location.Function != "depositETH" {
		t.Fatalf("contract-scope finding location = %+v, want depositETH with nonzero line", findings[0].Location)
	}
	gotRelated := map[string]bool{}
	gotLabels := map[string]string{}
	for _, loc := range findings[0].Related {
		gotRelated[loc.Function] = true
		gotLabels[loc.Function] = loc.Label
	}
	for _, want := range []string{"depositETH", "mintETH", "multicall"} {
		if !gotRelated[want] {
			t.Fatalf("related locations missing %s: %+v", want, findings[0].Related)
		}
	}
	// Labels come from the template branch's `label:` field, not engine
	// hardcoding. The payable sites carry the payable label; multicall carries
	// the batch label.
	if got := gotLabels["depositETH"]; got != "payable msg.value entrypoint" {
		t.Fatalf("depositETH label = %q, want %q", got, "payable msg.value entrypoint")
	}
	if got := gotLabels["multicall"]; got != "batch delegatecall entrypoint" {
		t.Fatalf("multicall label = %q, want %q", got, "batch delegatecall entrypoint")
	}
}

func TestContextHasGuard(t *testing.T) {
	db := types.NewDatabase()
	e := New(db)
	contract := &types.Contract{Name: "Test"}

	// Build a function with a require(msg.sender == owner) guard
	fnAST := types.NewASTNode(types.KindDeclFunction)

	reqNode := types.NewASTNode(types.KindCheckRequire)
	reqNode.Name = "require"

	senderNode := types.NewASTNode(types.KindExprMemberAccess)
	senderNode.Name = "sender"
	senderNode.SetAttribute("parent", "msg")
	reqNode.AddChild(senderNode)
	fnAST.AddChild(reqNode)

	fnWithGuard := &types.Function{Name: "withdrawal", Visibility: types.VisibilityPublic}
	fnWithGuard.AST = fnAST

	// Function without guard
	fnNoGuard := &types.Function{Name: "noGuard", Visibility: types.VisibilityPublic}
	fnNoGuard.AST = types.NewASTNode(types.KindDeclFunction)

	// has_guard rule: requires a guard that contains msg.sender
	hasGuardRule := Rule{
		HasGuard: &Rule{
			Contains: &Rule{
				Kind: types.KindExprMemberAccess,
				Name: `msg\.sender`,
			},
		},
	}

	t.Run("function with guard matches has_guard", func(t *testing.T) {
		result := e.VerifyAtFunction(fnWithGuard, hasGuardRule, contract)
		if !result {
			t.Error("Expected has_guard to match function containing require(msg.sender...)")
		}
	})

	t.Run("function without guard does not match has_guard", func(t *testing.T) {
		result := e.VerifyAtFunction(fnNoGuard, hasGuardRule, contract)
		if result {
			t.Error("Expected has_guard to NOT match function without any guard")
		}
	})

	// not.has_guard: function does NOT have a guard
	notHasGuardRule := Rule{
		Not: &Rule{
			HasGuard: &Rule{
				Contains: &Rule{
					Kind: types.KindExprMemberAccess,
					Name: `msg\.sender`,
				},
			},
		},
	}

	t.Run("not.has_guard matches function without guard", func(t *testing.T) {
		// need AST content to trigger AST matching
		fnNoGuard.AST.AddChild(types.NewASTNode(types.KindCallExternal))
		result := e.VerifyAtFunction(fnNoGuard, Rule{
			Not:      notHasGuardRule.Not,
			Contains: &Rule{Kind: types.KindCallExternal},
		}, contract)
		if !result {
			t.Error("Expected not.has_guard to match function WITHOUT guard that has external call")
		}
	})
}

// ─── Template Loading (silent failure fix) ────────────────────────────────────

func TestLoadTemplateValidation(t *testing.T) {
	// Valid template
	t.Run("valid template loads", func(t *testing.T) {
		yaml := `
meta:
  id: VALID-001
  severity: HIGH
  confidence: MEDIUM
query:
  select: outgoing_call
  from: entry_function
`
		tmpl, err := ParseTemplate(yaml)
		if err != nil {
			t.Fatalf("Expected valid template to load: %v", err)
		}
		if tmpl.Meta.ID != "VALID-001" {
			t.Errorf("Expected id 'VALID-001', got %q", tmpl.Meta.ID)
		}
	})

	// Invalid YAML
	t.Run("invalid YAML returns error", func(t *testing.T) {
		invalidYAML := `
meta:
  id: BROKEN
  : invalid yaml [[ !!!
`
		_, err := ParseTemplate(invalidYAML)
		if err == nil {
			t.Error("Expected invalid YAML to return an error")
		}
	})
}

func TestLoadTemplatesFailsClosedByDefault(t *testing.T) {
	dir := t.TempDir()
	valid := `
meta:
  id: VALID-001
  severity: HIGH
  confidence: MEDIUM
query:
  select: outgoing_call
  from: entry_function
`
	invalid := `
meta:
  id: INVALID-001
query:
  select: outgoing_call
  from: entry_function
`
	if err := os.WriteFile(filepath.Join(dir, "valid.yaml"), []byte(valid), 0644); err != nil {
		t.Fatalf("write valid template: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "invalid.yaml"), []byte(invalid), 0644); err != nil {
		t.Fatalf("write invalid template: %v", err)
	}

	if _, err := LoadTemplates(dir); err == nil {
		t.Fatal("LoadTemplates returned nil error; want fail-closed error for invalid template")
	} else if !strings.Contains(err.Error(), "missing meta.severity") {
		t.Fatalf("LoadTemplates error = %q; want missing severity context", err)
	}

	templates, err := LoadTemplatesWithOptions(dir, TemplateLoadOptions{IgnoreInvalid: true})
	if err != nil {
		t.Fatalf("LoadTemplatesWithOptions(ignore invalid) returned error: %v", err)
	}
	if len(templates) != 1 || templates[0].Meta.ID != "VALID-001" {
		t.Fatalf("lenient load = %+v; want only VALID-001", templates)
	}
}

func TestLoadTemplatesErrorsWhenNoTemplatesLoaded(t *testing.T) {
	if _, err := LoadTemplates(t.TempDir()); err == nil {
		t.Fatal("LoadTemplates(empty dir) returned nil error; want no valid templates error")
	}
}

// ─── IsContextOnly covers new fields ─────────────────────────────────────────

func TestIsContextOnly(t *testing.T) {
	tests := []struct {
		name     string
		rule     Rule
		expected bool
	}{
		{"modifier only", Rule{Modifier: "onlyOwner"}, true},
		{"func_name only", Rule{FuncName: "^withdraw$"}, true},
		{"visibility only", Rule{Visibility: "public"}, true},
		{"mutability only", Rule{Mutability: "payable"}, true},
		{"has_guard only", Rule{HasGuard: &Rule{Kind: "check.require"}}, true},
		{"kind only — NOT context", Rule{Kind: "call.external"}, false},
		{"contains only — NOT context", Rule{Contains: &Rule{Kind: "call.external"}}, false},
		{"func_name + contains — NOT purely context", Rule{FuncName: "^withdraw$", Contains: &Rule{Kind: "call.external"}}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.rule.IsContextOnly()
			if result != tt.expected {
				t.Errorf("IsContextOnly = %v, want %v", result, tt.expected)
			}
		})
	}
}
