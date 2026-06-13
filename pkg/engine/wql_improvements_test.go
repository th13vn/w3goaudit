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
  scope: entrypoint
  filter:
    not:
      modifier: nonReentrant
  match:
    sequence:
      - kind: outgoing_call
      - kind: state_write
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

func TestSourceRegexAcceptedInFilterAndMatch(t *testing.T) {
	yamlWithScopedSourceRegex := `
meta:
  id: TEST-SOURCE-REGEX-SCOPE
  title: "source regex scope"
  severity: LOW
  confidence: HIGH

query:
  scope: function
  filter:
    source_regex: "onlyFunctionBody"
  match:
    source_regex: "rawSnippetPredicate"
`
	tmpl, err := ParseTemplate(yamlWithScopedSourceRegex)
	if err != nil {
		t.Fatalf("ParseTemplate should accept source_regex in filter and match: %v", err)
	}
	if tmpl.Query.Filter == nil || tmpl.Query.Filter.SourceRegex == "" {
		t.Fatal("expected filter.source_regex to be preserved")
	}
	if tmpl.Query.Match.SourceRegex == "" {
		t.Fatal("expected match.source_regex to be preserved")
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

func TestContextVisibilityFilter(t *testing.T) {
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
			rule := Rule{VisibilityFilter: tt.visibilityFilter}
			result := e.VerifyAtFunction(tt.fn, rule, contract)
			if result != tt.expected {
				t.Errorf("VisibilityFilter %q = %v, want %v", tt.visibilityFilter, result, tt.expected)
			}
		})
	}
}

func TestContextMutabilityFilter(t *testing.T) {
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
			rule := Rule{MutabilityFilter: tt.mutabilityFilter}
			result := e.VerifyAtFunction(tt.fn, rule, contract)
			if result != tt.expected {
				t.Errorf("MutabilityFilter %q = %v, want %v", tt.mutabilityFilter, result, tt.expected)
			}
		})
	}
}

func TestSourceRegexScopedFunctionAndFilter(t *testing.T) {
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

	t.Run("source_regex matches current function source", func(t *testing.T) {
		result := e.VerifyAtFunction(fn, Rule{SourceRegex: `emit\s+Flagged`}, contract)
		if !result {
			t.Fatal("expected source_regex to match function source")
		}
	})

	t.Run("source_regex can compose with function filters", func(t *testing.T) {
		rule := Rule{All: []Rule{
			{SourceRegex: `emit\s+Flagged`},
			{VisibilityFilter: "external"},
		}}
		result := e.VerifyAtFunction(fn, rule, contract)
		if !result {
			t.Fatal("expected source_regex and visibility_filter to match together")
		}
	})

	t.Run("source_regex rejects non-matching scoped source", func(t *testing.T) {
		result := e.VerifyAtFunction(fn, Rule{SourceRegex: `NotHere`}, contract)
		if result {
			t.Fatal("expected source_regex to reject non-matching function source")
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

// ─── arg.N YAML Key Parsing ───────────────────────────────────────────────────

func TestArgNYAMLParsing(t *testing.T) {
	// arg.N flat-key style
	yamlArgN := `
meta:
  id: TEST-ARG-001
  title: "arg.N test"
  severity: HIGH
  confidence: MEDIUM

query:
  scope: entrypoint
  match:
    contains:
      kind: call.external
      name: ^transferFrom$
      arg.0:
        kind: expr.identifier
        tainted_from: parameter
`
	tmpl, err := ParseTemplate(yamlArgN)
	if err != nil {
		t.Fatalf("ParseTemplate failed: %v", err)
	}

	// The match contains rule should have Args[0] populated by normalizeArgNKeys
	// (the whole point of arg.N flat-key parsing).
	if tmpl.Query.Match.Contains == nil {
		t.Fatal("Expected match.contains to be set")
	}
	argRule, ok := tmpl.Query.Match.Contains.Args[0]
	if !ok {
		t.Fatalf("Expected Contains.Args[0] to be populated from `arg.0:`; got Args=%v", tmpl.Query.Match.Contains.Args)
	}
	if argRule.Kind != "expr.identifier" {
		t.Errorf("Contains.Args[0].Kind = %q, want expr.identifier", argRule.Kind)
	}
	if argRule.TaintedFrom != "parameter" {
		t.Errorf("Contains.Args[0].TaintedFrom = %q, want parameter", argRule.TaintedFrom)
	}
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
  scope: entrypoint
  match:
    kind: outgoing_call
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
  scope: entrypoint
  match:
    kind: outgoing_call
`
	invalid := `
meta:
  id: INVALID-001
query:
  scope: entrypoint
  match:
    kind: outgoing_call
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
		{"visibility_filter only", Rule{VisibilityFilter: "public"}, true},
		{"mutability_filter only", Rule{MutabilityFilter: "payable"}, true},
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
