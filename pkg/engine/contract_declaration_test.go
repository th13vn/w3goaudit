package engine

import (
	"sort"
	"strings"
	"testing"

	"github.com/th13vn/w3goaudit/pkg/types"
)

func TestContractASTMaterializesDeclarationsAndActiveOverrides(t *testing.T) {
	db := buildDBFromSource(t, `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
abstract contract Base {
    uint256 baseState;
    modifier onlyOwner(address owner) {
        require(msg.sender == owner, "owner");
        _;
    }
    function ping(uint256 amount) public virtual returns (uint256 result) {
        return amount;
    }
}
contract Child is Base {
    uint256 childState;
    function ping(uint256 amount) public override returns (uint256 result) {
        return amount + 1;
    }
    function execute(address target) external onlyOwner(msg.sender) {
        target.call("");
    }
}`).GetDatabase()
	child := db.GetContractByName("Child")
	root := New(db).buildContractAST(child)
	assertDeclarationNode(t, root, child.SourceFile, child.Name, child.StartLine, child.EndLine,
		child.StartCol, child.EndCol, child.StartByte, child.EndByte)
	counts := map[string]int{}
	root.WalkDescendants(func(n *types.ASTNode) bool {
		counts[n.Kind]++
		if strings.HasPrefix(n.Kind, "decl.") &&
			n.GetAttributeString("source_file") == "" {
			t.Errorf("%s %q missing source_file", n.Kind, n.Name)
		}
		return true
	})
	if counts[types.KindDeclModifier] == 0 ||
		counts[types.KindDeclVariable] < 2 ||
		counts[types.KindDeclParameter] < 4 {
		t.Fatalf("declaration counts=%v", counts)
	}
	pings := root.CollectDescendants(func(n *types.ASTNode) bool {
		return n.Kind == types.KindDeclFunction && n.Name == "ping"
	})
	if len(pings) != 1 {
		t.Fatalf("active ping declarations=%d, want 1", len(pings))
	}
	if pings[0].GetAttributeString("contract") != "Child" {
		t.Fatalf("active ping owner=%q", pings[0].GetAttributeString("contract"))
	}
	base := db.LinearizedContracts(child)[1]
	childPing := contractFunctionBySelector(t, child, "ping(uint256)")
	assertDeclarationNode(t, pings[0], childPing.SourceFile, child.Name, childPing.StartLine,
		childPing.EndLine, childPing.StartCol, childPing.EndCol, childPing.StartByte, childPing.EndByte)
	if got := pings[0].GetAttributeString("visibility"); got != string(childPing.Visibility) {
		t.Fatalf("ping visibility=%q, want %q", got, childPing.Visibility)
	}
	if got := pings[0].GetAttributeString("mutability"); got != string(childPing.StateMutability) {
		t.Fatalf("ping mutability=%q, want %q", got, childPing.StateMutability)
	}
	for _, tc := range []declarationExpectation{
		declarationCaseForVariable(t, child, "childState"),
		declarationCaseForVariable(t, base, "baseState"),
		declarationCaseForModifier(t, base, "onlyOwner"),
	} {
		node := root.FindDescendant(func(n *types.ASTNode) bool {
			return n.Kind == tc.kind && n.Name == tc.name && n.GetAttributeString("contract") == tc.owner
		})
		if node == nil {
			t.Fatalf("%s %s.%s missing", tc.kind, tc.owner, tc.name)
		}
		assertDeclarationNode(t, node, tc.source, tc.owner, tc.startLine, tc.endLine,
			tc.startCol, tc.endCol, tc.startByte, tc.endByte)
		if tc.typ != "" && node.GetAttributeString("type") != tc.typ {
			t.Fatalf("%s %s type=%q, want %q", tc.kind, tc.name, node.GetAttributeString("type"), tc.typ)
		}
		if tc.visibility != "" && node.GetAttributeString("visibility") != tc.visibility {
			t.Fatalf("%s %s visibility=%q, want %q", tc.kind, tc.name,
				node.GetAttributeString("visibility"), tc.visibility)
		}
	}
	assertParameterDeclaration(t, root, childPing.Parameters[0], child.SourceFile, "input")
	assertParameterDeclaration(t, root, childPing.Returns[0], child.SourceFile, "return")
	execute := contractFunctionBySelector(t, child, "execute(address)")
	assertParameterDeclaration(t, root, execute.Parameters[0], child.SourceFile, "input")
	onlyOwner := contractModifierByName(t, base, "onlyOwner")
	assertParameterDeclaration(t, root, onlyOwner.Parameters[0], base.SourceFile, "modifier")
}

func TestContractASTInheritedDeclarationsKeepOwnerSource(t *testing.T) {
	const baseFile = "/virtual/Base.sol"
	const childFile = "/virtual/Child.sol"
	db := types.NewDatabase()
	db.AddSourceFile(&types.SourceFile{Path: baseFile, Content: "abstract contract Base {}\n"})
	db.AddSourceFile(&types.SourceFile{Path: childFile, Content: "contract Child is Base {}\n"})
	baseRoot := types.NewASTNode(types.KindDeclFunction)
	baseRoot.Name = "baseFn"
	baseRoot.StartLine, baseRoot.EndLine = 3, 5
	baseRoot.StartCol, baseRoot.EndCol = 5, 6
	baseRoot.StartByte, baseRoot.EndByte = 30, 80
	baseFn := &types.Function{
		Name: "baseFn", ContractName: "Base", SourceFile: baseFile,
		Visibility: types.VisibilityInternal, Selector: "baseFn()",
		AST: baseRoot, StartLine: 3, EndLine: 5, StartCol: 5, EndCol: 6,
		StartByte: 30, EndByte: 80,
	}
	modifierRoot := types.NewASTNode(types.KindDeclModifier)
	modifierRoot.Name = "baseGuard"
	modifierRoot.StartLine, modifierRoot.EndLine = 7, 9
	modifierRoot.StartCol, modifierRoot.EndCol = 5, 6
	modifierRoot.StartByte, modifierRoot.EndByte = 90, 140
	modifierParam := &types.Parameter{
		Name: "who", TypeName: "address", StartLine: 7, EndLine: 7,
		StartCol: 24, EndCol: 35, StartByte: 109, EndByte: 120,
	}
	baseVariable := &types.StateVariable{
		Name: "baseState", TypeName: "uint256", Visibility: "internal",
		StartLine: 2, EndLine: 2, StartCol: 5, EndCol: 23, StartByte: 10, EndByte: 28,
	}
	baseModifier := &types.Modifier{
		Name: "baseGuard", Parameters: []*types.Parameter{modifierParam}, AST: modifierRoot,
		StartLine: 7, EndLine: 9, StartCol: 5, EndCol: 6, StartByte: 90, EndByte: 140,
	}
	base := &types.Contract{
		ID: types.MakeContractID(baseFile, "Base"), Name: "Base",
		SourceFile: baseFile, Kind: types.ContractKindAbstract,
		Functions:         []*types.Function{baseFn},
		StateVariables:    []*types.StateVariable{baseVariable},
		Modifiers:         []*types.Modifier{baseModifier},
		LinearizedBaseIDs: []string{types.MakeContractID(baseFile, "Base")},
	}
	child := &types.Contract{
		ID: types.MakeContractID(childFile, "Child"), Name: "Child",
		SourceFile: childFile, Kind: types.ContractKindContract,
		LinearizedBaseIDs: []string{
			types.MakeContractID(childFile, "Child"),
			types.MakeContractID(baseFile, "Base"),
		},
	}
	db.AddContract(base)
	db.AddContract(child)
	root := New(db).buildContractAST(child)
	for _, tc := range []struct {
		name, kind                                               string
		startLine, endLine, startCol, endCol, startByte, endByte int
	}{
		{name: "baseFn", kind: types.KindDeclFunction, startLine: 3, endLine: 5, startCol: 5, endCol: 6, startByte: 30, endByte: 80},
		{name: "baseState", kind: types.KindDeclVariable, startLine: 2, endLine: 2, startCol: 5, endCol: 23, startByte: 10, endByte: 28},
		{name: "baseGuard", kind: types.KindDeclModifier, startLine: 7, endLine: 9, startCol: 5, endCol: 6, startByte: 90, endByte: 140},
	} {
		node := root.FindDescendant(func(n *types.ASTNode) bool { return n.Kind == tc.kind && n.Name == tc.name })
		if node == nil {
			t.Fatalf("%s declaration missing", tc.name)
		}
		assertDeclarationNode(t, node, baseFile, "Base", tc.startLine, tc.endLine,
			tc.startCol, tc.endCol, tc.startByte, tc.endByte)
	}
	assertParameterDeclaration(t, root, modifierParam, baseFile, "modifier")
}

func TestActiveContractFunctionsUseExactMRO(t *testing.T) {
	db := types.NewDatabase()
	newFunction := func(file, contract, name, selector string) *types.Function {
		root := types.NewASTNode(types.KindDeclFunction)
		root.Name = name
		return &types.Function{Name: name, ContractName: contract, SourceFile: file, Selector: selector, AST: root}
	}
	const (
		baseFile  = "/virtual/Base.sol"
		leftFile  = "/virtual/Left.sol"
		rightFile = "/virtual/Right.sol"
		leafFile  = "/virtual/Leaf.sol"
	)
	base := &types.Contract{ID: types.MakeContractID(baseFile, "Base"), Name: "Base", SourceFile: baseFile}
	left := &types.Contract{ID: types.MakeContractID(leftFile, "Left"), Name: "Left", SourceFile: leftFile}
	right := &types.Contract{ID: types.MakeContractID(rightFile, "Right"), Name: "Right", SourceFile: rightFile}
	leaf := &types.Contract{ID: types.MakeContractID(leafFile, "Leaf"), Name: "Leaf", SourceFile: leafFile}
	base.Functions = []*types.Function{
		newFunction(baseFile, "Base", "foo", "foo(uint256)"),
		newFunction(baseFile, "Base", "foo", "foo(address)"),
		newFunction(baseFile, "Base", "diamond", "diamond()"),
		newFunction(baseFile, "Base", "constructor", ""),
	}
	base.Functions[3].IsConstructor = true
	left.Functions = []*types.Function{newFunction(leftFile, "Left", "diamond", "diamond()")}
	right.Functions = []*types.Function{newFunction(rightFile, "Right", "diamond", "diamond()")}
	leaf.Functions = []*types.Function{
		newFunction(leafFile, "Leaf", "foo", "foo(uint256)"),
		newFunction(leafFile, "Leaf", "constructor", ""),
		newFunction(leafFile, "Leaf", "receive", ""),
		newFunction(leafFile, "Leaf", "fallback", ""),
	}
	leaf.Functions[1].IsConstructor = true
	leaf.Functions[2].IsReceive = true
	leaf.Functions[3].IsFallback = true
	leaf.LinearizedBaseIDs = []string{leaf.ID, right.ID, left.ID, base.ID}
	for _, contract := range []*types.Contract{base, left, right, leaf} {
		db.AddContract(contract)
	}
	active := New(db).activeContractFunctions(leaf)
	if len(active) != 6 {
		t.Fatalf("active=%d, want 6: %+v", len(active), active)
	}
	wantOwners := map[string]string{
		"foo(uint256)": "Leaf", "foo(address)": "Base", "diamond()": "Right",
		"<constructor>": "Leaf", "<receive>": "Leaf", "<fallback>": "Leaf",
	}
	seen := map[string]string{}
	for _, owned := range active {
		key := activeFunctionKey(owned.fn)
		if prior := seen[key]; prior != "" {
			t.Fatalf("duplicate active key %q owned by %s and %s", key, prior, owned.owner.Name)
		}
		seen[key] = owned.owner.Name
	}
	for key, owner := range wantOwners {
		if seen[key] != owner {
			t.Errorf("active %s owner=%q, want %q; all=%v", key, seen[key], owner, seen)
		}
	}
	noConstructorLeaf := &types.Contract{
		ID:   types.MakeContractID("/virtual/NoConstructorLeaf.sol", "NoConstructorLeaf"),
		Name: "NoConstructorLeaf", SourceFile: "/virtual/NoConstructorLeaf.sol",
		LinearizedBaseIDs: []string{
			types.MakeContractID("/virtual/NoConstructorLeaf.sol", "NoConstructorLeaf"),
			base.ID,
		},
	}
	db.AddContract(noConstructorLeaf)
	for _, owned := range New(db).activeContractFunctions(noConstructorLeaf) {
		if activeFunctionKey(owned.fn) == "<constructor>" {
			t.Fatalf("derived contract without a local constructor inherited %s.%s",
				owned.owner.Name, owned.fn.Name)
		}
	}
}

type declarationExpectation struct {
	kind, name, owner, source, typ, visibility string
	startLine, endLine, startCol, endCol       int
	startByte, endByte                         int
}

func declarationCaseForVariable(t *testing.T, contract *types.Contract, name string) declarationExpectation {
	t.Helper()
	for _, variable := range contract.StateVariables {
		if variable != nil && variable.Name == name {
			return declarationExpectation{
				kind: types.KindDeclVariable, name: name, owner: contract.Name, source: contract.SourceFile,
				typ: variable.TypeName, visibility: variable.Visibility,
				startLine: variable.StartLine, endLine: variable.EndLine,
				startCol: variable.StartCol, endCol: variable.EndCol,
				startByte: variable.StartByte, endByte: variable.EndByte,
			}
		}
	}
	t.Fatalf("variable %s.%s missing", contract.Name, name)
	return declarationExpectation{}
}

func declarationCaseForModifier(t *testing.T, contract *types.Contract, name string) declarationExpectation {
	t.Helper()
	modifier := contractModifierByName(t, contract, name)
	return declarationExpectation{
		kind: types.KindDeclModifier, name: name, owner: contract.Name, source: contract.SourceFile,
		startLine: modifier.StartLine, endLine: modifier.EndLine,
		startCol: modifier.StartCol, endCol: modifier.EndCol,
		startByte: modifier.StartByte, endByte: modifier.EndByte,
	}
}

func contractFunctionBySelector(t *testing.T, contract *types.Contract, selector string) *types.Function {
	t.Helper()
	for _, fn := range contract.Functions {
		if fn != nil && fn.Selector == selector {
			return fn
		}
	}
	t.Fatalf("function %s.%s missing", contract.Name, selector)
	return nil
}

func contractModifierByName(t *testing.T, contract *types.Contract, name string) *types.Modifier {
	t.Helper()
	for _, modifier := range contract.Modifiers {
		if modifier != nil && modifier.Name == name {
			return modifier
		}
	}
	t.Fatalf("modifier %s.%s missing", contract.Name, name)
	return nil
}

func assertDeclarationNode(t *testing.T, node *types.ASTNode, source, owner string,
	startLine, endLine, startCol, endCol, startByte, endByte int,
) {
	t.Helper()
	if node == nil {
		t.Fatal("declaration node is nil")
	}
	gotOwner := node.GetAttributeString("contract")
	if node.Kind == types.KindDeclContract {
		gotOwner = node.Name
	}
	if node.GetAttributeString("source_file") != source || gotOwner != owner {
		t.Fatalf("%s %q source/owner=%q/%q, want %q/%q",
			node.Kind, node.Name, node.GetAttributeString("source_file"), gotOwner, source, owner)
	}
	if node.StartLine != startLine || node.EndLine != endLine || node.StartCol != startCol ||
		node.EndCol != endCol || node.StartByte != startByte || node.EndByte != endByte {
		t.Fatalf("%s %q span=%d:%d/%d:%d/%d:%d, want %d:%d/%d:%d/%d:%d",
			node.Kind, node.Name, node.StartLine, node.EndLine, node.StartCol, node.EndCol,
			node.StartByte, node.EndByte, startLine, endLine, startCol, endCol, startByte, endByte)
	}
}

func assertParameterDeclaration(t *testing.T, root *types.ASTNode, param *types.Parameter, source, role string) {
	t.Helper()
	node := root.FindDescendant(func(n *types.ASTNode) bool {
		return n.Kind == types.KindDeclParameter && n.Name == param.Name &&
			n.GetAttributeString("source_file") == source && n.GetAttributeString("parameter_role") == role
	})
	if node == nil {
		t.Fatalf("parameter %q role=%q source=%q missing", param.Name, role, source)
	}
	if got := node.GetAttributeString("type"); got != param.TypeName {
		t.Fatalf("parameter %q type=%q, want %q", param.Name, got, param.TypeName)
	}
	if node.StartLine != param.StartLine || node.EndLine != param.EndLine || node.StartCol != param.StartCol ||
		node.EndCol != param.EndCol || node.StartByte != param.StartByte || node.EndByte != param.EndByte {
		t.Fatalf("parameter %q span=%d:%d/%d:%d/%d:%d, want %d:%d/%d:%d/%d:%d",
			param.Name, node.StartLine, node.EndLine, node.StartCol, node.EndCol, node.StartByte, node.EndByte,
			param.StartLine, param.EndLine, param.StartCol, param.EndCol, param.StartByte, param.EndByte)
	}
}

func TestContractScopeInheritedVariableUsesDeclarationOwner(t *testing.T) {
	db, baseA, _, childA, _ := inheritedVariableIdentityDB()
	tmpl, err := ParseTemplate(`meta: {id: INHERITED-VAR, severity: LOW}
query:
  select: variable
  from: main_contract
  where:
    - name: ^shared$`)
	if err != nil {
		t.Fatalf("template: %v", err)
	}
	db.MainContracts = map[string]*types.MainContractEntry{
		childA.ID: {},
	}
	findings := New(db).Execute(tmpl)
	if len(findings) != 1 {
		t.Fatalf("findings=%d, want 1: %+v", len(findings), findings)
	}
	want := baseA.StateVariables[0]
	assertFindingDeclarationOwner(t, findings[0], baseA.SourceFile, baseA.Name, "", want.StartLine,
		want.EndLine, want.StartCol, want.EndCol, want.StartByte, want.EndByte)
	if len(findings[0].Related) != 1 {
		t.Fatalf("related=%+v, want one inherited variable site", findings[0].Related)
	}
	assertRelatedDeclarationOwner(t, findings[0].Related[0], baseA.SourceFile, baseA.Name, "", want.StartLine,
		want.EndLine, want.StartCol, want.EndCol, want.StartByte, want.EndByte)
}

func TestOrCompositionKeepsSameSpanInheritedVariablesFromDifferentFiles(t *testing.T) {
	db, baseA, baseB, childA, childB := inheritedVariableIdentityDB()
	db.MainContracts = map[string]*types.MainContractEntry{
		childA.ID: {},
		childB.ID: {},
	}
	tmpl, err := ParseTemplate(`meta: {id: INHERITED-VAR-OR, severity: LOW}
query:
  or:
    - select: variable
      from: main_contract
      where:
        - name: ^shared$
        - base: ^BaseA$
    - select: variable
      from: main_contract
      where:
        - name: ^shared$
        - base: ^BaseB$`)
	if err != nil {
		t.Fatalf("template: %v", err)
	}
	findings := New(db).Execute(tmpl)
	if len(findings) != 2 {
		t.Fatalf("findings=%d, want one exact inherited-variable site per base: %+v", len(findings), findings)
	}
	got := map[string]string{}
	for _, finding := range findings {
		got[finding.Location.File] = finding.Location.Contract
	}
	want := map[string]string{baseA.SourceFile: baseA.Name, baseB.SourceFile: baseB.Name}
	if len(got) != len(want) || got[baseA.SourceFile] != baseA.Name || got[baseB.SourceFile] != baseB.Name {
		t.Fatalf("owners=%v, want %v", got, want)
	}
}

func inheritedVariableIdentityDB() (*types.Database, *types.Contract, *types.Contract, *types.Contract, *types.Contract) {
	const (
		baseAFile  = "/virtual/BaseA.sol"
		baseBFile  = "/virtual/BaseB.sol"
		children   = "/virtual/Children.sol"
		sharedLine = 2
	)
	db := types.NewDatabase()
	for _, file := range []string{baseAFile, baseBFile, children} {
		db.AddSourceFile(&types.SourceFile{Path: file, Content: "contract placeholder {}\n"})
	}
	newBase := func(file, name string) *types.Contract {
		id := types.MakeContractID(file, name)
		return &types.Contract{
			ID: id, Name: name, SourceFile: file, Kind: types.ContractKindAbstract,
			StateVariables: []*types.StateVariable{{
				Name: "shared", TypeName: "uint256", Visibility: "internal",
				StartLine: sharedLine, EndLine: sharedLine, StartCol: 5, EndCol: 20,
				StartByte: 25, EndByte: 40,
			}},
			LinearizedBases: []string{name}, LinearizedBaseIDs: []string{id},
		}
	}
	baseA := newBase(baseAFile, "BaseA")
	baseB := newBase(baseBFile, "BaseB")
	newChild := func(name string, startLine int, base *types.Contract) *types.Contract {
		id := types.MakeContractID(children, name)
		return &types.Contract{
			ID: id, Name: name, SourceFile: children, Kind: types.ContractKindContract,
			StartLine: startLine, EndLine: startLine + 2, StartCol: 1, EndCol: 2,
			StartByte: startLine * 10, EndByte: startLine*10 + 20,
			LinearizedBases:   []string{name, base.Name},
			LinearizedBaseIDs: []string{id, base.ID},
		}
	}
	childA := newChild("ChildA", 10, baseA)
	childB := newChild("ChildB", 20, baseB)
	for _, contract := range []*types.Contract{baseA, baseB, childA, childB} {
		db.AddContract(contract)
	}
	return db, baseA, baseB, childA, childB
}

func assertFindingDeclarationOwner(t *testing.T, finding *Finding, file, contract, function string,
	startLine, endLine, startCol, endCol, startByte, endByte int,
) {
	t.Helper()
	loc := finding.Location
	if loc.File != file || loc.Contract != contract || loc.Function != function ||
		loc.Line != startLine || loc.EndLine != endLine || loc.Col != startCol || loc.EndCol != endCol ||
		loc.StartByte != startByte || loc.EndByte != endByte {
		t.Fatalf("location=%+v, want %s %s.%s span=%d:%d/%d:%d/%d:%d",
			loc, file, contract, function, startLine, endLine, startCol, endCol, startByte, endByte)
	}
}

func assertRelatedDeclarationOwner(t *testing.T, related RelatedLocation, file, contract, function string,
	startLine, endLine, startCol, endCol, startByte, endByte int,
) {
	t.Helper()
	if related.File != file || related.Contract != contract || related.Function != function ||
		related.Line != startLine || related.EndLine != endLine || related.Col != startCol || related.EndCol != endCol ||
		related.StartByte != startByte || related.EndByte != endByte {
		t.Fatalf("related=%+v, want %s %s.%s span=%d:%d/%d:%d/%d:%d",
			related, file, contract, function, startLine, endLine, startCol, endCol, startByte, endByte)
	}
}

func TestGuardedByMatchesAppliedModifierAndInlineGuard(t *testing.T) {
	db := buildDBFromSource(t, `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract Guarded {
    address owner;
    modifier onlyOwner() { require(msg.sender == owner, "owner"); _; }
    function modified(address target) external onlyOwner { target.call(""); }
    function inlineGuard(address target) external {
        require(msg.sender == owner, "owner");
        target.call("");
    }
}`).GetDatabase()
	modifierTemplate, err := ParseTemplate(`meta: {id: MOD, severity: LOW}
query:
  select: lowlevel_call
  from: entry_function
  where:
    - guarded_by: {block: modifier, name: ^onlyOwner$}`)
	if err != nil {
		t.Fatalf("modifier template: %v", err)
	}
	inlineTemplate, err := ParseTemplate(`meta: {id: INLINE, severity: LOW}
query:
  select: lowlevel_call
  from: entry_function
  where:
    - guarded_by: {block: require}`)
	if err != nil {
		t.Fatalf("inline template: %v", err)
	}
	modifierFindings := New(db).Execute(modifierTemplate)
	if got := findingFunctionNames(modifierFindings); !equalStrings(got, []string{"modified"}) {
		t.Fatalf("modifier guarded_by=%v, want [modified]", got)
	}
	for _, finding := range modifierFindings {
		if finding.Location.Function == "modified" &&
			(finding.PrimaryAST == nil ||
				finding.PrimaryAST.Kind != types.KindCallLowlevelCall) {
			t.Fatalf("primary=%+v, want low-level call sink", finding.PrimaryAST)
		}
	}
	inlineFindings := New(db).Execute(inlineTemplate)
	if got := findingFunctionNames(inlineFindings); !equalStrings(got, []string{"inlineGuard"}) {
		t.Fatalf("inline guarded_by=%v, want [inlineGuard]", got)
	}
}

func TestGuardedByResolvesInheritedAndOverriddenModifierDeclarations(t *testing.T) {
	db := buildDBFromSource(t, `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
abstract contract BaseGuard {
    modifier gate(address baseWho) virtual { assert(baseWho != address(0)); _; }
    modifier inheritedGuard(address who) { require(who != address(0), "zero"); _; }
}
contract GuardedChild is BaseGuard {
    modifier gate(address who) override { require(who == msg.sender, "sender"); _; }
    function overridden(address target) external gate(msg.sender) { target.call(""); }
    function inherited(address target) external inheritedGuard(msg.sender) { target.call(""); }
}`).GetDatabase()
	overriddenTemplate, err := ParseTemplate(`meta: {id: OVERRIDE-GUARD, severity: LOW}
query:
  select: lowlevel_call
  from: entry_function
  where:
    - guarded_by:
        and:
          - block: modifier
          - name: ^gate$
          - has: {block: parameter, name: ^who$}
          - has: {block: require}`)
	if err != nil {
		t.Fatalf("overridden template: %v", err)
	}
	inheritedTemplate, err := ParseTemplate(`meta: {id: INHERITED-GUARD, severity: LOW}
query:
  select: lowlevel_call
  from: entry_function
  where:
    - guarded_by:
        and:
          - block: modifier
          - name: ^inheritedGuard$
          - has: {block: parameter, name: ^who$}
          - has: {block: require}`)
	if err != nil {
		t.Fatalf("inherited template: %v", err)
	}
	if got := findingFunctionNames(New(db).Execute(overriddenTemplate)); !equalStrings(got, []string{"overridden"}) {
		t.Fatalf("overridden modifier findings=%v, want [overridden]", got)
	}
	if got := findingFunctionNames(New(db).Execute(inheritedTemplate)); !equalStrings(got, []string{"inherited"}) {
		t.Fatalf("inherited modifier findings=%v, want [inherited]", got)
	}
}

func TestGuardedByMatchesLocationlessModifierCompatibilityDeclaration(t *testing.T) {
	db := buildDBFromSource(t, `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract LegacyGuard {
    modifier legacyGuard() { _; }
    function run(address target) external legacyGuard { target.call(""); }
}`).GetDatabase()
	contract := db.GetContractByName("LegacyGuard")
	contract.Modifiers[0].AST = nil
	contract.Modifiers[0].StartLine = 0
	contract.Modifiers[0].EndLine = 0
	contract.Modifiers[0].StartCol = 0
	contract.Modifiers[0].EndCol = 0
	contract.Modifiers[0].StartByte = 0
	contract.Modifiers[0].EndByte = 0
	tmpl, err := ParseTemplate(`meta: {id: LEGACY-GUARD, severity: LOW}
query:
  select: lowlevel_call
  from: entry_function
  where:
    - guarded_by: {block: modifier, name: ^legacyGuard$}`)
	if err != nil {
		t.Fatalf("template: %v", err)
	}
	if got := findingFunctionNames(New(db).Execute(tmpl)); !equalStrings(got, []string{"run"}) {
		t.Fatalf("legacy modifier findings=%v, want [run]", got)
	}
}

func TestAppliedModifierDeclarationReusesBoundedContractMemo(t *testing.T) {
	db := buildDBFromSource(t, `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract First {
    modifier gate() { require(true); _; }
}
contract Second {
    modifier gate() { require(false); _; }
}`).GetDatabase()
	first := db.GetContractByName("First")
	second := db.GetContractByName("Second")
	engine := New(db)
	firstOne := engine.appliedModifierDeclaration(first, "gate")
	firstTwo := engine.appliedModifierDeclaration(first, "gate")
	if firstOne == nil || firstTwo == nil || firstOne != firstTwo {
		t.Fatalf("same-contract modifier declarations were rebuilt: %p %p", firstOne, firstTwo)
	}
	secondOne := engine.appliedModifierDeclaration(second, "gate")
	if secondOne == nil || secondOne == firstOne {
		t.Fatalf("cross-contract modifier memo leaked: first=%p second=%p", firstOne, secondOne)
	}
	if secondOne.GetAttributeString("contract") != "Second" ||
		secondOne.GetAttributeString("source_file") != second.SourceFile {
		t.Fatalf("second modifier owner=%q/%q, want Second/%s",
			secondOne.GetAttributeString("contract"), secondOne.GetAttributeString("source_file"), second.SourceFile)
	}
	firstAfterEviction := engine.appliedModifierDeclaration(first, "gate")
	if firstAfterEviction == nil {
		t.Fatal("first modifier missing after eviction")
	}
	if firstAfterEviction == firstOne || firstAfterEviction.GetAttributeString("contract") != "First" ||
		firstAfterEviction.GetAttributeString("source_file") != first.SourceFile {
		t.Fatalf("first modifier after eviction=%p owner=%q/%q, first before=%p",
			firstAfterEviction, firstAfterEviction.GetAttributeString("contract"),
			firstAfterEviction.GetAttributeString("source_file"), firstOne)
	}
	if firstAgain := engine.appliedModifierDeclaration(first, "gate"); firstAgain != firstAfterEviction {
		t.Fatalf("rebuilt first modifier after same-contract lookup: %p %p", firstAfterEviction, firstAgain)
	}
	sourceTemplate, err := ParseTemplate(`meta: {id: RESET-MODIFIER-MEMO, severity: LOW}
query:
  from: source
  where:
    - regex: pragma`)
	if err != nil {
		t.Fatalf("source template: %v", err)
	}
	engine.Execute(sourceTemplate)
	if engine.modifierDeclContract != nil || engine.modifierDeclByName != nil {
		t.Fatalf("Execute did not reset modifier memo: contract=%p declarations=%v",
			engine.modifierDeclContract, engine.modifierDeclByName)
	}
}

func TestAppliedModifierLookupDoesNotMaterializeContractAST(t *testing.T) {
	db := buildDBFromSource(t, `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract GuardOnly {
    modifier gate(address who) { require(who != address(0)); _; }
    function unrelated(uint256 value) external returns (uint256) {
        return value + 1;
    }
}`).GetDatabase()
	contract := db.GetContractByName("GuardOnly")
	engine := New(db)
	if engine.contractASTContract != nil || engine.contractASTRoot != nil {
		t.Fatalf("new engine unexpectedly has contract AST memo")
	}
	modifier := engine.appliedModifierDeclaration(contract, "gate")
	if modifier == nil || modifier.Kind != types.KindDeclModifier || modifier.Name != "gate" {
		t.Fatalf("modifier=%+v, want gate declaration", modifier)
	}
	if engine.contractASTContract != nil || engine.contractASTRoot != nil {
		t.Fatalf("modifier lookup materialized full contract AST: contract=%p root=%p",
			engine.contractASTContract, engine.contractASTRoot)
	}
	if engine.modifierDeclContract != contract || len(engine.modifierDeclByName) != 1 ||
		engine.modifierDeclByName["gate"] != modifier {
		t.Fatalf("modifier-only memo=%p/%v, want one gate declaration for contract",
			engine.modifierDeclContract, engine.modifierDeclByName)
	}
}

func findingFunctionNames(findings []*Finding) []string {
	out := make([]string, 0, len(findings))
	for _, finding := range findings {
		out = append(out, finding.Location.Function)
	}
	sort.Strings(out)
	return out
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}
