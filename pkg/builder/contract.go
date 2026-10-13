package builder

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/th13vn/solast-go/pkg/ast"
	"github.com/th13vn/w3goaudit/pkg/types"
)

// ContractExtractor extracts contracts from AST
type ContractExtractor struct {
	sourceFile      string
	db              *types.Database
	locator         *sourceLocator
	contracts       []*types.Contract
	currentContract *types.Contract
	functionASTs    map[*types.Function]*ast.FunctionDefinition // Store AST nodes for later processing
	modifierASTs    map[*types.Modifier]*ast.ModifierDefinition // Store modifier AST nodes for later processing
	udvts           []*types.UDVTDef                            // Contract-level user-defined value types
}

// visitContract processes a contract definition
func (ce *ContractExtractor) visitContract(node *ast.ContractDefinition) {
	contract := &types.Contract{
		Name:       node.Name,
		Kind:       ce.getContractKind(node),
		SourceFile: ce.sourceFile,
		IsAbstract: node.Kind == "abstract",
	}

	// Extract base contracts
	for _, base := range node.BaseContracts {
		if base.BaseName != nil {
			contract.BaseContracts = append(contract.BaseContracts, base.BaseName.NamePath)
		}
	}

	ce.currentContract = contract

	// Initialize function AST map if needed
	if ce.functionASTs == nil {
		ce.functionASTs = make(map[*types.Function]*ast.FunctionDefinition)
	}
	// Initialize modifier AST map if needed
	if ce.modifierASTs == nil {
		ce.modifierASTs = make(map[*types.Modifier]*ast.ModifierDefinition)
	}

	// Extract functions
	for _, subNode := range node.SubNodes {
		switch n := subNode.(type) {
		case *ast.FunctionDefinition:
			fn := ce.extractFunction(n)
			contract.Functions = append(contract.Functions, fn)
			// Store AST node for later processing
			ce.functionASTs[fn] = n

		case *ast.StateVariableDeclaration:
			for _, decl := range n.Variables {
				sv := ce.extractStateVariable(decl)
				contract.StateVariables = append(contract.StateVariables, sv)
			}

		case *ast.VariableDeclaration:
			if n.IsStateVar {
				sv := ce.extractStateVariable(n)
				contract.StateVariables = append(contract.StateVariables, sv)
			}

		case *ast.EventDefinition:
			ev := ce.extractEvent(n)
			contract.Events = append(contract.Events, ev)

		case *ast.ErrorDefinition:
			er := ce.extractError(n)
			contract.Errors = append(contract.Errors, er)

		case *ast.ModifierDefinition:
			mod := ce.extractModifier(n)
			contract.Modifiers = append(contract.Modifiers, mod)
			// Store AST node for later processing
			ce.modifierASTs[mod] = n

		case *ast.StructDefinition:
			st := ce.extractStruct(n)
			contract.Structs = append(contract.Structs, st)

		case *ast.EnumDefinition:
			en := ce.extractEnum(n)
			contract.Enums = append(contract.Enums, en)

		case *ast.UserDefinedValueTypeDefinition:
			ce.udvts = append(ce.udvts, ce.extractUDVT(n))

		case *ast.UsingForDeclaration:
			ud := ce.extractUsingDirective(n)
			contract.UsingDirectives = append(contract.UsingDirectives, ud)
		}
	}

	span := ce.locator.span(node)
	contract.StartLine, contract.EndLine, contract.StartCol, contract.EndCol, contract.StartByte, contract.EndByte = span.startLine, span.endLine, span.startCol, span.endCol, span.startByte, span.endByte

	ce.contracts = append(ce.contracts, contract)
	ce.currentContract = nil
}

// getContractKind determines the contract kind
func (ce *ContractExtractor) getContractKind(node *ast.ContractDefinition) types.ContractKind {
	switch node.Kind {
	case "interface":
		return types.ContractKindInterface
	case "library":
		return types.ContractKindLibrary
	case "abstract":
		return types.ContractKindAbstract
	case "contract":
		return types.ContractKindContract
	default:
		return types.ContractKindContract
	}
}

// extractFunction extracts a function from AST
func (ce *ContractExtractor) extractFunction(node *ast.FunctionDefinition) *types.Function {
	visibility := types.Visibility(node.Visibility)
	// Solidity versions before 0.5.0 defaulted a function without an
	// explicit visibility modifier to public. solast-go intentionally keeps
	// the source omission as an empty string, so recover the language default
	// here before entry-point and WQL context analysis.
	if visibility == "" && ce.legacySolidityDefaults() {
		visibility = types.VisibilityPublic
	}
	fn := &types.Function{
		Name:            node.Name,
		ContractName:    ce.currentContract.Name,
		SourceFile:      ce.currentContract.SourceFile,
		Visibility:      visibility,
		StateMutability: types.StateMutability(node.StateMutability),
		IsConstructor:   node.IsConstructor,
		IsReceive:       node.IsReceiveEther,
		IsFallback:      node.IsFallback,
		IsVirtual:       node.IsVirtual,
	}

	// Handle special function types (constructor, receive, fallback)
	if fn.IsConstructor {
		fn.Name = "constructor"
	}
	if fn.IsReceive {
		fn.Name = "receive"
	}
	if fn.IsFallback {
		fn.Name = "fallback"
	}

	// Check if function is override
	if len(node.Override) > 0 {
		fn.IsOverride = true
	}

	// Extract parameters
	for _, param := range node.Parameters {
		fn.Parameters = append(fn.Parameters, ce.extractParameter(param))
	}

	// Extract return parameters
	for _, ret := range node.ReturnParameters {
		fn.Returns = append(fn.Returns, ce.extractParameter(ret))
	}

	// Extract modifiers
	for _, mod := range node.Modifiers {
		if mod.Name == "" {
			continue
		}
		fn.Modifiers = append(fn.Modifiers, mod.Name)
		// The invocation range starts at the modifier-name token; keep just the
		// name span (not any argument list) as the xref reference range.
		span := ce.locator.span(mod)
		usage := &types.ModifierUsage{
			Name:      mod.Name,
			StartLine: span.startLine, EndLine: span.startLine,
			StartByte: span.startByte, EndByte: span.startByte + len(mod.Name),
		}
		if span.startLine > 0 {
			if col, ok := ce.locator.column(span.startLine, usage.StartByte); ok {
				usage.StartCol = col
			}
			if col, ok := ce.locator.column(span.startLine, usage.EndByte); ok {
				usage.EndCol = col
			}
		}
		fn.ModifierUsages = append(fn.ModifierUsages, usage)
	}

	// Extract full source location (line + column + byte offset)
	span := ce.locator.span(node)
	fn.StartLine, fn.EndLine, fn.StartCol, fn.EndCol, fn.StartByte, fn.EndByte = span.startLine, span.endLine, span.startCol, span.endCol, span.startByte, span.endByte

	// Note: Selector and signature are calculated in a separate phase
	// after all structs are extracted (see builder.calculateFunctionSelectors)

	return fn
}

var solidityVersionPattern = regexp.MustCompile(`^(>=|<=|==|>|<|=|\^|~)?\s*(\d+)(?:\.(\d+))?(?:\.(\d+))?$`)

// legacyPragmaBefore05 reports whether every version range admitted by a
// Solidity pragma is strictly before 0.5.0. Solidity 0.4.x had implicit
// public function visibility; guessing it for an open range (>=0.4.0) or a
// disjunction that also admits 0.5+ would create false entry points. Unknown
// or malformed constraints therefore return false.
func legacyPragmaBefore05(pragma string) bool {
	branches := strings.Split(strings.TrimSpace(pragma), "||")
	if len(branches) == 0 {
		return false
	}
	for _, branch := range branches {
		branch = strings.TrimSpace(branch)
		if branch == "" || !legacyVersionBranchBefore05(branch) {
			return false
		}
	}
	return true
}

func legacyVersionBranchBefore05(branch string) bool {
	tokens := strings.Fields(normalizeVersionBranchOperators(branch))
	if len(tokens) == 0 {
		return false
	}
	hasBound := false
	for _, token := range tokens {
		m := solidityVersionPattern.FindStringSubmatch(token)
		if len(m) != 5 {
			return false
		}
		major, err := strconv.Atoi(m[2])
		if err != nil {
			return false
		}
		minor := 0
		if m[3] != "" {
			minor, err = strconv.Atoi(m[3])
			if err != nil {
				return false
			}
		}
		patch := 0
		if m[4] != "" {
			patch, err = strconv.Atoi(m[4])
			if err != nil {
				return false
			}
		}
		legacy := major == 0 && minor < 5
		switch m[1] {
		case "^", "~":
			if m[3] == "" || !legacy {
				return false
			}
			hasBound = true
		case "", "=", "==":
			if m[3] == "" || !legacy {
				return false
			}
			hasBound = true
		case "<":
			// An upper bound below 0.5.0 closes the range to legacy
			// compilers. `<0.5` and `<0.5.0` are both accepted.
			if major > 0 || minor > 5 || (minor == 5 && patch > 0) {
				return false
			}
			hasBound = true
		case "<=":
			if !legacy {
				return false
			}
			hasBound = true
		case ">", ">=":
			// Lower bounds alone leave the range open to modern Solidity.
			// A separate legacy upper bound may still close it.
			if major > 0 || minor >= 5 {
				return false
			}
		default:
			return false
		}
	}
	return hasBound && branchHasLegacyUpperBound(tokens)
}

var spacedVersionOperatorPattern = regexp.MustCompile(`(>=|<=|==|>|<|=|\^|~)\s+(\d)`)

func normalizeVersionBranchOperators(branch string) string {
	return spacedVersionOperatorPattern.ReplaceAllString(branch, `$1$2`)
}

func branchHasLegacyUpperBound(tokens []string) bool {
	for _, token := range tokens {
		m := solidityVersionPattern.FindStringSubmatch(token)
		if len(m) != 5 {
			return false
		}
		major, _ := strconv.Atoi(m[2])
		minor := 0
		if m[3] != "" {
			minor, _ = strconv.Atoi(m[3])
		}
		legacy := major == 0 && minor < 5
		switch m[1] {
		case "^", "~", "", "=", "==":
			if legacy {
				return true
			}
		case "<", "<=":
			if legacy || (m[1] == "<" && major == 0 && minor == 5) {
				return true
			}
		}
	}
	return false
}

// legacySolidityDefaults reports whether the source pragma permits the
// pre-0.5 implicit-public function visibility. Keeping this version-gated is
// important because tolerant parsing can also produce an empty visibility for
// malformed modern Solidity, where guessing public would create false entry
// points.
func (ce *ContractExtractor) legacySolidityDefaults() bool {
	if ce == nil || ce.db == nil {
		return false
	}
	sf := ce.db.SourceFiles[ce.sourceFile]
	return sf != nil && legacyPragmaInSource(sf.Content)
}

// extractParameter extracts a parameter from AST
func (ce *ContractExtractor) extractParameter(node *ast.VariableDeclaration) *types.Parameter {
	typeName := getTypeName(node.TypeName)

	p := &types.Parameter{
		Name:     node.Name,
		TypeName: typeName,
	}
	span := ce.locator.span(node)
	p.StartLine, p.EndLine, p.StartCol, p.EndCol, p.StartByte, p.EndByte = span.startLine, span.endLine, span.startCol, span.endCol, span.startByte, span.endByte
	return p
}

// extractStateVariable extracts a state variable from AST
func (ce *ContractExtractor) extractStateVariable(node *ast.VariableDeclaration) *types.StateVariable {
	typeName := getTypeName(node.TypeName)

	sv := &types.StateVariable{
		Name:        node.Name,
		TypeName:    typeName,
		Visibility:  node.Visibility,
		IsConstant:  node.IsDeclaredConst,
		IsImmutable: node.IsImmutable,
	}
	span := ce.locator.span(node)
	sv.StartLine, sv.EndLine, sv.StartCol, sv.EndCol, sv.StartByte, sv.EndByte = span.startLine, span.endLine, span.startCol, span.endCol, span.startByte, span.endByte
	return sv
}

// extractEvent extracts an event from AST
func (ce *ContractExtractor) extractEvent(node *ast.EventDefinition) *types.Event {
	ev := &types.Event{
		Name: node.Name,
	}

	for _, param := range node.Parameters {
		p := ce.extractParameter(param)
		p.Indexed = param.IsIndexed
		ev.Parameters = append(ev.Parameters, p)
	}

	span := ce.locator.span(node)
	ev.StartLine, ev.EndLine, ev.StartCol, ev.EndCol, ev.StartByte, ev.EndByte = span.startLine, span.endLine, span.startCol, span.endCol, span.startByte, span.endByte

	return ev
}

// extractError extracts a custom error declaration from AST.
func (ce *ContractExtractor) extractError(node *ast.ErrorDefinition) *types.ErrorDef {
	er := &types.ErrorDef{
		Name: node.Name,
	}

	for _, param := range node.Parameters {
		er.Parameters = append(er.Parameters, ce.extractParameter(param))
	}

	span := ce.locator.span(node)
	er.StartLine, er.EndLine, er.StartCol, er.EndCol, er.StartByte, er.EndByte = span.startLine, span.endLine, span.startCol, span.endCol, span.startByte, span.endByte

	return er
}

// extractUDVT extracts a user-defined value type declaration from AST.
func (ce *ContractExtractor) extractUDVT(node *ast.UserDefinedValueTypeDefinition) *types.UDVTDef {
	u := &types.UDVTDef{
		Name:           node.Name,
		SourceFile:     ce.sourceFile,
		UnderlyingType: getTypeName(node.UnderlyingType),
	}
	span := ce.locator.span(node)
	u.StartLine, u.EndLine, u.StartCol, u.EndCol, u.StartByte, u.EndByte = span.startLine, span.endLine, span.startCol, span.endCol, span.startByte, span.endByte
	return u
}

// extractModifier extracts a modifier from AST
func (ce *ContractExtractor) extractModifier(node *ast.ModifierDefinition) *types.Modifier {
	mod := &types.Modifier{
		Name: node.Name,
	}

	for _, param := range node.Parameters {
		mod.Parameters = append(mod.Parameters, ce.extractParameter(param))
	}

	// Extract full source location (line + column + byte offset)
	span := ce.locator.span(node)
	mod.StartLine, mod.EndLine, mod.StartCol, mod.EndCol, mod.StartByte, mod.EndByte = span.startLine, span.endLine, span.startCol, span.endCol, span.startByte, span.endByte

	return mod
}

// extractStruct extracts a struct from AST
func (ce *ContractExtractor) extractStruct(node *ast.StructDefinition) *types.Struct {
	st := &types.Struct{
		Name: node.Name,
	}

	for _, member := range node.Members {
		typeName := getTypeName(member.TypeName)
		st.Members = append(st.Members, &types.Member{
			Name:     member.Name,
			TypeName: typeName,
		})
	}

	span := ce.locator.span(node)
	st.StartLine, st.EndLine, st.StartCol, st.EndCol, st.StartByte, st.EndByte = span.startLine, span.endLine, span.startCol, span.endCol, span.startByte, span.endByte

	return st
}

// extractEnum extracts an enum from AST
func (ce *ContractExtractor) extractEnum(node *ast.EnumDefinition) *types.Enum {
	en := &types.Enum{
		Name: node.Name,
	}

	for _, value := range node.Members {
		en.Values = append(en.Values, value.Name)
	}

	span := ce.locator.span(node)
	en.StartLine, en.EndLine, en.StartCol, en.EndCol, en.StartByte, en.EndByte = span.startLine, span.endLine, span.startCol, span.endCol, span.startByte, span.endByte

	return en
}

// extractUsingDirective extracts a 'using Library for Type' directive from AST
func (ce *ContractExtractor) extractUsingDirective(node *ast.UsingForDeclaration) *types.UsingDirective {
	forType := "*" // Default: applies to all types
	if node.TypeName != nil {
		forType = getTypeName(node.TypeName)
	}

	return &types.UsingDirective{
		Library:  node.LibraryName,
		ForType:  forType,
		IsGlobal: node.IsGlobal,
	}
}

// getTypeName extracts the type name string from a TypeName node
func getTypeName(node ast.Node) string {
	if node == nil {
		return "unknown"
	}

	switch t := node.(type) {
	case *ast.ElementaryTypeName:
		return t.Name
	case *ast.UserDefinedTypeName:
		return t.NamePath
	case *ast.ArrayTypeName:
		baseType := getTypeName(t.BaseTypeName)
		// Check for fixed-size array
		if t.Length != nil {
			lengthStr := getArrayLength(t.Length)
			return baseType + "[" + lengthStr + "]"
		}
		return baseType + "[]"
	case *ast.Mapping:
		keyType := getTypeName(t.KeyType)
		valueType := getTypeName(t.ValueType)
		return "mapping(" + keyType + " => " + valueType + ")"
	case *ast.FunctionTypeName:
		return "function"
	default:
		return "unknown"
	}
}

// getArrayLength extracts the length expression from an array length node
func getArrayLength(node ast.Node) string {
	if node == nil {
		return ""
	}

	switch n := node.(type) {
	case *ast.NumberLiteral:
		return n.Number
	case *ast.Identifier:
		return n.Name
	case *ast.MemberAccess:
		// For constants like MyContract.LENGTH
		return n.MemberName
	default:
		// For complex expressions, just return a placeholder
		return ""
	}
}
