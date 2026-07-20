package types

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/crypto/sha3"
)

var accessControlNameRegex = regexp.MustCompile(`(?i)(owner|admin|auth|authori[sz]ed|operator|role|permission|allow|whitelist|guardian|minter|pauser)`)

// Visibility represents function visibility
type Visibility string

const (
	VisibilityPublic   Visibility = "public"
	VisibilityExternal Visibility = "external"
	VisibilityInternal Visibility = "internal"
	VisibilityPrivate  Visibility = "private"
)

// StateMutability represents the state mutability of a function
type StateMutability string

const (
	StateMutabilityPure       StateMutability = "pure"
	StateMutabilityView       StateMutability = "view"
	StateMutabilityPayable    StateMutability = "payable"
	StateMutabilityNonPayable StateMutability = "nonpayable"
)

// Function represents a Solidity function
type Function struct {
	// Name of the function (empty for constructor, receive, fallback)
	Name string `json:"name"`

	// ContractName is the contract this function belongs to
	ContractName string `json:"contractName"`

	// SourceFile is the absolute path of the file that defines this function.
	// Recorded at build time so source lookups never have to re-resolve the
	// owning contract by name (which is ambiguous under name collisions).
	SourceFile string `json:"sourceFile,omitempty"`

	// Visibility of the function
	Visibility Visibility `json:"visibility"`

	// StateMutability of the function
	StateMutability StateMutability `json:"stateMutability,omitempty"`

	// Parameters of the function
	Parameters []*Parameter `json:"parameters,omitempty"`

	// Returns of the function
	Returns []*Parameter `json:"returns,omitempty"`

	// Modifiers applied to this function
	Modifiers []string `json:"modifiers,omitempty"`

	// IsConstructor indicates if this is a constructor
	IsConstructor bool `json:"isConstructor,omitempty"`

	// IsReceive indicates if this is the receive function
	IsReceive bool `json:"isReceive,omitempty"`

	// IsFallback indicates if this is the fallback function
	IsFallback bool `json:"isFallback,omitempty"`

	// IsVirtual indicates if function can be overridden
	IsVirtual bool `json:"isVirtual,omitempty"`

	// IsOverride indicates if function overrides a parent
	IsOverride bool `json:"isOverride,omitempty"`

	// Selector is the canonical function selector: functionName(param1Type,param2Type,...)
	Selector string `json:"selector,omitempty"`

	// Signature is the 4-byte function signature (first 4 bytes of keccak256(selector))
	Signature string `json:"signature,omitempty"`

	// Calls contains function calls made within this function
	Calls []*FunctionCall `json:"calls,omitempty"`

	// AST is the parsed Abstract Syntax Tree of the function body
	// Used for deep pattern matching in WQL templates.
	AST *ASTNode `json:"ast,omitempty"`

	// SourceLocation for debugging
	StartLine int `json:"startLine,omitempty"`
	EndLine   int `json:"endLine,omitempty"`
	StartCol  int `json:"startCol,omitempty"`
	EndCol    int `json:"endCol,omitempty"`
	StartByte int `json:"startByte,omitempty"`
	EndByte   int `json:"endByte,omitempty"`
}

// Parameter represents a function parameter or return value
type Parameter struct {
	Name     string `json:"name,omitempty"`
	TypeName string `json:"typeName"`
	Indexed  bool   `json:"indexed,omitempty"` // For event parameters

	// SourceLocation for debugging / click-to-jump
	StartLine int `json:"startLine,omitempty"`
	EndLine   int `json:"endLine,omitempty"`
	StartCol  int `json:"startCol,omitempty"`
	EndCol    int `json:"endCol,omitempty"`
	StartByte int `json:"startByte,omitempty"`
	EndByte   int `json:"endByte,omitempty"`
}

// FunctionCall represents a call to another function
type FunctionCall struct {
	// Target is the function being called (name as in source)
	Target string `json:"target"`

	// ContractName is the contract of the target (if external call)
	ContractName string `json:"contractName,omitempty"`

	// ResolvedContract is the actual contract where function is defined
	ResolvedContract string `json:"resolvedContract,omitempty"`

	// ResolvedContractID is the exact file#Contract identity. It is additive;
	// ResolvedContract remains the compatibility/display name.
	ResolvedContractID string `json:"resolvedContractId,omitempty"`

	// ResolvedFunction is the actual function name (after resolution)
	ResolvedFunction string `json:"resolvedFunction,omitempty"`

	// Signature is the 4-byte function signature (if applicable)
	Signature string `json:"signature,omitempty"`

	// CallType indicates the type of call
	CallType CallType `json:"callType"`

	// TargetKind is the kind of target (contract/abstract/library/interface)
	TargetKind ContractKind `json:"targetKind,omitempty"`

	// Line where the call occurs
	Line int `json:"line,omitempty"`

	// Col is the 1-based Unicode-code-point column of the call site; Byte is its
	// 0-based UTF-8 byte offset.
	Col  int `json:"col,omitempty"`
	Byte int `json:"byte,omitempty"`

	// Resolved indicates if target was fully resolved
	Resolved bool `json:"resolved,omitempty"`

	// ArgCount is the number of arguments at the call site.
	// Used to disambiguate overloaded functions with the same name.
	// -1 means unknown (e.g. loaded from old JSON without this field).
	ArgCount int `json:"argCount"`

	// Arguments preserves simplified argument ASTs when later semantic analysis
	// needs the exact call-site binding. The builder currently records these for
	// modifier invocations; the field is additive for schema-2.0.0 compatibility.
	Arguments []*ASTNode `json:"arguments,omitempty"`
}

// UnmarshalJSON preserves the distinction between legacy calls that omitted
// argCount (unknown, -1) and genuine zero-argument calls. The ordinary int
// zero value cannot represent both states.
func (call *FunctionCall) UnmarshalJSON(data []byte) error {
	type functionCallAlias FunctionCall
	decoded := struct {
		*functionCallAlias
		ArgCount json.RawMessage `json:"argCount"`
	}{
		functionCallAlias: (*functionCallAlias)(call),
	}
	call.ArgCount = -1
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	if len(decoded.ArgCount) == 0 {
		return nil
	}
	return json.Unmarshal(decoded.ArgCount, &call.ArgCount)
}

// IsEntrypoint returns true if function is a public/external entry point that can modify state
// View and pure functions are excluded as they cannot modify contract state
func (f *Function) IsEntrypoint() bool {
	if f.IsConstructor {
		return false
	}
	// Must be public or external
	if f.Visibility != VisibilityPublic && f.Visibility != VisibilityExternal {
		return false
	}
	// Exclude view and pure (they can't modify state)
	if f.StateMutability == StateMutabilityView || f.StateMutability == StateMutabilityPure {
		return false
	}
	return true
}

// GetSelector returns the function selector: functionName(param1Type,param2Type,...)
// with recursive struct resolution to tuple format
func (f *Function) GetSelector(structDefs map[string]*Struct) string {
	if f.IsConstructor {
		return ""
	}

	params := make([]string, len(f.Parameters))

	// Special case: receive and fallback have no types in signature calculation
	if f.IsReceive || f.IsFallback {
		// params stays empty
	} else {
		for i, p := range f.Parameters {
			params[i] = NormalizeType(p.TypeName, structDefs)
		}
	}

	return fmt.Sprintf("%s(%s)", f.Name, strings.Join(params, ","))
}

// GetSignature returns the 4-byte function signature (first 4 bytes of keccak256(selector))
func (f *Function) GetSignature(structDefs map[string]*Struct) string {
	if f.IsConstructor {
		return ""
	}

	selector := f.GetSelector(structDefs)
	if selector == "" {
		return ""
	}

	hash := keccak256([]byte(selector))
	return hex.EncodeToString(hash[:4])
}

// keccak256 computes the Keccak-256 hash
func keccak256(data []byte) []byte {
	hash := sha3.NewLegacyKeccak256()
	hash.Write(data)
	return hash.Sum(nil)
}

// NormalizeType converts Solidity types to their canonical form
// with recursive struct resolution. Structs are converted to tuple format: (type1,type2,...)
// If structDefs is nil, no struct resolution is performed
func NormalizeType(typeName string, structDefs map[string]*Struct) string {
	return normalizeTypeRecursive(typeName, structDefs, make(map[string]bool))
}

// normalizeTypeRecursive is the internal recursive implementation
func normalizeTypeRecursive(typeName string, structDefs map[string]*Struct, visited map[string]bool) string {
	// Remove storage location keywords
	typeName = strings.ReplaceAll(typeName, " memory", "")
	typeName = strings.ReplaceAll(typeName, " storage", "")
	typeName = strings.ReplaceAll(typeName, " calldata", "")
	typeName = strings.TrimSpace(typeName)

	// Handle dynamic arrays: type[]
	if strings.HasSuffix(typeName, "[]") {
		baseType := strings.TrimSuffix(typeName, "[]")
		resolvedBase := normalizeTypeRecursive(baseType, structDefs, visited)
		return resolvedBase + "[]"
	}

	// Handle fixed-size arrays: type[n]
	if idx := strings.LastIndex(typeName, "["); idx > 0 && strings.HasSuffix(typeName, "]") {
		baseType := typeName[:idx]
		arraySuffix := typeName[idx:]
		resolvedBase := normalizeTypeRecursive(baseType, structDefs, visited)
		return resolvedBase + arraySuffix
	}

	// Handle mapping type - not valid in function signatures but handle gracefully
	if strings.HasPrefix(typeName, "mapping(") {
		return typeName
	}

	// Handle function type
	if strings.HasPrefix(typeName, "function(") {
		return typeName
	}

	// Check if it's a primitive type (no struct resolution needed)
	if isPrimitiveType(typeName) {
		return typeName
	}

	// Try to resolve as a struct
	if structDefs != nil {
		if structDef, ok := structDefs[typeName]; ok {
			// Prevent infinite recursion for circular struct references
			if visited[typeName] {
				return typeName
			}
			visited[typeName] = true

			// Convert struct to tuple: (member1Type,member2Type,...)
			memberTypes := make([]string, len(structDef.Members))
			for i, member := range structDef.Members {
				memberTypes[i] = normalizeTypeRecursive(member.TypeName, structDefs, visited)
			}
			return "(" + strings.Join(memberTypes, ",") + ")"
		}
	}

	// Unknown type (could be enum, contract type, etc.), return as-is
	return typeName
}

// isPrimitiveType checks if a type is a Solidity primitive type
func isPrimitiveType(typeName string) bool {
	// Address types
	if typeName == "address" || typeName == "address payable" {
		return true
	}

	// Boolean
	if typeName == "bool" {
		return true
	}

	// String
	if typeName == "string" {
		return true
	}

	// Dynamic bytes
	if typeName == "bytes" {
		return true
	}

	// Fixed-size bytes: bytes1 to bytes32
	if strings.HasPrefix(typeName, "bytes") {
		suffix := strings.TrimPrefix(typeName, "bytes")
		if len(suffix) > 0 && len(suffix) <= 2 {
			for _, c := range suffix {
				if c < '0' || c > '9' {
					return false
				}
			}
			return true
		}
	}

	// Unsigned integers: uint, uint8, uint16, ..., uint256
	if strings.HasPrefix(typeName, "uint") {
		suffix := strings.TrimPrefix(typeName, "uint")
		if suffix == "" || isValidIntSize(suffix) {
			return true
		}
	}

	// Signed integers: int, int8, int16, ..., int256
	if strings.HasPrefix(typeName, "int") && !strings.HasPrefix(typeName, "interface") {
		suffix := strings.TrimPrefix(typeName, "int")
		if suffix == "" || isValidIntSize(suffix) {
			return true
		}
	}

	// byte is alias for bytes1
	if typeName == "byte" {
		return true
	}

	return false
}

// isValidIntSize checks if the string is a valid Solidity integer bit width:
// a multiple of 8 in [8, 256]. Validating this prevents a user type whose name
// merely starts with "int"/"uint" (e.g. a struct `intData`) from being treated
// as a primitive and skipping tuple/selector resolution.
func isValidIntSize(s string) bool {
	n, err := strconv.Atoi(s)
	if err != nil {
		return false
	}
	return n >= 8 && n <= 256 && n%8 == 0
}

// UniqueID generates a unique ID for the function based on contract and selector
func (f *Function) UniqueID(structDefs map[string]*Struct) string {
	selector := f.GetSelector(structDefs)
	if selector == "" {
		selector = f.Name
	}
	data := fmt.Sprintf("%s.%s", f.ContractName, selector)
	if f.SourceFile != "" {
		data = MakeFunctionID(f.SourceFile, f.ContractName, selector)
	}
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:8])
}

func functionIdentityKey(f *Function) string {
	if f == nil {
		return ""
	}
	selector := f.Selector
	if selector == "" {
		selector = f.Name
	}
	if f.SourceFile != "" {
		return MakeFunctionID(f.SourceFile, f.ContractName, selector)
	}
	return f.ContractName + "." + selector
}

type accessControlAnalysis struct {
	db    *Database
	stack map[string]bool
	memo  map[string]bool
}

// IsAccessControlled reports whether exact bodies prove privileged caller
// authorization. Modifier and helper names are descriptive only: applied
// modifiers and internal calls must resolve through db, then their actual body
// or recursively resolved behavior must contain a privileged caller check.
func (f *Function) IsAccessControlled(db *Database) bool {
	if f == nil {
		return false
	}
	analysis := &accessControlAnalysis{
		db:    db,
		stack: make(map[string]bool),
		memo:  make(map[string]bool),
	}
	return analysis.functionControlled(f, nil)
}

func (a *accessControlAnalysis) functionControlled(f *Function, callerParams map[string]bool) bool {
	if f == nil {
		return false
	}
	return a.bodyControlled("function:"+functionIdentityKey(f), f, callerParams)
}

func (a *accessControlAnalysis) modifierControlled(contract *Contract, mod *Modifier, invocation *FunctionCall, invokingFn *Function) bool {
	if contract == nil || mod == nil || invocation == nil {
		return false
	}
	authParams, fixedParams := modifierArgumentBindings(mod, invocation.Arguments, invokingFn, a.db)
	fn := &Function{
		Name:         mod.Name,
		ContractName: contract.Name,
		SourceFile:   contract.SourceFile,
		Parameters:   mod.Parameters,
		Calls:        mod.Calls,
		AST:          mod.AST,
	}
	identity := fmt.Sprintf("modifier:%s@%d:%d", MakeModifierID(contract.SourceFile, contract.Name, mod.Name), invocation.Line, invocation.Byte)
	return a.bodyControlledWithParams(identity, fn, nil, authParams, fixedParams)
}

// bodyControlled uses a context-aware key so the same exact body reached with
// different caller, authorization-boolean, or fixed-operand bindings cannot
// suppress a later authorized visit. stack detects only active recursion
// cycles; memo bounds repeated completed traversals within this analysis.
func (a *accessControlAnalysis) bodyControlled(identity string, f *Function, callerParams map[string]bool) (result bool) {
	return a.bodyControlledWithParams(identity, f, callerParams, nil, nil)
}

func (a *accessControlAnalysis) bodyControlledWithParams(identity string, f *Function, callerParams, authParams, fixedParams map[string]bool) (result bool) {
	key := accessControlContextKey(identity, callerParams, authParams, fixedParams)
	if cached, ok := a.memo[key]; ok {
		return cached
	}
	if a.stack[key] {
		return false
	}
	a.stack[key] = true
	defer func() {
		delete(a.stack, key)
		a.memo[key] = result
	}()

	for _, call := range f.Calls {
		if call == nil || call.CallType != CallTypeModifier {
			continue
		}
		contract, mod := resolveExactAppliedModifier(a.db, call)
		if a.modifierControlled(contract, mod, call, f) {
			return true
		}
	}

	if bodyEnforcesAuthorization(f.AST, f, a, callerParams, authParams, fixedParams) {
		return true
	}

	for _, call := range f.Calls {
		if !isInternalCall(call.CallType) {
			continue
		}
		callee := resolveExactAccessControlCallee(a.db, call)
		if callee == nil {
			continue
		}
		forwardedCaller, forwardedAuth, forwardedFixed := a.exactCallBindings(f, call, callee, callerParams, authParams, fixedParams)
		if a.bodyControlledWithParams("function:"+functionIdentityKey(callee), callee, forwardedCaller, forwardedAuth, forwardedFixed) {
			return true
		}
	}
	return false
}

func (a *accessControlAnalysis) exactCallBindings(fn *Function, call *FunctionCall, callee *Function, callerParams, authParams, fixedParams map[string]bool) (caller, auth, fixed map[string]bool) {
	node := exactASTCallForMetadata(fn, call)
	if node == nil || callee == nil {
		return nil, nil, nil
	}
	for i, argument := range solidityArgNodes(node) {
		if i >= len(callee.Parameters) || callee.Parameters[i] == nil || callee.Parameters[i].Name == "" {
			continue
		}
		name := callee.Parameters[i].Name
		if expressionIsCallerIdentity(argument, fn, a.db, callerParams) {
			if caller == nil {
				caller = make(map[string]bool)
			}
			caller[name] = true
		}
		if expressionRequiresAuthorization(argument, true, fn, a, callerParams, authParams, fixedParams) {
			if auth == nil {
				auth = make(map[string]bool)
			}
			auth[name] = true
		}
		if expressionIsFixedOperand(argument, fn, a.db, callerParams, fixedParams) {
			if fixed == nil {
				fixed = make(map[string]bool)
			}
			fixed[name] = true
		}
	}
	return caller, auth, fixed
}

func exactASTCallForMetadata(fn *Function, metadata *FunctionCall) *ASTNode {
	if fn == nil || fn.AST == nil || metadata == nil {
		return nil
	}
	var exact []*ASTNode
	var line []*ASTNode
	var named []*ASTNode
	fn.AST.WalkDescendants(func(node *ASTNode) bool {
		if node == nil || !strings.HasPrefix(node.Kind, "call.") || node.Name != metadata.Target {
			return true
		}
		named = append(named, node)
		if metadata.Byte > 0 && node.StartByte == metadata.Byte {
			exact = append(exact, node)
		}
		if metadata.Line > 0 && node.StartLine == metadata.Line {
			line = append(line, node)
		}
		return true
	})
	if len(exact) == 1 {
		return exact[0]
	}
	if len(exact) > 1 {
		return nil
	}
	if len(line) == 1 {
		return line[0]
	}
	if len(line) > 1 {
		return nil
	}
	if metadata.Byte == 0 && metadata.Line == 0 && len(named) == 1 {
		return named[0]
	}
	return nil
}

func accessControlContextKey(identity string, callerParams, authParams, fixedParams map[string]bool) string {
	return identity +
		"|caller=" + sortedBindingNames(callerParams) +
		"|auth=" + sortedBindingNames(authParams) +
		"|fixed=" + sortedBindingNames(fixedParams)
}

func sortedBindingNames(bindings map[string]bool) string {
	params := make([]string, 0, len(bindings))
	for name, active := range bindings {
		if active {
			params = append(params, name)
		}
	}
	sort.Strings(params)
	return strings.Join(params, ",")
}

func resolveExactAppliedModifier(db *Database, call *FunctionCall) (*Contract, *Modifier) {
	if db == nil || call == nil || !call.Resolved || call.ResolvedContractID == "" || call.ResolvedFunction == "" {
		return nil, nil
	}
	contract := db.GetContractByID(call.ResolvedContractID)
	if contract == nil {
		return nil, nil
	}
	for _, mod := range contract.Modifiers {
		if mod != nil && mod.Name == call.ResolvedFunction {
			return contract, mod
		}
	}
	return nil, nil
}

func resolveExactAccessControlCallee(db *Database, call *FunctionCall) *Function {
	if db == nil || call == nil || !call.Resolved || call.ResolvedContractID == "" || call.ResolvedFunction == "" {
		return nil
	}
	contract := db.GetContractByID(call.ResolvedContractID)
	if contract == nil {
		return nil
	}
	for _, fn := range contract.Functions {
		if fn == nil {
			continue
		}
		if fn.Selector != "" && fn.Selector == call.ResolvedFunction {
			return fn
		}
		if fn.Selector == "" && fn.Name == call.ResolvedFunction {
			return fn
		}
	}
	return nil
}

func modifierArgumentBindings(mod *Modifier, arguments []*ASTNode, fn *Function, db *Database) (authParams, fixedParams map[string]bool) {
	for i, param := range mod.Parameters {
		if i >= len(arguments) || param == nil || param.Name == "" {
			continue
		}
		if expressionRequiresAuthorization(arguments[i], true, fn, &accessControlAnalysis{db: db}, nil, nil, nil) {
			if authParams == nil {
				authParams = make(map[string]bool)
			}
			authParams[param.Name] = true
		}
		if expressionIsFixedOperand(arguments[i], fn, db, nil, nil) {
			if fixedParams == nil {
				fixedParams = make(map[string]bool)
			}
			fixedParams[param.Name] = true
		}
	}
	return authParams, fixedParams
}

func bodyEnforcesAuthorization(root *ASTNode, fn *Function, analysis *accessControlAnalysis, callerParams, authParams, fixedParams map[string]bool) bool {
	if root == nil {
		return false
	}
	found := false
	inspect := func(n *ASTNode) bool {
		if n == nil || !enforcementNodeIsUnconditional(n, root) {
			return true
		}
		switch n.Kind {
		case KindCheckRequire, KindCheckAssert:
			if len(n.Children) > 0 && expressionRequiresAuthorization(n.Children[0], true, fn, analysis, callerParams, authParams, fixedParams) {
				found = true
				return false
			}
		case KindStmtIf:
			if len(n.Children) < 2 {
				return true
			}
			thenReverts := branchAlwaysReverts(n.Children[1])
			elseReverts := len(n.Children) > 2 && branchAlwaysReverts(n.Children[2])
			if thenReverts == elseReverts {
				return true
			}
			requiredTruth := elseReverts
			if expressionRequiresAuthorization(n.Children[0], requiredTruth, fn, analysis, callerParams, authParams, fixedParams) {
				found = true
				return false
			}
		}
		return true
	}
	if !inspect(root) {
		return true
	}
	root.WalkDescendants(inspect)
	return found
}

func enforcementNodeIsUnconditional(node, root *ASTNode) bool {
	for current := node.Parent; current != nil && current != root; current = current.Parent {
		switch current.Kind {
		case KindStmtIf, KindStmtLoop, KindExprConditional, KindStmtTryCatch:
			return false
		}
	}
	return true
}

func branchAlwaysReverts(node *ASTNode) bool {
	if node == nil {
		return false
	}
	if node.Kind == KindCheckRevert {
		return true
	}
	if node.Kind == KindStmtBlock || node.Kind == KindStmtUnchecked {
		if len(node.Children) == 0 {
			return false
		}
		return branchAlwaysReverts(node.Children[len(node.Children)-1])
	}
	if node.Kind == KindStmtIf && len(node.Children) > 2 {
		return branchAlwaysReverts(node.Children[1]) && branchAlwaysReverts(node.Children[2])
	}
	return false
}

func expressionRequiresAuthorization(expr *ASTNode, wantTrue bool, fn *Function, analysis *accessControlAnalysis, callerParams, authParams, fixedParams map[string]bool) bool {
	if expr == nil {
		return false
	}
	var db *Database
	if analysis != nil {
		db = analysis.db
	}
	if expr.Kind == KindExprIdentifier && authParams[expr.Name] {
		return wantTrue
	}
	if roleCallProvesAuthorization(expr, fn, analysis, callerParams, fixedParams) || accessMappingProvesAuthorization(expr, fn, db, callerParams, fixedParams) {
		return wantTrue
	}
	if expr.Kind == KindExprUnaryOp && expr.GetAttributeString("operator") == "!" && len(expr.Children) > 0 {
		return expressionRequiresAuthorization(expr.Children[0], !wantTrue, fn, analysis, callerParams, authParams, fixedParams)
	}
	if expr.Kind != KindExprBinaryOp || len(expr.Children) < 2 {
		return false
	}
	op := expr.GetAttributeString("operator")
	left, right := expr.Children[0], expr.Children[1]
	switch op {
	case "&&":
		if wantTrue {
			return expressionRequiresAuthorization(left, true, fn, analysis, callerParams, authParams, fixedParams) ||
				expressionRequiresAuthorization(right, true, fn, analysis, callerParams, authParams, fixedParams)
		}
		return expressionRequiresAuthorization(left, false, fn, analysis, callerParams, authParams, fixedParams) &&
			expressionRequiresAuthorization(right, false, fn, analysis, callerParams, authParams, fixedParams)
	case "||":
		if wantTrue {
			return expressionRequiresAuthorization(left, true, fn, analysis, callerParams, authParams, fixedParams) &&
				expressionRequiresAuthorization(right, true, fn, analysis, callerParams, authParams, fixedParams)
		}
		return expressionRequiresAuthorization(left, false, fn, analysis, callerParams, authParams, fixedParams) ||
			expressionRequiresAuthorization(right, false, fn, analysis, callerParams, authParams, fixedParams)
	case "==", "!=":
		if value, ok := booleanLiteral(right); ok {
			required := wantTrue == (op == "==")
			if !value {
				required = !required
			}
			return expressionRequiresAuthorization(left, required, fn, analysis, callerParams, authParams, fixedParams)
		}
		if value, ok := booleanLiteral(left); ok {
			required := wantTrue == (op == "==")
			if !value {
				required = !required
			}
			return expressionRequiresAuthorization(right, required, fn, analysis, callerParams, authParams, fixedParams)
		}
		if privilegedCallerComparison(left, right, fn, db, callerParams) || privilegedCallerComparison(right, left, fn, db, callerParams) {
			if op == "==" {
				return wantTrue
			}
			return !wantTrue
		}
	}
	return false
}

func booleanLiteral(n *ASTNode) (bool, bool) {
	if n == nil || n.Kind != KindExprLiteral || n.GetAttributeString("subtype") != "bool" {
		return false, false
	}
	switch n.Value {
	case "true":
		return true, true
	case "false":
		return false, true
	default:
		return false, false
	}
}

func privilegedCallerComparison(caller, authority *ASTNode, fn *Function, db *Database, callerParams map[string]bool) bool {
	return expressionIsCallerIdentity(caller, fn, db, callerParams) &&
		!expressionIsCallerIdentity(authority, fn, db, callerParams) &&
		!isCallerControlledTarget(authority, fn, db)
}

func roleCallProvesAuthorization(call *ASTNode, fn *Function, analysis *accessControlAnalysis, callerParams, fixedParams map[string]bool) bool {
	if call == nil || call.Kind != KindCallInternal || call.Name != "hasRole" || analysis == nil || analysis.db == nil {
		return false
	}
	metadata := recordedExactInternalCallForNode(fn, call)
	callee := resolveExactAccessControlCallee(analysis.db, metadata)
	if callee == nil || callee.Name != "hasRole" || callee.AST == nil {
		return false
	}
	args := solidityArgNodes(call)
	if len(args) < 2 || len(callee.Parameters) < 2 || callee.Parameters[0] == nil || callee.Parameters[1] == nil ||
		callee.Parameters[0].Name == "" || callee.Parameters[1].Name == "" ||
		!expressionIsCallerIdentity(args[1], fn, analysis.db, callerParams) ||
		!expressionIsFixedOperand(args[0], fn, analysis.db, callerParams, fixedParams) {
		return false
	}
	calleeCaller := map[string]bool{callee.Parameters[1].Name: true}
	calleeFixed := map[string]bool{callee.Parameters[0].Name: true}
	return functionReturnsAccessMembership(callee, analysis.db, calleeCaller, calleeFixed)
}

func accessMappingProvesAuthorization(index *ASTNode, fn *Function, db *Database, callerParams, fixedParams map[string]bool) bool {
	base, keys := flattenIndexAccess(index)
	if base == nil || len(keys) == 0 || !isAccessControlName(accessLookupRootName(base)) {
		return false
	}
	callerKeys := 0
	for _, key := range keys {
		if expressionIsCallerIdentity(key, fn, db, callerParams) {
			callerKeys++
			if callerKeys > 1 {
				return false
			}
			continue
		}
		if expressionContainsCallerIdentity(key, fn, db, callerParams) {
			return false
		}
		if !expressionIsFixedOperand(key, fn, db, callerParams, fixedParams) {
			return false
		}
	}
	return callerKeys == 1
}

func flattenIndexAccess(index *ASTNode) (*ASTNode, []*ASTNode) {
	if index == nil || index.Kind != KindExprIndexAccess || len(index.Children) < 2 {
		return nil, nil
	}
	base := index.Children[0]
	keys := append([]*ASTNode(nil), index.Children[1:]...)
	if base.Kind == KindExprIndexAccess {
		root, innerKeys := flattenIndexAccess(base)
		if root == nil {
			return nil, nil
		}
		return root, append(innerKeys, keys...)
	}
	return base, keys
}

func accessLookupRootName(n *ASTNode) string {
	for n != nil {
		switch n.Kind {
		case KindExprIdentifier, KindExprMemberAccess:
			return n.Name
		case KindExprIndexAccess:
			if len(n.Children) == 0 {
				return ""
			}
			n = n.Children[0]
		default:
			return ""
		}
	}
	return ""
}

func expressionIsCallerIdentity(expr *ASTNode, fn *Function, db *Database, callerParams map[string]bool) bool {
	if expr == nil {
		return false
	}
	if isDirectAuthSource(expr, fn, db) {
		return true
	}
	if expr.Kind == KindExprIdentifier && callerParams[expr.Name] {
		return true
	}
	if expr.Kind == KindExprIdentifier && fn != nil && isTaintedIdentifier(expr.Name, fn.AST, fn, db) {
		return true
	}
	if (expr.Kind == KindCallInternal || expr.Kind == KindCallExternal) && isTypeCastName(expr.Name) && len(solidityArgNodes(expr)) == 1 {
		return expressionIsCallerIdentity(solidityArgNodes(expr)[0], fn, db, callerParams)
	}
	return false
}

func expressionContainsCallerIdentity(root *ASTNode, fn *Function, db *Database, callerParams map[string]bool) bool {
	if root == nil {
		return false
	}
	if expressionIsCallerIdentity(root, fn, db, callerParams) {
		return true
	}
	found := false
	root.WalkDescendants(func(n *ASTNode) bool {
		if expressionIsCallerIdentity(n, fn, db, callerParams) {
			found = true
			return false
		}
		return true
	})
	return found
}

func expressionIsFixedOperand(expr *ASTNode, fn *Function, db *Database, callerParams, fixedParams map[string]bool) bool {
	if expr == nil || expressionContainsCallerIdentity(expr, fn, db, callerParams) {
		return false
	}
	if expr.Kind == KindExprIdentifier && fixedParams[expr.Name] {
		return true
	}
	return !isCallerControlledTarget(expr, fn, db)
}

func recordedExactInternalCallForNode(fn *Function, node *ASTNode) *FunctionCall {
	if fn == nil || node == nil {
		return nil
	}
	var exact []*FunctionCall
	var line []*FunctionCall
	var named []*FunctionCall
	for _, call := range fn.Calls {
		if call == nil || !isInternalCall(call.CallType) || bareFuncName(call.Target) != node.Name {
			continue
		}
		named = append(named, call)
		if node.StartByte > 0 && call.Byte == node.StartByte {
			exact = append(exact, call)
		}
		if node.StartLine > 0 && call.Line == node.StartLine {
			line = append(line, call)
		}
	}
	if len(exact) == 1 {
		return exact[0]
	}
	if len(exact) > 1 {
		return nil
	}
	if len(line) == 1 {
		return line[0]
	}
	if len(line) > 1 {
		return nil
	}
	if node.StartByte == 0 && node.StartLine == 0 && len(named) == 1 {
		return named[0]
	}
	return nil
}

func functionReturnsAccessMembership(fn *Function, db *Database, callerParams, fixedParams map[string]bool) bool {
	if fn == nil || fn.AST == nil {
		return false
	}
	var returns []*ASTNode
	fn.AST.WalkDescendants(func(n *ASTNode) bool {
		if n.Kind == KindStmtReturn {
			returns = append(returns, n)
		}
		return true
	})
	if len(returns) == 0 {
		return false
	}
	for _, ret := range returns {
		if !enforcementNodeIsUnconditional(ret, fn.AST) || len(ret.Children) != 1 ||
			!accessMappingProvesAuthorization(ret.Children[0], fn, db, callerParams, fixedParams) {
			return false
		}
	}
	return true
}

// isInternalCall reports whether a call stays within the contract's own code
// (so its body is in scope for recursive auth/self-scoping analysis).
func isInternalCall(t CallType) bool {
	return t == "internal" || t == "inherited" || t == "self" || t == "super"
}

// resolveInternalCallee resolves an internal/inherited/self/super call to the
// most-derived implementation of the target function, or nil.
//
// It prefers the runtime implementation: iterate the deployment (main) contracts
// whose linearized hierarchy contains THIS function's contract, in deterministic
// order, and return the first match walking the C3 list derived-first. Falls
// back to the statically resolved contract. Resolution matches by bare function
// name (see calleeNameMatches) because the stored selector carries arg types.
func (f *Function) resolveInternalCallee(db *Database, call *FunctionCall) *Function {
	if db == nil || call == nil {
		return nil
	}
	targetFuncName := call.ResolvedFunction
	if targetFuncName == "" {
		targetFuncName = call.Target
	}

	mainIDs := make([]string, 0, len(db.MainContracts))
	for id := range db.MainContracts {
		mainIDs = append(mainIDs, id)
	}
	sort.Strings(mainIDs)

	for _, mainContractID := range mainIDs {
		mainContract := db.GetContract(mainContractID)
		if mainContract == nil || !contractHierarchyContains(db, mainContract, f) {
			continue
		}
		for _, baseContract := range db.LinearizedContracts(mainContract) {
			for _, baseFn := range baseContract.Functions {
				if calleeNameMatches(baseFn, call, targetFuncName) {
					return baseFn
				}
			}
		}
	}

	// Fallback: statically resolved contract.
	if call.ResolvedFunction != "" {
		targetContract := db.GetContractByID(call.ResolvedContractID)
		if targetContract == nil && call.ResolvedContract != "" {
			// Compatibility for caches written before ResolvedContractID.
			targetContract = db.ResolveContractName(call.ResolvedContract, f.SourceFile)
		}
		if targetContract != nil {
			for _, targetFn := range targetContract.Functions {
				if calleeNameMatches(targetFn, call, call.ResolvedFunction) {
					return targetFn
				}
			}
		}
	}
	return nil
}

// ComparesCallerIdentity reports whether the function constrains a caller-identity
// source (msg.sender / tx.origin / _msgSender) by comparing it — inside a guard or
// condition — against another operand, INCLUDING a function argument
// (e.g. require(from == msg.sender), if (from != msg.sender) revert,
// assert(request.from == msg.sender)).
//
// This is caller "self-scoping", NOT privileged access control: it does not gate
// the function to an owner/role, it binds a sensitive value to the caller. It is
// the canonical mitigation for arbitrary transferFrom (you can only move your own
// tokens), so detectors for that class treat it as a valid protection even though
// IsAccessControlled (privileged-only, by design) does not. Keep these concepts
// separate: self-scoping is permissionless and must not count as access control
// for entry-point classification.
func (f *Function) ComparesCallerIdentity(databases ...*Database) bool {
	var db *Database
	for _, candidate := range databases {
		if candidate != nil {
			db = candidate
			break
		}
	}
	return f.comparesCallerIdentityRecursive(db, make(map[string]bool), nil)
}

// comparesCallerIdentityRecursive is the interprocedural worker. callerParams
// names parameters of THIS function bound to a caller identity at the call site
// that recursed into it, so an item-ownership scope written against a forwarded
// caller — `_withdraw(msg.sender, …)` then `if (ownerOf(tokenId) != caller)
// revert` — is recognized as self-scoping even though the comparison lives in a
// callee. This is the NFT analogue of `require(from == msg.sender)`: it scopes
// the caller to their own resource, it does not gate to a privileged principal.
func (f *Function) comparesCallerIdentityRecursive(db *Database, visited, callerParams map[string]bool) bool {
	if f == nil {
		return false
	}
	key := functionIdentityKey(f)
	if visited[key] {
		return false
	}
	visited[key] = true

	if f.AST != nil {
		found := false
		f.AST.WalkDescendants(func(n *ASTNode) bool {
			if found {
				return false
			}
			// Direct caller-identity source used inside a comparison condition.
			if isDirectAuthSource(n, f, db) && isInsideCondition(n) && hasComparisonOperand(n) {
				found = true
				return false
			}
			// Local alias of a caller-identity source: address s = _msgSender(); … s == from.
			if n.Kind == KindExprIdentifier && isTaintedIdentifier(n.Name, f.AST, f, db) &&
				isInsideCondition(n) && hasComparisonOperand(n) {
				found = true
				return false
			}
			// Forwarded caller identity: a parameter the caller bound to msg.sender
			// at the call site, compared inside a condition (e.g. ownerOf(id) != caller).
			if len(callerParams) > 0 && n.Kind == KindExprIdentifier && callerParams[n.Name] &&
				isInsideCondition(n) && hasComparisonOperand(n) {
				found = true
				return false
			}
			return true
		})
		if found {
			return true
		}
	}

	if db != nil {
		for _, call := range f.Calls {
			if !isInternalCall(call.CallType) {
				continue
			}
			callee := f.resolveInternalCallee(db, call)
			if callee != nil &&
				callee.comparesCallerIdentityRecursive(db, visited, f.forwardedCallerParams(db, call, callee)) {
				return true
			}
		}
	}
	return false
}

// hasComparisonOperand reports whether n sits inside a binary comparison with a
// second operand (i.e. it is compared against something, not used standalone like
// require(isOperator[msg.sender])). The other operand may be anything — argument,
// state, literal — because this models self-scoping, not authority anchoring.
func hasComparisonOperand(n *ASTNode) bool {
	parent := n.FindAncestor(func(a *ASTNode) bool {
		return a.Kind == KindExprBinaryOp || a.Kind == "binary_op" || a.Kind == "binary_operation"
	})
	return parent != nil && len(parent.Children) >= 2
}

// contractHierarchyContains reports whether contractName appears in the
// deployment context of mainContract — either as the contract itself or
// anywhere in its C3 linearization. Used to scope internal-call resolution to
// the hierarchy that actually contains the caller.
func contractHierarchyContains(db *Database, mainContract *Contract, fn *Function) bool {
	if db == nil || mainContract == nil || fn == nil || fn.ContractName == "" {
		return false
	}
	if fn.SourceFile != "" {
		ownerID := MakeContractID(fn.SourceFile, fn.ContractName)
		for _, contract := range db.LinearizedContracts(mainContract) {
			if contract != nil && contract.ID == ownerID {
				return true
			}
		}
		return false
	}
	// Compatibility for old/synthetic functions without SourceFile.
	for _, contract := range db.LinearizedContracts(mainContract) {
		if contract != nil && contract.Name == fn.ContractName {
			return true
		}
	}
	return false
}

// hasParameterNamed reports whether the function declares a parameter with the
// given name. Used as a backstop to reject a comparison target whose RefKind was
// not resolved by the symbol table but is in fact an argument.
func (f *Function) hasParameterNamed(name string) bool {
	if f == nil || name == "" {
		return false
	}
	for _, p := range f.Parameters {
		if p != nil && p.Name == name {
			return true
		}
	}
	return false
}

// calleeNameMatches reports whether fn is the function referred to by a call.
// Resolution stores the callee as a full selector (`_withdraw(address,uint256,
// address,uint256)`) while Function.Name is the bare identifier (`_withdraw`),
// so a raw `fn.Name == resolved` comparison silently never matched and the
// interprocedural auth descent was dead for resolved calls. Compare against the
// bare name taken from the resolved selector, then fall back to the call target.
func calleeNameMatches(fn *Function, call *FunctionCall, resolved string) bool {
	if fn == nil {
		return false
	}
	if resolved != "" && strings.Contains(resolved, "(") {
		if fn.Selector != "" {
			return fn.Selector == resolved
		}
		// Compatibility for synthetic/legacy functions whose selector was never
		// materialized. Newly built functions always take the exact branch above.
		return fn.Name == bareFuncName(resolved)
	}
	if call != nil && call.ArgCount >= 0 && len(fn.Parameters) != call.ArgCount {
		return false
	}
	if bare := bareFuncName(resolved); bare != "" && fn.Name == bare {
		return true
	}
	return call != nil && call.Target != "" && fn.Name == call.Target
}

// bareFuncName strips a selector's argument list: `f(uint256,address)` → `f`.
// A name with no `(` is returned unchanged.
func bareFuncName(s string) string {
	if i := strings.IndexByte(s, '('); i >= 0 {
		return s[:i]
	}
	return s
}

// forwardedCallerParams returns the set of `callee` parameter names that receive
// a caller-identity argument (msg.sender / tx.origin / _msgSender(), or a local
// aliased from one) at this call site within f.AST. It lets the recursive auth
// check recognize an ownership guard written against a forwarded caller, e.g.
// `_withdraw(msg.sender, tokenId, receiver)` then `if (ownerOf(tokenId) !=
// caller) revert` — without it the gated NFT-vault withdrawal looks like an
// arbitrary ETH send. Returns nil when nothing is forwarded.
func (f *Function) forwardedCallerParams(db *Database, call *FunctionCall, callee *Function) map[string]bool {
	if f == nil || f.AST == nil || call == nil || callee == nil || len(callee.Parameters) == 0 {
		return nil
	}
	var result map[string]bool
	f.AST.WalkDescendants(func(n *ASTNode) bool {
		if n.Name != call.Target || !strings.HasPrefix(string(n.Kind), "call.") {
			return true
		}
		for i, arg := range solidityArgNodes(n) {
			if i >= len(callee.Parameters) {
				break
			}
			p := callee.Parameters[i]
			if p == nil || p.Name == "" {
				continue
			}
			if isForwardedCallerIdentity(arg, f.AST, f, db) {
				if result == nil {
					result = make(map[string]bool)
				}
				result[p.Name] = true
			}
		}
		return true
	})
	return result
}

// solidityArgNodes returns a call node's positional Solidity argument children,
// skipping the metadata children the AST builder attaches (the tagged
// `call_receiver` and the `{value:/gas:}` call-option expressions). This mirrors
// how the engine's matchArgs indexes arguments.
func solidityArgNodes(call *ASTNode) []*ASTNode {
	var args []*ASTNode
	for _, c := range call.Children {
		if c == nil {
			continue
		}
		if c.GetAttributeBool("call_receiver") || c.GetAttributeString("call_option") != "" {
			continue
		}
		args = append(args, c)
	}
	return args
}

// isForwardedCallerIdentity reports whether an argument expression is a
// caller-identity source: a direct msg.sender / tx.origin / _msgSender(), or a
// local variable aliased from one.
func isForwardedCallerIdentity(arg *ASTNode, root *ASTNode, fn *Function, db *Database) bool {
	if arg == nil {
		return false
	}
	if isDirectAuthSource(arg, fn, db) {
		return true
	}
	return arg.Kind == KindExprIdentifier && isTaintedIdentifier(arg.Name, root, fn, db)
}

func isAccessControlName(name string) bool {
	return name != "" && accessControlNameRegex.MatchString(name)
}

// elementaryTypeCastRegex matches Solidity built-in type names usable as a
// conversion: address, payable, bool, string, bytes, byte, and the sized
// uint/int/bytes families (uint, uint8…uint256, int…, bytes1…bytes32).
var elementaryTypeCastRegex = regexp.MustCompile(`^(address|payable|bool|string|byte|bytes([1-9]|[12][0-9]|3[0-2])?|uint([0-9]+)?|int([0-9]+)?)$`)

// isTypeCastName reports whether name is a built-in elementary type usable in a
// conversion expression. User-defined type casts (contract/interface) are
// intentionally excluded — they don't appear as the authority operand in a
// caller-identity comparison, and excluding them keeps getters from being
// misread as casts.
func isTypeCastName(name string) bool {
	return name != "" && elementaryTypeCastRegex.MatchString(name)
}

// isCallerControlledTarget reports whether the comparison target on the other
// side of a caller-identity check (msg.sender / tx.origin / _msgSender()) is a
// value the caller can freely choose — a function parameter, a local tainted
// SOLELY from parameters, or an index/member access whose base is itself
// caller-controlled. Such a comparison (e.g. require(from == msg.sender) where
// `from` is an argument) is self-authorization, not a privileged access gate, so
// it must NOT count as access control.
//
// Everything else is a legitimate authority anchor and is NOT caller-controlled:
// state variables, contract-fixed getters (owner(), hasRole(ROLE, msg.sender)),
// state mappings/structs, constants, immutables, address(this), and hardcoded
// literal addresses (require(msg.sender == 0xAbC…) gates to a fixed bytecode
// address the caller cannot influence). A getter the caller indexes with a
// resource id of their own choosing (ownerOf(tokenId)) is the exception — it is
// resource self-scoping, handled as caller-controlled (see getterIsResourceScoped).
func isCallerControlledTarget(n *ASTNode, fn *Function, db *Database) bool {
	if n == nil {
		return false
	}
	switch n.Kind {
	case KindExprLiteral:
		// Hardcoded literal address — fixed in bytecode, not caller-controlled.
		return false
	case KindExprIdentifier:
		switch n.RefKind {
		case "parameter":
			return true // caller chooses the argument value
		case "state_var":
			return false
		case "local_var":
			// Caller-controlled only when every taint source is a parameter. A
			// local seeded from state (or of unknown provenance) is not.
			return taintIsParameterOnly(n.TaintSources)
		default:
			// "" = constant / immutable / enum / contract ref / unresolved. None
			// are caller-controlled — but guard against a parameter that missed
			// the symbol table (or shadows a state var) via the param set.
			return fn.hasParameterNamed(n.Name)
		}
	case KindCallInternal, KindCallExternal:
		// Getter call. A getter whose result is fixed by the contract — `owner()`,
		// `getOwner()`, a role check like `hasRole(ROLE, msg.sender)` — is a
		// privileged authority anchor (NOT caller-controlled). But a getter the
		// CALLER indexes with a resource id of their own choosing — `ownerOf(tokenId)`,
		// `positions(id).owner` — only asserts "you own the item you named". That is
		// resource self-scoping, not a privileged gate, so it IS caller-controlled.
		return getterIsResourceScoped(n, fn, db)
	case KindExprIndexAccess, KindExprMemberAccess:
		// m[k] / s.f — caller-controlled iff the BASE is caller-controlled.
		if len(n.Children) > 0 {
			return isCallerControlledTarget(n.Children[0], fn, db)
		}
		return false
	default:
		return false
	}
}

// getterIsResourceScoped reports whether a getter call asserts ownership of a
// CALLER-SELECTED resource rather than membership in a contract-fixed authority.
// True when an argument is a free caller-controlled value (a parameter or
// arg-derived local) that is NOT itself a caller-identity source — i.e. the
// caller picks which item (`ownerOf(tokenId)`), so the check scopes the caller
// to their own asset instead of gating to a privileged principal. False for
// `owner()` (no args) and `hasRole(ROLE, msg.sender)` (no free resource selector).
func getterIsResourceScoped(call *ASTNode, fn *Function, db *Database) bool {
	for _, arg := range solidityArgNodes(call) {
		if isDirectAuthSource(arg, fn, db) {
			continue // msg.sender / tx.origin / _msgSender() is not a resource id
		}
		if isCallerControlledTarget(arg, fn, db) {
			return true
		}
	}
	return false
}

// taintIsParameterOnly reports whether a taint set is non-empty and consists
// exclusively of "parameter" sources. Empty (unknown) taint returns false so an
// untracked local is conservatively treated as a valid auth anchor rather than
// silently dropping a real access-control check.
func taintIsParameterOnly(sources []string) bool {
	if len(sources) == 0 {
		return false
	}
	for _, s := range sources {
		if s != "parameter" {
			return false
		}
	}
	return true
}

// isDirectAuthSource checks if node is msg.sender, tx.origin, or an exact
// zero-argument internal _msgSender() helper in the active function/database
// context. Same-named identifiers, external/self calls, unresolved calls, and
// nonzero overloads retain their ordinary provenance.
func isDirectAuthSource(n *ASTNode, fn *Function, db *Database) bool {
	if n == nil {
		return false
	}
	// 1. Check for msg.sender or tx.origin member access
	if n.Kind == KindExprMemberAccess {
		// Expecting structure: MemberAccess(sender) -> child: Identifier(msg)
		// Or: MemberAccess(origin) -> child: Identifier(tx)
		if len(n.Children) > 0 {
			expressionNode := n.Children[0]
			if expressionNode.Kind == KindExprIdentifier {
				if (expressionNode.Name == "msg" && n.Name == "sender") ||
					(expressionNode.Name == "tx" && n.Name == "origin") {
					return true
				}
			}
		}
	}

	// 2. _msgSender() is caller identity only for the exact zero-argument
	// internal-call shape. Recorded metadata and database resolution, when
	// available, must independently confirm that identity.
	if n.Kind != KindCallInternal || n.Name != "_msgSender" || len(solidityArgNodes(n)) != 0 {
		return false
	}
	call := recordedAuthCallForNode(fn, n)
	if call != nil {
		switch call.CallType {
		case CallTypeInternal, CallTypeInherited, CallTypeSuper:
		default:
			return false
		}
		if call.ArgCount != 0 || call.ResolvedFunction != "_msgSender()" {
			return false
		}
	}
	if helper, available := resolveMsgSenderAuthHelper(db, fn); available {
		return isMsgSenderAuthHelper(helper)
	}

	// Compatibility for synthetic/programmatic ASTs without usable database
	// resolution or call metadata: the exact zero-argument call.internal shape
	// is sufficient.
	return true
}

func recordedAuthCallForNode(fn *Function, node *ASTNode) *FunctionCall {
	if fn == nil || node == nil {
		return nil
	}
	var lineMatch *FunctionCall
	for _, call := range fn.Calls {
		if call == nil || bareFuncName(call.Target) != node.Name {
			continue
		}
		if node.StartByte > 0 && call.Byte == node.StartByte {
			return call
		}
		if node.StartLine > 0 && call.Line == node.StartLine && lineMatch == nil {
			lineMatch = call
		}
	}
	return lineMatch
}

func resolveMsgSenderAuthHelper(db *Database, fn *Function) (*Function, bool) {
	if db == nil || fn == nil || fn.ContractName == "" {
		return nil, false
	}
	var owner *Contract
	if fn.SourceFile != "" {
		owner = db.GetContractByID(MakeContractID(fn.SourceFile, fn.ContractName))
		if owner == nil {
			return nil, false
		}
	} else {
		var exact bool
		owner, exact = db.ResolveContractNameExact(fn.ContractName, fn.SourceFile)
		if !exact {
			return nil, false
		}
	}
	if owner == nil {
		return nil, false
	}
	for _, contract := range db.LinearizedContracts(owner) {
		for _, candidate := range contract.Functions {
			if isMsgSenderAuthHelper(candidate) {
				return candidate, true
			}
		}
	}
	return nil, true
}

func isMsgSenderAuthHelper(fn *Function) bool {
	return fn != nil && fn.Name == "_msgSender" && len(fn.Parameters) == 0 &&
		(fn.Selector == "" || fn.Selector == "_msgSender()")
}

// isTaintedIdentifier checks if a local variable is assigned from an auth source.
func isTaintedIdentifier(name string, root *ASTNode, fn *Function, db *Database) bool {
	if root == nil {
		return false
	}

	isTainted := false
	root.WalkDescendants(func(n *ASTNode) bool {
		if isTainted {
			return false // Already found
		}

		// Check for assignments: address s = _msgSender(); or s = msg.sender;
		if n.Kind == KindStmtAssign {
			// Assignment children: [LHS..., RHS] in our builder logic
			// Usually [Identifier(lhs), RHS_Expr]
			if len(n.Children) >= 2 {
				// Last child is RHS
				rhs := n.Children[len(n.Children)-1]

				// Check if any LHS matches name
				// Iterate all children except last
				for i := 0; i < len(n.Children)-1; i++ {
					lhs := n.Children[i]
					if lhs.Kind == KindExprIdentifier && lhs.Name == name {
						// Found assignment to our variable
						// Check if RHS is tainted source
						if isDirectAuthSource(rhs, fn, db) {
							isTainted = true
							return false
						}

						// Also check if RHS is ITSELF a tainted identifier (recursive, max 1 depth for now to keep it simple)
						// For now, strict direct source check seems sufficient for user pattern
					}
				}
			}
		}
		return true
	})
	return isTainted
}

// isInsideCondition checks if the node is inside a control flow condition (require, assert, if)
func isInsideCondition(n *ASTNode) bool {
	ancestor := n.FindAncestor(func(a *ASTNode) bool {
		// Check for require/assert/revert
		if IsCheck(a.Kind) {
			return true
		}
		// Check for if statement
		if a.Kind == KindStmtIf {
			return true
		}
		return false
	})
	return ancestor != nil
}
