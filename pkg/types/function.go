package types

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"

	"golang.org/x/crypto/sha3"
)

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
}

// Parameter represents a function parameter or return value
type Parameter struct {
	Name     string `json:"name,omitempty"`
	TypeName string `json:"typeName"`
	Indexed  bool   `json:"indexed,omitempty"` // For event parameters
}

// FunctionCall represents a call to another function
type FunctionCall struct {
	// Target is the function being called (name as in source)
	Target string `json:"target"`

	// ContractName is the contract of the target (if external call)
	ContractName string `json:"contractName,omitempty"`

	// ResolvedContract is the actual contract where function is defined
	ResolvedContract string `json:"resolvedContract,omitempty"`

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

	// Resolved indicates if target was fully resolved
	Resolved bool `json:"resolved,omitempty"`

	// ArgCount is the number of arguments at the call site.
	// Used to disambiguate overloaded functions with the same name.
	// -1 means unknown (e.g. loaded from old JSON without this field).
	ArgCount int `json:"argCount,omitempty"`
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

// isValidIntSize checks if the string is a valid integer size (8, 16, 24, ..., 256)
func isValidIntSize(s string) bool {
	// validSizes := map[string]bool{
	// 	"8": true, "16": true, "24": true, "32": true, "40": true, "48": true,
	// 	"56": true, "64": true, "72": true, "80": true, "88": true, "96": true,
	// 	"104": true, "112": true, "120": true, "128": true, "136": true, "144": true,
	// 	"152": true, "160": true, "168": true, "176": true, "184": true, "192": true,
	// 	"200": true, "208": true, "216": true, "224": true, "232": true, "240": true,
	// 	"248": true, "256": true,
	// }
	return true
}

// UniqueID generates a unique ID for the function based on contract and selector
func (f *Function) UniqueID(structDefs map[string]*Struct) string {
	data := fmt.Sprintf("%s.%s", f.ContractName, f.GetSelector(structDefs))
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:8])
}

// IsAccessControlled checks if the function has access control logic
// Checks for:
// 1. Access control modifiers (onlyOwner, auth, etc.)
// 2. msg.sender/tx.origin checks in require/assert/if statements
// 3. Recursive checks on internal calls
func (f *Function) IsAccessControlled(db *Database) bool {
	visited := make(map[string]bool)
	return f.isAccessControlledRecursive(db, visited)
}

// isAccessControlledRecursive internal recursive check
func (f *Function) isAccessControlledRecursive(db *Database, visited map[string]bool) bool {
	// 0. Cycle detection
	key := f.ContractName + "." + f.Name
	if visited[key] {
		return false
	}
	visited[key] = true

	// 1. Check modifiers
	// Use same regex as checkUnAuthenticated preset
	authModifierPattern := `(?i)(onlyOwner|onlyAdmin|onlyOperator|onlyRole|onlyGuardian|onlyGovernor|onlyGovernance|onlyGov|onlyManager|onlyController|auth|authorized|requiresAuth|onlyMinter|onlyPauser)`
	regex := regexp.MustCompile(authModifierPattern)

	for _, mod := range f.Modifiers {
		if regex.MatchString(mod) {
			return true
		}
	}

	// 2. Check for calls to internal auth functions (heuristic fallback)
	// Matches: _checkOwner, _requireAuth, _validateAdmin, _enforceRole, etc.
	authFuncPattern := `(?i)(_?check|_?require|_?verify|_?validate|_?enforce).(Owner|Auth|Admin|Role|Sender|Access|Permission)`
	authFuncRegex := regexp.MustCompile(authFuncPattern)
	for _, call := range f.Calls {
		// Only check internal or self calls (or inherited)
		if call.CallType == "internal" || call.CallType == "inherited" || call.CallType == "self" {
			if authFuncRegex.MatchString(call.Target) {
				return true
			}
		}
	}

	// 3. Check AST for msg.sender / tx.origin / _msgSender() checks
	if f.AST != nil {
		hasAuthCheck := false
		f.AST.WalkDescendants(func(n *ASTNode) bool {
			// Look for msg.sender in require/assert/if conditions
			if isAuthCheck(n, f.AST) {
				hasAuthCheck = true
				return false // Stop walking
			}
			return true
		})
		if hasAuthCheck {
			return true
		}
	}

	// 4. Recursive check on internal calls (Deep Inspection)
	if db != nil {
		for _, call := range f.Calls {
			// Only follow internal/inherited/self/super calls
			if call.CallType == "internal" || call.CallType == "inherited" ||
				call.CallType == "self" || call.CallType == "super" {

				// For inherited calls, we need to check the OVERRIDDEN version in the main contract
				// not the abstract base. Use the main contract's linearized bases to find the implementation.
				targetFuncName := call.ResolvedFunction
				if targetFuncName == "" {
					targetFuncName = call.Target
				}

				// Get the main contract that contains this function (or its most derived version)
				// We use db.MainContracts to find the actual runtime implementation
				foundInMain := false
				for mainContractID := range db.MainContracts {
					mainContract := db.GetContract(mainContractID)
					if mainContract == nil {
						continue
					}
					// LinearizedBases is derived-first: [MostDerived, ..., MostBase]
					// Iterate forward to find most-derived implementation first
					for _, baseName := range mainContract.LinearizedBases {
						baseContract := db.GetContractByName(baseName)
						if baseContract == nil {
							continue
						}
						for _, baseFn := range baseContract.Functions {
							if baseFn.Name == targetFuncName {
								if baseFn.isAccessControlledRecursive(db, visited) {
									return true
								}
								foundInMain = true
								break // Found function in this base, stop searching this base
							}
						}
						if foundInMain {
							break
						} // Found in linearized bases, stop
					}
					if foundInMain {
						break
					}
				}

				// Fallback: if not found in main contracts, use original resolution
				if !foundInMain && call.ResolvedContract != "" && call.ResolvedFunction != "" {
					targetContract := db.GetContractByName(call.ResolvedContract)
					if targetContract != nil {
						for _, targetFn := range targetContract.Functions {
							if targetFn.Name == call.ResolvedFunction {
								result := targetFn.isAccessControlledRecursive(db, visited)
								if result {
									return true
								}
								break
							}
						}
					}
				}
			}
		}
	}

	return false
}

// isAuthCheck checks if a node represents an authentication check (msg.sender, tx.origin, _msgSender)
// It checks both direct usage and simple local variable aliases (taint tracking).
// Returns true only if the auth source is compared against owner()/admin patterns.
func isAuthCheck(n *ASTNode, root *ASTNode) bool {
	// 1. Direct check
	if isDirectAuthSource(n) {
		if isInsideCondition(n) {
			// Must be compared against owner/admin, not just any comparison
			if isOwnerComparison(n) {
				return true
			}
			if isAccessMappingLookup(n) {
				return true
			}
		}
	}

	// 2. Taint tracking (local alias)
	// address sender = _msgSender(); require(sender == owner());
	if n.Kind == KindExprIdentifier {
		if isTaintedIdentifier(n.Name, root) {
			if isInsideCondition(n) {
				if isOwnerComparison(n) {
					return true
				}
			}
		}
	}

	return false
}

// isAccessMappingLookup recognizes boolean access maps used directly as guard
// conditions, e.g. require(isOperator[msg.sender]) or if (!hasRole[msg.sender]).
// The base name is intentionally vocabulary-gated so ordinary balance checks
// like require(balances[msg.sender] >= amount) are not treated as auth.
func isAccessMappingLookup(n *ASTNode) bool {
	for current := n.Parent; current != nil; current = current.Parent {
		if IsCheck(current.Kind) || current.Kind == KindStmtIf {
			return false
		}
		if current.Kind != KindExprIndexAccess || len(current.Children) == 0 {
			continue
		}
		baseName := accessLookupBaseName(current.Children[0])
		if baseName == "" {
			continue
		}
		if isAccessControlName(baseName) {
			return true
		}
	}
	return false
}

func accessLookupBaseName(n *ASTNode) string {
	if n == nil {
		return ""
	}
	switch n.Kind {
	case KindExprIdentifier, KindExprMemberAccess:
		return n.Name
	default:
		return ""
	}
}

func isAccessControlName(name string) bool {
	if name == "" {
		return false
	}
	pattern := regexp.MustCompile(`(?i)(owner|admin|auth|authori[sz]ed|operator|role|permission|allow|whitelist|guardian|minter|pauser)`)
	return pattern.MatchString(name)
}

// isOwnerComparison checks if the auth source (msg.sender / tx.origin) is compared
// against a meaningful non-literal target, which constitutes an access control check.
//
// This covers both named patterns (owner, admin, endpoint, …) and any comparison
// against a state variable / stored address — e.g.:
//   - require(msg.sender == owner())
//   - if (address(endpoint) != msg.sender) revert …
//   - if (_trustedForwarder != msg.sender) revert …
func isOwnerComparison(n *ASTNode) bool {
	// Find immediate Binary Operation ancestor
	parent := n.FindAncestor(func(a *ASTNode) bool {
		return a.Kind == KindExprBinaryOp || a.Kind == "binary_op" || a.Kind == "binary_operation"
	})

	if parent == nil || len(parent.Children) < 2 {
		return false
	}

	for _, child := range parent.Children {
		// Skip if this is the auth source node itself
		if child == n {
			continue
		}

		// Unwrap type casts like address(endpoint) → endpoint
		effective := unwrapTypeCast(child)

		// Any non-literal sibling is a valid access-control target
		if isNonLiteralAuthTarget(effective) {
			return true
		}
	}
	return false
}

// unwrapTypeCast strips a single-argument type-cast call (e.g. address(x), uint160(x))
// and returns the inner node. If the node is not a type-cast, it is returned as-is.
func unwrapTypeCast(n *ASTNode) *ASTNode {
	if n == nil {
		return n
	}
	// A type cast looks like: call.internal{name="address"} with exactly one child
	if (n.Kind == KindCallInternal || n.Kind == KindCallExternal) && len(n.Children) == 1 {
		return n.Children[0]
	}
	return n
}

// isNonLiteralAuthTarget returns true when a node represents a stored / computed
// address that is a legitimate access-control target (i.e. NOT a bare literal).
func isNonLiteralAuthTarget(n *ASTNode) bool {
	if n == nil {
		return false
	}
	switch n.Kind {
	case KindExprLiteral:
		// Bare literal (e.g. 0x1234…) — not a meaningful auth target
		return false
	case KindExprIdentifier:
		// Any named identifier (state var, local alias, parameter) is valid
		return n.Name != ""
	case KindCallInternal, KindCallExternal:
		// Internal calls like owner(), _owner(), getAdmin(), endpoint.getAddress(), …
		return n.Name != ""
	case KindExprMemberAccess:
		// e.g. some.field
		return true
	case KindExprIndexAccess:
		// e.g. allowed[msg.sender] or from[i]
		return true
	default:
		return false
	}
}

// isDirectAuthSource checks if node is msg.sender, tx.origin, or _msgSender()
func isDirectAuthSource(n *ASTNode) bool {
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

	// 2. Check for _msgSender() calls (Identifier or FunctionCall or InternalCall)
	if (n.Kind == KindExprIdentifier || n.Kind == KindCallExternal || n.Kind == KindCallInternal) && n.Name == "_msgSender" {
		return true
	}

	return false
}

// isTaintedIdentifier checks if a local variable is assigned from an auth source
func isTaintedIdentifier(name string, root *ASTNode) bool {
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
						if isDirectAuthSource(rhs) {
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
