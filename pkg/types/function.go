package types

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/crypto/sha3"
)

// Access-control heuristic patterns, compiled once at package init. These were
// previously recompiled on every (recursive) call of isAccessControlledRecursive,
// which is invoked per function per report — a measurable cost on large scans.
var (
	authModifierRegex = regexp.MustCompile(`(?i)(onlyOwner|onlyAdmin|onlyOperator|onlyRole|onlyGuardian|onlyGovernor|onlyGovernance|onlyGov|onlyManager|onlyController|auth|authorized|requiresAuth|onlyMinter|onlyPauser)`)
	authFuncRegex     = regexp.MustCompile(`(?i)(check|require|verify|validate|enforce)_*(owner|auth|admin|role|sender|access|permission)`)
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
	data := fmt.Sprintf("%s.%s", f.ContractName, f.GetSelector(structDefs))
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:8])
}

// modifierLooksProtective walks the function's contract and its linearized
// bases looking for a modifier definition with the given name, and returns
// true when the modifier body carries at least one auth-shaped signal —
// a require/assert/revert, an if/ternary, or a msg.sender / tx.origin
// reference. When the definition cannot be resolved (synthetic test data,
// inherited from a base that isn't in the database, or modifier AST not
// captured during build), the function returns true so callers fall back to
// trusting the modifier's name. It returns false only when the modifier is
// definitely a no-op decoy.
func modifierLooksProtective(db *Database, contractName, modName string) bool {
	if db == nil {
		return true
	}
	chain := []string{contractName}
	if c := db.GetContractByName(contractName); c != nil {
		chain = append(chain, c.LinearizedBases...)
	}
	seen := make(map[string]bool)
	for _, cname := range chain {
		if cname == "" || seen[cname] {
			continue
		}
		seen[cname] = true
		c := db.GetContractByName(cname)
		if c == nil {
			continue
		}
		for _, mod := range c.Modifiers {
			if mod == nil || mod.Name != modName {
				continue
			}
			if mod.AST == nil {
				return true // can't inspect — trust the name
			}
			return modifierBodyHasAuthSignal(mod.AST)
		}
	}
	return true // not found — trust the name
}

// modifierCallsAuthHelper resolves modName through contractName's linearization
// and reports whether the modifier's body calls an auth-shaped helper
// (e.g. _checkOwner, requireAuth). Relies on Modifier.Calls being populated by
// the call-graph builder's modifier-body analysis.
func modifierCallsAuthHelper(db *Database, contractName, modName string) bool {
	if db == nil {
		return false
	}
	chain := []string{contractName}
	if c := db.GetContractByName(contractName); c != nil {
		chain = append(chain, c.LinearizedBases...)
	}
	seen := make(map[string]bool)
	for _, cname := range chain {
		if cname == "" || seen[cname] {
			continue
		}
		seen[cname] = true
		c := db.GetContractByName(cname)
		if c == nil {
			continue
		}
		for _, mod := range c.Modifiers {
			if mod == nil || mod.Name != modName {
				continue
			}
			for _, call := range mod.Calls {
				if authFuncRegex.MatchString(call.Target) {
					return true
				}
			}
		}
	}
	return false
}

// modifierBodyHasAuthSignal reports whether the modifier's AST contains any
// auth-shaped marker. The check is intentionally lenient — its purpose is to
// distinguish a true no-op decoy (`modifier auth() { _; }`) from any modifier
// with a real body, not to validate that the check is correct.
func modifierBodyHasAuthSignal(root *ASTNode) bool {
	if root == nil {
		return false
	}
	found := false
	root.WalkDescendants(func(n *ASTNode) bool {
		if n == nil {
			return true
		}
		if IsGuard(n.Kind) || IsCheck(n.Kind) {
			found = true
			return false
		}
		if n.Kind == KindStmtIf || n.Kind == KindExprConditional {
			found = true
			return false
		}
		if n.Kind == KindExprMemberAccess {
			if strings.Contains(n.Name, "msg.sender") || strings.Contains(n.Name, "tx.origin") {
				found = true
				return false
			}
		}
		return true
	})
	return found
}

// IsAccessControlled checks if the function has access control logic
// Checks for:
//  1. Access control modifiers (onlyOwner, auth, etc.) — with best-effort
//     modifier-body validation to detect decoy modifiers
//  2. msg.sender/tx.origin checks in require/assert/if statements
//  3. Recursive checks on internal calls
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

	// 1. Check modifiers (auth-named, validated against decoys below).
	for _, modName := range f.Modifiers {
		if !authModifierRegex.MatchString(modName) {
			continue
		}
		// Best-effort body validation: an auth-named modifier whose body is
		// a no-op (`modifier auth() { _; }`) is a decoy — common in adversarial
		// or deliberately misleading code. Resolve the modifier definition
		// through the function's contract + its linearized bases and require
		// at least one auth-shaped signal (require/assert/revert/if or a
		// msg.sender / tx.origin reference) before trusting the name. When
		// the definition cannot be resolved (synthetic tests, inherited from
		// an out-of-scope base), fall back to trusting the name.
		if db != nil && !modifierLooksProtective(db, f.ContractName, modName) {
			continue
		}
		return true
	}

	// 1b. A modifier whose NAME isn't auth-shaped can still enforce access
	// control by calling an auth helper in its body (e.g.
	// `modifier gate { _enforceOwner(); _; }`). Now that modifier bodies are
	// walked into Modifier.Calls, detect that case.
	if db != nil {
		for _, modName := range f.Modifiers {
			if modifierCallsAuthHelper(db, f.ContractName, modName) {
				return true
			}
		}
	}

	// 2. Check for calls to internal auth functions (heuristic fallback)
	// Matches verb+noun auth helpers in both camelCase and snake_case:
	// _checkOwner, checkOwner, requireAuth, _validate_admin, enforceRole, etc.
	// The verb and noun may be joined directly or separated only by
	// underscores. (A literal `.` here was a bug: it required exactly one
	// character between verb and noun, so the common no-separator camelCase
	// forms like `_checkOwner` silently failed to match.)
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
			if isAuthCheck(n, f.AST, f) {
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
		// Iterate main contracts in deterministic (sorted) order, and only
		// consider deployment contexts whose linearized hierarchy actually
		// contains THIS function's contract. Previously this scanned every main
		// contract by bare function name, so a protected helper of the same name
		// in an unrelated contract would mark this function as access-controlled
		// (a false negative) — and because it walked a map, the result was
		// non-deterministic when two hierarchies defined same-named helpers.
		mainIDs := make([]string, 0, len(db.MainContracts))
		for id := range db.MainContracts {
			mainIDs = append(mainIDs, id)
		}
		sort.Strings(mainIDs)

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
				for _, mainContractID := range mainIDs {
					mainContract := db.GetContract(mainContractID)
					if mainContract == nil {
						continue
					}
					// Skip deployment contexts that don't contain this function's
					// contract — resolving the callee elsewhere is meaningless.
					if !contractHierarchyContains(mainContract, f.ContractName) {
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
func (f *Function) ComparesCallerIdentity() bool {
	if f.AST == nil {
		return false
	}
	found := false
	f.AST.WalkDescendants(func(n *ASTNode) bool {
		if found {
			return false
		}
		// Direct caller-identity source used inside a comparison condition.
		if isDirectAuthSource(n) && isInsideCondition(n) && hasComparisonOperand(n) {
			found = true
			return false
		}
		// Local alias of a caller-identity source: address s = _msgSender(); … s == from.
		if n.Kind == KindExprIdentifier && isTaintedIdentifier(n.Name, f.AST) &&
			isInsideCondition(n) && hasComparisonOperand(n) {
			found = true
			return false
		}
		return true
	})
	return found
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
func contractHierarchyContains(mainContract *Contract, contractName string) bool {
	if mainContract == nil || contractName == "" {
		return false
	}
	if mainContract.Name == contractName {
		return true
	}
	for _, base := range mainContract.LinearizedBases {
		if base == contractName {
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

// isAuthCheck checks if a node represents an authentication check (msg.sender, tx.origin, _msgSender)
// It checks both direct usage and simple local variable aliases (taint tracking).
// Returns true only if the auth source is compared against a storage-anchored
// authority (state var / getter / mapping / immutable / hardcoded address) — NOT
// against a caller-controlled value such as a function argument. fn supplies the
// parameter set used as a backstop when an identifier's RefKind is unresolved.
func isAuthCheck(n *ASTNode, root *ASTNode, fn *Function) bool {
	// 1. Direct check
	if isDirectAuthSource(n) {
		if isInsideCondition(n) {
			// Must be compared against a non-caller-controlled authority anchor,
			// not just any comparison (require(from == msg.sender) is self-auth).
			if isOwnerComparison(n, fn) {
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
				if isOwnerComparison(n, fn) {
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

// isOwnerComparison checks if the auth source (msg.sender / tx.origin / _msgSender)
// is compared against a non-caller-controlled authority anchor, which constitutes
// an access control check.
//
// A comparison counts as access control unless the other operand is something the
// caller can freely choose (a function argument or a value derived solely from
// arguments). It covers state vars, getters, mappings, immutables, constants, and
// hardcoded literal addresses — e.g.:
//   - require(msg.sender == owner())
//   - require(msg.sender == 0xAbC…)          // hardcoded authority
//   - if (address(endpoint) != msg.sender) revert …
//   - if (_trustedForwarder != msg.sender) revert …
//
// But NOT self-authorization, where the caller picks the comparison value:
//   - require(from == msg.sender)            // `from` is an argument
func isOwnerComparison(n *ASTNode, fn *Function) bool {
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

		// Skip the caller-identity side itself (the other operand is also a
		// caller-identity source, or n was wrapped in a cast) — we only judge
		// the authority target, not a sender-vs-sender comparison.
		if isDirectAuthSource(effective) {
			continue
		}

		// A sibling the caller cannot control is a valid access-control anchor.
		// Caller-controlled siblings (arguments, arg-derived locals) are not.
		if !isCallerControlledTarget(effective, fn) {
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

// isCallerControlledTarget reports whether the comparison target on the other
// side of a caller-identity check (msg.sender / tx.origin / _msgSender()) is a
// value the caller can freely choose — a function parameter, a local tainted
// SOLELY from parameters, or an index/member access whose base is itself
// caller-controlled. Such a comparison (e.g. require(from == msg.sender) where
// `from` is an argument) is self-authorization, not a privileged access gate, so
// it must NOT count as access control.
//
// Everything else is a legitimate authority anchor and is NOT caller-controlled:
// state variables, state-reading getters (owner(), ownerOf(id), hasRole(...)),
// state mappings/structs, constants, immutables, address(this), and hardcoded
// literal addresses (require(msg.sender == 0xAbC…) gates to a fixed bytecode
// address the caller cannot influence).
func isCallerControlledTarget(n *ASTNode, fn *Function) bool {
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
		// Getter call (owner(), ownerOf(id), hasRole(...)) — authority comes from
		// the state it reads, even if an argument selects which slot.
		return false
	case KindExprIndexAccess, KindExprMemberAccess:
		// m[k] / s.f — caller-controlled iff the BASE is caller-controlled.
		if len(n.Children) > 0 {
			return isCallerControlledTarget(n.Children[0], fn)
		}
		return false
	default:
		return false
	}
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
