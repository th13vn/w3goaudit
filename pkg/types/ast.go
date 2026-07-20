package types

import "strings"

// ASTNode represents a node in the Solidity Abstract Syntax Tree
// Used for deep pattern matching in WQL templates.
type ASTNode struct {
	// Kind is the type of AST node
	// Supported kinds: see Kind* constants
	Kind string `json:"kind"`

	// Name is the identifier or value of the node
	// For identifiers: the variable/function name
	// For calls: the function name
	// For literals: the literal value
	Name string `json:"name,omitempty"`

	// Value is the raw value for literals
	Value string `json:"value,omitempty"`

	// RefID is a reference to a definition (for taint analysis)
	// Format: filePath#Contract.function.varName or filePath#Contract.varName
	RefID string `json:"refId,omitempty"`

	// RefKind describes what the RefID points to
	// Values: parameter, state_var, local_var, function, contract
	RefKind string `json:"refKind,omitempty"`

	// TaintSources lists the original sources (parameter, state_var) that flow into this node
	TaintSources []string `json:"taintSources,omitempty"`

	// Children are the child nodes in the AST
	Children []*ASTNode `json:"children,omitempty"`

	// Parent is the parent node (set during tree construction)
	Parent *ASTNode `json:"-"`

	// Attributes store node-specific metadata
	// For identifiers: is_state_var, visibility
	// For calls: call_type (external/internal), contract_name
	// For functions: visibility, mutability
	Attributes map[string]interface{} `json:"attributes,omitempty"`

	// StartLine and EndLine for source location
	StartLine int `json:"startLine,omitempty"`
	EndLine   int `json:"endLine,omitempty"`

	// StartCol/EndCol are 1-based Unicode-code-point columns;
	// StartByte/EndByte are 0-based UTF-8 byte offsets. Zero when the node is
	// synthetic (no source counterpart).
	StartCol  int `json:"startCol,omitempty"`
	EndCol    int `json:"endCol,omitempty"`
	StartByte int `json:"startByte,omitempty"`
	EndByte   int `json:"endByte,omitempty"`
}

// NewASTNode creates a new AST node with the given kind
func NewASTNode(kind string) *ASTNode {
	return &ASTNode{
		Kind:       kind,
		Attributes: make(map[string]interface{}),
		Children:   make([]*ASTNode, 0),
	}
}

// AddChild adds a child node and sets the parent reference
func (n *ASTNode) AddChild(child *ASTNode) {
	if child != nil {
		child.Parent = n
		n.Children = append(n.Children, child)
	}
}

// AddChildren adds multiple child nodes
func (n *ASTNode) AddChildren(children ...*ASTNode) {
	for _, child := range children {
		n.AddChild(child)
	}
}

// RestoreParents rebuilds Parent pointers after JSON deserialization. Parent is
// intentionally not serialized, but ancestor-based matchers need it.
func (n *ASTNode) RestoreParents() {
	if n == nil {
		return
	}
	for _, child := range n.Children {
		if child == nil {
			continue
		}
		child.Parent = n
		child.RestoreParents()
	}
}

// SetAttribute sets a node attribute
func (n *ASTNode) SetAttribute(key string, value interface{}) {
	n.Attributes[key] = value
}

// GetAttribute gets a node attribute
func (n *ASTNode) GetAttribute(key string) (interface{}, bool) {
	val, exists := n.Attributes[key]
	return val, exists
}

// GetAttributeBool gets a boolean attribute
func (n *ASTNode) GetAttributeBool(key string) bool {
	if val, exists := n.Attributes[key]; exists {
		if b, ok := val.(bool); ok {
			return b
		}
	}
	return false
}

// GetAttributeString gets a string attribute
func (n *ASTNode) GetAttributeString(key string) string {
	if val, exists := n.Attributes[key]; exists {
		if s, ok := val.(string); ok {
			return s
		}
	}
	return ""
}

// IsLeaf returns true if the node has no children
func (n *ASTNode) IsLeaf() bool {
	return len(n.Children) == 0
}

// WalkDescendants performs a depth-first traversal of descendants
// The visitor function should return true to continue walking, false to stop
func (n *ASTNode) WalkDescendants(visitor func(*ASTNode) bool) {
	for _, child := range n.Children {
		if !visitor(child) {
			return
		}
		child.WalkDescendants(visitor)
	}
}

// WalkAncestors walks up the tree visiting ancestor nodes
// The visitor function should return true to continue walking, false to stop
func (n *ASTNode) WalkAncestors(visitor func(*ASTNode) bool) {
	current := n.Parent
	for current != nil {
		if !visitor(current) {
			return
		}
		current = current.Parent
	}
}

// FindDescendant finds the first descendant matching the predicate
func (n *ASTNode) FindDescendant(predicate func(*ASTNode) bool) *ASTNode {
	var result *ASTNode
	n.WalkDescendants(func(node *ASTNode) bool {
		if predicate(node) {
			result = node
			return false
		}
		return true
	})
	return result
}

// FindAncestor finds the first ancestor matching the predicate
func (n *ASTNode) FindAncestor(predicate func(*ASTNode) bool) *ASTNode {
	var result *ASTNode
	n.WalkAncestors(func(node *ASTNode) bool {
		if predicate(node) {
			result = node
			return false
		}
		return true
	})
	return result
}

// CollectDescendants collects all descendants matching the predicate
func (n *ASTNode) CollectDescendants(predicate func(*ASTNode) bool) []*ASTNode {
	var results []*ASTNode
	n.WalkDescendants(func(node *ASTNode) bool {
		if predicate(node) {
			results = append(results, node)
		}
		return true
	})
	return results
}

// ============================================================
// AST Node Kind Constants
// ============================================================
//
// WQL uses dot-notation hierarchy (call.external, stmt.assign, etc.)

// Call kinds
const (
	KindCallInternal         = "call.internal"
	KindCallExternal         = "call.external"
	KindCallLowlevelCall     = "call.lowlevel.call"
	KindCallLowlevelDelegate = "call.lowlevel.delegatecall"
	KindCallLowlevelStatic   = "call.lowlevel.staticcall"
	KindCallBuiltinTransfer  = "call.builtin.transfer"
	KindCallBuiltinSend      = "call.builtin.send"
	// KindCallBuiltinSelfdestruct covers Solidity-level `selfdestruct(addr)`
	// (and the deprecated `suicide(addr)`). Inline-asm `selfdestruct` opcode
	// is tracked separately as KindAsmSelfdestruct; the `selfdestruct`
	// semantic group matches both.
	KindCallBuiltinSelfdestruct = "call.builtin.selfdestruct"
	KindCallCreate              = "call.create"
)

// Check kinds (require/assert/revert)
const (
	KindCheckRequire = "check.require"
	KindCheckAssert  = "check.assert"
	KindCheckRevert  = "check.revert"
)

// Statement kinds
const (
	KindStmtAssign        = "stmt.assign"
	KindStmtStateMutation = "stmt.state_mutation"
	KindStmtIf            = "stmt.if"
	KindStmtLoop          = "stmt.loop"
	KindStmtReturn        = "stmt.return"
	KindStmtEmit          = "stmt.emit"
	KindStmtTryCatch      = "stmt.try_catch"
	KindStmtBlock         = "stmt.block"
	KindStmtUnchecked     = "stmt.unchecked"
)

// Expression kinds
const (
	KindExprIdentifier   = "expr.identifier"
	KindExprLiteral      = "expr.literal"
	KindExprBinaryOp     = "expr.binary_op"
	KindExprUnaryOp      = "expr.unary_op"
	KindExprMemberAccess = "expr.member_access"
	KindExprIndexAccess  = "expr.index_access"
	KindExprConditional  = "expr.conditional"
	KindExprTuple        = "expr.tuple"
)

// Declaration kinds
const (
	KindDeclFunction  = "decl.function"
	KindDeclContract  = "decl.contract"
	KindDeclVariable  = "decl.variable"
	KindDeclParameter = "decl.parameter"
	KindDeclModifier  = "decl.modifier"
)

// Assembly kinds
const (
	KindAsmBlock        = "asm.block"
	KindAsmCall         = "asm.call"
	KindAsmDelegatecall = "asm.delegatecall"
	KindAsmStaticcall   = "asm.staticcall"
	KindAsmSstore       = "asm.sstore"
	KindAsmSload        = "asm.sload"
	KindAsmSelfdestruct = "asm.selfdestruct"
	// Factory / deployment opcodes — security-relevant (untracked code execution).
	KindAsmCreate  = "asm.create"
	KindAsmCreate2 = "asm.create2"
	// Event emission opcodes — relevant for missing-event detectors operating
	// on assembly-heavy code.
	KindAsmLog0 = "asm.log0"
	KindAsmLog1 = "asm.log1"
	KindAsmLog2 = "asm.log2"
	KindAsmLog3 = "asm.log3"
	KindAsmLog4 = "asm.log4"
	// Control-flow inside assembly blocks.
	KindAsmRevert = "asm.revert"
	KindAsmReturn = "asm.return"
	// Generic fallback for any other Yul opcode.
	KindAsmOperation = "asm.operation"
)

// --- Semantic Group Matching ---

// IsOutgoingCall returns true if the kind represents any call to external code.
// Used for reentrancy detection. Matches: call.external, call.lowlevel.*,
// call.builtin.*, asm.call, asm.delegatecall, asm.staticcall.
func IsOutgoingCall(kind string) bool {
	switch kind {
	case KindCallExternal, KindCallLowlevelCall, KindCallLowlevelDelegate,
		KindCallLowlevelStatic, KindCallBuiltinTransfer, KindCallBuiltinSend,
		KindCallCreate,
		KindAsmCall, KindAsmDelegatecall, KindAsmStaticcall:
		return true
	}
	return false
}

// IsETHTransfer returns true if the kind represents an ETH value transfer.
func IsETHTransfer(kind string) bool {
	switch kind {
	case KindCallBuiltinTransfer, KindCallBuiltinSend,
		KindCallLowlevelCall, KindAsmCall:
		return true
	}
	return false
}

// IsDelegatecall returns true if the kind is a delegatecall operation.
func IsDelegatecall(kind string) bool {
	return kind == KindCallLowlevelDelegate || kind == KindAsmDelegatecall
}

// IsCheck returns true if the kind is a validation check (require/assert/revert).
func IsCheck(kind string) bool {
	switch kind {
	case KindCheckRequire, KindCheckAssert, KindCheckRevert:
		return true
	}
	return false
}

// IsAnyCall returns true if the kind is any call type (internal or external).
func IsAnyCall(kind string) bool {
	switch kind {
	case KindCallInternal, KindCallExternal, KindCallLowlevelCall,
		KindCallLowlevelDelegate, KindCallLowlevelStatic,
		KindCallBuiltinTransfer, KindCallBuiltinSend,
		KindCallBuiltinSelfdestruct, KindCallCreate:
		return true
	}
	return false
}

// KnownSemanticGroups is the closed set of WQL semantic-group names accepted by
// the engine's matchKind dispatcher. Used by template-load validation so a
// typo like `kind: outgoing_calls` (plural) errors at load instead of silently
// matching nothing at scan time.
var KnownSemanticGroups = map[string]bool{
	"outgoing_call": true,
	"eth_transfer":  true,
	"delegatecall":  true,
	"check":         true,
	"guard":         true, // alias for check
	"guard.require": true,
	"guard.assert":  true,
	"guard.revert":  true,
	"token_call":    true,
	"state_write":   true,
	"state_read":    true,
	"any_call":      true,
	"selfdestruct":  true,
}

// knownPrefixes is the closed set of dotted-prefix shortcuts. `kind: call`
// matches every `call.*` kind, etc. Used together with KnownSemanticGroups
// and the registered KindXxx exact strings by IsKnownKind.
var knownPrefixes = map[string]bool{
	"call":  true,
	"check": true,
	"stmt":  true,
	"expr":  true,
	"decl":  true,
	"asm":   true,
}

// allRegisteredKinds returns the set of all exact kind constants defined in
// this package. It's the source of truth for IsKnownKind; keep it aligned
// with the KindXxx constants above when adding new kinds.
func allRegisteredKinds() map[string]bool {
	return map[string]bool{
		// Call kinds
		KindCallInternal:            true,
		KindCallExternal:            true,
		KindCallLowlevelCall:        true,
		KindCallLowlevelDelegate:    true,
		KindCallLowlevelStatic:      true,
		KindCallBuiltinTransfer:     true,
		KindCallBuiltinSend:         true,
		KindCallBuiltinSelfdestruct: true,
		KindCallCreate:              true,
		// Check kinds
		KindCheckRequire: true,
		KindCheckAssert:  true,
		KindCheckRevert:  true,
		// Statement kinds
		KindStmtAssign:        true,
		KindStmtStateMutation: true,
		KindStmtIf:            true,
		KindStmtLoop:          true,
		KindStmtReturn:        true,
		KindStmtEmit:          true,
		KindStmtTryCatch:      true,
		KindStmtBlock:         true,
		KindStmtUnchecked:     true,
		// Expression kinds
		KindExprIdentifier:   true,
		KindExprLiteral:      true,
		KindExprBinaryOp:     true,
		KindExprUnaryOp:      true,
		KindExprMemberAccess: true,
		KindExprIndexAccess:  true,
		KindExprConditional:  true,
		KindExprTuple:        true,
		// Declaration kinds
		KindDeclFunction:  true,
		KindDeclContract:  true,
		KindDeclVariable:  true,
		KindDeclParameter: true,
		KindDeclModifier:  true,
		// Assembly kinds
		KindAsmBlock:        true,
		KindAsmCall:         true,
		KindAsmDelegatecall: true,
		KindAsmStaticcall:   true,
		KindAsmSstore:       true,
		KindAsmSload:        true,
		KindAsmSelfdestruct: true,
		KindAsmCreate:       true,
		KindAsmCreate2:      true,
		KindAsmLog0:         true,
		KindAsmLog1:         true,
		KindAsmLog2:         true,
		KindAsmLog3:         true,
		KindAsmLog4:         true,
		KindAsmRevert:       true,
		KindAsmReturn:       true,
		KindAsmOperation:    true,
	}
}

// IsKnownKind returns true if the given kind string is a registered exact
// kind, a known semantic group, a single-segment prefix, or a multi-segment
// dotted prefix of some registered kind (e.g. "call.lowlevel" prefixes
// "call.lowlevel.call"). Used by the template loader to reject `kind: <typo>`
// immediately rather than letting the scan silently produce zero findings.
//
// matchKind implements multi-segment prefix matching at scan time, so this must
// accept the same multi-segment prefixes — otherwise a documented form like
// `kind: call.lowlevel` would be rejected at load even though it works.
func IsKnownKind(kind string) bool {
	if kind == "" {
		return true // empty kind = "any" — handled elsewhere
	}
	if KnownSemanticGroups[kind] {
		return true
	}
	if knownPrefixes[kind] {
		return true
	}
	if allRegisteredKinds()[kind] {
		return true
	}
	// guard.* aliases check.* (matchKind rewrites the prefix).
	if strings.HasPrefix(kind, "guard.") {
		return allRegisteredKinds()[strings.Replace(kind, "guard.", "check.", 1)]
	}
	// Multi-segment prefix of a registered kind, e.g. "call.lowlevel",
	// "call.builtin".
	if strings.Contains(kind, ".") {
		prefix := kind + "."
		for registered := range allRegisteredKinds() {
			if strings.HasPrefix(registered, prefix) {
				return true
			}
		}
	}
	return false
}

// IsTokenCall returns true if the kind is an external call AND the name matches
// ERC20/ERC721 standard token methods.
// Note: This is evaluated at KIND level only — name matching is done separately.
// Evaluator compatibility helper; public WQL uses block: external_call plus
// name matching for ERC20/ERC721 methods.
func IsTokenCall(kind string) bool {
	// token_call maps to call.external — name filtering for ERC20/ERC721 methods
	// is handled separately via the `name` field in WQL rules.
	return kind == KindCallExternal
}

// IsGuard returns true if the kind is a validation check (require/assert/revert).
// This is an evaluator compatibility alias for IsCheck(); public WQL uses
// block: guard.
func IsGuard(kind string) bool {
	return IsCheck(kind)
}
