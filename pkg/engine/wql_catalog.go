package engine

// WQL → evaluator IR catalog mappings.
//
// WQL (see docs/wql-syntax.md) uses memorable
// names for block kinds (§5) and attributes (§7). None of these
// change the underlying engine — they are pure aliases resolved by the WQL
// compiler onto the exact `types` kind strings and node attribute keys.
//
// Every IR target string below has been verified against the current code:
//   - block kinds against pkg/types/ast.go (KindXxx constants, KnownSemanticGroups,
//     and the matchKind semantic-group switch in pkg/engine/verify.go)
//   - attribute keys against pkg/builder/ast_builder.go / semantic.go SetAttribute
//     call sites and pkg/engine/verify.go readers

// blockKindToIRTable is the §5 block-kind catalog: WQL name -> IR kind string
// (an exact `types.KindXxx` constant or a semantic-group name recognized by
// Engine.matchKind / types.KnownSemanticGroups).
//
// Where a single evaluator semantic group already merges the Solidity-level and
// inline-assembly forms of an operation (delegatecall, selfdestruct), the WQL
// name maps onto that group so a single `blockKindToIR` lookup gets full
// coverage for free — matching the "+" combinations documented in the
// language spec §5 table. Where no such merged group exists yet
// (staticcall, create), the mapping only reaches the Solidity-level kind;
// the asm sibling is separately exposed via `asm_staticcall` / `asm_create`.
// This is a known, documented coverage gap — see the report.
var blockKindToIRTable = map[string]string{
	// Calls
	"call":                 "any_call",                  // any internal/external/low-level call
	"outgoing_call":        "outgoing_call",             // semantic group: any call this function makes outward
	"external_call":        "call.external",             // exact kind
	"internal_call":        "call.internal",             // exact kind
	"delegatecall":         "delegatecall",              // semantic group: call.lowlevel.delegatecall + asm.delegatecall
	"staticcall":           "call.lowlevel.staticcall",  // exact kind only; no merged group with asm.staticcall today
	"lowlevel_call":        "call.lowlevel.call",        // exact kind
	"create":               "call.create",               // exact kind only; no merged group with asm.create/asm.create2 today
	"eth_transfer":         "eth_transfer",              // semantic group: .transfer/.send/call{value:}
	"selfdestruct":         "selfdestruct",              // semantic group: call.builtin.selfdestruct + asm.selfdestruct
	"builtin_transfer":     "call.builtin.transfer",     // exact kind: address.transfer(...)
	"builtin_send":         "call.builtin.send",         // exact kind: address.send(...)
	"builtin_selfdestruct": "call.builtin.selfdestruct", // exact kind (Solidity-level only; use "selfdestruct" for +asm)

	// Guards / checks
	"guard":   "check",         // semantic group: any require/assert/revert
	"require": "check.require", // exact kind
	"assert":  "check.assert",  // exact kind
	"revert":  "check.revert",  // exact kind

	// State
	"state_write": "state_write", // semantic group: state assign/mutation/unary writes, or asm.sstore
	"state_read":  "state_read",  // semantic group: state-var identifier read, or asm.sload

	// Statements
	"assign":    "stmt.assign",
	"if":        "stmt.if",
	"loop":      "stmt.loop",
	"return":    "stmt.return",
	"emit":      "stmt.emit",
	"try_catch": "stmt.try_catch",
	"unchecked": "stmt.unchecked",
	"block":     "stmt.block",

	// Expressions
	"identifier": "expr.identifier",
	"literal":    "expr.literal",
	"binary":     "expr.binary_op",
	"unary":      "expr.unary_op",
	"member":     "expr.member_access",
	"index":      "expr.index_access",
	"ternary":    "expr.conditional",
	"tuple":      "expr.tuple",

	// Declarations
	"function":  "decl.function",
	"contract":  "decl.contract",
	"variable":  "decl.variable",
	"parameter": "decl.parameter",
	"modifier":  "decl.modifier",

	// Assembly
	"asm":              "asm.block",
	"asm_sstore":       "asm.sstore",
	"asm_sload":        "asm.sload",
	"asm_delegatecall": "asm.delegatecall",
	"asm_call":         "asm.call",
	"asm_staticcall":   "asm.staticcall",
	"asm_create":       "asm.create",
	"asm_selfdestruct": "asm.selfdestruct",
	"asm_revert":       "asm.revert",
	"asm_return":       "asm.return",
	// NOTE: `asm_log` from the language spec §5 is intentionally NOT included:
	// there is no single evaluator kind for it. The AST only has per-arity opcode
	// kinds (asm.log0 .. asm.log4), so a single-string alias would silently
	// match only one arity. Add a semantic group for it if a template needs
	// "any asm log" matching; until then this name is unmapped (ok=false).
}

// blockKindToIR resolves a WQL block-kind name (§5) to the IR kind string
// (an exact types.KindXxx constant or a matchKind semantic-group name) the
// existing evaluator understands. ok is false for unknown WQL names.
func blockKindToIR(wqlName string) (string, bool) {
	ir, ok := blockKindToIRTable[wqlName]
	return ir, ok
}

// attrNameToIRTable is the §7 attribute catalog: WQL attribute name -> IR
// node-attribute key (the string key read via types.ASTNode.GetAttribute /
// GetAttributeString / GetAttributeBool).
//
// `name`, `visibility`, `mutability`, and `tainted` are deliberately NOT in
// this table. In the evaluator IR those are inline `Rule` fields (Rule.Name, Rule.Visibility,
// Rule.Mutability, Rule.TaintedFrom), not entries in the free-form Attr map,
// so they have no "attribute key" to alias — the WQL lowering step (Task A3)
// must route them straight onto those Rule fields instead of through
// attrNameToIR. Callers of attrNameToIR must special-case these four names
// before consulting the table (attrNameToIR returns ok=false for them, which
// is the correct "not an attr-map entry" signal, not an unknown-name error).
var attrNameToIRTable = map[string]string{
	// Core (§7)
	"receiver":      "call_receiver", // bool marker on the receiver child of a member call
	"receiver_name": "receiver_name", // direct receiver child name copied onto the call node
	"signature":     "called_signature",
	"has_value":     "has_value",
	"has_gas":       "has_gas",
	"call_option":   "call_option", // "value" or "gas" marker on a call-option child (verify.go reads it alongside call_receiver)
	"operator":      "operator",
	"type":          "type",
	"type_kind":     "type_kind",
	"literal_kind":  "subtype",
	"is_state_var":  "is_state_var",

	// Advanced (§7)
	"has_salt":                 "has_salt",
	"parent":                   "parent",
	"cond_role":                "cond_role",
	"conditional_part":         "conditional_part",
	"try_part":                 "try_part",
	"loop_type":                "loop_type",
	"receiver_type":            "receiver_type",
	"receiver_type_kind":       "receiver_type_kind",
	"receiver_type_is_address": "receiver_type_is_address",
}

// attrNameToIR resolves a WQL attribute name (§7) to the IR node-attribute
// key. ok is false both for unknown WQL names AND for the four
// Rule-field-backed names (`name`, `visibility`, `mutability`, `tainted`)
// that lowering must handle separately — see attrNameToIRTable's doc comment.
func attrNameToIR(wqlName string) (string, bool) {
	ir, ok := attrNameToIRTable[wqlName]
	return ir, ok
}
