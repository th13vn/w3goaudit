package engine

// WQL v2 → evaluator IR catalog mappings.
//
// WQL v2 (see .vscode/specs/2026-07-09-wql-v2-language-spec.md) uses memorable
// names for block kinds (§5), attributes (§7), and presets (§8). None of these
// change the underlying engine — they are pure aliases resolved by the v2
// compiler onto the exact `types` kind strings, node attribute keys, and
// `pkg/engine/presets.go` preset names the evaluator understands.
//
// Every IR target string below has been verified against the current code:
//   - block kinds against pkg/types/ast.go (KindXxx constants, KnownSemanticGroups,
//     and the matchKind semantic-group switch in pkg/engine/verify.go)
//   - attribute keys against pkg/builder/ast_builder.go / semantic.go SetAttribute
//     call sites and pkg/engine/verify.go readers
//   - presets against pkg/engine/presets.go (BuiltinPresets)

// blockKindToIRTable is the §5 block-kind catalog: v2 name -> IR kind string
// (an exact `types.KindXxx` constant or a semantic-group name recognized by
// Engine.matchKind / types.KnownSemanticGroups).
//
// Where a single evaluator semantic group already merges the Solidity-level and
// inline-assembly forms of an operation (delegatecall, selfdestruct), the v2
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
	"state_write": "state_write", // semantic group: stmt.assign w/ is_state_var, or asm.sstore
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

// blockKindToIR resolves a WQL v2 block-kind name (§5) to the IR kind string
// (an exact types.KindXxx constant or a matchKind semantic-group name) the
// existing evaluator understands. ok is false for unknown v2 names.
func blockKindToIR(v2 string) (string, bool) {
	ir, ok := blockKindToIRTable[v2]
	return ir, ok
}

// attrNameToIRTable is the §7 attribute catalog: v2 attribute name -> IR
// node-attribute key (the string key read via types.ASTNode.GetAttribute /
// GetAttributeString / GetAttributeBool).
//
// `name`, `visibility`, `mutability`, and `tainted` are deliberately NOT in
// this table. In the evaluator IR those are inline `Rule` fields (Rule.Name, Rule.Visibility,
// Rule.Mutability, Rule.TaintedFrom), not entries in the free-form Attr map,
// so they have no "attribute key" to alias — the v2 lowering step (Task A3)
// must route them straight onto those Rule fields instead of through
// attrNameToIR. Callers of attrNameToIR must special-case these four names
// before consulting the table (attrNameToIR returns ok=false for them, which
// is the correct "not an attr-map entry" signal, not an unknown-name error).
var attrNameToIRTable = map[string]string{
	// Core (§7)
	"receiver":     "call_receiver", // bool marker on the receiver child of a member call
	"signature":    "called_signature",
	"has_value":    "has_value",
	"has_gas":      "has_gas",
	"call_option":  "call_option", // "value" or "gas" marker on a call-option child (verify.go reads it alongside call_receiver)
	"operator":     "operator",
	"type":         "type",
	"type_kind":    "type_kind",
	"literal_kind": "subtype",
	"is_state_var": "is_state_var",

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

// attrNameToIR resolves a WQL v2 attribute name (§7) to the IR node-attribute
// key. ok is false both for unknown v2 names AND for the four
// Rule-field-backed names (`name`, `visibility`, `mutability`, `tainted`)
// that lowering must handle separately — see attrNameToIRTable's doc comment.
func attrNameToIR(v2 string) (string, bool) {
	ir, ok := attrNameToIRTable[v2]
	return ir, ok
}

// presetToIR resolves a WQL v2 preset name (§8) to the evaluator preset plus
// the polarity flip needed to preserve semantics.
//
// Evaluator presets are all "true = vulnerable": unAuthenticated,
// unCheckedSender, and unLocked each represent the ABSENCE of a safety property. v2
// presets are renamed to name the safety PROPERTY itself (access_controlled,
// caller_checked, reentrancy_guarded), so `preset: access_controlled` reads
// as "access control is present" — the natural affirmative statement — and a
// detector asserts the vulnerable condition via `not: { preset: access_controlled }`.
//
// negate=true signals to the lowering step that v2's polarity is inverted
// relative to the underlying evaluator preset function: v2 property-true
// corresponds to evaluator preset-false, and vice versa. The compiler translates:
//
//	preset: access_controlled          -> ctx.Not = { Preset: "unAuthenticated" }
//	not: { preset: access_controlled } -> ctx.Preset = "unAuthenticated"
//
// (mirrored for caller_checked/unCheckedSender and reentrancy_guarded/unLocked).
func presetToIR(v2 string) (ir string, negate bool, ok bool) {
	switch v2 {
	case "access_controlled":
		return "unAuthenticated", true, true
	case "caller_checked":
		return "unCheckedSender", true, true
	case "reentrancy_guarded":
		return "unLocked", true, true
	default:
		return "", false, false
	}
}
