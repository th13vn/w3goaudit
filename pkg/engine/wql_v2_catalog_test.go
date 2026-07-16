package engine

import "testing"

func TestBlockKindToIR(t *testing.T) {
	cases := []struct {
		v2     string
		wantIR string
		wantOk bool
	}{
		// The 9 call kinds (§5 "Calls" table).
		{"call", "any_call", true},
		{"external_call", "call.external", true},
		{"internal_call", "call.internal", true},
		{"delegatecall", "delegatecall", true},
		{"staticcall", "call.lowlevel.staticcall", true},
		{"lowlevel_call", "call.lowlevel.call", true},
		{"create", "call.create", true},
		{"eth_transfer", "eth_transfer", true},
		{"selfdestruct", "selfdestruct", true},
		{"outgoing_call", "outgoing_call", true},
		{"builtin_transfer", "call.builtin.transfer", true},
		{"builtin_send", "call.builtin.send", true},
		{"builtin_selfdestruct", "call.builtin.selfdestruct", true},

		// Guards / checks
		{"guard", "check", true},
		{"require", "check.require", true},
		{"assert", "check.assert", true},
		{"revert", "check.revert", true},

		// State
		{"state_write", "state_write", true},
		{"state_read", "state_read", true},

		// Statements
		{"assign", "stmt.assign", true},
		{"if", "stmt.if", true},
		{"loop", "stmt.loop", true},
		{"return", "stmt.return", true},
		{"emit", "stmt.emit", true},
		{"try_catch", "stmt.try_catch", true},
		{"unchecked", "stmt.unchecked", true},
		{"block", "stmt.block", true},

		// Expressions
		{"identifier", "expr.identifier", true},
		{"literal", "expr.literal", true},
		{"binary", "expr.binary_op", true},
		{"unary", "expr.unary_op", true},
		{"member", "expr.member_access", true},
		{"index", "expr.index_access", true},
		{"ternary", "expr.conditional", true},
		{"tuple", "expr.tuple", true},

		// Declarations
		{"function", "decl.function", true},
		{"contract", "decl.contract", true},
		{"variable", "decl.variable", true},
		{"parameter", "decl.parameter", true},
		{"modifier", "decl.modifier", true},

		// Assembly
		{"asm", "asm.block", true},
		{"asm_sstore", "asm.sstore", true},
		{"asm_sload", "asm.sload", true},
		{"asm_delegatecall", "asm.delegatecall", true},
		{"asm_call", "asm.call", true},
		{"asm_staticcall", "asm.staticcall", true},
		{"asm_create", "asm.create", true},
		{"asm_selfdestruct", "asm.selfdestruct", true},
		{"asm_revert", "asm.revert", true},
		{"asm_return", "asm.return", true},

		// Unknown / unsupported.
		{"asm_log", "", false},
		{"nope-not-a-kind", "", false},
		{"", "", false},
	}

	for _, tc := range cases {
		t.Run(tc.v2, func(t *testing.T) {
			gotIR, gotOk := blockKindToIR(tc.v2)
			if gotOk != tc.wantOk {
				t.Fatalf("blockKindToIR(%q) ok = %v, want %v", tc.v2, gotOk, tc.wantOk)
			}
			if gotOk && gotIR != tc.wantIR {
				t.Fatalf("blockKindToIR(%q) = %q, want %q", tc.v2, gotIR, tc.wantIR)
			}
		})
	}
}

func TestAttrNameToIR(t *testing.T) {
	cases := []struct {
		v2     string
		wantIR string
		wantOk bool
	}{
		// Core (§7)
		{"receiver", "call_receiver", true},
		{"signature", "called_signature", true},
		{"literal_kind", "subtype", true},
		{"has_value", "has_value", true},
		{"has_gas", "has_gas", true},
		{"call_option", "call_option", true},
		{"operator", "operator", true},
		{"type", "type", true},
		{"type_kind", "type_kind", true},
		{"is_state_var", "is_state_var", true},

		// Advanced (§7)
		{"has_salt", "has_salt", true},
		{"parent", "parent", true},
		{"cond_role", "cond_role", true},
		{"conditional_part", "conditional_part", true},
		{"try_part", "try_part", true},
		{"loop_type", "loop_type", true},
		{"receiver_type", "receiver_type", true},
		{"receiver_type_kind", "receiver_type_kind", true},
		{"receiver_type_is_address", "receiver_type_is_address", true},

		// Unknown.
		{"not-a-real-attr", "", false},
		{"", "", false},
	}

	for _, tc := range cases {
		t.Run(tc.v2, func(t *testing.T) {
			gotIR, gotOk := attrNameToIR(tc.v2)
			if gotOk != tc.wantOk {
				t.Fatalf("attrNameToIR(%q) ok = %v, want %v", tc.v2, gotOk, tc.wantOk)
			}
			if gotOk && gotIR != tc.wantIR {
				t.Fatalf("attrNameToIR(%q) = %q, want %q", tc.v2, gotIR, tc.wantIR)
			}
		})
	}
}

// TestAttrNameToIR_RuleFieldBackedNamesNotInMap documents (and locks in) that
// name/visibility/mutability/tainted are handled by lowering as inline Rule
// fields, NOT via attrNameToIR — see the doc comment on attrNameToIRTable.
func TestAttrNameToIR_RuleFieldBackedNamesNotInMap(t *testing.T) {
	for _, v2 := range []string{"name", "visibility", "mutability", "tainted"} {
		if _, ok := attrNameToIR(v2); ok {
			t.Fatalf("attrNameToIR(%q) ok = true, want false (Rule-field-backed, not an Attr-map entry)", v2)
		}
	}
}

func TestPresetToIR(t *testing.T) {
	cases := []struct {
		v2         string
		wantIR     string
		wantNegate bool
		wantOk     bool
	}{
		{"access_controlled", "unAuthenticated", true, true},
		{"caller_checked", "unCheckedSender", true, true},
		{"reentrancy_guarded", "unLocked", true, true},
		{"not-a-real-preset", "", false, false},
	}

	for _, tc := range cases {
		t.Run(tc.v2, func(t *testing.T) {
			gotIR, gotNegate, gotOk := presetToIR(tc.v2)
			if gotOk != tc.wantOk {
				t.Fatalf("presetToIR(%q) ok = %v, want %v", tc.v2, gotOk, tc.wantOk)
			}
			if gotOk {
				if gotIR != tc.wantIR {
					t.Fatalf("presetToIR(%q) IR = %q, want %q", tc.v2, gotIR, tc.wantIR)
				}
				if gotNegate != tc.wantNegate {
					t.Fatalf("presetToIR(%q) negate = %v, want %v", tc.v2, gotNegate, tc.wantNegate)
				}
				if !IsKnownPreset(gotIR) {
					t.Fatalf("presetToIR(%q) resolved to unregistered evaluator preset %q", tc.v2, gotIR)
				}
			}
		})
	}
}
