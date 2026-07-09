package types

import (
	"regexp"
	"testing"
)

func TestGetSelector(t *testing.T) {
	tests := []struct {
		name     string
		fn       *Function
		expected string
	}{
		{
			name: "no params",
			fn: &Function{
				Name: "pause",
			},
			expected: "pause()",
		},
		{
			name: "erc20 transfer",
			fn: &Function{
				Name: "transfer",
				Parameters: []*Parameter{
					{Name: "to", TypeName: "address"},
					{Name: "amount", TypeName: "uint256"},
				},
			},
			expected: "transfer(address,uint256)",
		},
		{
			name: "storage keyword stripped",
			fn: &Function{
				Name: "store",
				Parameters: []*Parameter{
					{Name: "data", TypeName: "bytes memory"},
				},
			},
			expected: "store(bytes)",
		},
		{
			name: "constructor has empty selector",
			fn: &Function{
				Name:          "",
				IsConstructor: true,
			},
			expected: "",
		},
		{
			name: "receive has no param types",
			fn: &Function{
				Name:      "",
				IsReceive: true,
			},
			expected: "()",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.fn.GetSelector(nil); got != tt.expected {
				t.Fatalf("GetSelector() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestGetSignatureIsKeccakOfSelector(t *testing.T) {
	fn := &Function{
		Name: "transfer",
		Parameters: []*Parameter{
			{Name: "to", TypeName: "address"},
			{Name: "amount", TypeName: "uint256"},
		},
	}

	// transfer(address,uint256) is the canonical ERC20 transfer selector.
	// Its 4-byte keccak256 signature is the well-known 0xa9059cbb.
	if got := fn.GetSignature(nil); got != "a9059cbb" {
		t.Fatalf("GetSignature() = %q, want %q", got, "a9059cbb")
	}

	// Structurally: the signature is the first 4 bytes (8 hex chars) of the
	// keccak256 of the selector — verify it matches independently.
	selector := fn.GetSelector(nil)
	want := hexEncode4(keccak256([]byte(selector)))
	if fn.GetSignature(nil) != want {
		t.Fatalf("GetSignature() should be first 4 bytes of keccak256(selector); got %q want %q",
			fn.GetSignature(nil), want)
	}
}

// hexEncode4 mirrors the encoding GetSignature performs, kept local to the test.
func hexEncode4(b []byte) string {
	const hexdigits = "0123456789abcdef"
	out := make([]byte, 8)
	for i := 0; i < 4; i++ {
		out[i*2] = hexdigits[b[i]>>4]
		out[i*2+1] = hexdigits[b[i]&0x0f]
	}
	return string(out)
}

func TestGetSignatureEmptyForConstructor(t *testing.T) {
	fn := &Function{IsConstructor: true}
	if got := fn.GetSignature(nil); got != "" {
		t.Fatalf("constructor GetSignature() = %q, want empty", got)
	}
}

func TestIsEntrypoint(t *testing.T) {
	tests := []struct {
		name string
		fn   *Function
		want bool
	}{
		{
			name: "public non-payable",
			fn:   &Function{Name: "f", Visibility: VisibilityPublic, StateMutability: StateMutabilityNonPayable},
			want: true,
		},
		{
			name: "external payable",
			fn:   &Function{Name: "f", Visibility: VisibilityExternal, StateMutability: StateMutabilityPayable},
			want: true,
		},
		{
			name: "internal is not an entrypoint",
			fn:   &Function{Name: "f", Visibility: VisibilityInternal},
			want: false,
		},
		{
			name: "private is not an entrypoint",
			fn:   &Function{Name: "f", Visibility: VisibilityPrivate},
			want: false,
		},
		{
			name: "public view is excluded",
			fn:   &Function{Name: "f", Visibility: VisibilityPublic, StateMutability: StateMutabilityView},
			want: false,
		},
		{
			name: "public pure is excluded",
			fn:   &Function{Name: "f", Visibility: VisibilityPublic, StateMutability: StateMutabilityPure},
			want: false,
		},
		{
			name: "constructor is excluded",
			fn:   &Function{Visibility: VisibilityPublic, IsConstructor: true},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.fn.IsEntrypoint(); got != tt.want {
				t.Fatalf("IsEntrypoint() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestUniqueIDFormatAndStability(t *testing.T) {
	fn := &Function{
		ContractName: "Token",
		Name:         "transfer",
		Parameters: []*Parameter{
			{TypeName: "address"},
			{TypeName: "uint256"},
		},
	}

	id := fn.UniqueID(nil)

	// UniqueID is the first 8 bytes of a sha256, hex-encoded => 16 hex chars.
	if len(id) != 16 {
		t.Fatalf("UniqueID length = %d, want 16", len(id))
	}
	if !regexp.MustCompile(`^[0-9a-f]{16}$`).MatchString(id) {
		t.Fatalf("UniqueID = %q is not lowercase hex", id)
	}

	// Deterministic: same input -> same ID.
	if id != fn.UniqueID(nil) {
		t.Fatal("UniqueID should be deterministic")
	}

	// Different contract name -> different ID (it is part of the hashed data).
	other := &Function{
		ContractName: "OtherToken",
		Name:         "transfer",
		Parameters:   fn.Parameters,
	}
	if other.UniqueID(nil) == id {
		t.Fatal("UniqueID should differ when the contract name differs")
	}
}

func TestIsAccessControlledNoModifier(t *testing.T) {
	fn := &Function{
		Name:       "open",
		Visibility: VisibilityPublic,
	}
	if fn.IsAccessControlled(NewDatabase()) {
		t.Fatal("a function with no modifiers, calls, or AST should not be access controlled")
	}
}

func TestIsAccessControlledViaInternalAuthCall(t *testing.T) {
	// The auth-function heuristic matches verb+noun helper names in both
	// camelCase and snake_case, joined directly or by underscores. Names with
	// no auth noun (checkBalance) or non-auth callees must NOT match.
	cases := []struct {
		target string
		want   bool
	}{
		{"_checkOwner", true},   // camelCase, leading underscore (OpenZeppelin style)
		{"checkOwner", true},    // camelCase, no underscore
		{"requireAuth", true},   // verb+noun, no separator
		{"validateAdmin", true}, // verb+noun, no separator
		{"verifyRole", true},
		{"enforceAccess", true},
		{"checkPermission", true},
		{"_check_Owner", true}, // snake_case with underscore separator
		{"check_owner", true},
		{"checkSender", true},
		{"checkBalance", false}, // "check" verb but no auth noun
		{"checkSupply", false},
		{"getOwner", false}, // auth noun but not a guard verb
		{"transfer", false},
		{"withdraw", false},
	}
	for _, tc := range cases {
		fn := &Function{
			Name:       "guarded",
			Visibility: VisibilityPublic,
			Calls:      []*FunctionCall{{Target: tc.target, CallType: CallTypeInternal}},
		}
		got := fn.IsAccessControlled(NewDatabase())
		if got != tc.want {
			t.Errorf("IsAccessControlled with internal call %q = %v, want %v", tc.target, got, tc.want)
		}
	}
}

func TestIsAccessControlledIgnoresUnrelatedModifier(t *testing.T) {
	fn := &Function{
		Name:      "f",
		Modifiers: []string{"nonReentrant"},
	}
	if fn.IsAccessControlled(NewDatabase()) {
		t.Fatal("nonReentrant is not an access-control modifier")
	}
}

func TestIsAccessControlledViaMsgSenderRequire(t *testing.T) {
	// Build: require(msg.sender == owner())
	//   require
	//     binary_op
	//       member_access "sender" -> identifier "msg"
	//       call.internal "owner"
	root := NewASTNode(KindDeclFunction)
	require := NewASTNode(KindCheckRequire)
	binop := NewASTNode(KindExprBinaryOp)

	memberAccess := NewASTNode(KindExprMemberAccess)
	memberAccess.Name = "sender"
	msgIdent := NewASTNode(KindExprIdentifier)
	msgIdent.Name = "msg"
	memberAccess.AddChild(msgIdent)

	ownerCall := NewASTNode(KindCallInternal)
	ownerCall.Name = "owner"

	binop.AddChild(memberAccess)
	binop.AddChild(ownerCall)
	require.AddChild(binop)
	root.AddChild(require)

	fn := &Function{
		Name:       "setOwner",
		Visibility: VisibilityPublic,
		AST:        root,
	}

	if !fn.IsAccessControlled(NewDatabase()) {
		t.Fatal("require(msg.sender == owner()) should be detected as access control")
	}
}

// TestIsAccessControlledRejectsParameterCompare documents the false positive fix:
// require(from == msg.sender) where `from` is a function argument is self-auth,
// not a privileged access gate, so it must NOT count as access control.
func TestIsAccessControlledRejectsParameterCompare(t *testing.T) {
	// Build: require(from == msg.sender)
	//   require
	//     binary_op
	//       identifier "from" (parameter)
	//       member_access "sender" -> identifier "msg"
	root := NewASTNode(KindDeclFunction)
	req := NewASTNode(KindCheckRequire)
	binop := NewASTNode(KindExprBinaryOp)

	fromIdent := NewASTNode(KindExprIdentifier)
	fromIdent.Name = "from"
	fromIdent.RefKind = "parameter"

	memberAccess := NewASTNode(KindExprMemberAccess)
	memberAccess.Name = "sender"
	msgIdent := NewASTNode(KindExprIdentifier)
	msgIdent.Name = "msg"
	memberAccess.AddChild(msgIdent)

	binop.AddChild(fromIdent)
	binop.AddChild(memberAccess)
	req.AddChild(binop)
	root.AddChild(req)

	fn := &Function{
		Name:       "move",
		Visibility: VisibilityExternal,
		Parameters: []*Parameter{{Name: "from"}},
		AST:        root,
	}

	if fn.IsAccessControlled(NewDatabase()) {
		t.Fatal("require(from == msg.sender) is self-auth, must NOT be access control")
	}
}

// TestIsAccessControlledAcceptsHardcodedAddress verifies that comparing the
// caller against a hardcoded literal address is access control (the caller
// cannot control a bytecode literal).
func TestIsAccessControlledAcceptsHardcodedAddress(t *testing.T) {
	// Build: require(msg.sender == 0xAbc…)
	root := NewASTNode(KindDeclFunction)
	req := NewASTNode(KindCheckRequire)
	binop := NewASTNode(KindExprBinaryOp)

	memberAccess := NewASTNode(KindExprMemberAccess)
	memberAccess.Name = "sender"
	msgIdent := NewASTNode(KindExprIdentifier)
	msgIdent.Name = "msg"
	memberAccess.AddChild(msgIdent)

	lit := NewASTNode(KindExprLiteral)
	lit.Value = "0xAbcdEF0123456789012345678901234567890123"

	binop.AddChild(memberAccess)
	binop.AddChild(lit)
	req.AddChild(binop)
	root.AddChild(req)

	fn := &Function{
		Name:       "hardcodedGate",
		Visibility: VisibilityExternal,
		AST:        root,
	}

	if !fn.IsAccessControlled(NewDatabase()) {
		t.Fatal("require(msg.sender == 0xAbc…) should be detected as access control")
	}
}

// TestForwardedOwnerOfIsSelfScopingNotAccessControl covers the SpiceFiNFT4626
// case: an entry point forwards msg.sender into an internal helper
// (`_withdraw(msg.sender, tokenId, receiver)`), and the helper checks
// `if (ownerOf(tokenId) != caller) revert`. `ownerOf(tokenId)` is indexed by a
// caller-chosen resource id, so this is item-ownership SELF-SCOPING — NOT
// privileged access control. IsAccessControlled must stay false (the function
// is not gated to an owner/role), while ComparesCallerIdentity must follow the
// forwarded caller and report true so detectors like arbitrary-send-eth
// (preset unCheckedSender) treat it as a valid mitigation.
func TestForwardedOwnerOfIsSelfScopingNotAccessControl(t *testing.T) {
	db := NewDatabase()

	// _withdraw(address caller, uint256 tokenId, address receiver):
	//   if (ownerOf(tokenId) != caller) revert;
	withdrawAST := NewASTNode(KindDeclFunction)
	ifStmt := NewASTNode(KindStmtIf)
	cmp := NewASTNode(KindExprBinaryOp)
	cmp.SetAttribute("operator", "!=")
	ownerOf := NewASTNode(KindCallInternal)
	ownerOf.Name = "ownerOf"
	ownerOfArg := NewASTNode(KindExprIdentifier) // ownerOf(tokenId) — caller-selected resource id
	ownerOfArg.Name = "tokenId"
	ownerOfArg.RefKind = "parameter"
	ownerOf.AddChild(ownerOfArg)
	callerIdent := NewASTNode(KindExprIdentifier)
	callerIdent.Name = "caller"
	callerIdent.RefKind = "parameter"
	cmp.AddChild(ownerOf)
	cmp.AddChild(callerIdent)
	ifStmt.AddChild(cmp)
	withdrawAST.AddChild(ifStmt)

	withdrawFn := &Function{
		Name:         "_withdraw",
		ContractName: "Vault",
		Visibility:   VisibilityInternal,
		Parameters:   []*Parameter{{Name: "caller"}, {Name: "tokenId"}, {Name: "receiver"}},
		AST:          withdrawAST,
	}

	// redeemETH(uint256 tokenId, address receiver):
	//   _withdraw(msg.sender, tokenId, receiver);
	redeemAST := NewASTNode(KindDeclFunction)
	call := NewASTNode(KindCallInternal)
	call.Name = "_withdraw"
	msgSender := NewASTNode(KindExprMemberAccess)
	msgSender.Name = "sender"
	msgIdent := NewASTNode(KindExprIdentifier)
	msgIdent.Name = "msg"
	msgSender.AddChild(msgIdent)
	tokenIdArg := NewASTNode(KindExprIdentifier)
	tokenIdArg.Name = "tokenId"
	receiverArg := NewASTNode(KindExprIdentifier)
	receiverArg.Name = "receiver"
	call.AddChild(msgSender)   // arg 0 -> caller
	call.AddChild(tokenIdArg)  // arg 1 -> tokenId
	call.AddChild(receiverArg) // arg 2 -> receiver
	redeemAST.AddChild(call)

	redeemFn := &Function{
		Name:         "redeemETH",
		ContractName: "Vault",
		Visibility:   VisibilityExternal,
		Parameters:   []*Parameter{{Name: "tokenId"}, {Name: "receiver"}},
		AST:          redeemAST,
		Calls: []*FunctionCall{{
			Target:   "_withdraw",
			CallType: CallTypeInternal,
			// Resolution stores the full selector, not the bare name — the auth
			// descent must still resolve it to the `_withdraw` function.
			ResolvedContract: "Vault",
			ResolvedFunction: "_withdraw(address,uint256,address,uint256)",
		}},
	}

	vault := &Contract{Name: "Vault", Functions: []*Function{redeemFn, withdrawFn}}
	db.AddContract(vault)

	if redeemFn.IsAccessControlled(db) {
		t.Fatal("ownerOf(tokenId) == caller is item-ownership self-scoping, NOT privileged access control")
	}
	if !redeemFn.ComparesCallerIdentity(db) {
		t.Fatal("forwarded caller compared to ownerOf(tokenId) must be recognized as self-scoping")
	}
}
