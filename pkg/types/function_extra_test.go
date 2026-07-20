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

	// The exact defining file is also part of identity: duplicate contract names
	// in different source files must never collapse to the same helper ID.
	fn.SourceFile = "/a/Token.sol"
	duplicate := *fn
	duplicate.SourceFile = "/z/Token.sol"
	if duplicate.UniqueID(nil) == fn.UniqueID(nil) {
		t.Fatal("UniqueID should differ when duplicate contracts live in different files")
	}
}

func TestAccessControlModifierLookupUsesExactFunctionOwner(t *testing.T) {
	db := NewDatabase()
	aGuard := NewASTNode(KindDeclModifier)
	aRequire := NewASTNode(KindCheckRequire)
	aComparison := NewASTNode(KindExprBinaryOp)
	aComparison.SetAttribute("operator", "==")
	aComparison.AddChild(testMsgSenderNode())
	aOwner := NewASTNode(KindExprIdentifier)
	aOwner.Name = "owner"
	aOwner.RefKind = "state_var"
	aComparison.AddChild(aOwner)
	aRequire.AddChild(aComparison)
	aGuard.AddChild(aRequire)
	zNoOp := NewASTNode(KindDeclModifier)
	aFn := &Function{
		Name: "run", ContractName: "Token", SourceFile: "/a/Token.sol", Modifiers: []string{"onlyOwner"},
		Calls: []*FunctionCall{{
			Target: "onlyOwner", ResolvedFunction: "onlyOwner", ResolvedContractID: "/a/Token.sol#Token",
			CallType: CallTypeModifier, Resolved: true, ArgCount: 0,
		}},
	}
	zFn := &Function{
		Name: "run", ContractName: "Token", SourceFile: "/z/Token.sol", Modifiers: []string{"onlyOwner"},
		Calls: []*FunctionCall{{
			Target: "onlyOwner", ResolvedFunction: "onlyOwner", ResolvedContractID: "/z/Token.sol#Token",
			CallType: CallTypeModifier, Resolved: true, ArgCount: 0,
		}},
	}
	a := &Contract{
		ID: "/a/Token.sol#Token", Name: "Token", SourceFile: "/a/Token.sol",
		LinearizedBases: []string{"Token"}, LinearizedBaseIDs: []string{"/a/Token.sol#Token"},
		Functions: []*Function{aFn}, Modifiers: []*Modifier{{Name: "onlyOwner", AST: aGuard}},
	}
	z := &Contract{
		ID: "/z/Token.sol#Token", Name: "Token", SourceFile: "/z/Token.sol",
		LinearizedBases: []string{"Token"}, LinearizedBaseIDs: []string{"/z/Token.sol#Token"},
		Functions: []*Function{zFn}, Modifiers: []*Modifier{{Name: "onlyOwner", AST: zNoOp}},
	}
	db.AddContract(a)
	db.AddContract(z)

	if !aFn.IsAccessControlled(db) {
		t.Fatal("a.Token.run should use a.Token's protective modifier")
	}
	if zFn.IsAccessControlled(db) {
		t.Fatal("z.Token.run must not borrow a.Token's protective same-named modifier")
	}
}

func TestRecursiveCallerCheckUsesResolvedContractID(t *testing.T) {
	db := NewDatabase()
	aRoot := NewASTNode(KindDeclFunction)
	requireNode := NewASTNode(KindCheckRequire)
	comparison := NewASTNode(KindExprBinaryOp)
	sender := NewASTNode(KindExprMemberAccess)
	sender.Name = "sender"
	msg := NewASTNode(KindExprIdentifier)
	msg.Name = "msg"
	sender.AddChild(msg)
	comparison.AddChild(sender)
	comparison.AddChild(NewASTNode(KindExprLiteral))
	requireNode.AddChild(comparison)
	aRoot.AddChild(requireNode)

	aScope := &Function{Name: "scope", Selector: "scope()", ContractName: "Token", SourceFile: "/a/Token.sol", AST: aRoot}
	zScope := &Function{Name: "scope", Selector: "scope()", ContractName: "Token", SourceFile: "/z/Token.sol", AST: NewASTNode(KindDeclFunction)}
	zRun := &Function{
		Name: "run", Selector: "run()", ContractName: "Token", SourceFile: "/z/Token.sol",
		Calls: []*FunctionCall{{
			Target: "scope", ResolvedFunction: "scope()", ResolvedContract: "Token",
			ResolvedContractID: "/z/Token.sol#Token", CallType: CallTypeInternal, Resolved: true,
		}},
	}
	a := &Contract{
		ID: "/a/Token.sol#Token", Name: "Token", SourceFile: "/a/Token.sol",
		LinearizedBases: []string{"Token"}, LinearizedBaseIDs: []string{"/a/Token.sol#Token"}, Functions: []*Function{aScope},
	}
	z := &Contract{
		ID: "/z/Token.sol#Token", Name: "Token", SourceFile: "/z/Token.sol",
		LinearizedBases: []string{"Token"}, LinearizedBaseIDs: []string{"/z/Token.sol#Token"}, Functions: []*Function{zRun, zScope},
	}
	db.AddContract(a)
	db.AddContract(z)

	if !aScope.ComparesCallerIdentity(db) {
		t.Fatal("a.Token.scope fixture should contain a caller comparison")
	}
	if zRun.ComparesCallerIdentity(db) {
		t.Fatal("z.Token.run must not recurse into a.Token.scope through a short-name collision")
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

func TestIsAccessControlledDoesNotTrustInternalHelperNames(t *testing.T) {
	for _, target := range []string{
		"_checkOwner", "checkOwner", "requireAuth", "validateAdmin",
		"verifyRole", "enforceAccess", "checkPermission", "_check_Owner",
		"check_owner", "checkSender", "checkBalance", "checkSupply",
		"getOwner", "transfer", "withdraw",
	} {
		fn := &Function{
			Name:       "guarded",
			Visibility: VisibilityPublic,
			Calls:      []*FunctionCall{{Target: target, CallType: CallTypeInternal}},
		}
		if fn.IsAccessControlled(NewDatabase()) {
			t.Errorf("internal helper name %q must not prove access control", target)
		}
	}
}

func TestIsAccessControlledRejectsAuthNamedDecoys(t *testing.T) {
	file := "/exact/Auth.sol"
	contractID := MakeContractID(file, "Auth")
	unrelatedGuard := NewASTNode(KindDeclModifier)
	requireAmount := NewASTNode(KindCheckRequire)
	amountComparison := NewASTNode(KindExprBinaryOp)
	amountComparison.SetAttribute("operator", ">")
	amount := NewASTNode(KindExprIdentifier)
	amount.Name = "amount"
	amount.RefKind = "parameter"
	amountComparison.AddChild(amount)
	amountComparison.AddChild(NewASTNode(KindExprLiteral))
	requireAmount.AddChild(amountComparison)
	unrelatedGuard.AddChild(requireAmount)

	modifierDecoy := &Function{
		Name: "modifierDecoy", Selector: "modifierDecoy(uint256)", ContractName: "Auth", SourceFile: file,
		Modifiers: []string{"onlyOwner"},
		Calls: []*FunctionCall{{
			Target: "onlyOwner", ResolvedFunction: "onlyOwner", ResolvedContractID: contractID,
			CallType: CallTypeModifier, Resolved: true, ArgCount: 1,
		}},
	}
	helperDecoy := &Function{
		Name: "helperDecoy", Selector: "helperDecoy()", ContractName: "Auth", SourceFile: file,
		Calls: []*FunctionCall{{
			Target: "_checkOwner", ResolvedFunction: "_checkOwner()",
			ResolvedContractID: contractID, CallType: CallTypeInternal, ArgCount: 0, Resolved: true,
		}},
	}
	emptyHelper := &Function{
		Name: "_checkOwner", Selector: "_checkOwner()", ContractName: "Auth", SourceFile: file,
		AST: NewASTNode(KindDeclFunction),
	}
	contract := &Contract{
		ID: contractID, Name: "Auth", SourceFile: file,
		LinearizedBases: []string{"Auth"}, LinearizedBaseIDs: []string{contractID},
		Functions: []*Function{modifierDecoy, helperDecoy, emptyHelper},
		Modifiers: []*Modifier{{
			Name: "onlyOwner", Parameters: []*Parameter{{Name: "amount", TypeName: "uint256"}}, AST: unrelatedGuard,
		}},
	}
	db := NewDatabase()
	db.AddContract(contract)

	if modifierDecoy.IsAccessControlled(db) {
		t.Fatal("auth-named modifier with unrelated require must not prove access control")
	}
	if helperDecoy.IsAccessControlled(db) {
		t.Fatal("empty auth-named helper must not prove access control")
	}
}

func TestIsAccessControlledRecursiveContextIsOrderIndependent(t *testing.T) {
	for _, forwardedFirst := range []bool{false, true} {
		name := "plain_then_forwarded"
		if forwardedFirst {
			name = "forwarded_then_plain"
		}
		t.Run(name, func(t *testing.T) {
			db, entry := recursiveCallerContextFixture(forwardedFirst)
			if !entry.IsAccessControlled(db) {
				t.Fatal("forwarded caller context must authorize regardless of call order")
			}
		})
	}
}

func TestIsAccessControlledRecursiveCyclesTerminate(t *testing.T) {
	t.Run("self recursive", func(t *testing.T) {
		file := "/exact/Self.sol"
		contractID := MakeContractID(file, "Self")
		fn := &Function{Name: "loop", Selector: "loop()", ContractName: "Self", SourceFile: file}
		fn.Calls = []*FunctionCall{{
			Target: "loop", ResolvedFunction: "loop()", ResolvedContractID: contractID,
			CallType: CallTypeInternal, Resolved: true, ArgCount: 0,
		}}
		contract := &Contract{
			ID: contractID, Name: "Self", SourceFile: file,
			LinearizedBases: []string{"Self"}, LinearizedBaseIDs: []string{contractID},
			Functions: []*Function{fn},
		}
		db := NewDatabase()
		db.AddContract(contract)
		if fn.IsAccessControlled(db) {
			t.Fatal("self-recursive function without a guard must not be controlled")
		}
	})

	t.Run("mutually recursive", func(t *testing.T) {
		file := "/exact/Mutual.sol"
		contractID := MakeContractID(file, "Mutual")
		a := &Function{Name: "a", Selector: "a()", ContractName: "Mutual", SourceFile: file}
		b := &Function{Name: "b", Selector: "b()", ContractName: "Mutual", SourceFile: file}
		a.Calls = []*FunctionCall{{
			Target: "b", ResolvedFunction: "b()", ResolvedContractID: contractID,
			CallType: CallTypeInternal, Resolved: true, ArgCount: 0,
		}}
		b.Calls = []*FunctionCall{{
			Target: "a", ResolvedFunction: "a()", ResolvedContractID: contractID,
			CallType: CallTypeInternal, Resolved: true, ArgCount: 0,
		}}
		contract := &Contract{
			ID: contractID, Name: "Mutual", SourceFile: file,
			LinearizedBases: []string{"Mutual"}, LinearizedBaseIDs: []string{contractID},
			Functions: []*Function{a, b},
		}
		db := NewDatabase()
		db.AddContract(contract)
		if a.IsAccessControlled(db) || b.IsAccessControlled(db) {
			t.Fatal("mutually recursive functions without guards must not be controlled")
		}
	})
}

func recursiveCallerContextFixture(forwardedFirst bool) (*Database, *Function) {
	file := "/exact/Forwarded.sol"
	contractID := MakeContractID(file, "Forwarded")

	gateRoot := NewASTNode(KindDeclFunction)
	require := NewASTNode(KindCheckRequire)
	comparison := NewASTNode(KindExprBinaryOp)
	comparison.SetAttribute("operator", "==")
	caller := NewASTNode(KindExprIdentifier)
	caller.Name = "caller"
	caller.RefKind = "parameter"
	owner := NewASTNode(KindExprIdentifier)
	owner.Name = "owner"
	owner.RefKind = "state_var"
	comparison.AddChild(caller)
	comparison.AddChild(owner)
	require.AddChild(comparison)
	gateRoot.AddChild(require)
	gate := &Function{
		Name: "gate", Selector: "gate(address)", ContractName: "Forwarded", SourceFile: file,
		Parameters: []*Parameter{{Name: "caller", TypeName: "address"}}, AST: gateRoot,
	}

	plainNode := NewASTNode(KindCallInternal)
	plainNode.Name = "plainGate"
	plainArg := NewASTNode(KindExprIdentifier)
	plainArg.Name = "user"
	plainArg.RefKind = "parameter"
	plainNode.AddChild(plainArg)
	forwardedNode := NewASTNode(KindCallInternal)
	forwardedNode.Name = "forwardedGate"
	forwardedNode.AddChild(testMsgSenderNode())
	entryRoot := NewASTNode(KindDeclFunction)
	entryRoot.AddChild(plainNode)
	entryRoot.AddChild(forwardedNode)

	plainCall := &FunctionCall{
		Target: "plainGate", ResolvedFunction: "gate(address)", ResolvedContractID: contractID,
		CallType: CallTypeInternal, ArgCount: 1, Resolved: true,
	}
	forwardedCall := &FunctionCall{
		Target: "forwardedGate", ResolvedFunction: "gate(address)", ResolvedContractID: contractID,
		CallType: CallTypeInternal, ArgCount: 1, Resolved: true,
	}
	calls := []*FunctionCall{plainCall, forwardedCall}
	if forwardedFirst {
		calls = []*FunctionCall{forwardedCall, plainCall}
	}
	entry := &Function{
		Name: "entry", Selector: "entry(address)", ContractName: "Forwarded", SourceFile: file,
		Parameters: []*Parameter{{Name: "user", TypeName: "address"}}, AST: entryRoot, Calls: calls,
	}
	contract := &Contract{
		ID: contractID, Name: "Forwarded", SourceFile: file,
		LinearizedBases: []string{"Forwarded"}, LinearizedBaseIDs: []string{contractID},
		Functions: []*Function{entry, gate},
	}
	db := NewDatabase()
	db.AddContract(contract)
	return db, entry
}

func testMsgSenderNode() *ASTNode {
	sender := NewASTNode(KindExprMemberAccess)
	sender.Name = "sender"
	msg := NewASTNode(KindExprIdentifier)
	msg.Name = "msg"
	sender.AddChild(msg)
	return sender
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
	binop.SetAttribute("operator", "==")

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

func TestSyntheticMsgSenderFallbackWithEmptyDatabase(t *testing.T) {
	fn, _ := syntheticMsgSenderGuardFunction()
	assertCallerIdentityAnalyses(t, fn, NewDatabase(), true)
}

func TestSyntheticMsgSenderFallbackIgnoresMismatchedFileOwner(t *testing.T) {
	fn, _ := syntheticMsgSenderGuardFunction()
	otherFile := "/other/SyntheticGuard.sol"
	other := &Contract{
		ID:         MakeContractID(otherFile, fn.ContractName),
		Name:       fn.ContractName,
		SourceFile: otherFile,
		Functions:  []*Function{{Name: "unrelated", ContractName: fn.ContractName, SourceFile: otherFile}},
	}
	db := NewDatabase()
	db.AddContract(other)

	assertCallerIdentityAnalyses(t, fn, db, true)
}

func TestSyntheticMsgSenderMetadataDisproof(t *testing.T) {
	for _, tc := range []struct {
		name string
		call *FunctionCall
	}{
		{
			name: "external call",
			call: &FunctionCall{
				Target: "_msgSender", CallType: CallTypeExternal,
				ResolvedFunction: "_msgSender()", ArgCount: 0,
			},
		},
		{
			name: "self call",
			call: &FunctionCall{
				Target: "_msgSender", CallType: CallTypeSelf,
				ResolvedFunction: "_msgSender()", ArgCount: 0,
			},
		},
		{
			name: "wrong selector",
			call: &FunctionCall{
				Target: "_msgSender", CallType: CallTypeInternal,
				ResolvedFunction: "_msgSender(address)", ArgCount: 0,
			},
		},
		{
			name: "nonzero arity",
			call: &FunctionCall{
				Target: "_msgSender", CallType: CallTypeInternal,
				ResolvedFunction: "_msgSender()", ArgCount: 1,
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fn, callNode := syntheticMsgSenderGuardFunction()
			tc.call.Line = callNode.StartLine
			tc.call.Byte = callNode.StartByte
			fn.Calls = []*FunctionCall{tc.call}
			assertCallerIdentityAnalyses(t, fn, NewDatabase(), false)
		})
	}
}

func TestSyntheticMsgSenderDatabaseDisproof(t *testing.T) {
	for _, tc := range []struct {
		name   string
		helper *Function
	}{
		{name: "no helper"},
		{
			name: "nonzero overload only",
			helper: &Function{
				Name: "_msgSender", Selector: "_msgSender(address)",
				Parameters: []*Parameter{{Name: "forwarder", TypeName: "address"}},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fn, _ := syntheticMsgSenderGuardFunction()
			id := MakeContractID(fn.SourceFile, fn.ContractName)
			functions := []*Function{fn}
			if tc.helper != nil {
				tc.helper.ContractName = fn.ContractName
				tc.helper.SourceFile = fn.SourceFile
				functions = append(functions, tc.helper)
			}
			contract := &Contract{
				ID: id, Name: fn.ContractName, SourceFile: fn.SourceFile,
				LinearizedBases: []string{fn.ContractName}, LinearizedBaseIDs: []string{id},
				Functions: functions,
			}
			db := NewDatabase()
			db.AddContract(contract)
			assertCallerIdentityAnalyses(t, fn, db, false)
		})
	}
}

func syntheticMsgSenderGuardFunction() (*Function, *ASTNode) {
	root := NewASTNode(KindDeclFunction)
	require := NewASTNode(KindCheckRequire)
	comparison := NewASTNode(KindExprBinaryOp)
	comparison.SetAttribute("operator", "==")
	owner := NewASTNode(KindExprIdentifier)
	owner.Name = "owner"
	owner.RefKind = "state_var"
	msgSender := NewASTNode(KindCallInternal)
	msgSender.Name = "_msgSender"
	msgSender.StartLine = 3
	msgSender.StartByte = 24

	comparison.AddChild(owner)
	comparison.AddChild(msgSender)
	require.AddChild(comparison)
	root.AddChild(require)

	return &Function{
		Name: "guarded", ContractName: "SyntheticGuard", SourceFile: "/virtual/SyntheticGuard.sol",
		Visibility: VisibilityExternal, AST: root,
	}, msgSender
}

func assertCallerIdentityAnalyses(t *testing.T, fn *Function, db *Database, want bool) {
	t.Helper()
	if got := fn.IsAccessControlled(db); got != want {
		t.Errorf("IsAccessControlled = %v, want %v", got, want)
	}
	if got := fn.ComparesCallerIdentity(db); got != want {
		t.Errorf("ComparesCallerIdentity = %v, want %v", got, want)
	}
}

func TestComparesCallerIdentityNoDatabaseCompatibility(t *testing.T) {
	root := NewASTNode(KindDeclFunction)
	require := NewASTNode(KindCheckRequire)
	comparison := NewASTNode(KindExprBinaryOp)
	comparison.SetAttribute("operator", "==")
	parameter := NewASTNode(KindExprIdentifier)
	parameter.Name = "from"
	parameter.RefKind = "parameter"
	caller := NewASTNode(KindExprMemberAccess)
	caller.Name = "sender"
	msg := NewASTNode(KindExprIdentifier)
	msg.Name = "msg"
	caller.AddChild(msg)
	comparison.AddChild(parameter)
	comparison.AddChild(caller)
	require.AddChild(comparison)
	root.AddChild(require)

	fn := &Function{Name: "scoped", ContractName: "Compat", AST: root}
	if !fn.ComparesCallerIdentity() {
		t.Fatal("no-argument ComparesCallerIdentity must preserve local caller comparison analysis")
	}
	if !fn.ComparesCallerIdentity(NewDatabase()) {
		t.Fatal("database-aware ComparesCallerIdentity must remain callable")
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
	binop.SetAttribute("operator", "==")

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
	binop.SetAttribute("operator", "==")

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
// (the canonical caller_checked preset) treat it as a valid mitigation.
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
			ResolvedFunction: "_withdraw(address,uint256,address)",
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
