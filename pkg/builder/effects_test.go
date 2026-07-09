package builder

import (
	"testing"

	"github.com/th13vn/w3goaudit/pkg/types"
)

// buildFromSource is a small helper: parse+build a database from one source.
func buildFromSource(t *testing.T, src string) *types.Database {
	t.Helper()
	db, err := New().Build([]*types.SourceFile{{Path: "/tmp/T.sol", Content: src}})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	return db
}

func effectsOf(db *types.Database, contract, selector string) *types.FunctionEffects {
	id := types.MakeFunctionID("/tmp/T.sol", contract, selector)
	return db.Semantics.GetFunctionEffects(id)
}

func TestEffectsStateWritesAndGuards(t *testing.T) {
	src := `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract Vault {
    address owner;
    mapping(address => uint256) balances;

    function setOwner(address o) external {
        require(msg.sender == owner, "not owner");
        owner = o;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }
}`
	db := buildFromSource(t, src)

	// setOwner: writes `owner`, has a require with msg.sender, so it's controlled.
	fe := effectsOf(db, "Vault", "setOwner(address)")
	if fe == nil {
		t.Fatal("no effects for setOwner")
	}
	if !hasWrite(fe, "owner") {
		t.Errorf("setOwner should write owner; writes=%v", fe.StateWrites)
	}
	if len(fe.Guards) == 0 {
		t.Error("setOwner should have a require guard")
	}
	if !fe.Auth.Controlled || len(fe.Auth.SenderChecks) == 0 {
		t.Errorf("setOwner should be access-controlled via msg.sender; auth=%+v", fe.Auth)
	}

	// deposit: writes `balances` via compound assignment; unprotected.
	fd := effectsOf(db, "Vault", "deposit()")
	if fd == nil {
		t.Fatal("no effects for deposit")
	}
	if !hasWrite(fd, "balances") {
		t.Errorf("deposit should write balances; writes=%v", fd.StateWrites)
	}
	if fd.Auth.Controlled {
		t.Error("deposit should be unprotected")
	}
}

func TestStateWriteAndGuardHaveLines(t *testing.T) {
	src := `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract Vault {
    address owner;
    mapping(address => uint256) balances;

    function setOwner(address o) external {
        require(msg.sender == owner, "not owner");
        owner = o;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }
}`
	db := buildFromSource(t, src)

	fe := effectsOf(db, "Vault", "setOwner(address)")
	if fe == nil {
		t.Fatal("no effects for setOwner")
	}
	if len(fe.StateWrites) == 0 {
		t.Fatal("expected setOwner to have state writes")
	}
	for _, w := range fe.StateWrites {
		if w.Line == 0 {
			t.Errorf("state write %q has Line == 0 (should be populated now)", w.Var)
		}
	}
	if len(fe.Guards) == 0 {
		t.Fatal("expected setOwner to have guards")
	}
	for _, g := range fe.Guards {
		if g.Line == 0 {
			t.Errorf("guard %q has Line == 0", g.Expr)
		}
	}
}

func hasWrite(fe *types.FunctionEffects, v string) bool {
	for _, w := range fe.StateWrites {
		if w.Var == v {
			return true
		}
	}
	return false
}
