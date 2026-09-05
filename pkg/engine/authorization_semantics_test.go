package engine

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/th13vn/w3goaudit/pkg/types"
)

func TestAuthorizationPresetWorksAsFunctionFilter(t *testing.T) {
	tmpl, err := ParseTemplate(`meta: {id: AUTH-FILTER, severity: HIGH}
query:
  select: function
  from: entry_function
  where:
    - func_name: ^receiveResult$
    - preset:
        authorization:
          type: protected
          principal: peer`)
	if err != nil {
		t.Fatalf("parse semantic filter: %v", err)
	}
	db := buildDBFromSource(t, `pragma solidity ^0.8.20; contract C { address peer; function receiveResult() external { require(msg.sender == peer); } }`).GetDatabase()
	findings := New(db).Execute(tmpl)
	if len(findings) != 1 || findings[0].Location.Function != "receiveResult" {
		t.Fatalf("semantic filter findings = %+v", findings)
	}
}

func TestAuthorizationPresetFailsClosedForUnknownAndLegacyFacts(t *testing.T) {
	tmpl, err := ParseTemplate(`meta: {id: AUTH-FILTER, severity: HIGH}
query:
  select: function
  from: entry_function
  where:
    - preset: {authorization: {type: protected}}`)
	if err != nil {
		t.Fatal(err)
	}
	db := buildDBFromSource(t, `pragma solidity ^0.8.20; contract C { address owner; uint x; function run() external { x = 1; require(msg.sender == owner); } }`).GetDatabase()
	if findings := New(db).Execute(tmpl); len(findings) != 0 {
		t.Fatalf("unknown authorization matched positive safety filter: %+v", findings)
	}
	db.Semantics.AuthorizationFactsVersion = ""
	if findings := New(db).Execute(tmpl); len(findings) != 0 {
		t.Fatalf("legacy authorization matched positive safety filter: %+v", findings)
	}
}

func TestNegatedAuthorizationPresetFailsClosedWhenFactsUnavailable(t *testing.T) {
	tmpl, err := ParseTemplate("meta: {id: AUTH-NEGATED, severity: HIGH}\nquery:\n  select: function\n  from: entry_function\n  where:\n    - not:\n        preset:\n          authorization:\n            type: protected")
	if err != nil {
		t.Fatal(err)
	}
	db := buildDBFromSource(t, "pragma solidity ^0.8.20; contract C { function run(address payable to) external { to.transfer(1); } }").GetDatabase()
	db.Semantics.AuthorizationFactsVersion = ""
	if findings := New(db).Execute(tmpl); len(findings) != 0 {
		t.Fatalf("negated authorization treated unavailable facts as unprotected: %+v", findings)
	}
}

func TestNegatedAuthorizationPresetComposesWithOtherContextPredicates(t *testing.T) {
	tmpl, err := ParseTemplate(`meta: {id: AUTH-NEGATED-COMPOSED, severity: HIGH}
query:
  select: function
  from: entry_function
  where:
    - not:
        preset:
          authorization:
            type: protected
        visibility: external`)
	if err != nil {
		t.Fatal(err)
	}
	db := buildDBFromSource(t, "pragma solidity ^0.8.20; contract C { function run() external {} }").GetDatabase()
	if findings := New(db).Execute(tmpl); len(findings) != 1 {
		t.Fatalf("not(protected and external) findings = %d, want 1: %+v", len(findings), findings)
	}
}

func TestAuthorizationPresetPreservesSourceCacheExecutionParity(t *testing.T) {
	tmpl, err := ParseTemplate(`meta: {id: AUTH-FILTER, severity: HIGH}
query:
  select: function
  from: entry_function
  where:
    - preset: {authorization: {type: protected, principal: peer}}`)
	if err != nil {
		t.Fatal(err)
	}
	db := buildDBFromSource(t, `pragma solidity ^0.8.20; contract C { address peer; function receiveResult() external { require(msg.sender == peer); } }`).GetDatabase()
	want, _ := json.Marshal(New(db).Execute(tmpl))
	raw, err := json.Marshal(db)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "db.json")
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	loaded, err := types.LoadFromJSON(path)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := json.Marshal(New(loaded).Execute(tmpl))
	if string(got) != string(want) {
		t.Fatalf("source/cache semantic execution mismatch\nsource=%s\ncache=%s", want, got)
	}
}

func TestAuthorizationPresetMatchesExactPrincipalEvidence(t *testing.T) {
	tmpl, err := ParseTemplate(`meta: {id: AUTH-EXPECTED, severity: HIGH}
query:
  select: function
  from: entry_function
  where:
    - preset:
        authorization:
          type: protected
          principal: pool`)
	if err != nil {
		t.Fatal(err)
	}
	db := buildDBFromSource(t, `pragma solidity ^0.8.20; contract ExternalPrincipal { address pool; function receiveResult() external { require(msg.sender == pool); } function ownerResult() external { require(msg.sender == address(0x1234)); } }`).GetDatabase()
	findings := New(db).Execute(tmpl)
	if len(findings) != 1 || findings[0].Location.Function != "receiveResult" {
		t.Fatalf("expected-principal filter findings = %+v", findings)
	}
}

func TestInitializerPresetWorksAsFunctionFilter(t *testing.T) {
	tmpl, err := ParseTemplate(`meta: {id: LIFECYCLE-FILTER, severity: HIGH}
query:
  select: function
  from: entry_function
  where:
    - func_name: '^initialize$'
    - preset: {initializer: {takeover: possible}}`)
	if err != nil {
		t.Fatal(err)
	}
	db := buildDBFromSource(t, `pragma solidity ^0.8.20; contract C { address owner; function initialize(address who) external { owner = who; } }`).GetDatabase()
	findings := New(db).Execute(tmpl)
	if len(findings) != 1 || findings[0].Location.Function != "initialize" {
		t.Fatalf("lifecycle filter findings = %+v", findings)
	}
}
