package engine

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/th13vn/w3goaudit/pkg/types"
)

func TestAuthorizationAttributesWorkAsFunctionFilters(t *testing.T) {
	tmpl, err := ParseTemplate(`meta: {id: AUTH-FILTER, severity: HIGH}
query:
  select: function
  from: entry_function
  where:
    - func_name: ^receiveResult$
    - attr:
        auth_verdict: protected
        auth_principal: expected_external
        auth_dominates: dominates`)
	if err != nil {
		t.Fatalf("parse semantic filter: %v", err)
	}
	db := buildDBFromSource(t, `pragma solidity ^0.8.20; contract C { address peer; function receiveResult() external { require(msg.sender == peer); } }`).GetDatabase()
	findings := New(db).Execute(tmpl)
	if len(findings) != 1 || findings[0].Location.Function != "receiveResult" {
		t.Fatalf("semantic filter findings = %+v", findings)
	}
}

func TestAuthorizationAttributesFailClosedForUnknownAndLegacyFacts(t *testing.T) {
	tmpl, err := ParseTemplate(`meta: {id: AUTH-FILTER, severity: HIGH}
query:
  select: function
  from: entry_function
  where:
    - attr: {auth_verdict: protected}`)
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

func TestAuthorizationAttributesPreserveSourceCacheExecutionParity(t *testing.T) {
	tmpl, err := ParseTemplate(`meta: {id: AUTH-FILTER, severity: HIGH}
query:
  select: function
  from: entry_function
  where:
    - attr: {auth_principal: expected_external}`)
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

func TestAuthorizationExpectedPrincipalAttributesMatchExactEvidence(t *testing.T) {
	tmpl, err := ParseTemplate(`meta: {id: AUTH-EXPECTED, severity: HIGH}
query:
  select: function
  from: entry_function
  where:
    - attr:
        auth_expected_principal: '^pool$'
        auth_expected_principal_ref: '.*#ExternalPrincipal\.pool$'`)
	if err != nil {
		t.Fatal(err)
	}
	db := buildDBFromSource(t, `pragma solidity ^0.8.20; contract ExternalPrincipal { address pool; function receiveResult() external { require(msg.sender == pool); } function ownerResult() external { require(msg.sender == address(0x1234)); } }`).GetDatabase()
	findings := New(db).Execute(tmpl)
	if len(findings) != 1 || findings[0].Location.Function != "receiveResult" {
		t.Fatalf("expected-principal filter findings = %+v", findings)
	}
}

func TestInitializerLifecycleAttributesWorkAsFunctionFilters(t *testing.T) {
	tmpl, err := ParseTemplate(`meta: {id: LIFECYCLE-FILTER, severity: HIGH}
query:
  select: function
  from: entry_function
  where:
    - attr:
        initializer_entry: true
        one_time_mutex: true
        first_call_takeover: unknown
        atomic_initialization: after_guard
        constructor_disable: false
        proxy_linkage: unknown`)
	if err != nil {
		t.Fatal(err)
	}
	db := buildDBFromSource(t, `pragma solidity ^0.8.20; contract C { bool initialized; address owner; function initialize(address who) external { require(!initialized); initialized = true; owner = who; } }`).GetDatabase()
	findings := New(db).Execute(tmpl)
	if len(findings) != 1 || findings[0].Location.Function != "initialize" {
		t.Fatalf("lifecycle filter findings = %+v", findings)
	}
}
