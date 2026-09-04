package engine

import (
	"strings"
	"testing"
)

func TestSemanticWrapperAuthorizationLowersImplicitAllPathProof(t *testing.T) {
	raw := "meta: {id: FRIENDLY-AUTH, severity: HIGH}\nquery:\n  select: function\n  from: entry_function\n  where:\n    - authorization:\n        expected_principal: [pool, pair]\n"
	tmpl, err := ParseTemplate(raw)
	if err != nil {
		t.Fatalf("ParseTemplate: %v", err)
	}
	filter := tmpl.Query.Filter
	if filter == nil || filter.Attr == nil {
		t.Fatalf("filter=%#v, want context attributes", filter)
	}
	want := map[string]interface{}{
		"auth_verdict":            "protected",
		"auth_principal":          "expected_external",
		"auth_expected_principal": "^(?:pool|pair)$",
		"auth_dominates":          "dominates",
	}
	for key, value := range want {
		if got := filter.Attr[key]; got != value {
			t.Errorf("filter.Attr[%q]=%#v, want %#v", key, got, value)
		}
	}
}

func TestSemanticWrapperAuthorizationRejectsDominatesField(t *testing.T) {
	raw := "meta: {id: FRIENDLY-AUTH-INVALID, severity: HIGH}\nquery:\n  select: function\n  from: entry_function\n  where:\n    - authorization:\n        expected_principal: pool\n        dominates: true\n"
	_, err := ParseTemplate(raw)
	if err == nil || !strings.Contains(err.Error(), "all-path coverage is implicit") {
		t.Fatalf("err=%v, want implicit dominance diagnostic", err)
	}
}

func TestSemanticWrapperAuthorizationRejectsFalseProof(t *testing.T) {
	raw := "meta: {id: FRIENDLY-AUTH-FALSE, severity: HIGH}\nquery:\n  select: function\n  from: entry_function\n  where:\n    - authorization: {protected: false}\n"
	_, err := ParseTemplate(raw)
	if err == nil || !strings.Contains(err.Error(), "only true is meaningful") {
		t.Fatalf("err=%v, want positive-proof diagnostic", err)
	}
}

func TestSemanticWrapperInitializerAndRuntimeLower(t *testing.T) {
	raw := "meta: {id: FRIENDLY-LIFECYCLE, severity: HIGH}\nquery:\n  select: function\n  from: entry_function\n  where:\n    - initializer:\n        entry: true\n        takeover: [possible, unknown]\n        atomic: after_guard\n    - runtime:\n        authorization: protected\n        dispatch: [virtual, super]\n"
	tmpl, err := ParseTemplate(raw)
	if err != nil {
		t.Fatalf("ParseTemplate: %v", err)
	}
	attrs := tmpl.Query.Filter.Attr
	for _, key := range []string{"initializer_entry", "first_call_takeover", "atomic_initialization", "auth_verdict", "auth_reason"} {
		if attrs[key] == nil {
			t.Errorf("missing attr %q", key)
		}
	}
}
