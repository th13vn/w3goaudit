package engine

import (
	"strings"
	"testing"
)

func TestSemanticPresetAuthorizationLowersDirectPredicate(t *testing.T) {
	tmpl, err := ParseTemplate(`meta: {id: PRESET-AUTH, severity: HIGH}
query:
  select: function
  from: entry_function
  where:
    - preset:
        authorization:
          type: protected
          principal: [" pool ", pair, pool]
`)
	if err != nil {
		t.Fatalf("ParseTemplate: %v", err)
	}
	filter := tmpl.Query.Filter
	if filter == nil || filter.Authorization == nil {
		t.Fatalf("filter=%#v, want direct authorization predicate", filter)
	}
	got := filter.Authorization
	if got.Type != "protected" {
		t.Fatalf("authorization type=%q, want protected", got.Type)
	}
	want := []string{"pair", "pool"}
	if len(got.Principals) != len(want) || got.Principals[0] != want[0] || got.Principals[1] != want[1] {
		t.Fatalf("principals=%v, want sorted deduplicated %v", got.Principals, want)
	}
	if len(filter.Attr) != 0 {
		t.Fatalf("direct preset unexpectedly lowered to attrs: %#v", filter.Attr)
	}
}

func TestSemanticPresetAuthorizationSupportsSelfSenderAndRegex(t *testing.T) {
	self, err := ParseTemplate(`meta: {id: PRESET-SELF, severity: HIGH}
query:
  select: function
  from: entry_function
  where:
    - preset: {authorization: {type: self_sender}}
`)
	if err != nil {
		t.Fatalf("self_sender parse: %v", err)
	}
	if self.Query.Filter == nil || self.Query.Filter.Authorization == nil || self.Query.Filter.Authorization.Type != "self_sender" {
		t.Fatalf("self_sender filter=%#v", self.Query.Filter)
	}
	regex, err := ParseTemplate(`meta: {id: PRESET-REGEX, severity: HIGH}
query:
  select: function
  from: entry_function
  where:
    - preset:
        authorization:
          type: protected
          principal: {regex: "(?i)^(pool|pair)$"}
`)
	if err != nil {
		t.Fatalf("regex parse: %v", err)
	}
	if got := regex.Query.Filter.Authorization.PrincipalRegex; got != "(?i)^(pool|pair)$" {
		t.Fatalf("principal regex=%q", got)
	}
}

func TestSemanticPresetAuthorizationExecutesSelfSenderAndPrincipalAlternatives(t *testing.T) {
	db := buildDBFromSource(t, `pragma solidity ^0.8.20; contract C { address owner; function own(address who) external { require(msg.sender == who); } function admin() external { require(msg.sender == owner); } }`).GetDatabase()
	self, err := ParseTemplate(`meta: {id: PRESET-SELF-EXEC, severity: HIGH}
query:
  select: function
  from: entry_function
  where:
    - preset: {authorization: {type: self_sender}}
`)
	if err != nil {
		t.Fatal(err)
	}
	findings := New(db).Execute(self)
	if len(findings) != 1 || findings[0].Location.Function != "own" {
		t.Fatalf("self_sender findings=%+v", findings)
	}
	protected, err := ParseTemplate(`meta: {id: PRESET-PROTECTED-EXEC, severity: HIGH}
query:
  select: function
  from: entry_function
  where:
    - preset:
        authorization:
          type: protected
          principal: [owner, pair, pool]
`)
	if err != nil {
		t.Fatal(err)
	}
	findings = New(db).Execute(protected)
	if len(findings) != 1 || findings[0].Location.Function != "admin" {
		t.Fatalf("protected findings=%+v", findings)
	}
}

func TestSemanticPresetInitializerUsesFunctionNameAndTakeover(t *testing.T) {
	tmpl, err := ParseTemplate(`meta: {id: PRESET-INIT, severity: HIGH}
query:
  select: function
  from: entry_function
  where:
    - func_name: '(?i)^(initialize|init)$'
    - preset: {initializer: {takeover: possible}}
`)
	if err != nil {
		t.Fatalf("ParseTemplate: %v", err)
	}
	filter := tmpl.Query.Filter
	if filter == nil || filter.Initializer == nil || filter.Initializer.Takeover != "possible" {
		t.Fatalf("initializer filter=%#v", filter)
	}
	if filter.FuncName == "" {
		t.Fatal("func_name was not retained")
	}
}

func TestSemanticPresetRejectsLegacyWrappersRuntimeAndUnknownValues(t *testing.T) {
	cases := []string{
		`- authorization: {protected: true}`,
		`- initializer: {takeover: possible}`,
		`- runtime: {authorization: protected}`,
		`- preset: {runtime: {dispatch: virtual}}`,
		`- preset: {authorization: {type: unknown}}`,
		`- preset: {initializer: {takeover: unknown}}`,
	}
	for i, matcher := range cases {
		t.Run(string(rune('a'+i)), func(t *testing.T) {
			raw := "meta: {id: PRESET-INVALID, severity: HIGH}\nquery:\n  select: function\n  from: entry_function\n  where:\n    " + matcher + "\n"
			if _, err := ParseTemplate(raw); err == nil {
				t.Fatalf("invalid syntax loaded: %s", matcher)
			}
		})
	}
}

func TestSemanticPresetRejectsSelfSenderPrincipalAndInvalidPrincipal(t *testing.T) {
	cases := []string{
		`{type: self_sender, principal: owner}`,
		`{type: protected, principal: []}`,
		`{type: protected, principal: {regex: "["}}`,
	}
	for _, authorization := range cases {
		t.Run(strings.ReplaceAll(authorization, " ", "_"), func(t *testing.T) {
			raw := "meta: {id: PRESET-INVALID-AUTH, severity: HIGH}\nquery:\n  select: function\n  from: entry_function\n  where:\n    - preset: {authorization: " + authorization + "}\n"
			if _, err := ParseTemplate(raw); err == nil {
				t.Fatalf("invalid authorization loaded: %s", authorization)
			}
		})
	}
}

func TestLegacyScalarPresetsRemainValid(t *testing.T) {
	if _, err := ParseTemplate(`meta: {id: PRESET-LEGACY, severity: INFO}
query:
  select: function
  from: entry_function
  where:
    - not: {preset: access_controlled}
`); err != nil {
		t.Fatalf("legacy scalar preset rejected: %v", err)
	}
}

func TestProgrammaticSemanticAttributesAreNotEvaluatorPredicates(t *testing.T) {
	raw := Rule{Attr: map[string]interface{}{"auth_verdict": "protected"}}
	fields := presentRuleFields(&raw)
	if len(fields) != 1 || fields[0].name != "attr" || fields[0].class != classAST {
		t.Fatalf("raw semantic attr fields=%+v, want ordinary AST attribute", fields)
	}
}
