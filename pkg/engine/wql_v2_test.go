package engine

import (
	"strings"
	"testing"
)

const v2DelegatecallYAML = `
meta: { id: delegatecall-user-input, severity: CRITICAL, title: Delegatecall to user-controlled target }
query:
  select: delegatecall
  from: entry_function
  where:
    - arg.0: { tainted: parameter }
    - not: { preset: access_controlled }
`

const v2ComboSelectYAML = `
meta: { id: multicall-msgvalue, severity: HIGH, title: msg.value reuse across multicall }
query:
  select: [delegatecall, external_call]
  from: main_contract
  where:
    - block: function
`

const missingSelectAndFromYAML = `
meta:
  id: incomplete-template
  severity: LOW
query:
  where:
    - block: delegatecall
`

const missingQueryYAML = `
meta:
  id: no-query-template
  severity: LOW
`

func TestParseV2_ScalarSelect(t *testing.T) {
	doc, err := parseV2([]byte(v2DelegatecallYAML))
	if err != nil {
		t.Fatalf("parseV2 returned error: %v", err)
	}

	if doc.Meta.ID != "delegatecall-user-input" {
		t.Errorf("Meta.ID = %q, want %q", doc.Meta.ID, "delegatecall-user-input")
	}

	q := doc.Query
	if q == nil {
		t.Fatalf("Query = nil, want a query")
	}
	if q.Select != "delegatecall" {
		t.Errorf("Select = %q, want %q", q.Select, "delegatecall")
	}

	if q.From != "entry_function" {
		t.Errorf("From = %q, want %q", q.From, "entry_function")
	}

	if len(q.Where) != 2 {
		t.Fatalf("len(Where) = %d, want 2", len(q.Where))
	}

	key, _, ok := q.Where[0].key()
	if !ok {
		t.Fatalf("Where[0].key() ok = false, want true")
	}
	if key != "arg.0" {
		t.Errorf("Where[0] key = %q, want %q", key, "arg.0")
	}
}

func TestParseV2RejectsListSelect(t *testing.T) {
	_, err := parseV2([]byte(v2ComboSelectYAML))
	if err == nil || !strings.Contains(err.Error(), "select must be a scalar block kind") {
		t.Fatalf("error = %v", err)
	}
}

func TestLowerErrorOnMissingSelectAndFrom(t *testing.T) {
	doc, err := parseV2([]byte(missingSelectAndFromYAML))
	if err != nil {
		t.Fatalf("parseV2 returned error: %v", err)
	}
	if _, err := doc.lower(); err == nil || !strings.Contains(err.Error(), "neither select nor from") {
		t.Fatalf("lower error = %v, want neither-select-nor-from error", err)
	}
}

func TestParseV2_ErrorOnMissingQuery(t *testing.T) {
	_, err := parseV2([]byte(missingQueryYAML))
	if err == nil || !strings.Contains(err.Error(), "no query:") {
		t.Fatalf("error = %v, want missing-query error", err)
	}
}

func TestMatcherV2Key(t *testing.T) {
	doc, err := parseV2([]byte(v2DelegatecallYAML))
	if err != nil {
		t.Fatalf("parseV2 returned error: %v", err)
	}

	key, _, ok := doc.Query.Where[1].key()
	if !ok {
		t.Fatalf("Where[1].key() ok = false, want true")
	}
	if key != "not" {
		t.Errorf("Where[1] key = %q, want %q", key, "not")
	}

	// Empty matcher map should report ok=false.
	empty := MatcherV2{}
	if _, _, ok := empty.key(); ok {
		t.Errorf("empty MatcherV2.key() ok = true, want false")
	}

	// Multi-key matcher map should report ok=false.
	multi := MatcherV2{"a": {}, "b": {}}
	if _, _, ok := multi.key(); ok {
		t.Errorf("multi-key MatcherV2.key() ok = true, want false")
	}
}

func TestMatcherV2CompilesNestedArgN(t *testing.T) {
	cases := []struct {
		name  string
		where string
		index int
	}{
		{name: "top level", where: `- arg.0: {tainted: parameter}`, index: 0},
		{name: "has", where: `- has: {block: external_call, arg.1: {tainted: parameter}}`, index: 1},
		{name: "sequence", where: `- sequence: [{block: external_call, arg.2: {tainted: parameter}}]`, index: 2},
		{name: "all", where: `- all: [{block: external_call, arg.3: {tainted: parameter}}]`, index: 3},
		{name: "any", where: `- any: [{block: external_call, arg.4: {tainted: parameter}}]`, index: 4},
		{name: "not", where: `- not: {block: external_call, arg.5: {tainted: parameter}}`, index: 5},
		{name: "nested argument", where: `- arg.0: {arg.6: {tainted: parameter}}`, index: 6},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc, err := parseV2([]byte("meta: {id: nested-arg, severity: HIGH}\nquery:\n  select: external_call\n  from: entry_function\n  where:\n    " + tc.where + "\n"))
			if err != nil {
				t.Fatalf("parseV2 returned error: %v", err)
			}
			tmpl, err := doc.lower()
			if err != nil {
				t.Fatalf("lower returned error: %v", err)
			}
			arg, ok := findArgRule(&tmpl.Query.Match, tc.index)
			if !ok {
				t.Fatalf("arg.%d was not compiled into Rule.Args: %#v", tc.index, tmpl.Query.Match)
			}
			if arg.TaintedFrom != "parameter" {
				t.Fatalf("arg.%d = %#v, want tainted_from=parameter", tc.index, arg)
			}
		})
	}
}

func findArgRule(rule *Rule, index int) (Rule, bool) {
	if rule == nil {
		return Rule{}, false
	}
	if arg, ok := rule.Args[index]; ok {
		return arg, true
	}
	children := []*Rule{rule.Not, rule.Contains, rule.Inside, rule.Left, rule.Right, rule.HasGuard, rule.StatementContains, rule.ArgAny}
	for _, child := range children {
		if arg, ok := findArgRule(child, index); ok {
			return arg, true
		}
	}
	for i := range rule.All {
		if arg, ok := findArgRule(&rule.All[i], index); ok {
			return arg, true
		}
	}
	for i := range rule.Any {
		if arg, ok := findArgRule(&rule.Any[i], index); ok {
			return arg, true
		}
	}
	for i := range rule.Sequence {
		if arg, ok := findArgRule(&rule.Sequence[i], index); ok {
			return arg, true
		}
	}
	for _, arg := range rule.Args {
		argCopy := arg
		if nested, ok := findArgRule(&argCopy, index); ok {
			return nested, true
		}
	}
	return Rule{}, false
}
