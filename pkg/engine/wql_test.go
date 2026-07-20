package engine

import (
	"strings"
	"testing"
)

const delegatecallWQL = `
meta: { id: delegatecall-user-input, severity: CRITICAL, title: Delegatecall to user-controlled target }
query:
  select: delegatecall
  from: entry_function
  where:
    - arg.0: { tainted: parameter }
    - not: { preset: access_controlled }
`

const comboSelectWQL = `
meta: { id: multicall-msgvalue, severity: HIGH, title: msg.value reuse across multicall }
query:
  select: [delegatecall, external_call]
  from: main_contract
  where:
    - block: function
`

const missingSelectFromAndWhereYAML = `
meta:
  id: incomplete-template
  severity: LOW
query: {}
`

const missingQueryYAML = `
meta:
  id: no-query-template
  severity: LOW
`

func TestParseWQL_ScalarSelect(t *testing.T) {
	doc, err := parseWQL([]byte(delegatecallWQL))
	if err != nil {
		t.Fatalf("parseWQL returned error: %v", err)
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

func TestParseWQLRejectsListSelect(t *testing.T) {
	_, err := parseWQL([]byte(comboSelectWQL))
	if err == nil || !strings.Contains(err.Error(), "select must be a scalar block kind") {
		t.Fatalf("error = %v", err)
	}
}

func TestParseWQLRejectsPublicAllMatcher(t *testing.T) {
	_, err := ParseTemplate(`
meta: {id: T, severity: HIGH}
query:
  select: external_call
  where:
    - all: [{name: transfer}, {arg.0: {tainted: parameter}}]
`)
	if err == nil || !strings.Contains(err.Error(), `unknown matcher key "all"`) {
		t.Fatalf("error = %v, want canonical and: rejection", err)
	}
}

func TestParseTemplateRejectsLegacyRuleKeys(t *testing.T) {
	for _, key := range []string{"source_regex", "visibility_filter", "mutability_filter"} {
		t.Run(key, func(t *testing.T) {
			_, err := ParseTemplate("meta: {id: legacy-key, severity: HIGH}\nquery:\n  select: external_call\n  from: entry_function\n  where:\n    - " + key + ": public\n")
			if err == nil || !strings.Contains(err.Error(), `unknown matcher key "`+key+`"`) {
				t.Fatalf("error = %v, want strict rejection of legacy WQL key %q", err, key)
			}
		})
	}
}

func TestLowerErrorOnMissingSelectFromAndWhere(t *testing.T) {
	doc, err := parseWQL([]byte(missingSelectFromAndWhereYAML))
	if err != nil {
		t.Fatalf("parseWQL returned error: %v", err)
	}
	if _, err := doc.lower(); err == nil || !strings.Contains(err.Error(), "neither select, from, nor where") {
		t.Fatalf("lower error = %v, want neither-select-from-nor-where error", err)
	}
}

func TestParseWQL_ErrorOnMissingQuery(t *testing.T) {
	_, err := parseWQL([]byte(missingQueryYAML))
	if err == nil || !strings.Contains(err.Error(), "no query:") {
		t.Fatalf("error = %v, want missing-query error", err)
	}
}

func TestMatcherKey(t *testing.T) {
	doc, err := parseWQL([]byte(delegatecallWQL))
	if err != nil {
		t.Fatalf("parseWQL returned error: %v", err)
	}

	key, _, ok := doc.Query.Where[1].key()
	if !ok {
		t.Fatalf("Where[1].key() ok = false, want true")
	}
	if key != "not" {
		t.Errorf("Where[1] key = %q, want %q", key, "not")
	}

	// Empty matcher map should report ok=false.
	empty := Matcher{}
	if _, _, ok := empty.key(); ok {
		t.Errorf("empty Matcher.key() ok = true, want false")
	}

	// Multi-key matcher map should report ok=false.
	multi := Matcher{"a": {}, "b": {}}
	if _, _, ok := multi.key(); ok {
		t.Errorf("multi-key Matcher.key() ok = true, want false")
	}
}

func TestMatcherCompilesNestedArgN(t *testing.T) {
	cases := []struct {
		name  string
		where string
		index int
	}{
		{name: "top level", where: `- arg.0: {tainted: parameter}`, index: 0},
		{name: "has", where: `- has: {block: external_call, arg.1: {tainted: parameter}}`, index: 1},
		{name: "sequence", where: `- sequence: [{block: external_call, arg.2: {tainted: parameter}}]`, index: 2},
		{name: "and", where: `- and: [{block: external_call, arg.3: {tainted: parameter}}]`, index: 3},
		{name: "any", where: `- any: [{block: external_call, arg.4: {tainted: parameter}}]`, index: 4},
		{name: "not", where: `- not: {block: external_call, arg.5: {tainted: parameter}}`, index: 5},
		{name: "nested argument", where: `- arg.0: {arg.6: {tainted: parameter}}`, index: 6},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc, err := parseWQL([]byte("meta: {id: nested-arg, severity: HIGH}\nquery:\n  select: external_call\n  from: entry_function\n  where:\n    " + tc.where + "\n"))
			if err != nil {
				t.Fatalf("parseWQL returned error: %v", err)
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
