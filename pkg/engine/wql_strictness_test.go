package engine

import (
	"fmt"
	"strings"
	"testing"

	"github.com/th13vn/w3goaudit/pkg/types"
)

func TestParseTemplateRejectsExplicitlyEmptyQueryFields(t *testing.T) {
	cases := []struct {
		name  string
		query string
		path  string
	}{
		{name: "top select null", query: "select: null\n  from: entry_function", path: "query.select"},
		{name: "top select empty", query: "select: ''\n  from: entry_function", path: "query.select"},
		{name: "top from null", query: "select: delegatecall\n  from: null", path: "query.from"},
		{name: "top from empty", query: "select: delegatecall\n  from: ''", path: "query.from"},
		{name: "top where null", query: "select: delegatecall\n  from: entry_function\n  where: null", path: "query.where"},
		{name: "top where empty", query: "select: delegatecall\n  from: entry_function\n  where: []", path: "query.where"},
		{
			name:  "or branch select null",
			query: "or:\n    - {select: null, from: entry_function}\n    - {select: state_write, from: entry_function}",
			path:  "query.or branch 1.select",
		},
		{
			name:  "or branch select empty",
			query: "or:\n    - {select: '', from: entry_function}\n    - {select: state_write, from: entry_function}",
			path:  "query.or branch 1.select",
		},
		{
			name:  "or branch from null",
			query: "or:\n    - {select: delegatecall, from: null}\n    - {select: state_write, from: entry_function}",
			path:  "query.or branch 1.from",
		},
		{
			name:  "or branch from empty",
			query: "or:\n    - {select: delegatecall, from: ''}\n    - {select: state_write, from: entry_function}",
			path:  "query.or branch 1.from",
		},
		{
			name:  "or branch where null",
			query: "or:\n    - {select: delegatecall, from: entry_function, where: null}\n    - {select: state_write, from: entry_function}",
			path:  "query.or branch 1.where",
		},
		{
			name:  "or branch where empty",
			query: "or:\n    - {select: delegatecall, from: entry_function, where: []}\n    - {select: state_write, from: entry_function}",
			path:  "query.or branch 1.where",
		},
		{
			name:  "or branch label null",
			query: "or:\n    - {label: null, select: delegatecall, from: entry_function}\n    - {select: state_write, from: entry_function}",
			path:  "query.or branch 1.label",
		},
		{
			name:  "or branch label empty",
			query: "or:\n    - {label: '', select: delegatecall, from: entry_function}\n    - {select: state_write, from: entry_function}",
			path:  "query.or branch 1.label",
		},
		{
			name:  "and branch select null",
			query: "from: main_contract\n  and:\n    - {select: null}\n    - {select: state_write}",
			path:  "query.and branch 1.select",
		},
		{
			name:  "and branch select empty",
			query: "from: main_contract\n  and:\n    - {select: ''}\n    - {select: state_write}",
			path:  "query.and branch 1.select",
		},
		{
			name:  "and branch from null",
			query: "from: main_contract\n  and:\n    - {select: delegatecall, from: null}\n    - {select: state_write}",
			path:  "query.and branch 1.from",
		},
		{
			name:  "and branch from empty",
			query: "from: main_contract\n  and:\n    - {select: delegatecall, from: ''}\n    - {select: state_write}",
			path:  "query.and branch 1.from",
		},
		{
			name:  "and branch where null",
			query: "from: main_contract\n  and:\n    - {select: delegatecall, where: null}\n    - {select: state_write}",
			path:  "query.and branch 1.where",
		},
		{
			name:  "and branch where empty",
			query: "from: main_contract\n  and:\n    - {select: delegatecall, where: []}\n    - {select: state_write}",
			path:  "query.and branch 1.where",
		},
		{
			name:  "and branch label null",
			query: "from: main_contract\n  and:\n    - {label: null, select: delegatecall}\n    - {select: state_write}",
			path:  "query.and branch 1.label",
		},
		{
			name:  "and branch label empty",
			query: "from: main_contract\n  and:\n    - {label: '', select: delegatecall}\n    - {select: state_write}",
			path:  "query.and branch 1.label",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseTemplate(strictnessTemplate(tc.query))
			if err == nil || !strings.Contains(err.Error(), tc.path) {
				t.Fatalf("error = %v, want pointed error containing %q", err, tc.path)
			}
		})
	}
}

func TestParseTemplateRejectsVacuousMatchers(t *testing.T) {
	matchers := []string{
		"any: []",
		"and: []",
		"sequence: []",
		"attr: {}",
		"has: {}",
		"has: []",
		"in: {}",
		"not: {}",
		"not: []",
		"left: {}",
		"right: {}",
		"statement_has: {}",
		"guarded_by: {}",
		"arg.0: {}",
		"arg.any: {}",
		"any: [{}]",
		"and: [{}]",
		"sequence: [{}]",
		"name: ''",
		"regex: ''",
		"tainted: ''",
		"visibility: ''",
		"mutability: ''",
		"operator: ''",
		"modifier: ''",
		"base: ''",
		"func_name: ''",
		"version: ''",
		"has_param: ''",
		"unchecked_var: false",
	}

	for _, matcher := range matchers {
		matcher := matcher
		t.Run(matcher, func(t *testing.T) {
			query := "select: delegatecall\n  from: entry_function\n  where:\n    - " + matcher
			if _, err := ParseTemplate(strictnessTemplate(query)); err == nil {
				t.Fatalf("ParseTemplate accepted vacuous matcher %q", matcher)
			}
		})
	}
}

func TestParseTemplateRejectsInvalidArgumentIndexesAtEveryDepth(t *testing.T) {
	for _, key := range []string{"arg.-1", "arg.+1", "arg.one"} {
		for _, where := range []string{
			fmt.Sprintf("- %s: {name: value}", key),
			fmt.Sprintf("- has: {%s: {name: value}}", key),
		} {
			name := key + "/" + strings.TrimSpace(where[:strings.Index(where, ":")])
			t.Run(name, func(t *testing.T) {
				query := "select: delegatecall\n  from: entry_function\n  where:\n    " + where
				_, err := ParseTemplate(strictnessTemplate(query))
				if err == nil || !strings.Contains(err.Error(), "invalid arg index") {
					t.Fatalf("error = %v, want invalid arg index for %s", err, where)
				}
			})
		}
	}
}

func TestParseTemplateAcceptsNonNegativeDecimalArgumentIndexes(t *testing.T) {
	query := "select: delegatecall\n  from: entry_function\n  where:\n    - arg.0: {name: value}\n    - arg.12: {name: value}"
	if _, err := ParseTemplate(strictnessTemplate(query)); err != nil {
		t.Fatalf("ParseTemplate rejected valid arg.0/arg.12 indexes: %v", err)
	}
}

func TestMatchArgsRejectsNegativeProgrammaticIndexWithoutPanic(t *testing.T) {
	call := types.NewASTNode(types.KindCallExternal)
	call.AddChild(types.NewASTNode(types.KindExprIdentifier))
	if New(types.NewDatabase()).Verify(call, Rule{Args: map[int]Rule{-1: {Name: "value"}}}) {
		t.Fatal("negative argument index matched")
	}
}

func strictnessTemplate(query string) string {
	return "meta: {id: strictness, severity: HIGH}\nquery:\n  " + query + "\n"
}
