package engine

import (
	"strings"
	"testing"
)

// FuzzParseTemplate fuzzes the WQL loader, which is the project's only untrusted
// input surface besides Solidity source: a template can come from a downloaded
// pack or a third-party directory passed to --template.
//
// The invariant is not "every input parses" — most inputs are rejected, and that
// is correct. It is that the loader always terminates with either a template or
// an error, and never panics, and never returns a (nil, nil) pair that a caller
// would dereference. The recursive validators (walkRules, prepareRuleForEvaluation)
// and the depth/cycle guards are the parts most likely to be surprised by a
// hostile shape, so the seeds concentrate there.
func FuzzParseTemplate(f *testing.F) {
	const meta = "meta:\n  id: FUZZ-1\n  severity: HIGH\n"

	seeds := []string{
		// Valid baselines.
		meta + "query:\n  select: external_call\n  from: entry_function\n",
		meta + "query:\n  from: entry_function\n  where:\n    - block: eth_transfer\n",
		meta + "query:\n  from: source\n  where:\n    - regex: 'abc'\n",
		// Composition.
		meta + "query:\n  or:\n    - {from: function, select: external_call}\n    - {from: function, select: delegatecall}\n",
		meta + "query:\n  and:\n    - {label: a, select: external_call}\n    - {label: b, select: state_write}\n",
		// Shapes the loader must reject rather than crash on.
		"",
		"meta:\n",
		meta,
		meta + "query:\n",
		meta + "query: []\n",
		meta + "query: null\n",
		meta + "query:\n  from: nope\n  select: external_call\n",
		meta + "query:\n  select: []\n  from: function\n",
		meta + "query:\n  from: function\n  where: []\n",
		meta + "query:\n  from: function\n  where:\n    - {}\n",
		meta + "query:\n  from: function\n  where:\n    - unknown_key: x\n",
		meta + "query:\n  from: function\n  where:\n    - preset: not_a_preset\n",
		meta + "query:\n  from: function\n  where:\n    - block: not_a_kind\n",
		meta + "query:\n  from: function\n  where:\n    - name: '('\n",
		meta + "query:\n  from: function\n  where:\n    - version: nonsense\n",
		meta + "query:\n  from: function\n  where:\n    - arg.-1: {block: literal}\n",
		meta + "query:\n  from: function\n  where:\n    - arg.0x1: {block: literal}\n",
		meta + "query:\n  from: function\n  where:\n    - unchecked_var: false\n",
		// YAML merge keys are rejected recursively.
		"x: &a {select: external_call}\n" + meta + "query:\n  <<: *a\n  from: function\n",
		// Deep nesting, to exercise the recursion cap rather than the Go stack.
		meta + "query:\n  from: function\n  where:\n    - " + strings.Repeat("not: {", 80) +
			"block: external_call" + strings.Repeat("}", 80) + "\n",
		// Anchors/aliases that expand into a large document.
		"a: &a [1,1,1,1,1]\nb: &b [*a,*a,*a,*a,*a]\n" + meta + "query:\n  from: function\n",
	}
	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, data string) {
		template, err := ParseTemplate(data)
		if err != nil {
			// Rejection is the expected outcome for most inputs. The contract is
			// only that a failure yields no template for a caller to use.
			if template != nil {
				t.Fatalf("ParseTemplate returned both a template and an error %v", err)
			}
			return
		}
		if template == nil {
			t.Fatal("ParseTemplate returned (nil, nil)")
		}
		// A template the loader accepted must be self-consistent enough to run:
		// finalization guarantees an id, a severity, and at least one query block.
		if template.Meta.ID == "" {
			t.Error("accepted template has no meta.id")
		}
		if template.Meta.Severity == "" {
			t.Error("accepted template has no meta.severity")
		}
		if template.Query.Scope == "" {
			t.Error("accepted template has an empty scope")
		}

		// Evaluating an accepted template against a nil database and nil nodes must
		// also not panic; this is the path an SDK caller hits with an empty project.
		engine := New(nil)
		_ = engine.Verify(nil, template.Query.Match)
		for _, block := range template.Queries {
			_ = engine.Verify(nil, block.Match)
		}
	})
}
