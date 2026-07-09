package engine

import "testing"

const v2DelegatecallYAML = `
meta: { id: delegatecall-user-input, severity: CRITICAL, title: Delegatecall to user-controlled target }
select: delegatecall
from: entry_function
where:
  - arg.0: { tainted: parameter }
  - not: { preset: access_controlled }
`

const v2ComboSelectYAML = `
meta: { id: multicall-msgvalue, severity: HIGH, title: msg.value reuse across multicall }
select: [delegatecall, external_call]
from: main_contract
where:
  - block: function
`

const v1QueryYAML = `
meta:
  id: some-v1-template
  severity: HIGH
query:
  scope: entrypoint
  match:
    kind: call.lowlevel.delegatecall
`

const junkYAML = `
not_a_template: true
random: [1, 2, 3]
`

const missingSelectAndFromYAML = `
meta:
  id: incomplete-template
  severity: LOW
where:
  - block: delegatecall
`

func TestParseV2_ScalarSelect(t *testing.T) {
	tmpl, err := parseV2([]byte(v2DelegatecallYAML))
	if err != nil {
		t.Fatalf("parseV2 returned error: %v", err)
	}

	if tmpl.Meta.ID != "delegatecall-user-input" {
		t.Errorf("Meta.ID = %q, want %q", tmpl.Meta.ID, "delegatecall-user-input")
	}

	var selectVal string
	if err := tmpl.Select.Decode(&selectVal); err != nil {
		t.Fatalf("Select.Decode(&string) failed: %v", err)
	}
	if selectVal != "delegatecall" {
		t.Errorf("Select = %q, want %q", selectVal, "delegatecall")
	}

	if tmpl.From != "entry_function" {
		t.Errorf("From = %q, want %q", tmpl.From, "entry_function")
	}

	if len(tmpl.Where) != 2 {
		t.Fatalf("len(Where) = %d, want 2", len(tmpl.Where))
	}

	key, _, ok := tmpl.Where[0].key()
	if !ok {
		t.Fatalf("Where[0].key() ok = false, want true")
	}
	if key != "arg.0" {
		t.Errorf("Where[0] key = %q, want %q", key, "arg.0")
	}
}

func TestParseV2_ListSelect(t *testing.T) {
	tmpl, err := parseV2([]byte(v2ComboSelectYAML))
	if err != nil {
		t.Fatalf("parseV2 returned error: %v", err)
	}

	var selectVal []string
	if err := tmpl.Select.Decode(&selectVal); err != nil {
		t.Fatalf("Select.Decode(&[]string) failed: %v", err)
	}
	if len(selectVal) != 2 {
		t.Fatalf("len(select) = %d, want 2", len(selectVal))
	}
	if selectVal[0] != "delegatecall" || selectVal[1] != "external_call" {
		t.Errorf("select = %v, want [delegatecall external_call]", selectVal)
	}
}

func TestParseV2_ErrorOnMissingSelectAndFrom(t *testing.T) {
	_, err := parseV2([]byte(missingSelectAndFromYAML))
	if err == nil {
		t.Fatalf("parseV2 expected an error for a doc with neither select nor from, got nil")
	}
}

func TestIsV2Source(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want bool
	}{
		{"v2 scalar select", v2DelegatecallYAML, true},
		{"v2 combo select", v2ComboSelectYAML, true},
		{"v1 query doc", v1QueryYAML, false},
		{"junk doc", junkYAML, false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := isV2Source([]byte(c.raw))
			if got != c.want {
				t.Errorf("isV2Source(%s) = %v, want %v", c.name, got, c.want)
			}
		})
	}
}

func TestMatcherV2Key(t *testing.T) {
	tmpl, err := parseV2([]byte(v2DelegatecallYAML))
	if err != nil {
		t.Fatalf("parseV2 returned error: %v", err)
	}

	key, _, ok := tmpl.Where[1].key()
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
