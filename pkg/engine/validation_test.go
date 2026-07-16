package engine

import (
	"strings"
	"testing"
	"testing/fstest"

	"github.com/th13vn/w3goaudit/pkg/types"
	"gopkg.in/yaml.v3"
)

// validMeta is a minimal valid meta block for assembling test templates.
const validMeta = "meta:\n  id: T\n  severity: HIGH\n  confidence: HIGH\n"

func TestParseTemplateAcceptsWQL(t *testing.T) {
	tmpl, err := ParseTemplate(`
meta: {id: valid-v2, severity: HIGH}
query:
  select: external_call
  from: entry_function
  where: [{name: transfer}]
`)
	if err != nil {
		t.Fatalf("ParseTemplate returned error: %v", err)
	}
	if tmpl.Meta.ID != "valid-v2" || tmpl.Query.Scope != ScopeEntrypoint {
		t.Fatalf("template = %#v, want valid-v2 entrypoint template", tmpl)
	}
}

func TestParseTemplateRejectsIRShapedQuery(t *testing.T) {
	// The evaluator IR shape (scope/filter/match) is not the authoring
	// surface: a query: written that way must fail strict decoding.
	_, err := ParseTemplate(`
meta: {id: bad-shape, severity: HIGH}
query: {scope: entrypoint, match: {kind: call.external}}
`)
	if err == nil || !strings.Contains(err.Error(), "field scope not found") {
		t.Fatalf("error = %v, want strict unknown-field error for query.scope", err)
	}
}

func TestTemplateRejectsDirectYAMLUnmarshal(t *testing.T) {
	var tmpl Template
	err := yaml.Unmarshal([]byte(`
meta: {id: direct, severity: HIGH}
query: {scope: entrypoint, match: {kind: call.external}}
`), &tmpl)
	if err == nil || !strings.Contains(err.Error(), "use ParseTemplate or LoadTemplate") {
		t.Fatalf("error = %v, want loader-redirect guidance", err)
	}
}

func TestParseTemplateRejectsUnknownTopLevelKey(t *testing.T) {
	_, err := ParseTemplate(`
meta: {id: bad-key, severity: HIGH}
query:
  select: external_call
  from: entry_function
  where: [{name: transfer}]
bogus: true
`)
	if err == nil || !strings.Contains(err.Error(), "field bogus not found") {
		t.Fatalf("error = %v, want strict unknown-field error", err)
	}
}

func TestParseTemplateRejectsMultipleYAMLDocuments(t *testing.T) {
	_, err := ParseTemplate(`
meta: {id: first, severity: HIGH}
query:
  select: external_call
  from: entry_function
---
meta: {id: second, severity: LOW}
query:
  select: state_write
  from: function
`)
	if err == nil || !strings.Contains(err.Error(), "multiple YAML documents are unsupported") {
		t.Fatalf("error = %v, want multiple-document error", err)
	}
}

func TestParseTemplateRejectsInvalidDocuments(t *testing.T) {
	cases := []struct {
		name string
		yaml string
		want string
	}{
		{
			name: "removed matcher name",
			yaml: `
meta: {id: removed-matcher, severity: HIGH}
query:
  select: external_call
  from: entry_function
  where: [{contains: {block: identifier}}]
`,
			want: `unknown matcher key "contains"`,
		},
		{
			name: "where without from or select",
			yaml: `
meta: {id: no-source, severity: HIGH}
query:
  where: [{block: external_call}]
`,
			want: "neither select nor from",
		},
		{
			name: "no actionable AST or source matcher",
			yaml: `
meta: {id: context-only, severity: HIGH}
query:
  from: entry_function
  where: [{modifier: onlyOwner}]
`,
			want: "select: required",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseTemplate(tc.yaml)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want substring %q", err, tc.want)
			}
		})
	}
}

// TestLoadRejectsBadValues verifies the closed-set/load-time validations: each
// of these used to load cleanly and then silently misbehave at scan time.
func TestLoadRejectsBadValues(t *testing.T) {
	cases := []struct {
		name string
		yaml string
		want string // substring expected in the error
	}{
		{
			name: "unknown scope",
			yaml: validMeta + "query:\n  select: external_call\n  from: functions\n",
			want: "unknown scope",
		},
		{
			name: "bad tainted_from",
			yaml: validMeta + "query:\n  select: external_call\n  from: entry_function\n  where: [{tainted: parameters}]\n",
			want: "unknown tainted_from",
		},
		{
			name: "bad visibility",
			yaml: validMeta + "query:\n  select: external_call\n  from: entry_function\n  where: [{visibility: exernal}]\n",
			want: "unknown visibility",
		},
		{
			name: "bad version constraint",
			yaml: validMeta + "query:\n  select: external_call\n  from: entry_function\n  where: [{version: not-a-version}]\n",
			want: "invalid version constraint",
		},
		{
			name: "bad severity",
			yaml: "meta:\n  id: T\n  severity: hgih\n  confidence: HIGH\nquery:\n  select: external_call\n  from: entry_function\n",
			want: "invalid severity",
		},
		{
			name: "source scope without regex",
			yaml: validMeta + "query:\n  select: external_call\n  from: source\n",
			want: "source scope",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseTemplate(tc.yaml)
			if err == nil {
				t.Fatalf("expected load error containing %q, got nil", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %q, want substring %q", err.Error(), tc.want)
			}
		})
	}
}

// TestLoadAcceptsValidForms verifies representative WQL forms that must not
// error.
func TestLoadAcceptsValidForms(t *testing.T) {
	cases := map[string]string{
		"lowlevel call":        validMeta + "query:\n  select: lowlevel_call\n  from: entry_function\n",
		"builtin call":         validMeta + "query:\n  select: builtin_transfer\n  from: entry_function\n",
		"tainted_from sender":  validMeta + "query:\n  select: external_call\n  from: entry_function\n  where: [{tainted: sender}]\n",
		"caret version":        validMeta + "query:\n  select: external_call\n  from: entry_function\n  where: [{version: ^0.8.0}]\n",
		"empty scope defaults": "meta:\n  id: T\n  severity: LOW\n  confidence: LOW\nquery:\n  select: external_call\n",
		"contract scope name":  validMeta + "query:\n  from: contract\n  where: [{name: Vault}]\n",
		"contract scope AST":   validMeta + "query:\n  from: contract\n  where: [{has: {block: external_call}}]\n",
	}
	for name, y := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseTemplate(y); err != nil {
				t.Fatalf("expected valid template, got error: %v", err)
			}
		})
	}
}

// TestAnchoredOperatorMatching verifies attribute matching is anchored:
// operator: "=" must match exactly "=", not "==".
func TestAnchoredOperatorMatching(t *testing.T) {
	e := &Engine{}
	eq := types.NewASTNode("expr.binary_op")
	eq.SetAttribute("operator", "=")
	eqeq := types.NewASTNode("expr.binary_op")
	eqeq.SetAttribute("operator", "==")

	if !e.matchAttributeValue(eq, "operator", "=") {
		t.Error(`"=" attribute should match pattern "="`)
	}
	if e.matchAttributeValue(eqeq, "operator", "=") {
		t.Error(`"==" attribute should NOT match anchored pattern "=" (regression: unanchored regex)`)
	}
}

// TestBoolAttrTolerance verifies a YAML bool template value matches a
// string-stored "true"/"false" attribute (and vice versa).
func TestBoolAttrTolerance(t *testing.T) {
	e := &Engine{}
	n := types.NewASTNode("expr.conditional")
	n.SetAttribute("conditional_part", "true") // stored as string by the builder

	if !e.matchAttributeValue(n, "conditional_part", true) {
		t.Error("YAML bool `true` should match string attribute \"true\"")
	}
	if e.matchAttributeValue(n, "conditional_part", false) {
		t.Error("YAML bool `false` should not match string attribute \"true\"")
	}
}

// TestVersionChecking exercises the version comparator (previously untested).
func TestVersionChecking(t *testing.T) {
	cmpCases := []struct {
		a, b string
		want int
	}{
		{"0.8.0", "0.8.0", 0},
		{"0.7.6", "0.8.0", -1},
		{"0.8.1", "0.8.0", 1},
		{"0.8.0", "0.8", 0}, // missing patch treated as 0
	}
	for _, c := range cmpCases {
		if got := compareVersions(c.a, c.b); got != c.want {
			t.Errorf("compareVersions(%q,%q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}

	// parseVersionConstraint splits operator from version.
	if op, v := parseVersionConstraint(">=0.8.0"); op != ">=" || v != "0.8.0" {
		t.Errorf("parseVersionConstraint(>=0.8.0) = (%q,%q), want (>=,0.8.0)", op, v)
	}

	// checkVersion against a pragma.
	e := &Engine{}
	e.currentSourceFile = &types.SourceFile{PragmaVersion: "^0.8.13"}
	if !e.checkVersion(">=0.8.0") {
		t.Error("checkVersion(>=0.8.0) against ^0.8.13 should be true")
	}
	if e.checkVersion("<0.8.0") {
		t.Error("checkVersion(<0.8.0) against ^0.8.13 should be false")
	}

	// Missing pragma → skip (vacuously true).
	e.currentSourceFile = &types.SourceFile{}
	if !e.checkVersion(">=0.8.0") {
		t.Error("checkVersion with no pragma should skip (return true)")
	}
}

// TestLoadTemplatesFromFS verifies templates load from an fs.FS with the same
// validation (one good, one bad → fail-closed error).
func TestLoadTemplatesFromFS(t *testing.T) {
	good := validMeta + "query:\n  select: external_call\n  from: entry_function\n"
	fsys := fstest.MapFS{
		"pack/a.yaml": &fstest.MapFile{Data: []byte(good)},
	}
	tmpls, err := LoadTemplatesFromFS(fsys, "pack", TemplateLoadOptions{})
	if err != nil {
		t.Fatalf("LoadTemplatesFromFS: %v", err)
	}
	if len(tmpls) != 1 {
		t.Fatalf("want 1 template, got %d", len(tmpls))
	}

	bad := validMeta + "query:\n  select: external_call\n  from: bogus\n"
	fsysBad := fstest.MapFS{
		"pack/a.yaml": &fstest.MapFile{Data: []byte(good)},
		"pack/b.yaml": &fstest.MapFile{Data: []byte(bad)},
	}
	if _, err := LoadTemplatesFromFS(fsysBad, "pack", TemplateLoadOptions{}); err == nil {
		t.Fatal("expected fail-closed error for an invalid template in the FS")
	}
}
