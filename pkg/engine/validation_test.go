package engine

import (
	"strings"
	"testing"
	"testing/fstest"

	"github.com/th13vn/w3goaudit/pkg/types"
)

// validMeta is a minimal valid meta block for assembling test templates.
const validMeta = "meta:\n  id: T\n  severity: HIGH\n  confidence: HIGH\n"

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
			yaml: validMeta + "query:\n  scope: functions\n  match:\n    kind: call.external\n",
			want: "unknown scope",
		},
		{
			name: "bad tainted_from",
			yaml: validMeta + "query:\n  scope: entrypoint\n  match:\n    tainted_from: parameters\n",
			want: "unknown tainted_from",
		},
		{
			name: "bad visibility_filter",
			yaml: validMeta + "query:\n  scope: entrypoint\n  filter:\n    visibility_filter: exernal\n  match:\n    kind: call.external\n",
			want: "unknown visibility_filter",
		},
		{
			name: "bad version constraint",
			yaml: validMeta + "query:\n  scope: entrypoint\n  filter:\n    version: not-a-version\n  match:\n    kind: call.external\n",
			want: "invalid version constraint",
		},
		{
			name: "AST op at contract scope matches everything",
			yaml: validMeta + "query:\n  scope: contract\n  match:\n    contains:\n      kind: call.external\n",
			want: "not supported at a contract scope",
		},
		{
			name: "bad severity",
			yaml: "meta:\n  id: T\n  severity: hgih\n  confidence: HIGH\nquery:\n  scope: entrypoint\n  match:\n    kind: call.external\n",
			want: "invalid severity",
		},
		{
			name: "source scope without source_regex",
			yaml: validMeta + "query:\n  scope: source\n  match:\n    kind: call.external\n",
			want: "scope: source",
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

// TestLoadAcceptsValidForms verifies forms that must NOT error, including the
// call.lowlevel multi-segment prefix (previously rejected by IsKnownKind while
// matchKind implemented it).
func TestLoadAcceptsValidForms(t *testing.T) {
	cases := map[string]string{
		"call.lowlevel prefix": validMeta + "query:\n  scope: entrypoint\n  match:\n    kind: call.lowlevel\n",
		"call.builtin prefix":  validMeta + "query:\n  scope: entrypoint\n  match:\n    kind: call.builtin\n",
		"tainted_from sender":  validMeta + "query:\n  scope: entrypoint\n  match:\n    kind: call.external\n    tainted_from: sender\n",
		"caret version":        validMeta + "query:\n  scope: entrypoint\n  filter:\n    version: ^0.8.0\n  match:\n    kind: call.external\n",
		"empty scope defaults": "meta:\n  id: T\n  severity: LOW\n  confidence: LOW\nquery:\n  match:\n    kind: call.external\n",
		"contract scope name":  validMeta + "query:\n  scope: contract\n  match:\n    name: Vault\n",
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
	good := validMeta + "query:\n  scope: entrypoint\n  match:\n    kind: call.external\n"
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

	bad := validMeta + "query:\n  scope: bogus\n  match:\n    kind: call.external\n"
	fsysBad := fstest.MapFS{
		"pack/a.yaml": &fstest.MapFile{Data: []byte(good)},
		"pack/b.yaml": &fstest.MapFile{Data: []byte(bad)},
	}
	if _, err := LoadTemplatesFromFS(fsysBad, "pack", TemplateLoadOptions{}); err == nil {
		t.Fatal("expected fail-closed error for an invalid template in the FS")
	}
}
