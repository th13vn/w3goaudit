package engine_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/th13vn/w3goaudit/pkg/engine"
	"gopkg.in/yaml.v3"
)

func TestTemplatePublicIRRejectsYAMLAndPreservesJSON(t *testing.T) {
	var decoded engine.Template
	err := yaml.Unmarshal([]byte(`
meta: {id: direct, severity: HIGH}
query: {scope: entrypoint, match: {kind: call.external}}
`), &decoded)
	if err == nil || !strings.Contains(err.Error(), "use ParseTemplate or LoadTemplate") {
		t.Fatalf("YAML error = %v, want loader-redirect guidance", err)
	}

	original := engine.Template{
		Meta: engine.TemplateMeta{ID: "programmatic", Severity: "HIGH"},
		Query: engine.QueryBlock{
			Scope: engine.ScopeEntrypoint,
			Match: engine.Rule{Kind: "call.external"},
		},
	}
	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if decoded.Meta.ID != original.Meta.ID || decoded.Query.Match.Kind != original.Query.Match.Kind {
		t.Fatalf("JSON round trip = %#v, want %#v", decoded, original)
	}
}
