package engine

import (
	"encoding/json"
	"testing"

	"github.com/th13vn/w3goaudit/pkg/types"
)

// TestSourceContentSurvivesJSONRoundTrip guards the `build -> JSON -> scan --db`
// path for source-text templates. SourceFile.Content is serialized so a reloaded
// database is self-contained: `scope: source` / `regex` reproduce the
// same findings even when the original files are no longer present on disk
// (the path below is virtual and never exists, so the engine's os.ReadFile
// fallback cannot rescue a non-serialized Content).
func TestSourceContentSurvivesJSONRoundTrip(t *testing.T) {
	const path = "/virtual/does-not-exist/Token.sol"
	const src = "// SPDX-License-Identifier: MIT\n" +
		"pragma solidity ^0.8.0;\n" +
		"contract Token {\n" +
		"    function kill() public { selfdestruct(payable(msg.sender)); }\n" +
		"}\n"

	build := func() *types.Database {
		db := types.NewDatabase()
		db.SourceFiles[path] = &types.SourceFile{Path: path, Content: src}
		return db
	}

	tmpl := &Template{
		Meta: TemplateMeta{ID: "TEST-SRC-ROUNDTRIP", Severity: "LOW", Confidence: "LOW"},
		Query: QueryBlock{
			Scope: ScopeSource,
			Match: Rule{Regex: "selfdestruct"},
		},
	}

	before := New(build()).ExecuteAll([]*Template{tmpl})
	if len(before) != 1 {
		t.Fatalf("expected 1 source-scope finding before round-trip, got %d", len(before))
	}

	// Simulate `build` (marshal) then `scan --db` (unmarshal).
	data, err := json.Marshal(build())
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var loaded types.Database
	if err := json.Unmarshal(data, &loaded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if sf := loaded.SourceFiles[path]; sf == nil || sf.Content == "" {
		t.Fatal("SourceFile.Content was not preserved across the JSON round-trip")
	}

	after := New(&loaded).ExecuteAll([]*Template{tmpl})
	if len(after) != len(before) {
		t.Fatalf("source-scope findings changed after round-trip: before=%d after=%d (file-content predicates regressed)", len(before), len(after))
	}
}
