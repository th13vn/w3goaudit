package engine

import (
	"encoding/json"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/th13vn/w3goaudit/pkg/builder"
	"github.com/th13vn/w3goaudit/pkg/reader"
	"github.com/th13vn/w3goaudit/pkg/types"
)

// TestOfficialPackIsDeterministicAcrossSourceAndCache builds the canonical
// security fixture corpus once, executes the official pack repeatedly, then
// executes it against the JSON round-trip database. Mechanical template edits
// must not change finding identity, order, or source/cache parity.
func TestOfficialPackIsDeterministicAcrossSourceAndCache(t *testing.T) {
	root := repoRoot(t)
	sources, err := reader.New().Read(filepath.Join(root, "test-data/security"))
	if err != nil {
		t.Fatalf("read security fixtures: %v", err)
	}
	db, err := builder.New().Build(sources)
	if err != nil {
		t.Fatalf("build security fixtures: %v", err)
	}
	templates, err := LoadTemplates(filepath.Join(root, "templates/official"))
	if err != nil {
		t.Fatalf("load official pack: %v", err)
	}

	encodeFindings := func(db *types.Database) []byte {
		t.Helper()
		findings := New(db).ExecuteAll(templates)
		raw, err := json.Marshal(findings)
		if err != nil {
			t.Fatalf("marshal findings: %v", err)
		}
		return raw
	}

	want := encodeFindings(db)
	if len(want) == 0 {
		t.Fatal("official pack produced no findings on security fixtures")
	}
	for run := 0; run < 3; run++ {
		if got := encodeFindings(db); !reflect.DeepEqual(got, want) {
			t.Fatalf("source execution changed on repeat %d", run+1)
		}
	}

	rawDB, err := json.Marshal(db)
	if err != nil {
		t.Fatalf("marshal source database: %v", err)
	}
	var cached types.Database
	if err := json.Unmarshal(rawDB, &cached); err != nil {
		t.Fatalf("unmarshal cached database: %v", err)
	}
	cached.RestoreASTParents()
	if got := encodeFindings(&cached); !reflect.DeepEqual(got, want) {
		t.Fatalf("source/cache official findings differ")
	}
}
