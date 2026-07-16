package engine

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/th13vn/w3goaudit/pkg/logging"
	"github.com/th13vn/w3goaudit/pkg/types"
)

func TestEngineScanLocalLoggerIsolation(t *testing.T) {
	newEngine := func(id string, out *bytes.Buffer) (*Engine, *Template) {
		db := types.NewDatabaseWithOptions(types.DatabaseOptions{Logger: logging.Disabled()})
		db.AddSourceFile(&types.SourceFile{Path: "/tmp/" + id + ".sol", Content: "contract " + id + " {}"})
		return NewWithOptions(db, Options{Logger: logging.New(true, out)}), &Template{
			Meta:  TemplateMeta{ID: id, Title: id, Severity: "LOW"},
			Query: QueryBlock{Scope: ScopeSource, Match: Rule{Regex: "contract"}},
		}
	}

	var left, right bytes.Buffer
	leftEngine, leftTemplate := newEngine("left-only", &left)
	rightEngine, rightTemplate := newEngine("right-only", &right)
	var wg sync.WaitGroup
	for _, tc := range []struct {
		engine   *Engine
		template *Template
	}{{leftEngine, leftTemplate}, {rightEngine, rightTemplate}} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tc.engine.Execute(tc.template)
		}()
	}
	wg.Wait()

	if strings.Contains(left.String(), "right-only") || strings.Contains(right.String(), "left-only") {
		t.Fatalf("engine logs crossed streams: left=%q right=%q", left.String(), right.String())
	}
}

func TestTemplateLoadOptionsUsesScanLocalLogger(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "local.yaml")
	content := "meta:\n  id: local-template\n  severity: LOW\nquery:\n  from: source\n  where:\n    - regex: contract\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	if _, err := LoadTemplatesWithOptions(dir, TemplateLoadOptions{Logger: logging.New(true, &out)}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "local-template") {
		t.Fatalf("template loader did not use scan-local logger: %q", out.String())
	}
}
