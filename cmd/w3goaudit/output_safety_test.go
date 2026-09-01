package main

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateOutputBoundaryRejectsOverlap(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "project")
	if err := os.MkdirAll(filepath.Join(source, "contracts"), 0o755); err != nil {
		t.Fatal(err)
	}
	safeSibling := filepath.Join(root, "project-audit")
	cases := []struct {
		name   string
		output string
	}{
		{name: "equal", output: source},
		{name: "output inside source", output: filepath.Join(source, "audit")},
		{name: "source inside output", output: root},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateOutputBoundary(source, "", tc.output)
			if err == nil || !strings.Contains(err.Error(), "overlap") {
				t.Fatalf("error = %v, want overlap rejection", err)
			}
		})
	}
	if err := validateOutputBoundary(source, "", safeSibling); err != nil {
		t.Fatalf("safe sibling rejected: %v", err)
	}
}

func TestValidateOutputBoundaryResolvesSymlinkAliases(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source")
	if err := os.MkdirAll(source, 0o755); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(root, "alias")
	if err := os.Symlink(source, alias); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if err := validateOutputBoundary(source, "", alias); err == nil || !strings.Contains(err.Error(), "overlap") {
		t.Fatalf("symlink alias error = %v", err)
	}
}

func TestValidateOutputBoundaryUsesCachedScanTarget(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "project")
	if err := os.MkdirAll(filepath.Join(source, "contracts"), 0o755); err != nil {
		t.Fatal(err)
	}
	cache := filepath.Join(root, "database.json")
	raw, err := json.Marshal(map[string]string{
		"projectRoot": source,
		"scanTarget":  filepath.Join(source, "contracts"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cache, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validateOutputBoundary("", cache, filepath.Join(source, "contracts", "audit")); err == nil {
		t.Fatal("cached scan target overlap was accepted")
	}
}

func TestValidateOutputBoundaryPrefersDatabaseWhenBothInputsAreSet(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "cached-project")
	if err := os.MkdirAll(source, 0o755); err != nil {
		t.Fatal(err)
	}
	cache := filepath.Join(root, "database.json")
	raw, err := json.Marshal(map[string]string{
		"projectRoot": source,
		"scanTarget":  source,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cache, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	unusedInput := filepath.Join(root, "unused-input")
	if err := os.MkdirAll(unusedInput, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := validateOutputBoundary(unusedInput, cache, filepath.Join(source, "audit")); err == nil {
		t.Fatal("cached boundary was ignored when a positional input was also set")
	}
}

func TestExecuteScanRejectsOverlapBeforeWritingAnything(t *testing.T) {
	source := filepath.Join(t.TempDir(), "project")
	keep := filepath.Join(source, "contracts", "KEEP.sol")
	if err := os.MkdirAll(filepath.Dir(keep), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keep, []byte("contract KEEP {}"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := executeScan(scanOptions{
		InputPath: source, TemplatePath: "../../templates/official", OutputPath: source,
		Stdout: io.Discard, Stderr: io.Discard,
	})
	if err == nil || !strings.Contains(err.Error(), "overlap") {
		t.Fatalf("executeScan error = %v", err)
	}
	if _, err := os.Stat(keep); err != nil {
		t.Fatalf("source file was removed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(source, "run.log")); !os.IsNotExist(err) {
		t.Fatalf("run.log was created before safety validation: %v", err)
	}
}

func TestExecuteScanDoesNotFollowRunLogSymlink(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "project")
	out := filepath.Join(root, "result")
	if err := os.MkdirAll(source, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "C.sol"), []byte("contract C {}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(out, 0o755); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(root, "outside.log")
	if err := os.WriteFile(sentinel, []byte("outside-log"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(sentinel, filepath.Join(out, "run.log")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	if err := executeScan(scanOptions{
		InputPath: source, TemplatePath: "../../templates/official", OutputPath: out,
		Stdout: io.Discard, Stderr: io.Discard,
	}); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(sentinel)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "outside-log" {
		t.Fatalf("outside run-log sentinel = %q", got)
	}
	info, err := os.Lstat(filepath.Join(out, "run.log"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		t.Fatal("run.log remained a symlink")
	}
}
