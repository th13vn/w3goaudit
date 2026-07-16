package home

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	c := defaultConfig()
	if c.Templates.Repo != DefaultTemplatesRepo {
		t.Errorf("default repo = %q, want %q", c.Templates.Repo, DefaultTemplatesRepo)
	}
	if c.Color != "auto" {
		t.Errorf("default color = %q, want auto", c.Color)
	}
	if len(c.Scan.ExcludePaths) == 0 {
		t.Error("expected default exclude_paths to be non-empty")
	}
	if c.Scan.StrictImports {
		t.Error("strict imports must remain opt-in by default")
	}
}

func TestLoadStrictImportsConfig(t *testing.T) {
	homeDir := t.TempDir()
	t.Setenv("HOME", homeDir)
	configDir := filepath.Join(homeDir, ".w3goaudit")
	if err := os.MkdirAll(configDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(configDir, "config.yml"), []byte("scan:\n  strict_imports: true\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Scan.StrictImports {
		t.Fatal("scan.strict_imports was not loaded")
	}
}

func TestArchiveRelativePathStripsTopLevel(t *testing.T) {
	cases := map[string]string{
		"th13vn-w3goaudit-templates-abc123/official/reentrancy.yaml": "official/reentrancy.yaml",
		"repo-sha/README.md":  "README.md",
		"toplevelonly":        "", // no slash → dropped
		"repo-sha/a/b/c.yaml": "a/b/c.yaml",
	}
	for in, want := range cases {
		got, err := archiveRelativePath(in)
		if err != nil {
			t.Errorf("archiveRelativePath(%q): %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("archiveRelativePath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestLoadReturnsDefaultsWhenMissing(t *testing.T) {
	// Point HOME at an empty temp dir so config.yml is absent.
	t.Setenv("HOME", t.TempDir())
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Templates.Repo != DefaultTemplatesRepo {
		t.Errorf("repo = %q, want default", cfg.Templates.Repo)
	}
}
