package home

import "testing"

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
}

func TestStripTopLevel(t *testing.T) {
	cases := map[string]string{
		"th13vn-w3goaudit-templates-abc123/official/reentrancy.yaml": "official/reentrancy.yaml",
		"repo-sha/README.md":  "README.md",
		"toplevelonly":        "", // no slash → dropped
		"repo/../etc/passwd":  "", // zip-slip → rejected
		"repo-sha/a/b/c.yaml": "a/b/c.yaml",
	}
	for in, want := range cases {
		if got := stripTopLevel(in); got != want {
			t.Errorf("stripTopLevel(%q) = %q, want %q", in, got, want)
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
