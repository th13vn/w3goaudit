package engine

import (
	"io/fs"
	"path/filepath"
	"testing"
)

func TestRepositoryTemplatePackIsValidWQL(t *testing.T) {
	root := repoRoot(t)
	templateRoots := []string{
		"templates/official",
		"templates/test",
		"benchmarks/templates",
	}

	for _, templateRoot := range templateRoots {
		validateRepositoryTemplateLane(t, root, templateRoot)
	}
}

func validateRepositoryTemplateLane(t *testing.T, root, templateRoot string) {
	t.Helper()

	laneRoot := filepath.Join(root, filepath.FromSlash(templateRoot))
	count := 0
	err := filepath.WalkDir(laneRoot, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || filepath.Ext(path) != ".yaml" {
			return nil
		}

		count++
		rel, err := filepath.Rel(root, path)
		if err != nil {
			rel = path
		}
		if _, err := LoadTemplate(path); err != nil {
			t.Errorf("LoadTemplate(%s): %v", rel, err)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk required template lane %s: %v", templateRoot, err)
	}

	if count == 0 {
		t.Fatalf("required template lane %s contains no .yaml templates", templateRoot)
	}
}
