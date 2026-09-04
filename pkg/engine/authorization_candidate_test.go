package engine

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/th13vn/w3goaudit/pkg/types"
)

func TestCandidateAuthorizationPackExecutesSemanticContracts(t *testing.T) {
	root := repoRoot(t)
	callbackDB := buildRepositoryFixtureDatabase(t, root, "test-data/security/authorization-runtime/callbacks.sol")
	callback := executeRepositoryTemplate(t, root, callbackDB, "templates/candidate/authorization/expected-principal-callback.yaml")
	assertFindingSetContains(t, callback, []string{
		"CallbackCandidateMatrix.uniswapV3SwapCallback",
		"CallbackCandidateMatrix.uniswapV3MintCallback",
	})
	assertFindingSetExcludes(t, callback, []string{
		"CallbackCandidateMatrix.uniswapV3FlashCallback",
	})

	v4 := executeRepositoryTemplate(t, root, callbackDB, "templates/candidate/authorization/v4-manager-callback.yaml")
	assertFindingSetContains(t, v4, []string{"V4CallbackCandidateMatrix.beforeSwap"})
	assertFindingSetExcludes(t, v4, []string{"V4CallbackCandidateMatrix.afterSwap"})

	lifecycleDB := buildRepositoryFixtureDatabase(t, root, "test-data/security/authorization-runtime/lifecycle.sol")
	initializer := executeRepositoryTemplate(t, root, lifecycleDB, "templates/candidate/authorization/unprotected-initializer.yaml")
	assertFindingSetContains(t, initializer, []string{
		"FirstCallTakeover.initialize",
	})
	assertFindingSetExcludes(t, initializer, []string{"MutexOnly.initialize", "DisabledImplementation.initialize", "ProxyNamedOnly.initialize"})
}

func TestCandidateAuthorizationPackPreservesSourceCacheExecutionParity(t *testing.T) {
	root := repoRoot(t)
	for _, tc := range []struct {
		fixture, template string
	}{
		{"test-data/security/authorization-runtime/callbacks.sol", "templates/candidate/authorization/expected-principal-callback.yaml"},
		{"test-data/security/authorization-runtime/callbacks.sol", "templates/candidate/authorization/v4-manager-callback.yaml"},
		{"test-data/security/authorization-runtime/lifecycle.sol", "templates/candidate/authorization/unprotected-initializer.yaml"},
	} {
		t.Run(filepath.Base(tc.template), func(t *testing.T) {
			db := buildRepositoryFixtureDatabase(t, root, tc.fixture)
			want := executeRepositoryTemplate(t, root, db, tc.template)
			raw, err := json.Marshal(db)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "database.json")
			if err := os.WriteFile(path, raw, 0o644); err != nil {
				t.Fatal(err)
			}
			loaded, err := types.LoadFromJSON(path)
			if err != nil {
				t.Fatal(err)
			}
			got := executeRepositoryTemplate(t, root, loaded, tc.template)
			wantJSON, _ := json.Marshal(want)
			gotJSON, _ := json.Marshal(got)
			if string(gotJSON) != string(wantJSON) {
				t.Fatalf("candidate execution changed across cache round trip\nsource=%s\ncache=%s", wantJSON, gotJSON)
			}
		})
	}
}

func TestCandidateAuthorizationPackStrictLoads(t *testing.T) {
	templates, err := LoadTemplates(filepath.Join(repoRoot(t), "templates/candidate/authorization"))
	if err != nil {
		t.Fatalf("load candidate authorization pack: %v", err)
	}
	if len(templates) != 3 {
		t.Fatalf("candidate authorization templates = %d, want 3", len(templates))
	}
}
