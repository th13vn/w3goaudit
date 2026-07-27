package reader

import (
	"path/filepath"
	"testing"
)

// The user's motivating case: Etherscan-fetched source importing prb-math with
// no remappings file. The "@prb/math/" prefix cannot be predicted, only mapped
// to its conventional lib/ layout.
func TestResolveConventionPrbMath(t *testing.T) {
	t.Setenv("FOUNDRY_PROFILE", "")
	root := t.TempDir()
	want := filepath.Join(root, "lib", "prb-math", "src", "UD60x18.sol")
	writeResolverTarget(t, want)

	got, err := NewResolver(root).Resolve("@prb/math/src/UD60x18.sol", filepath.Join(root, "src", "lib", "Curve.sol"))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if filepath.Clean(got) != filepath.Clean(want) {
		t.Fatalf("Resolve = %q, want conventional prb-math target %q", got, want)
	}
}

func TestResolveConventionOpenZeppelinContracts(t *testing.T) {
	t.Setenv("FOUNDRY_PROFILE", "")
	root := t.TempDir()
	want := filepath.Join(root, "lib", "openzeppelin-contracts", "contracts", "token", "ERC20", "ERC20.sol")
	writeResolverTarget(t, want)

	got, err := NewResolver(root).Resolve("@openzeppelin/contracts/token/ERC20/ERC20.sol", filepath.Join(root, "src", "A.sol"))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if filepath.Clean(got) != filepath.Clean(want) {
		t.Fatalf("Resolve = %q, want conventional OZ target %q", got, want)
	}
}

func TestResolveConventionOpenZeppelinNodeModules(t *testing.T) {
	t.Setenv("FOUNDRY_PROFILE", "")
	root := t.TempDir()
	want := filepath.Join(root, "node_modules", "@openzeppelin", "contracts", "access", "Ownable.sol")
	writeResolverTarget(t, want)

	got, err := NewResolver(root).Resolve("@openzeppelin/contracts/access/Ownable.sol", filepath.Join(root, "src", "A.sol"))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if filepath.Clean(got) != filepath.Clean(want) {
		t.Fatalf("Resolve = %q, want conventional OZ node_modules target %q", got, want)
	}
}

// Convention must win before the fuzzy suffix matcher: a decoy .sol with the
// same basename elsewhere in lib/ must not divert a known-prefix import.
func TestResolveConventionPreferredOverSuffix(t *testing.T) {
	t.Setenv("FOUNDRY_PROFILE", "")
	root := t.TempDir()
	want := filepath.Join(root, "lib", "prb-math", "src", "UD60x18.sol")
	writeResolverTarget(t, want)
	writeResolverTarget(t, filepath.Join(root, "lib", "decoy", "src", "UD60x18.sol"))

	got, err := NewResolver(root).Resolve("@prb/math/src/UD60x18.sol", filepath.Join(root, "src", "A.sol"))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if filepath.Clean(got) != filepath.Clean(want) {
		t.Fatalf("Resolve = %q, want conventional target %q despite decoy", got, want)
	}
}

// Unknown prefix, but a unique file shares a >=2-segment suffix on disk.
func TestResolveSuffixMatchUnique(t *testing.T) {
	t.Setenv("FOUNDRY_PROFILE", "")
	root := t.TempDir()
	want := filepath.Join(root, "lib", "somelib", "contracts", "utils", "Strings.sol")
	writeResolverTarget(t, want)

	got, err := NewResolver(root).Resolve("@weird/unpredictable/utils/Strings.sol", filepath.Join(root, "src", "A.sol"))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if filepath.Clean(got) != filepath.Clean(want) {
		t.Fatalf("Resolve = %q, want unique suffix match %q", got, want)
	}
}

// Two files tie at the longest suffix — the matcher must abstain, leaving the
// import unresolved rather than guessing.
func TestResolveSuffixMatchAmbiguousAbstains(t *testing.T) {
	t.Setenv("FOUNDRY_PROFILE", "")
	root := t.TempDir()
	writeResolverTarget(t, filepath.Join(root, "lib", "a", "src", "Token.sol"))
	writeResolverTarget(t, filepath.Join(root, "lib", "b", "src", "Token.sol"))

	const importPath = "@x/pkg/src/Token.sol"
	got, err := NewResolver(root).Resolve(importPath, filepath.Join(root, "src", "A.sol"))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got != importPath {
		t.Fatalf("Resolve = %q, want unresolved (%q) on ambiguous suffix", got, importPath)
	}
}

// A bare basename-only overlap (one segment) is too weak to accept.
func TestResolveSuffixMatchSingleSegmentRejected(t *testing.T) {
	t.Setenv("FOUNDRY_PROFILE", "")
	root := t.TempDir()
	writeResolverTarget(t, filepath.Join(root, "lib", "somelib", "src", "Lonely.sol"))

	const importPath = "@x/Lonely.sol"
	got, err := NewResolver(root).Resolve(importPath, filepath.Join(root, "src", "A.sol"))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got != importPath {
		t.Fatalf("Resolve = %q, want unresolved (%q) on single-segment overlap", got, importPath)
	}
}

// Heuristics are a last resort: an explicit remapping to an existing file must
// still win over both of them.
func TestResolveRemappingWinsOverHeuristics(t *testing.T) {
	t.Setenv("FOUNDRY_PROFILE", "")
	root := t.TempDir()
	remapped := filepath.Join(root, "vendor", "math", "UD60x18.sol")
	writeResolverTarget(t, remapped)
	writeResolverTarget(t, filepath.Join(root, "lib", "prb-math", "src", "UD60x18.sol"))

	res := NewResolver(root)
	res.AddRemapping("@prb/math/", "vendor/math/")

	got, err := res.Resolve("@prb/math/UD60x18.sol", filepath.Join(root, "src", "A.sol"))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if filepath.Clean(got) != filepath.Clean(remapped) {
		t.Fatalf("Resolve = %q, want explicit remapping target %q", got, remapped)
	}
}
