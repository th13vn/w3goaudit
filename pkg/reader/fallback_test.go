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

// TestResolveSuffixMatchTruncatedWalkAbstains pins that hitting the walk file cap
// makes the suffix matcher abstain rather than answer from a partial view.
//
// The cap bounds cost on huge dependency trees, but uniqueness is only meaningful
// over a COMPLETE view: here two equally-good candidates exist, so a full walk
// correctly sees ambiguity and abstains. A truncated walk sees only the first one,
// concludes "unique", and binds the import to it — silently picking the wrong
// dependency. Abstaining instead leaves the import unresolved, which the reader
// records as a durable `import.unresolved` diagnostic.
func TestResolveSuffixMatchTruncatedWalkAbstains(t *testing.T) {
	t.Setenv("FOUNDRY_PROFILE", "")
	root := t.TempDir()

	// Two candidates aligning the same three trailing segments. Walk order is
	// lexical, so "aaa" is examined first and "zzz" last.
	first := filepath.Join(root, "lib", "aaa", "some-dep", "src", "Target.sol")
	second := filepath.Join(root, "lib", "zzz", "some-dep", "src", "Target.sol")
	writeResolverTarget(t, first)
	writeResolverTarget(t, second)
	// Filler between them so a low cap stops before "zzz" is reached.
	for _, name := range []string{"mmm1", "mmm2", "mmm3"} {
		writeResolverTarget(t, filepath.Join(root, "lib", name, "Filler.sol"))
	}

	// A scoped prefix that no remapping or plain lib/node_modules stat resolves,
	// so the suffix matcher is genuinely the path under test.
	importPath := "@scope/some-dep/src/Target.sol"
	from := filepath.Join(root, "src", "A.sol")

	// Full walk: two equally-good candidates are ambiguous, so it must abstain.
	if got, err := NewResolver(root).Resolve(importPath, from); err == nil &&
		(filepath.Clean(got) == filepath.Clean(first) || filepath.Clean(got) == filepath.Clean(second)) {
		t.Fatalf("baseline: ambiguous candidates must abstain, got %q", got)
	}

	// Truncated walk: sees only "aaa", so uniqueness looks established. It must
	// still abstain rather than resolve from the partial view.
	restore := suffixWalkFileLimit
	suffixWalkFileLimit = 2
	t.Cleanup(func() { suffixWalkFileLimit = restore })

	got, err := NewResolver(root).Resolve(importPath, from)
	if err == nil && filepath.Clean(got) == filepath.Clean(first) {
		t.Fatal("a truncated walk must abstain, not resolve from a partial view")
	}
}
