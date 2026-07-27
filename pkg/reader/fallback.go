package reader

import (
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Fallback import-resolution heuristics.
//
// These run only after remappings and the plain node_modules/lib/root stat
// fallbacks have all failed, i.e. for an import that would otherwise be recorded
// as unresolved. They exist because verified sources fetched from block
// explorers (Etherscan standard-JSON / multi-file) frequently ship import
// prefixes such as "@prb/math/" or "@openzeppelin/contracts/" without a
// remappings file, so the prefix cannot be predicted — only reconstructed.
//
// Both heuristics are conservative: they accept only an existing regular file
// that is contained within the owning sub-project, and the suffix matcher
// abstains whenever the longest match is not unique. They never invent a path;
// on failure resolution continues to return the import unchanged so the
// unresolved-import diagnostic is still recorded.

// conventionalLayout maps a well-known import prefix to the directory layouts
// dependency managers conventionally install it under, relative to a project
// root. Targets are tried in order; the first existing regular file wins.
type conventionalLayout struct {
	prefix  string
	targets []string
}

// conventionalLayouts is sorted longest-prefix-first by init() so that a more
// specific prefix (e.g. "@openzeppelin/contracts/") is attempted before a
// broader one (e.g. "@openzeppelin/"). Declaration order is preserved for ties.
var conventionalLayouts = []conventionalLayout{
	{prefix: "@openzeppelin/contracts-upgradeable/", targets: []string{
		"lib/openzeppelin-contracts-upgradeable/contracts/",
		"node_modules/@openzeppelin/contracts-upgradeable/",
	}},
	{prefix: "@openzeppelin/contracts/", targets: []string{
		"lib/openzeppelin-contracts/contracts/",
		"node_modules/@openzeppelin/contracts/",
	}},
	{prefix: "@openzeppelin/", targets: []string{
		"lib/openzeppelin-contracts/",
		"node_modules/@openzeppelin/",
	}},
	// prb-* imports usually already carry the intermediate dir (e.g.
	// "@prb/math/src/UD60x18.sol"), but some spellings omit it. Try the bare
	// target first, then the src/-suffixed variant, so either form resolves.
	{prefix: "@prb/math/", targets: []string{
		"lib/prb-math/", "node_modules/@prb/math/",
		"lib/prb-math/src/", "node_modules/@prb/math/src/",
	}},
	{prefix: "@prb/test/", targets: []string{
		"lib/prb-test/", "node_modules/@prb/test/",
		"lib/prb-test/src/", "node_modules/@prb/test/src/",
	}},
	{prefix: "prb-math/", targets: []string{
		"node_modules/prb-math/", "lib/prb-math/",
		"node_modules/prb-math/src/", "lib/prb-math/src/",
	}},
	{prefix: "@prb-math/", targets: []string{"lib/prb-math/", "lib/prb-math/src/"}},
	{prefix: "forge-std/", targets: []string{"lib/forge-std/src/"}},
	{prefix: "ds-test/", targets: []string{"lib/ds-test/src/", "lib/forge-std/lib/ds-test/src/"}},
	{prefix: "@rari-capital/solmate/", targets: []string{"lib/solmate/", "node_modules/@rari-capital/solmate/"}},
	{prefix: "solmate/", targets: []string{"lib/solmate/src/", "node_modules/solmate/src/"}},
	{prefix: "@solmate/", targets: []string{"lib/solmate/src/"}},
	{prefix: "solady/", targets: []string{"lib/solady/src/", "node_modules/solady/src/"}},
	{prefix: "@uniswap/v2-core/", targets: []string{"node_modules/@uniswap/v2-core/", "lib/v2-core/"}},
	{prefix: "@uniswap/v2-periphery/", targets: []string{"node_modules/@uniswap/v2-periphery/", "lib/v2-periphery/"}},
	{prefix: "@uniswap/v3-core/", targets: []string{"node_modules/@uniswap/v3-core/", "lib/v3-core/"}},
	{prefix: "@uniswap/v3-periphery/", targets: []string{"node_modules/@uniswap/v3-periphery/", "lib/v3-periphery/"}},
}

func init() {
	sort.SliceStable(conventionalLayouts, func(i, j int) bool {
		return len(conventionalLayouts[i].prefix) > len(conventionalLayouts[j].prefix)
	})
}

// suffixWalkFileLimit bounds how many .sol files the suffix matcher inspects so
// that a large node_modules tree cannot make a last-resort lookup pathological.
const suffixWalkFileLimit = 20000

// resolveByConvention rewrites importPath using the conventional dependency
// layouts and returns the first candidate that is an existing regular file
// contained within root.
func resolveByConvention(root, importPath string) (string, bool) {
	for _, layout := range conventionalLayouts {
		if !strings.HasPrefix(importPath, layout.prefix) {
			continue
		}
		rest := filepath.FromSlash(importPath[len(layout.prefix):])
		for _, target := range layout.targets {
			candidate := filepath.Join(root, filepath.FromSlash(target), rest)
			if isRegularFile(candidate) && withinRoot(root, candidate) {
				return candidate, true
			}
		}
	}
	return "", false
}

// resolveBySuffixMatch finds the .sol file under root's lib/ and node_modules/
// whose path shares the longest trailing path-segment suffix with importPath.
// A match must align at least two segments (<dir>/<file>.sol) and be unique at
// the longest length; otherwise the matcher abstains rather than guess.
func (r *Resolver) resolveBySuffixMatch(root, importPath string) (string, bool) {
	wantSegs := pathSegments(importPath)
	if len(wantSegs) == 0 || !strings.HasSuffix(wantSegs[len(wantSegs)-1], ".sol") {
		return "", false
	}

	bestPath := ""
	bestScore := 0
	ambiguous := false
	examined := 0

	for _, depDir := range []string{"lib", "node_modules"} {
		base := filepath.Join(root, depDir)
		_ = filepath.WalkDir(base, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				// Tolerate unreadable subtrees; skip a bad directory, ignore a bad file.
				if d != nil && d.IsDir() {
					return fs.SkipDir
				}
				return nil
			}
			if d.IsDir() {
				// Skip VCS and hidden directories; they never hold dependency sources.
				if name := d.Name(); path != base && strings.HasPrefix(name, ".") {
					return fs.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(d.Name(), ".sol") {
				return nil
			}
			examined++
			if examined > suffixWalkFileLimit {
				return fs.SkipAll
			}
			score := commonSuffixSegments(wantSegs, pathSegments(filepath.ToSlash(path)))
			if score < 2 {
				return nil
			}
			switch {
			case score > bestScore:
				bestScore, bestPath, ambiguous = score, path, false
			case score == bestScore && path != bestPath:
				ambiguous = true
			}
			return nil
		})
	}

	if bestScore < 2 || ambiguous || !withinRoot(root, bestPath) {
		return "", false
	}
	return bestPath, true
}

// pathSegments splits a slash-or-OS path into its non-empty segments.
func pathSegments(p string) []string {
	p = filepath.ToSlash(p)
	parts := strings.Split(p, "/")
	out := parts[:0]
	for _, part := range parts {
		if part != "" && part != "." {
			out = append(out, part)
		}
	}
	return out
}

// commonSuffixSegments counts trailing segments that a and b share, compared
// case-sensitively to match Solidity's case-sensitive import semantics.
func commonSuffixSegments(a, b []string) int {
	i, j, n := len(a)-1, len(b)-1, 0
	for i >= 0 && j >= 0 && a[i] == b[j] {
		n++
		i--
		j--
	}
	return n
}

func isRegularFile(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}

// withinRoot reports whether candidate is contained within root after resolving
// symlinks, mirroring the containment rule enforced for sub-project config.
func withinRoot(root, candidate string) bool {
	if candidate == "" {
		return false
	}
	rootBoundary, err := canonicalBoundaryPath(root)
	if err != nil {
		return false
	}
	candidateBoundary, err := canonicalBoundaryPath(candidate)
	if err != nil {
		return false
	}
	return pathWithinRoot(rootBoundary, candidateBoundary)
}
