package reader

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/th13vn/w3goaudit/pkg/logging"
)

// Remapping represents an import remapping
type Remapping struct {
	Context string // Optional context (usually empty)
	From    string // Import path prefix to match
	To      string // Local path to map to
}

// subProject holds the remappings for one Foundry/Hardhat project rooted at Root.
// In a monorepo the scan root (e.g. a git root) contains several of these, each
// with its own foundry.toml/remappings.txt and its own lib/.
type subProject struct {
	Root       string
	Remappings []Remapping
}

// Resolver handles import resolution and remapping.
//
// ProjectRoot is the top-level scan root (often a git root). Remappings holds
// the remappings discovered at that root. In a monorepo the root frequently has
// no remappings at all — each file's imports are resolved against its nearest
// enclosing sub-project instead (see subProjectFor), so that per-package
// foundry.toml remappings and per-package lib/ directories are honored.
type Resolver struct {
	ProjectRoot string
	Remappings  []Remapping
	Framework   Framework
	logger      *logging.Logger
	legacy      bool

	// subCache memoizes per-sub-project remappings keyed by the sub-project root.
	subCache map[string]*subProject
}

// NewResolver creates an import resolver using the legacy package-global
// verbose configuration.
func NewResolver(projectRoot string) *Resolver {
	return newResolver(projectRoot, nil, true)
}

func newResolver(projectRoot string, logger *logging.Logger, legacy bool) *Resolver {
	if logger == nil && !legacy {
		logger = logging.Disabled()
	}
	framework := DetectFramework(projectRoot)
	r := &Resolver{
		ProjectRoot: projectRoot,
		Framework:   framework,
		Remappings:  make([]Remapping, 0),
		subCache:    make(map[string]*subProject),
		logger:      logger,
		legacy:      legacy,
	}

	// Auto-load remappings for the top-level root.
	r.loadRemappings()

	return r
}

func (r *Resolver) logf(format string, args ...any) {
	if r != nil && r.legacy {
		VerboseLog(format, args...)
		return
	}
	if r != nil {
		r.logger.Printf(format, args...)
	}
}

// loadRemappings loads remappings for the top-level project root.
func (r *Resolver) loadRemappings() {
	r.Remappings = append(r.Remappings, loadRemappingsFor(r.ProjectRoot, r.Framework, r.logf)...)
	r.logf("Loaded %d remappings for root %s (framework: %v)", len(r.Remappings), r.ProjectRoot, r.Framework)
}

// loadRemappingsFor gathers all remappings that apply within a single project
// root: remappings.txt entries, foundry.toml `remappings = [...]` entries, and
// framework-derived defaults (forge-std, lib/*, node_modules/@openzeppelin).
// Targets are kept as written (often relative to root); Resolve joins them
// against the owning root.
func loadRemappingsFor(root string, framework Framework, logf func(string, ...any)) []Remapping {
	var out []Remapping

	// remappings.txt (Foundry style)
	remappingsPath := filepath.Join(root, "remappings.txt")
	if remappings, err := parseRemappingsFile(remappingsPath); err == nil {
		logf("  Loaded %d remappings from %s", len(remappings), remappingsPath)
		out = append(out, remappings...)
	} else if !os.IsNotExist(err) {
		logf("  Could not parse remappings from %s: %v", remappingsPath, err)
	}

	// foundry.toml `remappings = [...]` array (used when auto_detect_remappings
	// is off and there is no remappings.txt — common in modern Foundry repos).
	foundryToml := filepath.Join(root, "foundry.toml")
	if remappings, err := parseFoundryTomlRemappings(foundryToml); err == nil && len(remappings) > 0 {
		logf("  Loaded %d remappings from %s", len(remappings), foundryToml)
		out = append(out, remappings...)
	} else if err != nil && !os.IsNotExist(err) {
		logf("  Could not parse remappings from %s: %v", foundryToml, err)
	}

	// Framework-derived defaults.
	out = append(out, defaultRemappings(root, framework)...)
	return out
}

// defaultRemappings returns framework-specific default remappings rooted at root.
func defaultRemappings(root string, framework Framework) []Remapping {
	var out []Remapping
	switch framework {
	case FrameworkFoundry:
		// Add forge-std if lib/forge-std exists
		forgeStd := filepath.Join(root, "lib", "forge-std", "src")
		if _, err := os.Stat(forgeStd); err == nil {
			out = append(out, Remapping{From: "forge-std/", To: forgeStd + "/"})
		}

		// Add lib/* remappings
		libDir := filepath.Join(root, "lib")
		if entries, err := os.ReadDir(libDir); err == nil {
			for _, entry := range entries {
				if entry.IsDir() {
					name := entry.Name()
					srcPath := filepath.Join(libDir, name, "src")
					if _, err := os.Stat(srcPath); err == nil {
						out = append(out, Remapping{From: name + "/", To: srcPath + "/"})
					}
				}
			}
		}

	case FrameworkHardhat:
		// Add @openzeppelin if node_modules/@openzeppelin exists
		ozPath := filepath.Join(root, "node_modules", "@openzeppelin", "contracts")
		if _, err := os.Stat(ozPath); err == nil {
			out = append(out, Remapping{From: "@openzeppelin/contracts/", To: ozPath + "/"})
		}
	}
	return out
}

// hasProjectConfig reports whether dir looks like a Foundry/Hardhat/Truffle
// project root (carries a config file that defines source/remapping layout).
func hasProjectConfig(dir string) bool {
	for _, marker := range []string{"foundry.toml", "remappings.txt", "hardhat.config.js", "hardhat.config.ts", "truffle-config.js"} {
		if _, err := os.Stat(filepath.Join(dir, marker)); err == nil {
			return true
		}
	}
	return false
}

// findSubRoot walks up from fromFile to the nearest enclosing project root,
// bounded by ProjectRoot. If no nested project config is found, ProjectRoot is
// returned. This is what makes monorepos work: a file in
// packages/eip-3/src/Foo.sol resolves against packages/eip-3, not the git root.
func (r *Resolver) findSubRoot(fromFile string) string {
	rootBoundary, err := canonicalBoundaryPath(r.ProjectRoot)
	if err != nil {
		return r.ProjectRoot
	}
	dir, err := filepath.Abs(filepath.Dir(fromFile))
	if err != nil {
		return r.ProjectRoot
	}
	dir = filepath.Clean(dir)
	dirBoundary, err := canonicalBoundaryPath(dir)
	if err != nil || !pathWithinRoot(rootBoundary, dirBoundary) {
		return r.ProjectRoot
	}

	for {
		if dirBoundary == rootBoundary {
			return r.ProjectRoot
		}
		if hasProjectConfig(dir) {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return r.ProjectRoot
		}
		parentBoundary, err := canonicalBoundaryPath(parent)
		if err != nil || !pathWithinRoot(rootBoundary, parentBoundary) {
			return r.ProjectRoot
		}
		dir = parent
		dirBoundary = parentBoundary
	}
}

// canonicalBoundaryPath resolves symlinks in the nearest existing ancestor and
// then reattaches any missing suffix. This keeps containment comparisons stable
// on systems where temporary paths such as /var resolve through /private/var.
func canonicalBoundaryPath(path string) (string, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	absPath = filepath.Clean(absPath)

	current := absPath
	var suffix []string
	for {
		resolved, resolveErr := filepath.EvalSymlinks(current)
		if resolveErr == nil {
			for i := len(suffix) - 1; i >= 0; i-- {
				resolved = filepath.Join(resolved, suffix[i])
			}
			return filepath.Clean(resolved), nil
		}
		if !os.IsNotExist(resolveErr) {
			return "", resolveErr
		}
		parent := filepath.Dir(current)
		if parent == current {
			return absPath, nil
		}
		suffix = append(suffix, filepath.Base(current))
		current = parent
	}
}

func pathWithinRoot(root, candidate string) bool {
	relative, err := filepath.Rel(root, candidate)
	if err != nil || filepath.IsAbs(relative) {
		return false
	}
	return relative == "." || (relative != ".." && !strings.HasPrefix(relative, ".."+string(os.PathSeparator)))
}

// subProjectFor returns the sub-project (root + remappings) that owns fromFile.
// The top-level root reuses the live r.Remappings slice so that AddRemapping and
// the eager root load keep working; nested sub-projects are loaded once and
// memoized.
func (r *Resolver) subProjectFor(fromFile string) *subProject {
	root := r.findSubRoot(fromFile)
	if root == r.ProjectRoot {
		return &subProject{Root: r.ProjectRoot, Remappings: r.Remappings}
	}
	if sp, ok := r.subCache[root]; ok {
		return sp
	}
	sp := &subProject{Root: root, Remappings: loadRemappingsFor(root, DetectFramework(root), r.logf)}
	r.logf("Discovered sub-project %s with %d remappings", root, len(sp.Remappings))
	r.subCache[root] = sp
	return sp
}

// Resolve resolves an import path to an absolute file path
func (r *Resolver) Resolve(importPath string, fromFile string) (string, error) {
	r.logf("Resolving import: '%s' from file: %s", importPath, fromFile)

	// Handle relative imports (independent of any project root).
	if strings.HasPrefix(importPath, "./") || strings.HasPrefix(importPath, "../") {
		baseDir := filepath.Dir(fromFile)
		resolved := filepath.Join(baseDir, importPath)
		absPath, err := filepath.Abs(resolved)
		r.logf("  → Relative import resolved to: %s", absPath)
		if _, statErr := os.Stat(absPath); statErr == nil {
			r.logf("  ✓ File exists")
		} else {
			r.logf("  ✗ File NOT found")
		}
		return absPath, err
	}

	// Resolve against the sub-project that owns fromFile so that per-package
	// remappings and per-package lib/ directories are honored in monorepos.
	sub := r.subProjectFor(fromFile)
	r.logf("  Sub-project root: %s (%d remappings)", sub.Root, len(sub.Remappings))

	// Context specificity takes precedence over import-prefix specificity;
	// declaration order breaks exact ties without mutating configured mappings.
	matchingRemappings := applicableRemappings(sub.Remappings, sub.Root, fromFile, importPath)
	for i, remap := range matchingRemappings {
		r.logf("  Trying remapping [%d]: context '%s', '%s' → '%s'", i, remap.Context, remap.From, remap.To)
		resolved := strings.Replace(importPath, remap.From, remap.To, 1)
		if !filepath.IsAbs(resolved) {
			resolved = filepath.Join(sub.Root, resolved)
		}
		absPath, err := filepath.Abs(resolved)
		if err != nil {
			r.logf("  ✗ Could not make remapped path absolute: %v", err)
			continue
		}
		r.logf("  → Remapped to: %s", absPath)
		if info, statErr := os.Stat(absPath); statErr == nil && info.Mode().IsRegular() {
			r.logf("  ✓ Regular file exists - using this remapping")
			return absPath, nil
		} else if statErr != nil {
			r.logf("  ✗ File NOT found: %v", statErr)
		} else {
			r.logf("  ✗ Candidate is not a regular file")
		}
	}

	// Try node_modules
	nodeModulesPath := filepath.Join(sub.Root, "node_modules", importPath)
	r.logf("  Trying node_modules: %s", nodeModulesPath)
	if info, err := os.Stat(nodeModulesPath); err == nil && info.Mode().IsRegular() {
		r.logf("  ✓ Found in node_modules")
		return filepath.Abs(nodeModulesPath)
	}

	// Try lib directory (Foundry)
	libPath := filepath.Join(sub.Root, "lib", importPath)
	r.logf("  Trying lib directory: %s", libPath)
	if info, err := os.Stat(libPath); err == nil && info.Mode().IsRegular() {
		r.logf("  ✓ Found in lib")
		return filepath.Abs(libPath)
	}

	// Try relative to the sub-project root
	rootPath := filepath.Join(sub.Root, importPath)
	r.logf("  Trying project root: %s", rootPath)
	if info, err := os.Stat(rootPath); err == nil && info.Mode().IsRegular() {
		r.logf("  ✓ Found in project root")
		return filepath.Abs(rootPath)
	}

	// Return as-is if nothing found
	r.logf("  ✗ Import NOT resolved, returning as-is: %s", importPath)
	return importPath, nil
}

// AddRemapping adds a custom remapping
func (r *Resolver) AddRemapping(from, to string) {
	r.Remappings = append(r.Remappings, Remapping{
		From: from,
		To:   to,
	})
}
