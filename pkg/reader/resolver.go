package reader

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"
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

	// subCache memoizes per-sub-project remappings keyed by the sub-project root.
	subCache map[string]*subProject
}

// NewResolver creates a new import resolver
func NewResolver(projectRoot string) *Resolver {
	framework := DetectFramework(projectRoot)
	r := &Resolver{
		ProjectRoot: projectRoot,
		Framework:   framework,
		Remappings:  make([]Remapping, 0),
		subCache:    make(map[string]*subProject),
	}

	// Auto-load remappings for the top-level root.
	r.loadRemappings()

	return r
}

// loadRemappings loads remappings for the top-level project root.
func (r *Resolver) loadRemappings() {
	r.Remappings = append(r.Remappings, loadRemappingsFor(r.ProjectRoot, r.Framework)...)
	VerboseLog("Loaded %d remappings for root %s (framework: %v)", len(r.Remappings), r.ProjectRoot, r.Framework)
}

// loadRemappingsFor gathers all remappings that apply within a single project
// root: remappings.txt entries, foundry.toml `remappings = [...]` entries, and
// framework-derived defaults (forge-std, lib/*, node_modules/@openzeppelin).
// Targets are kept as written (often relative to root); Resolve joins them
// against the owning root.
func loadRemappingsFor(root string, framework Framework) []Remapping {
	var out []Remapping

	// remappings.txt (Foundry style)
	remappingsPath := filepath.Join(root, "remappings.txt")
	if remappings, err := parseRemappingsFile(remappingsPath); err == nil {
		VerboseLog("  Loaded %d remappings from %s", len(remappings), remappingsPath)
		out = append(out, remappings...)
	}

	// foundry.toml `remappings = [...]` array (used when auto_detect_remappings
	// is off and there is no remappings.txt — common in modern Foundry repos).
	foundryToml := filepath.Join(root, "foundry.toml")
	if remappings, err := parseFoundryTomlRemappings(foundryToml); err == nil && len(remappings) > 0 {
		VerboseLog("  Loaded %d remappings from %s", len(remappings), foundryToml)
		out = append(out, remappings...)
	}

	// Framework-derived defaults.
	out = append(out, defaultRemappings(root, framework)...)
	return out
}

// parseRemappingsFile parses a remappings.txt file
func parseRemappingsFile(path string) ([]Remapping, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var remappings []Remapping
	scanner := bufio.NewScanner(file)

	// Pattern: context:from=to or from=to
	pattern := regexp.MustCompile(`^(?:([^:]*):)?([^=]+)=(.+)$`)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		matches := pattern.FindStringSubmatch(line)
		if matches != nil {
			remappings = append(remappings, Remapping{
				Context: matches[1],
				From:    matches[2],
				To:      matches[3],
			})
		}
	}

	return remappings, scanner.Err()
}

// parseFoundryTomlRemappings extracts the `remappings = [...]` entries from a
// foundry.toml file. It collects every remappings array in the file (across
// profiles) and parses each quoted "from=to" entry. Returns an empty slice if
// the file has no remappings; an error only if the file cannot be read.
func parseFoundryTomlRemappings(path string) ([]Remapping, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var remappings []Remapping
	// Match `remappings = [ ... ]`, possibly spanning multiple lines.
	arrayPattern := regexp.MustCompile(`(?s)remappings\s*=\s*\[(.*?)\]`)
	entryPattern := regexp.MustCompile(`["']([^"']+)["']`)
	for _, block := range arrayPattern.FindAllStringSubmatch(string(content), -1) {
		for _, entry := range entryPattern.FindAllStringSubmatch(block[1], -1) {
			line := strings.TrimSpace(entry[1])
			if from, to, ok := strings.Cut(line, "="); ok {
				remappings = append(remappings, Remapping{From: from, To: to})
			}
		}
	}
	return remappings, nil
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
	dir := filepath.Dir(fromFile)
	for {
		if hasProjectConfig(dir) {
			return dir
		}
		if dir == r.ProjectRoot {
			return r.ProjectRoot
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			// Walked above the scan root without finding a config.
			return r.ProjectRoot
		}
		dir = parent
	}
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
	sp := &subProject{Root: root, Remappings: loadRemappingsFor(root, DetectFramework(root))}
	VerboseLog("Discovered sub-project %s with %d remappings", root, len(sp.Remappings))
	r.subCache[root] = sp
	return sp
}

// Resolve resolves an import path to an absolute file path
func (r *Resolver) Resolve(importPath string, fromFile string) (string, error) {
	VerboseLog("Resolving import: '%s' from file: %s", importPath, fromFile)

	// Handle relative imports (independent of any project root).
	if strings.HasPrefix(importPath, "./") || strings.HasPrefix(importPath, "../") {
		baseDir := filepath.Dir(fromFile)
		resolved := filepath.Join(baseDir, importPath)
		absPath, err := filepath.Abs(resolved)
		VerboseLog("  → Relative import resolved to: %s", absPath)
		if _, statErr := os.Stat(absPath); statErr == nil {
			VerboseLog("  ✓ File exists")
		} else {
			VerboseLog("  ✗ File NOT found")
		}
		return absPath, err
	}

	// Resolve against the sub-project that owns fromFile so that per-package
	// remappings and per-package lib/ directories are honored in monorepos.
	sub := r.subProjectFor(fromFile)
	VerboseLog("  Sub-project root: %s (%d remappings)", sub.Root, len(sub.Remappings))

	// Try remappings (targets are relative to the sub-project root).
	for i, remap := range sub.Remappings {
		VerboseLog("  Trying remapping [%d]: '%s' → '%s'", i, remap.From, remap.To)
		if strings.HasPrefix(importPath, remap.From) {
			resolved := strings.Replace(importPath, remap.From, remap.To, 1)
			if !filepath.IsAbs(resolved) {
				resolved = filepath.Join(sub.Root, resolved)
			}
			absPath, err := filepath.Abs(resolved)
			VerboseLog("  → Remapped to: %s", absPath)
			if _, statErr := os.Stat(absPath); statErr == nil {
				VerboseLog("  ✓ File exists - using this remapping")
			} else {
				VerboseLog("  ✗ File NOT found: %v", statErr)
			}
			return absPath, err
		}
	}

	// Try node_modules
	nodeModulesPath := filepath.Join(sub.Root, "node_modules", importPath)
	VerboseLog("  Trying node_modules: %s", nodeModulesPath)
	if _, err := os.Stat(nodeModulesPath); err == nil {
		VerboseLog("  ✓ Found in node_modules")
		return filepath.Abs(nodeModulesPath)
	}

	// Try lib directory (Foundry)
	libPath := filepath.Join(sub.Root, "lib", importPath)
	VerboseLog("  Trying lib directory: %s", libPath)
	if _, err := os.Stat(libPath); err == nil {
		VerboseLog("  ✓ Found in lib")
		return filepath.Abs(libPath)
	}

	// Try relative to the sub-project root
	rootPath := filepath.Join(sub.Root, importPath)
	VerboseLog("  Trying project root: %s", rootPath)
	if _, err := os.Stat(rootPath); err == nil {
		VerboseLog("  ✓ Found in project root")
		return filepath.Abs(rootPath)
	}

	// Return as-is if nothing found
	VerboseLog("  ✗ Import NOT resolved, returning as-is: %s", importPath)
	return importPath, nil
}

// AddRemapping adds a custom remapping
func (r *Resolver) AddRemapping(from, to string) {
	r.Remappings = append(r.Remappings, Remapping{
		From: from,
		To:   to,
	})
}
