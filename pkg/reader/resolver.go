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

// Resolver handles import resolution and remapping
type Resolver struct {
	ProjectRoot string
	Remappings  []Remapping
	Framework   Framework
}

// NewResolver creates a new import resolver
func NewResolver(projectRoot string) *Resolver {
	framework := DetectFramework(projectRoot)
	r := &Resolver{
		ProjectRoot: projectRoot,
		Framework:   framework,
		Remappings:  make([]Remapping, 0),
	}

	// Auto-load remappings
	r.loadRemappings()

	return r
}

// loadRemappings loads remappings from various sources
func (r *Resolver) loadRemappings() {
	// Try remappings.txt (Foundry style)
	remappingsPath := filepath.Join(r.ProjectRoot, "remappings.txt")
	VerboseLog("Loading remappings from: %s", remappingsPath)
	if remappings, err := parseRemappingsFile(remappingsPath); err == nil {
		VerboseLog("  Loaded %d remappings from file", len(remappings))
		for i, remap := range remappings {
			VerboseLog("    [%d] %s → %s", i, remap.From, remap.To)
		}
		r.Remappings = append(r.Remappings, remappings...)
	} else {
		VerboseLog("  Failed to load remappings file: %v", err)
	}

	// Add default remappings based on framework
	beforeCount := len(r.Remappings)
	r.addDefaultRemappings()
	afterCount := len(r.Remappings)
	VerboseLog("Added %d default remappings (framework: %v)", afterCount-beforeCount, r.Framework)
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

// addDefaultRemappings adds framework-specific default remappings
func (r *Resolver) addDefaultRemappings() {
	switch r.Framework {
	case FrameworkFoundry:
		// Add forge-std if lib/forge-std exists
		forgeStd := filepath.Join(r.ProjectRoot, "lib", "forge-std", "src")
		if _, err := os.Stat(forgeStd); err == nil {
			r.Remappings = append(r.Remappings, Remapping{
				From: "forge-std/",
				To:   forgeStd + "/",
			})
		}

		// Add lib/* remappings
		libDir := filepath.Join(r.ProjectRoot, "lib")
		if entries, err := os.ReadDir(libDir); err == nil {
			for _, entry := range entries {
				if entry.IsDir() {
					name := entry.Name()
					srcPath := filepath.Join(libDir, name, "src")
					if _, err := os.Stat(srcPath); err == nil {
						r.Remappings = append(r.Remappings, Remapping{
							From: name + "/",
							To:   srcPath + "/",
						})
					}
				}
			}
		}

	case FrameworkHardhat:
		// Add @openzeppelin if node_modules/@openzeppelin exists
		ozPath := filepath.Join(r.ProjectRoot, "node_modules", "@openzeppelin", "contracts")
		if _, err := os.Stat(ozPath); err == nil {
			r.Remappings = append(r.Remappings, Remapping{
				From: "@openzeppelin/contracts/",
				To:   ozPath + "/",
			})
		}
	}
}

// Resolve resolves an import path to an absolute file path
func (r *Resolver) Resolve(importPath string, fromFile string) (string, error) {
	VerboseLog("Resolving import: '%s' from file: %s", importPath, fromFile)
	VerboseLog("  Project root: %s", r.ProjectRoot)
	VerboseLog("  Available remappings: %d", len(r.Remappings))
	
	// Handle relative imports
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

	// Try remappings
	for i, remap := range r.Remappings {
		VerboseLog("  Trying remapping [%d]: '%s' → '%s'", i, remap.From, remap.To)
		if strings.HasPrefix(importPath, remap.From) {
			resolved := strings.Replace(importPath, remap.From, remap.To, 1)
			if !filepath.IsAbs(resolved) {
				resolved = filepath.Join(r.ProjectRoot, resolved)
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
	nodeModulesPath := filepath.Join(r.ProjectRoot, "node_modules", importPath)
	VerboseLog("  Trying node_modules: %s", nodeModulesPath)
	if _, err := os.Stat(nodeModulesPath); err == nil {
		VerboseLog("  ✓ Found in node_modules")
		return filepath.Abs(nodeModulesPath)
	}

	// Try lib directory (Foundry)
	libPath := filepath.Join(r.ProjectRoot, "lib", importPath)
	VerboseLog("  Trying lib directory: %s", libPath)
	if _, err := os.Stat(libPath); err == nil {
		VerboseLog("  ✓ Found in lib")
		return filepath.Abs(libPath)
	}

	// Try relative to project root
	rootPath := filepath.Join(r.ProjectRoot, importPath)
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
