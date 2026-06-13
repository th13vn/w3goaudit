// Package reader provides file and directory reading capabilities for Solidity projects.
package reader

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/th13vn/w3goaudit/pkg/types"
)

// Reader handles reading Solidity files and directories
type Reader struct {
	// ProjectRoot is the detected project root
	ProjectRoot string

	// SourceFiles is the list of discovered source files
	SourceFiles []*types.SourceFile

	// loadedPaths tracks files already loaded to prevent duplicates
	loadedPaths map[string]bool

	// resolver handles import path resolution
	resolver *Resolver
}

// New creates a new Reader
func New() *Reader {
	return &Reader{
		SourceFiles: make([]*types.SourceFile, 0),
		loadedPaths: make(map[string]bool),
	}
}

// ReadFile reads a single Solidity file
func (r *Reader) ReadFile(path string) (*types.SourceFile, error) {
	absPath, err := canonicalPath(path)
	if err != nil {
		return nil, err
	}

	VerboseLog("Reading file: %s", absPath)

	// Check for .sol extension
	if !strings.HasSuffix(absPath, ".sol") {
		return nil, fmt.Errorf("not a Solidity file: %s", absPath)
	}

	// Skip duplicate loads (symlinks, relative-path aliasing, etc.).
	// Without this check, the same file could be added twice with different
	// path spellings, producing duplicate Contracts entries.
	if r.loadedPaths[absPath] {
		// Return existing entry so callers don't see two copies.
		for _, existing := range r.SourceFiles {
			if existing.Path == absPath {
				return existing, nil
			}
		}
	}

	content, err := os.ReadFile(absPath)
	if err != nil {
		return nil, err
	}

	VerboseLog("Successfully read %d bytes from %s", len(content), filepath.Base(absPath))

	sf := &types.SourceFile{
		Path:     absPath,
		Content:  stripBOM(string(content)),
		Checksum: calculateChecksum(content),
	}

	r.SourceFiles = append(r.SourceFiles, sf)
	r.loadedPaths[absPath] = true
	return sf, nil
}

// ReadFiles reads multiple Solidity files
func (r *Reader) ReadFiles(paths []string) ([]*types.SourceFile, error) {
	var result []*types.SourceFile

	for _, path := range paths {
		sf, err := r.ReadFile(path)
		if err != nil {
			return nil, err
		}
		result = append(result, sf)
	}

	return result, nil
}

// ReadDirectory recursively reads all .sol files in a directory
func (r *Reader) ReadDirectory(dirPath string) ([]*types.SourceFile, error) {
	if dirPath == "" {
		return nil, fmt.Errorf("empty directory path")
	}
	absPath, err := canonicalPath(dirPath)
	if err != nil {
		return nil, err
	}

	VerboseLog("Scanning directory: %s", absPath)

	var result []*types.SourceFile

	err = filepath.Walk(absPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip hidden directories
		if info.IsDir() && strings.HasPrefix(info.Name(), ".") {
			VerboseLog("Skipping hidden directory: %s", info.Name())
			return filepath.SkipDir
		}

		// Skip node_modules, build directories, test folders, and other non-source directories
		if info.IsDir() {
			name := info.Name()
			// Folders to skip:
			// - node_modules: npm dependencies
			// - out, artifacts, cache, forge-cache: build outputs and caches
			// - test, tests: test files
			// - script, scripts: deployment/utility scripts (Foundry)
			// - lib: external dependencies (Foundry)
			// - mocks, mock: mock contracts for testing
			// - broadcast: Foundry broadcast files
			// - coverage: coverage reports
			// - typechain, typechain-types: TypeChain generated files
			// - deployments: Hardhat deployment files
			// - interfaces: often auto-generated or external interfaces
			skipDirs := map[string]bool{
				"node_modules":    true,
				"out":             true,
				"artifacts":       true,
				"cache":           true,
				"forge-cache":     true,
				"test":            true,
				"tests":           true,
				"script":          true,
				"scripts":         true,
				"lib":             true,
				"mocks":           true,
				"mock":            true,
				"broadcast":       true,
				"coverage":        true,
				"typechain":       true,
				"typechain-types": true,
				"deployments":     true,
				"logs":            true,
				"dependencies":    true,
			}
			if skipDirs[name] {
				VerboseLog("Skipping directory: %s", name)
				return filepath.SkipDir
			}
		}

		// Only process .sol files
		if !info.IsDir() && strings.HasSuffix(path, ".sol") {
			sf, err := r.ReadFile(path)
			if err != nil {
				return err
			}
			result = append(result, sf)
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	VerboseLog("Found %d Solidity files in directory", len(result))

	return result, nil
}

// Read reads from a path (automatically detects file or directory)
func (r *Reader) Read(path string) ([]*types.SourceFile, error) {
	if path == "" {
		return nil, fmt.Errorf("empty path: provide a Solidity file or directory to scan")
	}
	absPath, err := canonicalPath(path)
	if err != nil {
		return nil, err
	}

	info, err := os.Stat(absPath)
	if err != nil {
		return nil, err
	}

	if info.IsDir() {
		VerboseLog("Auto-detected directory: %s", absPath)
		return r.ReadDirectory(absPath)
	}

	VerboseLog("Auto-detected file: %s", absPath)
	sf, err := r.ReadFile(absPath)
	if err != nil {
		return nil, err
	}

	return []*types.SourceFile{sf}, nil
}

// GetAllSources returns all discovered source files.
// Returns a fresh slice so callers can't mutate the reader's internal state.
func (r *Reader) GetAllSources() []*types.SourceFile {
	out := make([]*types.SourceFile, len(r.SourceFiles))
	copy(out, r.SourceFiles)
	return out
}

// ResolveImports recursively loads imported files using remapping resolution
func (r *Reader) ResolveImports(projectRoot string) error {
	VerboseLog("Starting import resolution with project root: %s", projectRoot)

	// Initialize resolver if not already done
	if r.resolver == nil {
		r.resolver = NewResolver(projectRoot)
	}

	// Track initially loaded files
	for _, sf := range r.SourceFiles {
		r.loadedPaths[sf.Path] = true
		VerboseLog("Marking initial file as loaded: %s", sf.Path)
	}

	initialCount := len(r.SourceFiles)
	VerboseLog("Processing imports from %d initial files", initialCount)

	// Process imports from all files (loop extends as new files are added)
	for i := 0; i < len(r.SourceFiles); i++ {
		sf := r.SourceFiles[i]
		if err := r.processFileImports(sf); err != nil {
			VerboseLog("Error processing imports from %s: %v", sf.Path, err)
			// Continue processing other files even if one fails
		}
	}

	loadedCount := len(r.SourceFiles) - initialCount
	VerboseLog("Import resolution complete: loaded %d additional files", loadedCount)

	return nil
}

// processFileImports extracts and loads all imports from a single file
func (r *Reader) processFileImports(sf *types.SourceFile) error {
	imports := extractImports(sf.Content)

	if len(imports) == 0 {
		return nil
	}

	VerboseLog("Found %d imports in %s", len(imports), filepath.Base(sf.Path))

	for _, importPath := range imports {
		if err := r.loadImport(importPath, sf.Path); err != nil {
			VerboseLog("  Could not load import '%s': %v", importPath, err)
			// Continue with other imports
		}
	}

	return nil
}

// loadImport resolves and loads a single import if not already loaded
func (r *Reader) loadImport(importPath string, fromFile string) error {
	// Resolve import to absolute path
	resolved, err := r.resolver.Resolve(importPath, fromFile)
	if err != nil {
		return fmt.Errorf("failed to resolve: %w", err)
	}

	// Skip if empty or same as import path (couldn't resolve)
	if resolved == "" || resolved == importPath {
		return fmt.Errorf("could not resolve import path")
	}

	// Canonicalize so that symlink / relative-spelling aliases share one key.
	absPath, err := canonicalPath(resolved)
	if err != nil {
		return fmt.Errorf("failed to canonicalize: %w", err)
	}

	// Skip if already loaded (canonical key — no aliasing).
	if r.loadedPaths[absPath] {
		VerboseLog("  ✓ %s (already loaded)", importPath)
		return nil
	}

	// Check if file exists
	if _, err := os.Stat(absPath); os.IsNotExist(err) {
		return fmt.Errorf("file does not exist: %s", absPath)
	}

	// Load the file
	VerboseLog("  → Loading %s", importPath)
	VerboseLog("    Resolved to: %s", absPath)

	importedFile, err := r.readFileWithoutTracking(absPath)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	// Mark as loaded and add to source files
	r.loadedPaths[absPath] = true
	r.SourceFiles = append(r.SourceFiles, importedFile)

	VerboseLog("  ✓ Loaded successfully (%d bytes)", len(importedFile.Content))

	return nil
}

// readFileWithoutTracking reads a file without adding to loadedPaths
// This is used internally by loadImport which handles tracking
func (r *Reader) readFileWithoutTracking(absPath string) (*types.SourceFile, error) {
	// Check for .sol extension
	if !strings.HasSuffix(absPath, ".sol") {
		return nil, fmt.Errorf("not a Solidity file: %s", absPath)
	}

	content, err := os.ReadFile(absPath)
	if err != nil {
		return nil, err
	}

	return &types.SourceFile{
		Path:     absPath,
		Content:  stripBOM(string(content)),
		Checksum: calculateChecksum(content),
	}, nil
}

// extractImports extracts all import paths from Solidity source code
func extractImports(content string) []string {
	// Match: import "path"; or import { ... } from "path"; or import * as Name from "path";
	pattern := regexp.MustCompile(`import\s+(?:(?:\{[^}]*\}|\*)\s+(?:as\s+\w+\s+)?from\s+)?["']([^"']+)["']`)
	matches := pattern.FindAllStringSubmatch(content, -1)

	var imports []string
	seen := make(map[string]bool)

	for _, match := range matches {
		if len(match) > 1 {
			importPath := match[1]
			// Deduplicate
			if !seen[importPath] {
				imports = append(imports, importPath)
				seen[importPath] = true
			}
		}
	}

	return imports
}

// calculateChecksum returns the SHA256 hash of the content
func calculateChecksum(content []byte) string {
	hash := sha256.Sum256(content)
	return hex.EncodeToString(hash[:])
}

// canonicalPath turns any input path into a single, comparable absolute key.
// It resolves symlinks, collapses `..`/`.` segments, and absolutizes — without
// this, the same file accessed via two spellings would be loaded twice and the
// Database would end up with duplicate Contracts entries.
//
// If EvalSymlinks fails (e.g. the file doesn't exist yet), we fall back to
// `filepath.Abs(filepath.Clean(path))` which is still better than raw Abs.
func canonicalPath(path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("empty path")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	abs = filepath.Clean(abs)
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		return filepath.Clean(resolved), nil
	}
	return abs, nil
}

// stripBOM removes a leading UTF-8 byte-order mark from source content.
// Without this, pragma and import regexes that anchor on "pragma"/"import"
// at the start of the file silently fail to match.
func stripBOM(s string) string {
	const bom = "\xEF\xBB\xBF"
	if strings.HasPrefix(s, bom) {
		return s[len(bom):]
	}
	return s
}
