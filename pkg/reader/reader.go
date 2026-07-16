// Package reader provides file and directory reading capabilities for Solidity projects.
package reader

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/th13vn/w3goaudit/pkg/logging"
	"github.com/th13vn/w3goaudit/pkg/types"
)

// Options configures one Reader instance.
type Options struct {
	Logger *logging.Logger
}

// Reader handles reading Solidity files and directories
type Reader struct {
	logger *logging.Logger
	legacy bool

	// ProjectRoot is the detected project root
	ProjectRoot string

	// SourceFiles is the list of discovered source files
	SourceFiles []*types.SourceFile

	// loadedPaths tracks files already loaded to prevent duplicates
	loadedPaths map[string]bool

	// resolver handles import path resolution
	resolver *Resolver

	// diagnostics persist analysis loss for transfer into the built database.
	diagnostics []types.Diagnostic
}

// UnresolvedImport records an import statement that could not be resolved to a
// file on disk, and the file it appeared in.
type UnresolvedImport struct {
	ImportPath string
	FromFile   string
	Reason     string
}

// New creates a Reader that preserves the legacy package-global verbose
// configuration. New code should use NewWithOptions for scan-local logging.
func New() *Reader {
	return newReader(nil, true)
}

// NewWithOptions creates a Reader with scan-local configuration. A nil logger
// is treated as disabled and never falls back to package globals.
func NewWithOptions(opts Options) *Reader {
	return newReader(opts.Logger, false)
}

func newReader(logger *logging.Logger, legacy bool) *Reader {
	if logger == nil && !legacy {
		logger = logging.Disabled()
	}
	return &Reader{
		logger:      logger,
		legacy:      legacy,
		SourceFiles: make([]*types.SourceFile, 0),
		loadedPaths: make(map[string]bool),
	}
}

func (r *Reader) logf(format string, args ...any) {
	if r != nil && r.legacy {
		VerboseLog(format, args...)
		return
	}
	if r != nil {
		r.logger.Printf(format, args...)
	}
}

// ReadFile reads a single Solidity file
func (r *Reader) ReadFile(path string) (*types.SourceFile, error) {
	absPath, err := canonicalPath(path)
	if err != nil {
		return nil, err
	}

	r.logf("Reading file: %s", absPath)

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

	r.logf("Successfully read %d bytes from %s", len(content), filepath.Base(absPath))

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

	r.logf("Scanning directory: %s", absPath)

	var result []*types.SourceFile

	err = filepath.Walk(absPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip hidden directories
		if info.IsDir() && strings.HasPrefix(info.Name(), ".") {
			r.logf("Skipping hidden directory: %s", info.Name())
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
				r.logf("Skipping directory: %s", name)
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

	r.logf("Found %d Solidity files in directory", len(result))

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
		r.logf("Auto-detected directory: %s", absPath)
		return r.ReadDirectory(absPath)
	}

	r.logf("Auto-detected file: %s", absPath)
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
	r.logf("Starting import resolution with project root: %s", projectRoot)

	// Initialize resolver if not already done
	if r.resolver == nil {
		r.resolver = newResolver(projectRoot, r.logger, r.legacy)
	}

	// Track initially loaded files
	for _, sf := range r.SourceFiles {
		r.loadedPaths[sf.Path] = true
		r.logf("Marking initial file as loaded: %s", sf.Path)
	}

	initialCount := len(r.SourceFiles)
	r.logf("Processing imports from %d initial files", initialCount)

	// Process imports from all files (loop extends as new files are added)
	for i := 0; i < len(r.SourceFiles); i++ {
		sf := r.SourceFiles[i]
		if err := r.processFileImports(sf); err != nil {
			r.logf("Error processing imports from %s: %v", sf.Path, err)
			// Continue processing other files even if one fails
		}
	}

	loadedCount := len(r.SourceFiles) - initialCount
	r.logf("Import resolution complete: loaded %d additional files", loadedCount)

	return nil
}

// processFileImports extracts and loads all imports from a single file
func (r *Reader) processFileImports(sf *types.SourceFile) error {
	imports := extractImports(sf.Content)

	if len(imports) == 0 {
		return nil
	}

	r.logf("Found %d imports in %s", len(imports), filepath.Base(sf.Path))

	for _, importPath := range imports {
		resolvedPath, err := r.loadImport(importPath, sf.Path)
		if err != nil {
			r.logf("  Could not load import '%s': %v", importPath, err)
			// Record it durably so source and cache scans expose the same known
			// analysis loss.
			r.diagnostics = append(r.diagnostics, types.Diagnostic{
				Code:       types.DiagnosticUnresolvedImport,
				Severity:   types.DiagnosticWarning,
				Phase:      "reader",
				Message:    err.Error(),
				File:       sf.Path,
				ImportPath: importPath,
				Incomplete: true,
			})
			// Continue with other imports
			continue
		}
		recordResolvedImport(sf, resolvedPath)
	}

	return nil
}

// UnresolvedImports returns the imports that could not be resolved to a file on
// disk during ResolveImports. Deduplicated by (import path, source file).
func (r *Reader) UnresolvedImports() []UnresolvedImport {
	diagnostics := r.Diagnostics()
	out := make([]UnresolvedImport, 0, len(diagnostics))
	seen := make(map[string]struct{}, len(diagnostics))
	for _, diagnostic := range diagnostics {
		if diagnostic.Code != types.DiagnosticUnresolvedImport {
			continue
		}
		key := diagnostic.ImportPath + "\x00" + diagnostic.File
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, UnresolvedImport{
			ImportPath: diagnostic.ImportPath,
			FromFile:   diagnostic.File,
			Reason:     diagnostic.Message,
		})
	}
	return out
}

// Diagnostics returns a normalized defensive copy of all analysis diagnostics
// recorded while reading and resolving imports.
func (r *Reader) Diagnostics() []types.Diagnostic {
	if r == nil || len(r.diagnostics) == 0 {
		return []types.Diagnostic{}
	}
	seen := make(map[types.Diagnostic]struct{}, len(r.diagnostics))
	out := make([]types.Diagnostic, 0, len(r.diagnostics))
	for _, diagnostic := range r.diagnostics {
		if _, exists := seen[diagnostic]; exists {
			continue
		}
		seen[diagnostic] = struct{}{}
		out = append(out, diagnostic)
	}
	types.SortDiagnostics(out)
	return out
}

// loadImport resolves and loads a single import if not already loaded
func (r *Reader) loadImport(importPath string, fromFile string) (string, error) {
	// Resolve import to absolute path
	resolved, err := r.resolver.Resolve(importPath, fromFile)
	if err != nil {
		return "", fmt.Errorf("failed to resolve: %w", err)
	}

	// Skip if empty or same as import path (couldn't resolve)
	if resolved == "" || resolved == importPath {
		return "", fmt.Errorf("could not resolve import path")
	}

	// Canonicalize so that symlink / relative-spelling aliases share one key.
	absPath, err := canonicalPath(resolved)
	if err != nil {
		return "", fmt.Errorf("failed to canonicalize: %w", err)
	}

	// Skip if already loaded (canonical key — no aliasing).
	if r.loadedPaths[absPath] {
		r.logf("  ✓ %s (already loaded)", importPath)
		return absPath, nil
	}

	// Check if file exists
	if _, err := os.Stat(absPath); os.IsNotExist(err) {
		return "", fmt.Errorf("file does not exist: %s", absPath)
	}

	// Load the file
	r.logf("  → Loading %s", importPath)
	r.logf("    Resolved to: %s", absPath)

	importedFile, err := r.readFileWithoutTracking(absPath)
	if err != nil {
		return "", fmt.Errorf("failed to read file: %w", err)
	}

	// Mark as loaded and add to source files
	r.loadedPaths[absPath] = true
	r.SourceFiles = append(r.SourceFiles, importedFile)

	r.logf("  ✓ Loaded successfully (%d bytes)", len(importedFile.Content))

	return absPath, nil
}

func recordResolvedImport(sf *types.SourceFile, resolvedPath string) {
	if sf == nil || resolvedPath == "" {
		return
	}
	for _, existing := range sf.ResolvedImports {
		if existing == resolvedPath {
			return
		}
	}
	sf.ResolvedImports = append(sf.ResolvedImports, resolvedPath)
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
