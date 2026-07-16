package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/th13vn/w3goaudit/pkg/builder"
	"github.com/th13vn/w3goaudit/pkg/logging"
	"github.com/th13vn/w3goaudit/pkg/reader"
	"github.com/th13vn/w3goaudit/pkg/types"
)

// resolveOutputDir picks the result-folder path. An explicit -o wins; otherwise
// the folder is named after the scanned project directory (or the .sol file
// stem, or the database stem). When the derived name would collide with the
// scanned input directory itself, "-audit" is appended so we never write report
// files into the source tree.
func resolveOutputDir(inputPath, dbPath, outputFlag string) string {
	return resolveOutputDirWithBase(inputPath, dbPath, outputFlag, "")
}

func resolveOutputDirWithBase(inputPath, dbPath, outputFlag, outputBaseDir string) string {
	if outputFlag != "" {
		return outputFlag
	}

	base := ""
	switch {
	case inputPath != "":
		if info, err := os.Stat(inputPath); err == nil && info.IsDir() {
			base = filepath.Base(filepath.Clean(inputPath))
		} else {
			b := filepath.Base(inputPath)
			base = strings.TrimSuffix(b, filepath.Ext(b))
		}
	case dbPath != "":
		b := filepath.Base(dbPath)
		base = strings.TrimSuffix(b, filepath.Ext(b))
	}

	switch base {
	case "", ".", "/", "..":
		base = "w3goaudit-report"
	}

	// Honor config output.base_dir: default-named folders are created under it.
	out := base
	if outputBaseDir != "" {
		out = filepath.Join(outputBaseDir, base)
	}

	// Guard against writing into the scanned directory.
	if inputPath != "" {
		if inAbs, err := filepath.Abs(inputPath); err == nil {
			if outAbs, err := filepath.Abs(out); err == nil {
				if inAbs == outAbs {
					out += "-audit"
				}
			}
		}
	}
	return out
}

// setupRunLog opens <dir>/run.log and returns the scan-local logger that owns
// it. run.log always captures full detail; terminal verbose mode additionally
// tees detail to stdout. No package-global logger state is mutated.
func setupRunLog(dir string, terminalVerbose bool, stdout io.Writer) (*logging.Logger, func() error, error) {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, nil, fmt.Errorf("creating output folder %s: %w", dir, err)
	}
	f, err := os.Create(filepath.Join(dir, "run.log"))
	if err != nil {
		return nil, nil, fmt.Errorf("creating run.log: %w", err)
	}

	var w io.Writer = f
	if terminalVerbose {
		w = io.MultiWriter(f, stdout)
	}
	return logging.New(true, w), f.Close, nil
}

// setupBuildLogger creates the build subcommand's optional scan-local logger.
// A bare --verbose writes to stdout; --verbose=<path> writes only to that file.
func setupBuildLogger(enabled bool, verbosePath string, stdout, stderr io.Writer) (*logging.Logger, func() error, error) {
	if !enabled {
		return logging.Disabled(), func() error { return nil }, nil
	}
	if verbosePath == "" || verbosePath == "true" {
		return logging.New(true, stdout), func() error { return nil }, nil
	}
	if dir := filepath.Dir(verbosePath); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, nil, fmt.Errorf("creating verbose directory %s: %w", dir, err)
		}
	}
	f, err := os.Create(verbosePath)
	if err != nil {
		return nil, nil, fmt.Errorf("creating verbose log: %w", err)
	}
	fmt.Fprintf(stderr, "Verbose logging enabled (output: %s)\n", verbosePath)
	return logging.New(true, f), f.Close, nil
}

// buildDatabaseWithOptions is the common source pipeline: read → resolve
// imports → build database. Metadata and diagnostics are transferred into the
// builder before any analysis phase runs.
func buildDatabaseWithOptions(opts databaseLoadOptions) (*types.Database, error) {
	logger := opts.Logger
	if logger == nil {
		logger = logging.Disabled()
	}
	r := reader.NewWithOptions(reader.Options{Logger: logger})
	scanTarget, err := canonicalScanTarget(opts.InputPath)
	if err != nil {
		return nil, fmt.Errorf("resolving scan target: %w", err)
	}
	sources, err := r.Read(opts.InputPath)
	if err != nil {
		return nil, fmt.Errorf("reading files: %w", err)
	}
	logger.Printf("Found %d Solidity files", len(sources))

	projectRoot, err := reader.DetectProjectRoot(opts.InputPath)
	if err != nil {
		return nil, fmt.Errorf("detecting project root: %w", err)
	}
	framework := reader.DetectFramework(projectRoot)
	logger.Printf("Project root: %s", projectRoot)
	logger.Printf("Framework: %s", framework)

	if err := r.ResolveImports(projectRoot); err != nil {
		return nil, fmt.Errorf("resolving imports: %w", err)
	}
	sources = r.GetAllSources()
	logger.Printf("After import resolution: %d total files", len(sources))

	b := builder.NewWithOptions(builder.Options{
		Logger:      logger,
		ProjectRoot: projectRoot,
		ScanTarget:  scanTarget,
		Diagnostics: r.Diagnostics(),
	})
	db, err := b.Build(sources)
	if err != nil {
		return nil, fmt.Errorf("building database: %w", err)
	}
	db.Framework = string(framework)
	db.NormalizeDiagnostics()
	return db, nil
}

func canonicalScanTarget(inputPath string) (string, error) {
	absPath, err := filepath.Abs(inputPath)
	if err != nil {
		return "", err
	}
	if resolved, err := filepath.EvalSymlinks(absPath); err == nil {
		return filepath.Clean(resolved), nil
	}
	return filepath.Clean(absPath), nil
}

// loadOrBuildDatabaseWithOptions loads a cache or builds from source using the
// same logger and warning channel. Persisted diagnostics make both modes expose
// unresolved imports identically.
func loadOrBuildDatabaseWithOptions(opts databaseLoadOptions) (*types.Database, error) {
	logger := opts.Logger
	if logger == nil {
		logger = logging.Disabled()
	}
	var (
		db  *types.Database
		err error
	)
	if opts.DBPath != "" {
		logger.Printf("Loading database from %s", opts.DBPath)
		db, err = types.LoadFromJSONWithOptions(opts.DBPath, types.LoadOptions{Logger: logger})
		if err != nil {
			return nil, fmt.Errorf("loading database: %w", err)
		}
		db.NormalizeDiagnostics()
		stats := db.GetStats()
		logger.Printf("Loaded database: %d contracts, %d functions", stats.TotalContracts, stats.TotalFunctions)
	} else {
		db, err = buildDatabaseWithOptions(opts)
		if err != nil {
			return nil, err
		}
	}
	emitImportDiagnostics(opts.Stderr, db)
	return db, nil
}

func emitImportDiagnostics(w io.Writer, db *types.Database) {
	if w == nil || db == nil {
		return
	}
	diagnostics := make([]types.Diagnostic, 0)
	for _, diagnostic := range db.Diagnostics {
		if diagnostic.Code == types.DiagnosticUnresolvedImport {
			diagnostics = append(diagnostics, diagnostic)
		}
	}
	if len(diagnostics) == 0 {
		return
	}
	fmt.Fprintf(w, "Warning: %d import(s) could not be resolved — analysis may be incomplete:\n", len(diagnostics))
	limit := len(diagnostics)
	if limit > 10 {
		limit = 10
	}
	for _, diagnostic := range diagnostics[:limit] {
		fmt.Fprintf(w, "  - %q (in %s)\n", diagnostic.ImportPath, filepath.Base(diagnostic.File))
	}
	if len(diagnostics) > limit {
		fmt.Fprintf(w, "  … and %d more\n", len(diagnostics)-limit)
	}
}

// loadOrBuildDatabase preserves the existing private helper signature for
// extract commands while avoiding package-global verbose configuration.
func loadOrBuildDatabase(inputPath, dbPath string, verbose bool) (*types.Database, error) {
	logger := logging.New(verbose, os.Stdout)
	return loadOrBuildDatabaseWithOptions(databaseLoadOptions{
		InputPath: inputPath,
		DBPath:    dbPath,
		Logger:    logger,
		Stdout:    os.Stdout,
		Stderr:    os.Stderr,
	})
}

// writeOutput writes content to file or stdout. Returns an error rather than
// calling os.Exit. If outputPath points at an existing file, a brief notice
// is printed so the user knows their previous report is being replaced.
func writeOutput(content, outputPath string) error {
	if outputPath == "" {
		fmt.Println(content)
		return nil
	}

	// Create parent directories if they don't exist
	if dir := filepath.Dir(outputPath); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create output directory %s: %w", dir, err)
		}
	}

	if info, err := os.Stat(outputPath); err == nil {
		if info.IsDir() {
			return fmt.Errorf("output path %s is a directory", outputPath)
		}
		fmt.Fprintf(os.Stderr, "Replacing existing file: %s\n", outputPath)
	}
	if err := os.WriteFile(outputPath, []byte(content), 0644); err != nil {
		return fmt.Errorf("writing output to %s: %w", outputPath, err)
	}
	fmt.Fprintf(os.Stderr, "Output written to %s\n", outputPath)
	return nil
}
