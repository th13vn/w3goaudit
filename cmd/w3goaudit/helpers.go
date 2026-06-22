package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/th13vn/w3goaudit/pkg/builder"
	"github.com/th13vn/w3goaudit/pkg/engine"
	"github.com/th13vn/w3goaudit/pkg/reader"
	"github.com/th13vn/w3goaudit/pkg/report"
	"github.com/th13vn/w3goaudit/pkg/types"
)

// runLogFile holds the run.log handle for the current scan (if any).
var runLogFile *os.File

// resolveOutputDir picks the result-folder path. An explicit -o wins; otherwise
// the folder is named after the scanned project directory (or the .sol file
// stem, or the database stem). When the derived name would collide with the
// scanned input directory itself, "-audit" is appended so we never write report
// files into the source tree.
func resolveOutputDir(inputPath, dbPath, outputFlag string) string {
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

// setupRunLog opens <dir>/run.log and routes verbose detail to it. run.log
// always captures full detail; when terminalVerbose is set, detail is also teed
// to stdout. Returns a close function.
func setupRunLog(dir string, terminalVerbose bool) (func(), error) {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("creating output folder %s: %w", dir, err)
	}
	f, err := os.Create(filepath.Join(dir, "run.log"))
	if err != nil {
		return nil, fmt.Errorf("creating run.log: %w", err)
	}
	runLogFile = f

	var w io.Writer = f
	if terminalVerbose {
		w = io.MultiWriter(f, os.Stdout)
	}
	enableVerbose(w)

	return func() {
		if runLogFile != nil {
			runLogFile.Close()
			runLogFile = nil
		}
	}, nil
}

// enableVerbose turns on verbose logging for every package and routes it to w.
func enableVerbose(w io.Writer) {
	reader.VerboseEnabled = true
	builder.VerboseEnabled = true
	engine.VerboseEnabled = true
	types.VerboseEnabled = true
	report.VerboseEnabled = true

	reader.SetVerboseWriter(w)
	builder.SetVerboseWriter(w)
	engine.SetVerboseWriter(w)
	types.SetVerboseWriter(w)
	report.SetVerboseWriter(w)
}

// enableVerboseStdout enables verbose logging straight to the terminal, used by
// --stdout mode where there is no run.log.
func enableVerboseStdout() {
	enableVerbose(os.Stdout)
}

// verboseFile holds the current verbose file handle (if any)
var verboseFile *os.File

// setupVerboseLogging configures verbose output based on the verbose flag value
// If verbosePath is empty or "true", verbose goes to stdout
// Otherwise, verbose is written to the specified file
func setupVerboseLogging(verbosePath string) error {
	// Enable verbose for all packages
	reader.VerboseEnabled = true
	builder.VerboseEnabled = true
	engine.VerboseEnabled = true
	types.VerboseEnabled = true
	report.VerboseEnabled = true

	// If no path or "true", use stdout (default)
	if verbosePath == "" || verbosePath == "true" {
		return nil
	}

	// Create parent directories if they don't exist
	if dir := filepath.Dir(verbosePath); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create verbose directory %s: %w", dir, err)
		}
	}

	// Create verbose file
	f, err := os.Create(verbosePath)
	if err != nil {
		return fmt.Errorf("failed to create verbose file: %w", err)
	}

	verboseFile = f

	// Set verbose writers for all packages
	reader.SetVerboseWriter(f)
	builder.SetVerboseWriter(f)
	engine.SetVerboseWriter(f)
	types.SetVerboseWriter(f)
	report.SetVerboseWriter(f)

	fmt.Fprintf(os.Stderr, "Verbose logging enabled (output: %s)\n", verbosePath)
	return nil
}

// closeVerboseFile closes the verbose file if it was opened
func closeVerboseFile() {
	if verboseFile != nil {
		verboseFile.Close()
		verboseFile = nil
	}
}

// buildDatabase is the common pipeline: read → resolve imports → build database.
// Returns an error rather than calling os.Exit so SDK consumers can recover.
func buildDatabase(inputPath string, verbose bool) (*types.Database, error) {
	r := reader.New()
	sources, err := r.Read(inputPath)
	if err != nil {
		return nil, fmt.Errorf("reading files: %w", err)
	}

	if verbose {
		fmt.Printf("Found %d Solidity files\n", len(sources))
	}

	projectRoot, err := reader.DetectProjectRoot(inputPath)
	framework := reader.DetectFramework(projectRoot)
	if err == nil && verbose {
		fmt.Printf("Project root: %s\n", projectRoot)
		fmt.Printf("Framework: %s\n", framework)
	}

	// Resolve imports recursively. Warnings go to stderr so they don't corrupt
	// machine-readable output piped from stdout (e.g. --json).
	if err := r.ResolveImports(projectRoot); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: import resolution failed: %v\n", err)
	}
	sources = r.GetAllSources()

	if verbose {
		fmt.Printf("After import resolution: %d total files\n", len(sources))
	}

	// Build database
	b := builder.New()
	db, err := b.Build(sources)
	if err != nil {
		return nil, fmt.Errorf("building database: %w", err)
	}

	db.ProjectRoot = projectRoot
	db.Framework = string(framework)
	return db, nil
}

// loadOrBuildDatabase loads from --db if provided, otherwise builds from source path.
func loadOrBuildDatabase(inputPath, dbPath string, verbose bool) (*types.Database, error) {
	if dbPath != "" {
		if verbose {
			fmt.Printf("Loading database from %s\n", dbPath)
		}
		db, err := types.LoadFromJSON(dbPath)
		if err != nil {
			return nil, fmt.Errorf("loading database: %w", err)
		}
		if verbose {
			stats := db.GetStats()
			fmt.Printf("Loaded database: %d contracts, %d functions\n", stats.TotalContracts, stats.TotalFunctions)
		}
		return db, nil
	}

	return buildDatabase(inputPath, verbose)
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
