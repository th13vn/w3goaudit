package main

import (
	"fmt"
	"os"

	"github.com/th13vn/w3goaudit-engine/pkg/builder"
	"github.com/th13vn/w3goaudit-engine/pkg/engine"
	"github.com/th13vn/w3goaudit-engine/pkg/reader"
	"github.com/th13vn/w3goaudit-engine/pkg/report"
	"github.com/th13vn/w3goaudit-engine/pkg/types"
)

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

	fmt.Printf("Verbose logging enabled (output: %s)\n", verbosePath)
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

	// Resolve imports recursively
	if err := r.ResolveImports(projectRoot); err != nil {
		fmt.Printf("Warning: import resolution failed: %v\n", err)
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

// loadDatabaseRequired loads database from --db path (required).
func loadDatabaseRequired(dbPath string, verbose bool) (*types.Database, error) {
	if dbPath == "" {
		return nil, fmt.Errorf("--db flag is required")
	}
	if verbose {
		fmt.Printf("Loading database from %s\n", dbPath)
	}
	db, err := types.LoadFromJSON(dbPath)
	if err != nil {
		return nil, fmt.Errorf("loading database: %w", err)
	}
	return db, nil
}

// writeOutput writes content to file or stdout. Returns an error rather than
// calling os.Exit. If outputPath points at an existing file, a brief notice
// is printed so the user knows their previous report is being replaced.
func writeOutput(content, outputPath string) error {
	if outputPath == "" {
		fmt.Println(content)
		return nil
	}
	if info, err := os.Stat(outputPath); err == nil {
		if info.IsDir() {
			return fmt.Errorf("output path %s is a directory", outputPath)
		}
		fmt.Printf("Replacing existing file: %s\n", outputPath)
	}
	if err := os.WriteFile(outputPath, []byte(content), 0644); err != nil {
		return fmt.Errorf("writing output to %s: %w", outputPath, err)
	}
	fmt.Printf("Output written to %s\n", outputPath)
	return nil
}
