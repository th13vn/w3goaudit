package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/th13vn/w3goaudit/pkg/types"
)

var buildCmd = &cobra.Command{
	Use:   "build [path]",
	Short: "Build contract database from Solidity source files",
	Long: `Build a comprehensive contract database from Solidity source files.

The database includes contracts, functions, inheritance (C3), call graph,
entry points, and function selectors. Output as JSON for reuse with --db flag.

Examples:
  w3goaudit build ./contracts/ -o database.json
  w3goaudit build ./contracts/ -o database.json --verbose`,
	Args: cobra.ExactArgs(1),
	RunE: runBuild,
}

var (
	buildOutputPath string
	buildVerbose    string
	buildDbPath     string
)

func init() {
	buildCmd.Flags().StringVarP(&buildOutputPath, "output", "o", "", "Output JSON file path (required)")
	buildCmd.Flags().StringVar(&buildVerbose, "verbose", "", "Enable verbose logging (optional: path to log file)")
	buildCmd.Flags().StringVar(&buildDbPath, "db", "", "Load existing database instead of rebuilding")
	buildCmd.MarkFlagRequired("output")
}

func runBuild(cmd *cobra.Command, args []string) error {
	isVerbose := cmd.Flags().Changed("verbose")
	if isVerbose {
		verbosePath := buildVerbose
		if verbosePath == "" {
			verbosePath = "true"
		}
		if err := setupVerboseLogging(verbosePath); err != nil {
			return fmt.Errorf("error setting up verbose logging: %w", err)
		}
		defer closeVerboseFile()
	}

	inputPath := args[0]

	var db *types.Database

	if buildDbPath != "" {
		// Load existing database
		if isVerbose {
			fmt.Printf("Loading existing database from %s\n", buildDbPath)
		}
		var err error
		db, err = types.LoadFromJSON(buildDbPath)
		if err != nil {
			return fmt.Errorf("error loading database: %w", err)
		}
	} else {
		var err error
		db, err = buildDatabase(inputPath, isVerbose)
		if err != nil {
			return err
		}
	}

	// Output database as JSON
	data, err := json.MarshalIndent(db, "", "  ")
	if err != nil {
		return fmt.Errorf("error encoding JSON: %w", err)
	}

	// Create parent directories if they don't exist
	if dir := filepath.Dir(buildOutputPath); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("error creating output directory %s: %w", dir, err)
		}
	}

	if err := os.WriteFile(buildOutputPath, data, 0644); err != nil {
		return fmt.Errorf("error writing output: %w", err)
	}

	stats := db.GetStats()
	fmt.Printf("\nDatabase built successfully!\n")
	fmt.Printf("  Files: %d\n", stats.TotalFiles)
	fmt.Printf("  Contracts: %d (Interfaces: %d, Libraries: %d)\n",
		stats.TotalContracts, stats.TotalInterfaces, stats.TotalLibraries)
	fmt.Printf("  Functions: %d (Entry: %d)\n",
		stats.TotalFunctions, stats.TotalEntryFunctions)
	fmt.Printf("  Main Contracts: %d\n", len(db.MainContracts))
	fmt.Printf("  Output: %s\n", buildOutputPath)

	return nil
}
