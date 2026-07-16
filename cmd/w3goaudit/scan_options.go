package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/th13vn/w3goaudit/pkg/engine"
	"github.com/th13vn/w3goaudit/pkg/logging"
	"github.com/th13vn/w3goaudit/pkg/report"
	"github.com/th13vn/w3goaudit/pkg/types"
)

// scanOptions is an immutable snapshot of one root-command invocation. Cobra
// flag globals are copied into this value once; the scan pipeline never reads
// or mutates them, so direct executeScan calls are safe to run concurrently.
type scanOptions struct {
	InputPath       string
	DBPath          string
	TemplatePath    string
	TemplateHomeDir string
	OutputPath      string
	OutputBaseDir   string

	Severity    string
	MinSeverity string
	Include     string
	Exclude     string

	Verbose                bool
	HTML                   bool
	StdoutOnly             bool
	NoColor                bool
	IgnoreInvalidTemplates bool
	ListTemplates          bool
	StrictImports          bool

	Stdout io.Writer
	Stderr io.Writer
	Now    func() time.Time
}

// databaseLoadOptions carries one logger and output channels through source
// builds and cache loads. It intentionally contains no package-global state.
type databaseLoadOptions struct {
	InputPath string
	DBPath    string
	Logger    *logging.Logger
	Stdout    io.Writer
	Stderr    io.Writer
}

func normalizeScanOptions(opts scanOptions) scanOptions {
	if opts.Stdout == nil {
		opts.Stdout = os.Stdout
	}
	if opts.Stderr == nil {
		opts.Stderr = os.Stderr
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return opts
}

func validateScanOptions(opts scanOptions) error {
	if !opts.ListTemplates && opts.InputPath == "" && opts.DBPath == "" {
		return fmt.Errorf("provide a path to scan or use --db to load a database\n\nUsage: w3goaudit <path> [flags]")
	}
	if opts.Severity != "" && opts.MinSeverity != "" {
		return fmt.Errorf("use only one of --severity (exact set) or --min-severity (threshold)")
	}
	if opts.MinSeverity != "" && !report.IsKnownSeverity(opts.MinSeverity) {
		return fmt.Errorf("--min-severity must be one of: critical, high, medium, low, info")
	}
	for _, severity := range splitGlobs(opts.Severity) {
		if !report.IsKnownSeverity(severity) {
			return fmt.Errorf("--severity %q: must be one of: critical, high, medium, low, info", severity)
		}
	}
	if opts.TemplatePath != "" {
		if info, err := os.Stat(opts.TemplatePath); err == nil && !info.IsDir() {
			ext := strings.ToLower(filepath.Ext(opts.TemplatePath))
			if ext != ".yaml" && ext != ".yml" {
				return fmt.Errorf("--template %s: expected .yaml/.yml file or directory", opts.TemplatePath)
			}
		}
	}
	if opts.InputPath != "" && opts.DBPath == "" {
		if _, err := os.Stat(opts.InputPath); err != nil {
			return fmt.Errorf("path %q does not exist", opts.InputPath)
		}
	}
	return nil
}

// enforceStrictImports turns durable unresolved-import diagnostics into a
// fail-closed policy when explicitly requested. Default scans remain tolerant.
func enforceStrictImports(db *types.Database, strict bool) error {
	if !strict || db == nil {
		return nil
	}
	for _, diagnostic := range db.Diagnostics {
		if diagnostic.Code == types.DiagnosticUnresolvedImport {
			return fmt.Errorf("strict imports: unresolved import %q in %s", diagnostic.ImportPath, diagnostic.File)
		}
	}
	return nil
}

// executeScan runs one scan using only the supplied options and scan-local
// objects. It is suitable for concurrent invocation with independent writers.
func executeScan(raw scanOptions) error {
	opts := normalizeScanOptions(raw)
	if err := validateScanOptions(opts); err != nil {
		return err
	}

	if opts.ListTemplates {
		logger := logging.New(opts.Verbose, opts.Stdout)
		templates, source, err := loadScanTemplatesWithOptions(scanTemplateOptions{
			TemplatePath:           opts.TemplatePath,
			TemplateHomeDir:        opts.TemplateHomeDir,
			IgnoreInvalidTemplates: opts.IgnoreInvalidTemplates,
			Logger:                 logger,
		})
		if err != nil {
			return err
		}
		printTemplateListTo(opts.Stdout, templates, source)
		return nil
	}

	var logger *logging.Logger
	closeLog := func() error { return nil }
	outDir := ""
	if opts.StdoutOnly {
		logger = logging.New(opts.Verbose, opts.Stdout)
	} else {
		outDir = resolveOutputDirWithBase(opts.InputPath, opts.DBPath, opts.OutputPath, opts.OutputBaseDir)
		var err error
		logger, closeLog, err = setupRunLog(outDir, opts.Verbose, opts.Stdout)
		if err != nil {
			return fmt.Errorf("setting up run log: %w", err)
		}
		defer func() { _ = closeLog() }()
	}

	templateOpts := scanTemplateOptions{
		TemplatePath:           opts.TemplatePath,
		TemplateHomeDir:        opts.TemplateHomeDir,
		IgnoreInvalidTemplates: opts.IgnoreInvalidTemplates,
		Logger:                 logger,
	}
	scanStart := time.Now()
	progressTo(opts.Stdout, "Reading sources", opts.InputPath, opts.DBPath)
	db, err := loadOrBuildDatabaseWithOptions(databaseLoadOptions{
		InputPath: opts.InputPath,
		DBPath:    opts.DBPath,
		Logger:    logger,
		Stdout:    opts.Stdout,
		Stderr:    opts.Stderr,
	})
	if err != nil {
		return err
	}
	if err := enforceStrictImports(db, opts.StrictImports); err != nil {
		return err
	}

	stats := db.GetStats()
	progressTo(opts.Stdout, "Building database", fmt.Sprintf("%d files, %d contracts, %d functions",
		stats.TotalFiles, stats.TotalContracts, stats.TotalFunctions), "")

	// Capture one timestamp so every artifact in this scan observes the same
	// clock value even when the caller supplied time.Now directly.
	generatedAt := opts.Now().UTC()
	fixedNow := func() time.Time { return generatedAt }
	gen := report.NewGeneratorWithOptions(db, report.GeneratorOptions{Logger: logger, Now: fixedNow})
	summary := gen.GenerateSummary()

	templates, templateSource, err := loadScanTemplatesWithOptions(templateOpts)
	if err != nil {
		return err
	}
	progressTo(opts.Stdout, "Scanning", fmt.Sprintf("%d templates (%s)", len(templates), templateSource), "")

	e := engine.NewWithOptions(db, engine.Options{Logger: logger})
	findings, err := filterFindingsWithOptions(e.ExecuteAll(templates), findingFilterOptions{
		Severity:    opts.Severity,
		MinSeverity: opts.MinSeverity,
		Include:     opts.Include,
		Exclude:     opts.Exclude,
	})
	if err != nil {
		return err
	}

	colorMode := report.ColorAuto
	if opts.NoColor {
		colorMode = report.ColorNever
	}
	plain := colorMode == report.ColorNever
	elapsed := time.Since(scanStart).Round(time.Millisecond).String()
	if opts.StdoutOnly {
		report.PrintConsoleSummaryHeader(opts.Stdout, findings, len(db.MainContracts), elapsed, colorMode)
		fmt.Fprintln(opts.Stdout)
		printCombinedConsoleTo(opts.Stdout, stats, summary, findings, plain, opts.Verbose)
		printUnresolvedTo(opts.Stdout, db, plain)
		return nil
	}

	progressTo(opts.Stdout, "Writing report", outDir, "")
	tool := report.ToolMeta{Name: "w3goaudit", Version: Version}
	if err := report.WriteBundle(outDir, db, summary, findings, tool, report.BundleOptions{HTML: opts.HTML, Now: fixedNow}); err != nil {
		return err
	}

	fmt.Fprintln(opts.Stdout)
	report.PrintConsoleSummaryHeader(opts.Stdout, findings, len(db.MainContracts), elapsed, colorMode)
	fmt.Fprintln(opts.Stdout)
	printFindingsTo(opts.Stdout, findings, plain, opts.Verbose)
	printUnresolvedTo(opts.Stdout, db, plain)
	printResultLocationTo(opts.Stdout, outDir, opts.HTML, plain)
	return nil
}
