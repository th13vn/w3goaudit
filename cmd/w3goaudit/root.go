package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/th13vn/w3goaudit/pkg/engine"
	"github.com/th13vn/w3goaudit/pkg/report"
	"github.com/th13vn/w3goaudit/pkg/types"
)

// Version information
var (
	Version   = "0.2.0"
	BuildTime = "dev"
)

var rootCmd = &cobra.Command{
	Use:   "w3goaudit [path]",
	Short: "Solidity Smart Contract Audit Engine",
	Long: `W3GoAudit - A Go-based static analysis engine for Solidity smart contracts.

Scan contracts for security vulnerabilities using WQL templates.
Output includes project stats, contract overview, and security findings.

Examples:
  w3goaudit ./contracts/                               # Scan with console output
  w3goaudit ./contracts/ --template ./templates/official/        # Scan with templates
  w3goaudit ./contracts/ --template ./templates/official/ --md   # Markdown report
  w3goaudit ./contracts/ --db db.json --template ./t/   # Use pre-built database`,
	Args: cobra.MaximumNArgs(1),
	RunE: runScan,
	// Usage errors print the usage block; runtime/scan errors and the --fail-on
	// gate do not (main.go prints those to stderr). Without this, every error
	// dumped the full 25-line help.
	SilenceUsage:  true,
	SilenceErrors: true,
}

// Flags for root scan command
var (
	templatePath           string
	outputPath             string
	dbPath                 string
	verbose                string
	jsonOutput             bool
	htmlOutput             bool
	mdOutput               bool
	sarifOutput            bool
	noColor                bool
	ignoreInvalidTemplates bool
	locationSource         string
	failOnSeverity         string
	minSeverity            string
	includeTemplates       string
	excludeTemplates       string
	listTemplates          bool
)

func init() {
	rootCmd.Flags().StringVar(&templatePath, "template", "", "Path to template file or directory (default: built-in production pack)")
	rootCmd.Flags().StringVarP(&outputPath, "output", "o", "", "Output file path (default: stdout). Splits into <stem>.overview.<ext> and <stem>.findings.<ext>.")
	rootCmd.Flags().StringVar(&dbPath, "db", "", "Path to pre-built database JSON file")
	rootCmd.Flags().StringVar(&verbose, "verbose", "", "Enable verbose logging (optional: path to log file)")
	rootCmd.Flags().BoolVar(&jsonOutput, "json", false, "Output as JSON (split: overview.json + findings.json, schemaVersion 1.0.0)")
	rootCmd.Flags().BoolVar(&htmlOutput, "html", false, "Output as HTML (split: overview.html + findings.html)")
	rootCmd.Flags().BoolVar(&mdOutput, "md", false, "Output as Markdown (split: overview.md + findings.md)")
	rootCmd.Flags().BoolVar(&sarifOutput, "sarif", false, "Also emit SARIF 2.1.0 to <stem>.sarif (or <output>.sarif when -o is set)")
	rootCmd.Flags().BoolVar(&noColor, "no-color", false, "Disable ANSI color in console output (also honored: NO_COLOR env)")
	rootCmd.Flags().BoolVar(&ignoreInvalidTemplates, "ignore-invalid-templates", false, "Skip invalid templates in a template directory instead of failing the scan")
	rootCmd.Flags().StringVar(&locationSource, "location-source", "verifier", "Finding location provenance: verifier or matched")
	rootCmd.Flags().StringVar(&failOnSeverity, "fail-on", "", "Exit with code 2 when any finding (across ALL templates, ignoring display filters) is at or above this severity (critical|high|medium|low|info) — for CI gating")
	rootCmd.Flags().StringVar(&minSeverity, "min-severity", "", "Only report findings at or above this severity (critical|high|medium|low|info)")
	rootCmd.Flags().StringVar(&includeTemplates, "include", "", "Comma-separated template-ID glob(s); only matching findings are reported")
	rootCmd.Flags().StringVar(&excludeTemplates, "exclude", "", "Comma-separated template-ID glob(s); matching findings are suppressed")
	rootCmd.Flags().BoolVar(&listTemplates, "list-templates", false, "List the templates that would run (id, severity, confidence, title) and exit")

	// Allow a bare --verbose (no value) to mean "verbose to stdout"; otherwise
	// cobra rejects it with "flag needs an argument".
	rootCmd.Flags().Lookup("verbose").NoOptDefVal = "true"

	// Add subcommands
	rootCmd.AddCommand(buildCmd)
	rootCmd.AddCommand(extractCmd)
	rootCmd.AddCommand(completionCmd)
	rootCmd.AddCommand(versionCmd)

	// Better feedback on mistyped commands/flags. Cobra suggests near-miss
	// subcommands ("Did you mean this?"); the flag-error hook points users at
	// --help instead of dumping the whole usage block. Applied to the root and
	// inherited by every subcommand.
	rootCmd.SuggestionsMinimumDistance = 2
	rootCmd.SetFlagErrorFunc(func(c *cobra.Command, err error) error {
		return fmt.Errorf("%w\n\nRun `%s --help` to see available flags", err, c.CommandPath())
	})
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Show version information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("w3goaudit version %s (%s)\n", Version, BuildTime)
	},
}

func runScan(cmd *cobra.Command, args []string) error {
	// Setup verbose logging
	isVerbose := cmd.Flags().Changed("verbose")
	if isVerbose {
		verbosePath := verbose
		if verbosePath == "" {
			verbosePath = "true"
		}
		if err := setupVerboseLogging(verbosePath); err != nil {
			return fmt.Errorf("error setting up verbose logging: %w", err)
		}
		defer closeVerboseFile()
	}

	// Need at least a path or --db
	if len(args) == 0 && dbPath == "" {
		return fmt.Errorf("provide a path to scan or use --db to load a database\n\nUsage: w3goaudit <path> [flags]")
	}

	// Reject conflicting format flags up front — the switch below would
	// silently pick one (json wins, then html, then md), which surprises users.
	formatCount := 0
	if jsonOutput {
		formatCount++
	}
	if htmlOutput {
		formatCount++
	}
	if mdOutput {
		formatCount++
	}
	if formatCount > 1 {
		return fmt.Errorf("only one of --json, --html, --md may be set (got %d)", formatCount)
	}

	switch strings.ToLower(locationSource) {
	case "verifier", "":
		locationSource = "verifier"
	case "matched", "matched-node":
		locationSource = "matched"
	default:
		return fmt.Errorf("--location-source must be one of: verifier, matched")
	}

	// Validate severity-threshold flags early so a typo fails fast instead of
	// silently never tripping (--fail-on) or filtering nothing (--min-severity).
	if failOnSeverity != "" && !report.IsKnownSeverity(failOnSeverity) {
		return fmt.Errorf("--fail-on must be one of: critical, high, medium, low, info")
	}
	if minSeverity != "" && !report.IsKnownSeverity(minSeverity) {
		return fmt.Errorf("--min-severity must be one of: critical, high, medium, low, info")
	}

	// If -o is set without an explicit format flag, infer format from the
	// file extension. Previously this silently defaulted to markdown even
	// when -o report.html was provided without --html.
	if outputPath != "" && formatCount == 0 {
		switch strings.ToLower(filepath.Ext(outputPath)) {
		case ".json":
			jsonOutput = true
		case ".html", ".htm":
			htmlOutput = true
		case ".md", ".markdown":
			mdOutput = true
		case ".sarif":
			sarifOutput = true
		default:
			mdOutput = true
		}
	}

	// Honor the NO_COLOR convention (https://no-color.org).
	if os.Getenv("NO_COLOR") != "" {
		noColor = true
	}

	// Validate template path extension early — yaml-unmarshalling a README.md
	// produces an opaque error deep in the engine package.
	if templatePath != "" {
		if info, err := os.Stat(templatePath); err == nil && !info.IsDir() {
			ext := strings.ToLower(filepath.Ext(templatePath))
			if ext != ".yaml" && ext != ".yml" {
				return fmt.Errorf("--template %s: expected .yaml/.yml file or directory", templatePath)
			}
		}
	}

	inputPath := ""
	if len(args) > 0 {
		inputPath = args[0]
	}

	// Friendly typo handling: the root command takes a path, so a mistyped
	// subcommand (e.g. `w3goaudit buil ./x` or `w3goaudit etract …`) is parsed
	// as a path argument and would otherwise fail deep in the reader with an
	// opaque "reading files" error. Catch the non-existent path here and, when
	// it looks like a near-miss subcommand, point the user at the right one.
	if inputPath != "" && dbPath == "" {
		if _, statErr := os.Stat(inputPath); os.IsNotExist(statErr) {
			msg := fmt.Sprintf("path %q does not exist", inputPath)
			if sugs := cmd.Root().SuggestionsFor(inputPath); len(sugs) > 0 {
				msg += fmt.Sprintf("\n\nDid you mean the subcommand %q?  (try: w3goaudit %s --help)", sugs[0], sugs[0])
			}
			msg += "\n\nUsage: w3goaudit <path> [flags]   —  run `w3goaudit --help` for all commands"
			return fmt.Errorf("%s", msg)
		}
	}

	// Time the scan so the console summary can show elapsed time.
	scanStart := time.Now()

	// Load or build database
	db, err := loadOrBuildDatabase(inputPath, dbPath, isVerbose)
	if err != nil {
		return err
	}

	// Wire project root into the report formatters so paths render relative.
	report.SetReportProjectRoot(db.ProjectRoot)

	// Print stats
	stats := db.GetStats()
	if isVerbose {
		fmt.Printf("\nDatabase Statistics:\n")
		fmt.Printf("  Files: %d\n", stats.TotalFiles)
		fmt.Printf("  Contracts: %d\n", stats.TotalContracts)
		fmt.Printf("  Interfaces: %d\n", stats.TotalInterfaces)
		fmt.Printf("  Libraries: %d\n", stats.TotalLibraries)
		fmt.Printf("  Functions: %d\n", stats.TotalFunctions)
		fmt.Printf("  Entry Functions: %d\n", stats.TotalEntryFunctions)
		fmt.Printf("  Main Contracts: %d\n", len(db.MainContracts))
		for contractID := range db.MainContracts {
			fmt.Printf("    - %s\n", contractID)
		}
	}

	// Generate summary (overview of main contracts)
	gen := report.NewGenerator(db)
	summary := gen.GenerateSummary()

	// Load templates: an explicit --template path, otherwise the built-in
	// production pack embedded in the binary (so a bare scan works out of the box).
	templates, templateSource, err := loadScanTemplates()
	if err != nil {
		return err
	}

	// --list-templates: print the rule inventory and exit (no scan needed).
	if listTemplates {
		printTemplateList(templates, templateSource)
		return nil
	}

	e := engine.New(db)
	if locationSource == "matched" {
		e.SetLocationSource(engine.LocationSourceMatchedNode)
	}
	// allFindings is the complete scan result; --fail-on gates on THIS set so a
	// display filter (--min-severity / --include / --exclude) can never silently
	// disarm the CI gate. `findings` is the filtered set that gets reported.
	allFindings := e.ExecuteAll(templates)
	findings, err := filterFindings(allFindings)
	if err != nil {
		return err
	}

	if isVerbose {
		fmt.Fprintf(os.Stderr, "\nScan: %s, %d templates, %d findings (%d after filters)\n",
			templateSource, len(templates), len(allFindings), len(findings))
	}

	// Tool metadata propagated to JSON/SARIF.
	tool := report.ToolMeta{Name: "w3goaudit", Version: Version}

	// Determine output format.
	// Output rule:
	//   -o report.<ext>  → split into report.overview.<ext> + report.findings.<ext>.
	//   no -o            → render to stdout (combined where it makes sense).
	switch {
	case jsonOutput:
		if outputPath != "" {
			ovPath, fdPath := splitOutputPaths(outputPath, ".json")
			ov := report.BuildOverviewJSON(tool, summary, stats)
			if data, err := json.MarshalIndent(ov, "", "  "); err == nil {
				if err := writeOutput(string(data), ovPath); err != nil {
					return err
				}
			} else {
				return fmt.Errorf("error encoding overview JSON: %w", err)
			}
			fd := report.BuildFindingsJSON(tool, findings)
			if data, err := json.MarshalIndent(fd, "", "  "); err == nil {
				if err := writeOutput(string(data), fdPath); err != nil {
					return err
				}
			} else {
				return fmt.Errorf("error encoding findings JSON: %w", err)
			}
		} else {
			// Single combined doc to stdout: overview + findings under one envelope.
			combined := map[string]interface{}{
				"schemaVersion": report.SchemaVersion,
				"tool":          tool,
				"overview":      report.BuildOverviewJSON(tool, summary, stats),
				"findings":      report.BuildFindingsJSON(tool, findings),
			}
			data, err := json.MarshalIndent(combined, "", "  ")
			if err != nil {
				return fmt.Errorf("error encoding JSON: %w", err)
			}
			if err := writeOutput(string(data), ""); err != nil {
				return err
			}
		}

	case htmlOutput:
		if outputPath != "" {
			ovPath, fdPath := splitOutputPaths(outputPath, ".html")
			if err := writeOutput(summary.ToHTML(), ovPath); err != nil {
				return err
			}
			if err := writeOutput(report.FormatFindingsAsHTML(findings, db), fdPath); err != nil {
				return err
			}
		} else {
			// Stdout: append findings after overview.
			out := summary.ToHTML() + "\n\n" + report.FormatFindingsAsHTML(findings, db)
			if err := writeOutput(out, ""); err != nil {
				return err
			}
		}

	case mdOutput || (outputPath != "" && !sarifOutput):
		if outputPath != "" {
			ovPath, fdPath := splitOutputPaths(outputPath, ".md")
			if err := writeOutput(summary.ToMarkdown(), ovPath); err != nil {
				return err
			}
			if err := writeOutput(report.FormatFindingsAsMarkdown(findings, db), fdPath); err != nil {
				return err
			}
		} else {
			out := summary.ToMarkdown() + "\n---\n\n" + report.FormatFindingsAsMarkdown(findings, db)
			if err := writeOutput(out, ""); err != nil {
				return err
			}
		}

	default:
		// Console: summary header → stats → overview → findings.
		colorMode := report.ColorAuto
		if noColor {
			colorMode = report.ColorNever
		}
		elapsed := time.Since(scanStart).Round(time.Millisecond).String()
		report.PrintConsoleSummaryHeader(os.Stdout, findings, len(db.MainContracts), elapsed, colorMode)
		fmt.Println()
		printCombinedConsole(stats, summary, findings, colorMode == report.ColorNever)
	}

	// SARIF is additive: emitted whenever --sarif is set, alongside any other format.
	if sarifOutput {
		sarifStr, err := report.FormatFindingsAsSARIF(findings, tool, db.ProjectRoot)
		if err != nil {
			return fmt.Errorf("error encoding SARIF: %w", err)
		}
		if outputPath != "" {
			if err := writeOutput(sarifStr, sarifOutputPath(outputPath)); err != nil {
				return err
			}
		} else {
			if err := writeOutput(sarifStr, ""); err != nil {
				return err
			}
		}
	}

	// CI gate: exit non-zero (code 2) when any finding meets the --fail-on
	// threshold. Evaluated over ALL scan findings (not the display-filtered set)
	// so --min-severity/--include/--exclude can't silently weaken the gate. Done
	// last so the report is always produced first.
	if failOnSeverity != "" {
		if n := countAtLeast(allFindings, failOnSeverity); n > 0 {
			return &failOnError{msg: fmt.Sprintf("--fail-on %s: %d finding(s) at or above %s severity",
				strings.ToLower(failOnSeverity), n, strings.ToUpper(failOnSeverity))}
		}
	}

	return nil
}

// countAtLeast counts findings whose severity is at least `threshold`.
func countAtLeast(findings []*engine.Finding, threshold string) int {
	n := 0
	for _, f := range findings {
		if report.SeverityAtLeast(f.Severity, threshold) {
			n++
		}
	}
	return n
}

// splitOutputPaths derives the two output paths from a base -o path.
// Both files get an explicit ".overview" / ".findings" infix, so callers always
// know which file is which. Examples:
//
//	-o report.md   → report.overview.md   + report.findings.md
//	-o report.html → report.overview.html + report.findings.html
//	-o report.json → report.overview.json + report.findings.json
//	-o out/audit   → out/audit.overview.md  + out/audit.findings.md  (default ext .md)
func splitOutputPaths(outputPath, defaultExt string) (overviewPath, findingsPath string) {
	ext := filepath.Ext(outputPath)
	stem := outputPath
	if ext != "" {
		stem = outputPath[:len(outputPath)-len(ext)]
	} else {
		ext = defaultExt
	}
	overviewPath = stem + ".overview" + ext
	findingsPath = stem + ".findings" + ext
	return
}

// sarifOutputPath derives the SARIF output path from -o.
// Always uses .sarif extension regardless of the user's -o suffix.
func sarifOutputPath(outputPath string) string {
	if outputPath == "" {
		return ""
	}
	ext := filepath.Ext(outputPath)
	stem := outputPath
	if ext != "" {
		stem = outputPath[:len(outputPath)-len(ext)]
	}
	return stem + ".sarif"
}

// emojiOr returns "" when plainMode is true so --no-color / NO_COLOR / non-TTY
// output stays free of decorative characters that screen readers and grep
// users can't handle.
func emojiOr(e string, plain bool) string {
	if plain {
		return ""
	}
	return e
}

// printCombinedConsole prints the combined output to console.
// plainMode is set by --no-color / NO_COLOR / non-TTY stdout; when true,
// decorative emojis are suppressed for grep / pipe consumers.
func printCombinedConsole(stats *types.DatabaseStats, summary *report.SummaryReport, findings []*engine.Finding, plainMode bool) {
	// Section 1: Stats
	fmt.Println("╔══════════════════════════════════════════════════════════════╗")
	fmt.Println("║                    W3GoAudit Scan Results                    ║")
	fmt.Println("╚══════════════════════════════════════════════════════════════╝")
	fmt.Println()
	fmt.Printf("  %s Files:       %d\n", emojiOr("📁", plainMode), stats.TotalFiles)
	fmt.Printf("  %s Contracts:   %d (Interfaces: %d, Libraries: %d)\n",
		emojiOr("📝", plainMode), stats.TotalContracts, stats.TotalInterfaces, stats.TotalLibraries)
	fmt.Printf("  %s Functions:   %d (Entry: %d)\n",
		emojiOr("🔧", plainMode), stats.TotalFunctions, stats.TotalEntryFunctions)
	fmt.Printf("  %s Main:        %d\n", emojiOr("🏗️ ", plainMode), len(summary.MainContracts))
	fmt.Println()

	// Section 2: Overview per main contract
	if len(summary.MainContracts) > 0 {
		fmt.Println("── Main Contracts ──────────────────────────────────────────────")
		fmt.Println()
		for _, mc := range summary.MainContracts {
			fmt.Printf("  %s %s\n", emojiOr("📋", plainMode), mc.Name)
			if mc.SourceFile != "" {
				path := mc.SourceFile
				if cwd, err := os.Getwd(); err == nil {
					if rel, err := filepath.Rel(cwd, path); err == nil {
						path = rel
					}
				}
				fmt.Printf("     Source: %s\n", path)
			}
			if len(mc.InheritanceChain) > 0 {
				var names []string
				for _, ic := range mc.InheritanceChain {
					names = append(names, ic.Name)
				}
				fmt.Printf("     Inheritance: %s\n", strings.Join(names, " → "))
			}
			fmt.Printf("     Entry Points: %d\n", len(mc.EntryFunctions))
			for _, ep := range mc.EntryFunctions {
				mods := ""
				if len(ep.Modifiers) > 0 {
					mods = " [" + strings.Join(ep.Modifiers, ", ") + "]"
				}
				fmt.Printf("       → %s(%s)%s\n", ep.Name, ep.Selector, mods)
			}
			fmt.Println()
		}
	}

	// Section 3: Findings
	if len(findings) == 0 {
		fmt.Println("── Findings ────────────────────────────────────────────────────")
		fmt.Println()
		fmt.Printf("  %s No security issues found.\n", emojiOr("✅", plainMode))
		if templatePath == "" {
			fmt.Printf("  %s Use --template flag to specify audit rules.\n", emojiOr("💡", plainMode))
		}
		fmt.Println()
	} else {
		printFindings(findings, plainMode)
	}
}

// printFindings renders findings to console grouped by severity.
// plainMode suppresses emoji severity icons (set by --no-color / NO_COLOR).
func printFindings(findings []*engine.Finding, plainMode bool) {
	fmt.Println("── Findings ────────────────────────────────────────────────────")
	fmt.Println()

	// Group by severity
	severityGroups := make(map[string][]*engine.Finding)
	for _, f := range findings {
		sev := strings.ToUpper(f.Severity)
		if sev == "" {
			sev = "UNKNOWN"
		}
		severityGroups[sev] = append(severityGroups[sev], f)
	}

	severityOrder := []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"}
	for _, severity := range severityOrder {
		group, ok := severityGroups[severity]
		if !ok || len(group) == 0 {
			continue
		}

		icon := emojiOr(getSeverityIcon(severity), plainMode)
		if icon != "" {
			icon = icon + " "
		}
		fmt.Printf("  %s%s (%d findings)\n", icon, severity, len(group))
		fmt.Println("  " + strings.Repeat("─", 56))

		for i, f := range group {
			title := f.Title
			if title == "" {
				title = f.TemplateID
			}
			fmt.Printf("  %d. %s\n", i+1, title)

			path := f.Location.File
			if cwd, err := os.Getwd(); err == nil {
				if rel, err := filepath.Rel(cwd, path); err == nil {
					path = rel
				}
			}
			locInfo := fmt.Sprintf("%s:%d", path, f.Location.Line)
			if f.Location.Function != "" {
				locInfo += fmt.Sprintf(" in %s()", f.Location.Function)
			}
			fmt.Printf("     Location: %s\n", locInfo)

			// Reachability continuation: when the dangerous statement is
			// reached via an internal call chain (more than one hop), show
			// the path "entry ⇒ … ⇒ host" so a console reader sees both the
			// fix-here function and where the bug actually lives.
			if f.Reachability != nil && len(f.Reachability.Steps) > 1 {
				names := make([]string, 0, len(f.Reachability.Steps))
				for _, s := range f.Reachability.Steps {
					fqn := s.Function
					if s.Contract != "" && s.Function != "" {
						fqn = s.Contract + "." + s.Function
					}
					names = append(names, fqn+"()")
				}
				fmt.Printf("     ↳ via %s\n", strings.Join(names, " ⇒ "))
				if f.EntryPoint != nil && f.EntryPoint.Function != "" {
					fix := f.EntryPoint.Function
					if f.EntryPoint.Contract != "" {
						fix = f.EntryPoint.Contract + "." + f.EntryPoint.Function
					}
					fmt.Printf("     ↳ fix-here: %s\n", fix)
				}
			}

			if f.Confidence != "" {
				fmt.Printf("     Confidence: %s\n", f.Confidence)
			}
			if f.Message != "" {
				lines := strings.Split(f.Message, "\n")
				fmt.Printf("     Details: %s\n", lines[0])
			}
			fmt.Println()
		}
	}

	fmt.Println("  " + strings.Repeat("═", 56))
	fmt.Printf("  Scan Complete. Total Issues: %d\n", len(findings))
	fmt.Println("  Use -o report.md --md to generate full report.")
	fmt.Println()
}

func getSeverityIcon(severity string) string {
	switch strings.ToLower(severity) {
	case "critical":
		return "🔴"
	case "high":
		return "🟠"
	case "medium":
		return "🟡"
	case "low":
		return "🔵"
	case "info":
		return "ℹ️"
	default:
		return "❓"
	}
}
