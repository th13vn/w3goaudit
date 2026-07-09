package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/th13vn/w3goaudit/pkg/engine"
	"github.com/th13vn/w3goaudit/pkg/home"
	"github.com/th13vn/w3goaudit/pkg/report"
	"github.com/th13vn/w3goaudit/pkg/types"
)

// Version information
var (
	Version   = "0.3.1"
	BuildTime = "dev"
)

var rootCmd = &cobra.Command{
	Use:   "w3goaudit [path]",
	Short: "Solidity Smart Contract Audit Engine",
	Long: `W3GoAudit - A Go-based static analysis engine for Solidity smart contracts.

Scan a project (or a single .sol file) for security vulnerabilities using WQL
templates. Results are written to a folder: README, summary, overview, findings,
a machine-readable data/ folder (JSON + SARIF), and one sub-folder per main
contract (under contracts/, mirroring source paths) containing per-entry workflow
files and a state-change report.

Examples:
  w3goaudit ./contracts/                       # scan → ./contracts result folder
  w3goaudit Token.sol -o audit/                # scan one file → audit/ folder
  w3goaudit ./contracts/ -t ./my-templates/    # use a custom template dir
  w3goaudit ./contracts/ -s high,critical      # only high+critical findings
  w3goaudit ./contracts/ -q                    # print summary only, write nothing
  w3goaudit -d audit/data/database.json        # re-scan a pre-built database`,
	Args:          cobra.MaximumNArgs(1),
	RunE:          runScan,
	SilenceUsage:  true,
	SilenceErrors: true,
}

// Flags for root scan command
var (
	templatePath           string
	outputPath             string
	dbPath                 string
	verbose                bool
	htmlOutput             bool
	stdoutOnly             bool
	noColor                bool
	ignoreInvalidTemplates bool
	severityList           string
	minSeverity            string
	includeTemplates       string
	excludeTemplates       string
	listTemplates          bool
	updateTemplates        bool
	updateTool             bool
)

func init() {
	rootCmd.Flags().StringVarP(&templatePath, "template", "t", "", "Template file or directory (default: ~/.w3goaudit/templates, else built-in official pack)")
	rootCmd.Flags().StringVarP(&outputPath, "output", "o", "", "Result folder path (default: a folder named after the scanned project/file)")
	rootCmd.Flags().StringVarP(&dbPath, "db", "d", "", "Load a pre-built database JSON instead of parsing source")
	rootCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Show detailed progress on the terminal (full detail is always written to run.log)")
	rootCmd.Flags().BoolVarP(&htmlOutput, "html", "H", false, "Also emit overview.html + findings.html into the result folder")
	rootCmd.Flags().BoolVarP(&stdoutOnly, "stdout", "q", false, "Print the summary to the terminal only; write no files")
	rootCmd.Flags().BoolVar(&noColor, "no-color", false, "Disable ANSI color in console output (also honored: NO_COLOR env)")
	rootCmd.Flags().BoolVar(&ignoreInvalidTemplates, "ignore-invalid-templates", false, "Skip invalid templates in a template directory instead of failing the scan")
	rootCmd.Flags().StringVarP(&severityList, "severity", "s", "", "Report only these severities (comma-separated: critical,high,medium,low,info)")
	rootCmd.Flags().StringVarP(&minSeverity, "min-severity", "m", "", "Report findings at or above this severity (critical|high|medium|low|info)")
	rootCmd.Flags().StringVarP(&includeTemplates, "include", "i", "", "Comma-separated template-ID glob(s); only matching findings are reported")
	rootCmd.Flags().StringVarP(&excludeTemplates, "exclude", "e", "", "Comma-separated template-ID glob(s); matching findings are suppressed")
	rootCmd.Flags().BoolVarP(&listTemplates, "list-templates", "l", false, "List the templates that would run (id, severity, confidence, title) and exit")
	rootCmd.Flags().BoolVarP(&updateTemplates, "update-templates", "T", false, "Update the template home (~/.w3goaudit/templates) from the latest published release and exit")
	rootCmd.Flags().BoolVarP(&updateTool, "update", "u", false, "Update w3goaudit itself via `go install …@latest` and exit")

	// Add subcommands
	rootCmd.AddCommand(buildCmd)
	rootCmd.AddCommand(extractCmd)
	rootCmd.AddCommand(completionCmd)
	rootCmd.AddCommand(versionCmd)

	// Better feedback on mistyped commands/flags.
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
	// Load the user config and apply it as defaults (CLI flags override).
	cfg, cfgErr := home.Load()
	if cfgErr != nil {
		fmt.Fprintf(os.Stderr, "warning: %v\n", cfgErr)
	}
	applyConfigDefaults(cmd, cfg)

	// --update upgrades the tool itself via the Go toolchain and exits.
	if updateTool {
		return runSelfUpdate()
	}

	// --update-templates is a maintenance command: refresh the home and exit.
	if updateTemplates {
		return runUpdateTemplates(cfg)
	}

	// First-run provisioning of ~/.w3goaudit (config + template download).
	// Skipped when the user supplies an explicit --template, since the home
	// pack would not be used. Failures are non-fatal (embedded fallback).
	if templatePath == "" {
		home.EnsureInit(func(format string, a ...any) { fmt.Printf(format+"\n", a...) })
		if cfg != nil {
			if dir, err := cfg.ResolveTemplatesDir(); err == nil && home.HasTemplates(dir) {
				templateHomeDir = dir
			}
		}
	}

	// --list-templates is an inventory query: it needs no scan target or
	// database, so handle it before requiring a path.
	if listTemplates {
		templates, templateSource, err := loadScanTemplates()
		if err != nil {
			return err
		}
		printTemplateList(templates, templateSource)
		return nil
	}

	// Need at least a path or --db.
	if len(args) == 0 && dbPath == "" {
		return fmt.Errorf("provide a path to scan or use --db to load a database\n\nUsage: w3goaudit <path> [flags]")
	}

	// --severity and --min-severity are two different filter models; using both
	// is ambiguous, so reject it up front.
	if severityList != "" && minSeverity != "" {
		return fmt.Errorf("use only one of --severity (exact set) or --min-severity (threshold)")
	}
	if minSeverity != "" && !report.IsKnownSeverity(minSeverity) {
		return fmt.Errorf("--min-severity must be one of: critical, high, medium, low, info")
	}
	for _, s := range splitGlobs(severityList) {
		if !report.IsKnownSeverity(s) {
			return fmt.Errorf("--severity %q: must be one of: critical, high, medium, low, info", s)
		}
	}

	// Honor the NO_COLOR convention (https://no-color.org).
	if os.Getenv("NO_COLOR") != "" {
		noColor = true
	}

	// Validate template path extension early.
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

	// Friendly typo handling: a mistyped subcommand parsed as a path.
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

	// Resolve the result folder and start logging into it (run.log captures full
	// detail regardless of --verbose; --verbose also tees detail to the terminal).
	var outDir string
	if !stdoutOnly {
		outDir = resolveOutputDir(inputPath, dbPath, outputPath)
		closeLog, err := setupRunLog(outDir, verbose)
		if err != nil {
			return fmt.Errorf("setting up run log: %w", err)
		}
		defer closeLog()
	} else if verbose {
		enableVerboseStdout()
	}

	scanStart := time.Now()
	progress("Reading sources", inputPath, dbPath)

	db, err := loadOrBuildDatabase(inputPath, dbPath, verbose)
	if err != nil {
		return err
	}
	report.SetReportProjectRoot(db.ProjectRoot)

	stats := db.GetStats()
	progress("Building database", fmt.Sprintf("%d files, %d contracts, %d functions",
		stats.TotalFiles, stats.TotalContracts, stats.TotalFunctions), "")

	gen := report.NewGenerator(db)
	summary := gen.GenerateSummary()

	templates, templateSource, err := loadScanTemplates()
	if err != nil {
		return err
	}

	progress("Scanning", fmt.Sprintf("%d templates (%s)", len(templates), templateSource), "")

	e := engine.New(db)
	allFindings := e.ExecuteAll(templates)
	findings, err := filterFindings(allFindings)
	if err != nil {
		return err
	}

	tool := report.ToolMeta{Name: "w3goaudit", Version: Version}
	colorMode := report.ColorAuto
	if noColor {
		colorMode = report.ColorNever
	}
	plain := colorMode == report.ColorNever
	elapsed := time.Since(scanStart).Round(time.Millisecond).String()

	// --stdout: console only, write nothing.
	if stdoutOnly {
		report.PrintConsoleSummaryHeader(os.Stdout, findings, len(db.MainContracts), elapsed, colorMode)
		fmt.Println()
		printCombinedConsole(stats, summary, findings, plain)
		printUnresolved(db, plain)
		return nil
	}

	progress("Writing report", outDir, "")
	if err := report.WriteBundle(outDir, db, summary, findings, tool, report.BundleOptions{HTML: htmlOutput}); err != nil {
		return err
	}

	// Terminal: summary header + findings + where the report landed.
	fmt.Println()
	report.PrintConsoleSummaryHeader(os.Stdout, findings, len(db.MainContracts), elapsed, colorMode)
	fmt.Println()
	printFindings(findings, plain)
	printUnresolved(db, plain)
	printResultLocation(outDir, htmlOutput, plain)
	return nil
}

// progress prints a single staged progress line to stdout. When --verbose is
// set the per-package detail goes to the terminal as well (via the verbose
// writers); these lines always appear so a default run shows what's happening.
func progress(stage, detail, extra string) {
	line := "▶ " + stage
	if detail != "" {
		line += ": " + detail
	}
	if extra != "" {
		line += " " + extra
	}
	fmt.Println(line)
}

// printResultLocation tells the user where the result folder is and what's in it.
func printResultLocation(dir string, html, plain bool) {
	icon := emojiOr("📂", plain)
	if icon != "" {
		icon += " "
	}
	fmt.Println()
	fmt.Printf("%sResults written to: %s\n", icon, dir)
	fmt.Printf("   README.md · summary.md · overview.md · findings.md · results.sarif · run.log\n")
	fmt.Printf("   data/ (manifest.json, findings.json, overview.json, database.json)\n")
	fmt.Printf("   contracts/<path>/<Contract>/ (README.md, state-changes.md, workflows/)\n")
	if html {
		fmt.Printf("   overview.html · findings.html\n")
	}
	fmt.Println()
}

// printUnresolved surfaces contracts/bases the builder could not resolve, so an
// auditor knows what was skipped rather than silently trusting full coverage.
func printUnresolved(db *types.Database, plain bool) {
	missing := db.UnresolvedBases()
	if len(missing) == 0 {
		return
	}
	icon := emojiOr("⚠", plain)
	if icon != "" {
		icon += " "
	}
	fmt.Printf("%sUnresolved references (%d) — analysis may be incomplete:\n", icon, len(missing))
	for _, m := range missing {
		fmt.Printf("   - %s\n", m)
	}
	fmt.Println()
}

// emojiOr returns "" when plainMode is true so --no-color / NO_COLOR / non-TTY
// output stays free of decorative characters.
func emojiOr(e string, plain bool) string {
	if plain {
		return ""
	}
	return e
}

// printCombinedConsole prints the stats + overview + findings to the console.
func printCombinedConsole(stats *types.DatabaseStats, summary *report.SummaryReport, findings []*engine.Finding, plainMode bool) {
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
			if mc.Version != "" {
				fmt.Printf("     Version: %s\n", mc.Version)
			}
			fmt.Printf("     Entry Points: %d\n", len(mc.EntryFunctions))
		}
		fmt.Println()
	}

	if len(findings) == 0 {
		fmt.Println("── Findings ────────────────────────────────────────────────────")
		fmt.Println()
		fmt.Printf("  %s No security issues found.\n", emojiOr("✅", plainMode))
		fmt.Println()
	} else {
		printFindings(findings, plainMode)
	}
}

// printFindings renders findings to console grouped by severity.
func printFindings(findings []*engine.Finding, plainMode bool) {
	fmt.Println("── Findings ────────────────────────────────────────────────────")
	fmt.Println()

	if len(findings) == 0 {
		fmt.Printf("  %s No security issues found.\n\n", emojiOr("✅", plainMode))
		return
	}

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

			// Default console output is title-only to stay within terminal
			// width — full detail (location, reachability, message,
			// recommendation) is always written to the result folder
			// (findings.md / data/findings.json). Use --verbose to tee the
			// full per-finding detail to the terminal as well.
			if !verbose {
				fmt.Printf("  %d. %s\n", i+1, title)
				continue
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
		if !verbose {
			fmt.Println()
		}
	}

	fmt.Println("  " + strings.Repeat("═", 56))
	fmt.Printf("  Scan Complete. Total Issues: %d\n", len(findings))
	if !verbose {
		fmt.Println("  (full detail in the result folder; re-run with --verbose for console detail)")
	}
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
