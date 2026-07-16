package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/th13vn/w3goaudit/pkg/home"
)

// Version information
var (
	Version   = "0.4.0"
	BuildTime = "dev"
)

var rootCmd = &cobra.Command{
	Use:     "w3goaudit [path]",
	Version: Version, // wires the --version flag (in addition to the `version` subcommand)
	Short:   "Solidity Smart Contract Audit Engine",
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
	strictImports          bool
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
	rootCmd.Flags().BoolVar(&strictImports, "strict-imports", false, "Fail when any Solidity import cannot be resolved")
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
	cfg, cfgErr := home.Load()
	if cfgErr != nil {
		fmt.Fprintf(os.Stderr, "warning: %v\n", cfgErr)
	}

	if updateTool {
		return runSelfUpdate()
	}
	if updateTemplates {
		return runUpdateTemplates(cfg)
	}

	inputPath := ""
	if len(args) > 0 {
		inputPath = args[0]
	}
	opts := scanOptions{
		InputPath:              inputPath,
		DBPath:                 dbPath,
		TemplatePath:           templatePath,
		OutputPath:             outputPath,
		Severity:               severityList,
		MinSeverity:            minSeverity,
		Include:                includeTemplates,
		Exclude:                excludeTemplates,
		Verbose:                verbose,
		HTML:                   htmlOutput,
		StdoutOnly:             stdoutOnly,
		NoColor:                noColor,
		IgnoreInvalidTemplates: ignoreInvalidTemplates,
		ListTemplates:          listTemplates,
		StrictImports:          strictImports,
		Stdout:                 os.Stdout,
		Stderr:                 os.Stderr,
	}
	applyConfigDefaults(cmd, cfg, &opts)
	if os.Getenv("NO_COLOR") != "" {
		opts.NoColor = true
	}

	if opts.TemplatePath == "" {
		home.EnsureInit(func(format string, a ...any) { fmt.Fprintf(opts.Stderr, format+"\n", a...) })
		if cfg != nil {
			if dir, err := cfg.ResolveTemplatesDir(); err == nil && home.HasTemplates(dir) {
				opts.TemplateHomeDir = dir
			}
		}
	}

	if opts.InputPath != "" && opts.DBPath == "" {
		if _, statErr := os.Stat(inputPath); os.IsNotExist(statErr) {
			msg := fmt.Sprintf("path %q does not exist", inputPath)
			if sugs := cmd.Root().SuggestionsFor(inputPath); len(sugs) > 0 {
				msg += fmt.Sprintf("\n\nDid you mean the subcommand %q?  (try: w3goaudit %s --help)", sugs[0], sugs[0])
			}
			msg += "\n\nUsage: w3goaudit <path> [flags]   —  run `w3goaudit --help` for all commands"
			return fmt.Errorf("%s", msg)
		}
	}
	return executeScan(opts)
}

// emojiOr returns "" when plainMode is true so --no-color / NO_COLOR / non-TTY
// output stays free of decorative characters.
func emojiOr(e string, plain bool) string {
	if plain {
		return ""
	}
	return e
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
