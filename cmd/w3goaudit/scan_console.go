package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/th13vn/w3goaudit/pkg/engine"
	"github.com/th13vn/w3goaudit/pkg/report"
	"github.com/th13vn/w3goaudit/pkg/types"
)

func progressTo(w io.Writer, stage, detail, extra string) {
	line := "▶ " + stage
	if detail != "" {
		line += ": " + detail
	}
	if extra != "" {
		line += " " + extra
	}
	fmt.Fprintln(w, line)
}

func printResultLocationTo(w io.Writer, dir string, html, plain bool) {
	icon := emojiOr("📂", plain)
	if icon != "" {
		icon += " "
	}
	fmt.Fprintln(w)
	fmt.Fprintf(w, "%sResults written to: %s\n", icon, dir)
	fmt.Fprintln(w, "   README.md · summary.md · overview.md · findings.md · results.sarif · run.log")
	fmt.Fprintln(w, "   data/ (manifest.json, findings.json, overview.json, diagnostics.json, database.json)")
	fmt.Fprintln(w, "   contracts/<path>/<Contract>/ (README.md, state-changes.md, workflows/)")
	if html {
		fmt.Fprintln(w, "   overview.html · findings.html")
	}
	fmt.Fprintln(w)
}

func printUnresolvedTo(w io.Writer, db *types.Database, plain bool) {
	missing := db.UnresolvedBases()
	if len(missing) == 0 {
		return
	}
	icon := emojiOr("⚠", plain)
	if icon != "" {
		icon += " "
	}
	fmt.Fprintf(w, "%sUnresolved references (%d) — analysis may be incomplete:\n", icon, len(missing))
	for _, unresolved := range missing {
		fmt.Fprintf(w, "   - %s\n", unresolved)
	}
	fmt.Fprintln(w)
}

func printCombinedConsoleTo(w io.Writer, stats *types.DatabaseStats, summary *report.SummaryReport, findings []*engine.Finding, plain, verbose bool) {
	fmt.Fprintln(w, "╔══════════════════════════════════════════════════════════════╗")
	fmt.Fprintln(w, "║                    W3GoAudit Scan Results                    ║")
	fmt.Fprintln(w, "╚══════════════════════════════════════════════════════════════╝")
	fmt.Fprintln(w)
	fmt.Fprintf(w, "  %s Files:       %d\n", emojiOr("📁", plain), stats.TotalFiles)
	fmt.Fprintf(w, "  %s Contracts:   %d (Interfaces: %d, Libraries: %d)\n", emojiOr("📝", plain), stats.TotalContracts, stats.TotalInterfaces, stats.TotalLibraries)
	fmt.Fprintf(w, "  %s Functions:   %d (Entry: %d)\n", emojiOr("🔧", plain), stats.TotalFunctions, stats.TotalEntryFunctions)
	fmt.Fprintf(w, "  %s Main:        %d\n\n", emojiOr("🏗️ ", plain), len(summary.MainContracts))
	if len(summary.MainContracts) > 0 {
		fmt.Fprintln(w, "── Main Contracts ──────────────────────────────────────────────")
		fmt.Fprintln(w)
		for _, contract := range summary.MainContracts {
			fmt.Fprintf(w, "  %s %s\n", emojiOr("📋", plain), contract.Name)
			if contract.SourceFile != "" {
				path := contract.SourceFile
				if cwd, err := os.Getwd(); err == nil {
					if rel, err := filepath.Rel(cwd, path); err == nil {
						path = rel
					}
				}
				fmt.Fprintf(w, "     Source: %s\n", path)
			}
			if contract.Version != "" {
				fmt.Fprintf(w, "     Version: %s\n", contract.Version)
			}
			fmt.Fprintf(w, "     Entry Points: %d\n", len(contract.EntryFunctions))
		}
		fmt.Fprintln(w)
	}
	printFindingsTo(w, findings, plain, verbose)
}

func printFindingsTo(w io.Writer, findings []*engine.Finding, plain, verbose bool) {
	fmt.Fprintln(w, "── Findings ────────────────────────────────────────────────────")
	fmt.Fprintln(w)
	if len(findings) == 0 {
		fmt.Fprintf(w, "  %s No security issues found.\n\n", emojiOr("✅", plain))
		return
	}
	groups := make(map[string][]*engine.Finding)
	for _, finding := range findings {
		severity := strings.ToUpper(finding.Severity)
		if severity == "" {
			severity = "UNKNOWN"
		}
		groups[severity] = append(groups[severity], finding)
	}
	for _, severity := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"} {
		group := groups[severity]
		if len(group) == 0 {
			continue
		}
		icon := emojiOr(getSeverityIcon(severity), plain)
		if icon != "" {
			icon += " "
		}
		fmt.Fprintf(w, "  %s%s (%d findings)\n", icon, severity, len(group))
		fmt.Fprintln(w, "  "+strings.Repeat("─", 56))
		for index, finding := range group {
			title := finding.Title
			if title == "" {
				title = finding.TemplateID
			}
			fmt.Fprintf(w, "  %d. %s\n", index+1, title)
			if !verbose {
				continue
			}

			path := finding.Location.File
			if cwd, err := os.Getwd(); err == nil {
				if rel, err := filepath.Rel(cwd, path); err == nil {
					path = rel
				}
			}
			location := fmt.Sprintf("%s:%d", path, finding.Location.Line)
			if finding.Location.Function != "" {
				location += fmt.Sprintf(" in %s()", finding.Location.Function)
			}
			fmt.Fprintf(w, "     Location: %s\n", location)

			if finding.Reachability != nil && len(finding.Reachability.Steps) > 1 {
				names := make([]string, 0, len(finding.Reachability.Steps))
				for _, step := range finding.Reachability.Steps {
					name := step.Function
					if step.Contract != "" && step.Function != "" {
						name = step.Contract + "." + step.Function
					}
					names = append(names, name+"()")
				}
				fmt.Fprintf(w, "     ↳ via %s\n", strings.Join(names, " ⇒ "))
				if finding.EntryPoint != nil && finding.EntryPoint.Function != "" {
					fix := finding.EntryPoint.Function
					if finding.EntryPoint.Contract != "" {
						fix = finding.EntryPoint.Contract + "." + finding.EntryPoint.Function
					}
					fmt.Fprintf(w, "     ↳ fix-here: %s\n", fix)
				}
			}
			if finding.Confidence != "" {
				fmt.Fprintf(w, "     Confidence: %s\n", finding.Confidence)
			}
			if finding.Message != "" {
				fmt.Fprintf(w, "     Details: %s\n", strings.Split(finding.Message, "\n")[0])
			}
			fmt.Fprintln(w)
		}
		fmt.Fprintln(w)
	}
	fmt.Fprintln(w, "  "+strings.Repeat("═", 56))
	fmt.Fprintf(w, "  Scan Complete. Total Issues: %d\n", len(findings))
	if !verbose {
		fmt.Fprintln(w, "  (full detail in the result folder; re-run with --verbose for console detail)")
	}
	fmt.Fprintln(w)
}
