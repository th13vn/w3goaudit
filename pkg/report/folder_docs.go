package report

import (
	"fmt"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/th13vn/w3goaudit/pkg/engine"
	"github.com/th13vn/w3goaudit/pkg/types"
)

// This file renders the folder-level human documents of a result folder:
//
//	README.md   — the landing page (FormatFolderReadme)
//	summary.md  — metrics + findings-by-severity + rules-hit (FormatSummaryMarkdown)
//	overview.md — project metrics + a navigable IN-SCOPE CONTRACT INDEX
//	              (FormatOverviewMarkdown) — NOT a per-contract dump
//	contracts/<path>/<Name>/README.md — the per-contract landing (FormatContractReadme)
//
// The per-contract architectural detail (inheritance, functions, state vars)
// that used to be inlined into overview.md now lives in each contract's own
// README so the top-level overview stays a scannable index.

// contractFolderRel returns the slash path of a contract's folder relative to
// the result-folder root, mirroring the source layout:
//
//	contracts/<relative-source-path-without-ext>/<ContractName>
//
// e.g. src/vault/Vault.sol :: VulnerableVault ->
//
//	contracts/src/vault/Vault/VulnerableVault
func contractFolderRel(mc *ContractSummary) string {
	rel := relPathForReport(mc.SourceFile)
	rel = strings.TrimSuffix(rel, filepath.Ext(rel))
	return path.Join("contracts", filepath.ToSlash(rel), sanitizeName(mc.Name))
}

// findingsForContract returns the findings whose primary location is inside the
// given main contract (matched by contract name and defining source file).
func findingsForContract(findings []*engine.Finding, mc *ContractSummary) []*engine.Finding {
	var out []*engine.Finding
	for _, f := range findings {
		if f.Location.Contract == mc.Name && f.Location.File == mc.SourceFile {
			out = append(out, f)
		}
	}
	return out
}

// renderProjectMetrics writes the shared "Project Metrics" table.
func renderProjectMetrics(sb *strings.Builder, summary *SummaryReport) {
	s := summary.Stats
	if s == nil {
		return
	}
	sb.WriteString("## Project Metrics\n\n")
	sb.WriteString("| Metric | Value |\n")
	sb.WriteString("|--------|-------|\n")
	fmt.Fprintf(sb, "| Source Files | %d |\n", s.TotalFiles)
	fmt.Fprintf(sb, "| nSLOC | %d |\n", s.NSLOC)
	fmt.Fprintf(sb, "| Total Contracts | %d |\n", s.TotalContracts+s.TotalInterfaces+s.TotalLibraries)
	fmt.Fprintf(sb, "| - Contracts | %d |\n", s.TotalContracts)
	fmt.Fprintf(sb, "| - Interfaces | %d |\n", s.TotalInterfaces)
	fmt.Fprintf(sb, "| - Libraries | %d |\n", s.TotalLibraries)
	fmt.Fprintf(sb, "| Total Functions | %d |\n", s.TotalFunctions)
	fmt.Fprintf(sb, "| Entry Functions | %d |\n", s.TotalEntryFunctions)
	fmt.Fprintf(sb, "| Main Contracts | %d |\n", len(summary.MainContracts))
	if s.Framework != "" && s.Framework != "unknown" {
		fmt.Fprintf(sb, "| Framework | %s |\n", s.Framework)
	}
	sb.WriteString("\n")
}

// renderSeverityCounts writes a findings-by-severity table.
func renderSeverityCounts(sb *strings.Builder, findings []*engine.Finding) {
	counts := countBySeverity(findings)
	sb.WriteString("| Severity | Count |\n")
	sb.WriteString("|----------|-------|\n")
	for _, sev := range SeverityOrder {
		fmt.Fprintf(sb, "| %s | %d |\n", sevTitle(sev), counts[sev])
	}
	if counts["UNKNOWN"] > 0 {
		fmt.Fprintf(sb, "| Unknown | %d |\n", counts["UNKNOWN"])
	}
	fmt.Fprintf(sb, "| **Total** | **%d** |\n", len(findings))
	sb.WriteString("\n")
}

// sevTitle title-cases a canonical severity label (CRITICAL -> Critical).
func sevTitle(sev string) string {
	if sev == "" {
		return sev
	}
	return strings.ToUpper(sev[:1]) + strings.ToLower(sev[1:])
}

// header writes the shared document header block (generated time, repo/branch).
func writeDocHeader(sb *strings.Builder, summary *SummaryReport) {
	fmt.Fprintf(sb, "**Generated:** %s  \n", summary.GeneratedAt.Format("2006-01-02 15:04:05"))
	if summary.GitInfo != nil && summary.GitInfo.RemoteURL != "" {
		fmt.Fprintf(sb, "**Repository:** [%s](%s)  \n", summary.GitInfo.RemoteURL, summary.GitInfo.RemoteURL)
		if summary.GitInfo.Branch != "" {
			fmt.Fprintf(sb, "**Branch:** `%s`  \n", summary.GitInfo.Branch)
		}
	} else if summary.ProjectRoot != "" {
		fmt.Fprintf(sb, "**Project Root:** `%s`  \n", summary.ProjectRoot)
	}
	sb.WriteString("\n")
}

// FormatFolderReadme renders README.md — the result folder's landing page.
// It orients a human: what this is, the headline finding counts, and links to
// every other artifact in the folder.
func FormatFolderReadme(tool ToolMeta, summary *SummaryReport, findings []*engine.Finding) string {
	var sb strings.Builder

	name := "Audit"
	if summary.ProjectRoot != "" {
		name = filepath.Base(summary.ProjectRoot)
	}
	fmt.Fprintf(&sb, "# %s — %s Report\n\n", name, tool.Name)
	fmt.Fprintf(&sb, "**Tool:** `%s %s`  \n", tool.Name, tool.Version)
	writeDocHeader(&sb, summary)

	c := countBySeverity(findings)
	fmt.Fprintf(&sb, "**%d findings** — %d critical, %d high, %d medium, %d low, %d info.\n\n",
		len(findings), c["CRITICAL"], c["HIGH"], c["MEDIUM"], c["LOW"], c["INFO"])
	renderSeverityCounts(&sb, findings)

	sb.WriteString("## Contents\n\n")
	sb.WriteString("| File | What's inside |\n")
	sb.WriteString("|------|---------------|\n")
	sb.WriteString("| [findings.md](findings.md) | Full security findings, severity-sorted, with reachability traces and fixes |\n")
	sb.WriteString("| [summary.md](summary.md) | Metrics, findings-by-severity, and rules-hit tables |\n")
	sb.WriteString("| [overview.md](overview.md) | Project metrics and the in-scope contract index |\n")
	sb.WriteString("| [results.sarif](results.sarif) | SARIF 2.1.0 for CI / GitHub Code Scanning |\n")
	sb.WriteString("| [contracts/](contracts/) | Per-contract detail (README, state-changes, workflows) mirroring source paths |\n")
	sb.WriteString("| [data/](data/) | Machine-readable output (manifest, findings, overview, database) |\n")
	sb.WriteString("| run.log | Full scan log |\n")
	sb.WriteString("\n")

	return sb.String()
}

// FormatSummaryMarkdown renders summary.md — a compact, machine-and-human
// friendly digest: project metrics, findings by severity, and a rules-hit table.
func FormatSummaryMarkdown(tool ToolMeta, summary *SummaryReport, findings []*engine.Finding) string {
	var sb strings.Builder
	sb.WriteString("# Scan Summary\n\n")
	fmt.Fprintf(&sb, "**Tool:** `%s %s`  \n", tool.Name, tool.Version)
	writeDocHeader(&sb, summary)

	renderProjectMetrics(&sb, summary)

	sb.WriteString("## Findings by Severity\n\n")
	renderSeverityCounts(&sb, findings)

	sb.WriteString("## Rules Hit\n\n")
	renderRulesHit(&sb, findings)

	return sb.String()
}

// renderRulesHit writes a table of the templates that produced findings, sorted
// by severity then by occurrence count (descending).
func renderRulesHit(sb *strings.Builder, findings []*engine.Finding) {
	if len(findings) == 0 {
		sb.WriteString("_No findings._\n")
		return
	}
	type ruleRow struct {
		id, title, severity string
		count               int
	}
	byID := make(map[string]*ruleRow)
	var order []string
	for _, f := range findings {
		key := f.TemplateID
		if key == "" {
			key = "(no-id): " + f.Title
		}
		if r, ok := byID[key]; ok {
			r.count++
		} else {
			byID[key] = &ruleRow{id: f.TemplateID, title: f.Title, severity: normalizeSeverity(f.Severity), count: 1}
			order = append(order, key)
		}
	}
	rows := make([]*ruleRow, 0, len(order))
	for _, k := range order {
		rows = append(rows, byID[k])
	}
	sort.SliceStable(rows, func(i, j int) bool {
		ri, rj := SeverityRank(rows[i].severity), SeverityRank(rows[j].severity)
		if ri != rj {
			return ri < rj
		}
		if rows[i].count != rows[j].count {
			return rows[i].count > rows[j].count
		}
		return rows[i].id < rows[j].id
	})

	sb.WriteString("| Severity | Rule ID | Title | Occurrences |\n")
	sb.WriteString("|----------|---------|-------|-------------|\n")
	for _, r := range rows {
		id := r.id
		if id == "" {
			id = "—"
		}
		fmt.Fprintf(sb, "| %s | `%s` | %s | %d |\n", sevTitle(r.severity), id, r.title, r.count)
	}
	sb.WriteString("\n")
}

// FormatOverviewMarkdown renders overview.md as a navigable index: project
// metrics plus one row per in-scope main contract (with a link into its folder),
// rather than dumping every contract's full detail inline.
func FormatOverviewMarkdown(summary *SummaryReport, findings []*engine.Finding, db *types.Database) string {
	var sb strings.Builder
	sb.WriteString("# Project Overview\n\n")
	writeDocHeader(&sb, summary)
	renderProjectMetrics(&sb, summary)

	sb.WriteString("## Contracts\n\n")
	if len(summary.MainContracts) == 0 {
		sb.WriteString("_No main contracts._\n")
		return sb.String()
	}

	sb.WriteString("| Contract | Source | Version | Entry Pts | State Vars | Findings | Detail |\n")
	sb.WriteString("|----------|--------|---------|-----------|------------|----------|--------|\n")
	for _, mc := range summary.MainContracts {
		src := relPathForReport(mc.SourceFile)
		src = filepath.ToSlash(src)
		version := mc.Version
		if version == "" {
			version = "—"
		}
		nf := len(findingsForContract(findings, mc))
		link := contractFolderRel(mc) + "/README.md"
		fmt.Fprintf(&sb, "| `%s` | `%s` | `%s` | %d | %d | %d | [detail](%s) |\n",
			mc.Name, src, version, mc.EntryFunctionCount, mc.StateVariableCount, nf, link)
	}
	sb.WriteString("\n")
	return sb.String()
}

// FormatContractReadme renders the per-contract README.md: a header, the
// findings that land in this contract, the architectural detail (inheritance,
// functions, state variables), and links to the sibling detail files.
//
// rootPrefix is the relative path back to the result-folder root (e.g.
// "../../../../") so links to top-level files resolve regardless of how deep
// the mirrored source path nests this contract's folder.
func FormatContractReadme(mc *ContractSummary, findings []*engine.Finding, gitInfo *GitInfo, projectRoot, rootPrefix string) string {
	var sb strings.Builder

	fmt.Fprintf(&sb, "# %s\n\n", mc.Name)

	// File path — link to the repo when a git URL is available.
	fileDisplay := relPathForReport(mc.SourceFile)
	if gitInfo != nil && gitInfo.RemoteURL != "" && projectRoot != "" {
		if relPath, err := filepath.Rel(projectRoot, mc.SourceFile); err == nil {
			relPath = filepath.ToSlash(relPath)
			gitURL := gitInfo.RemoteURL + "/blob/" + gitInfo.Branch + "/" + relPath
			fileDisplay = fmt.Sprintf("[%s](%s)", relPath, gitURL)
		}
	}
	fmt.Fprintf(&sb, "**File:** %s  \n", fileDisplay)
	if mc.Version != "" {
		fmt.Fprintf(&sb, "**Version:** `%s`  \n", mc.Version)
	}
	fmt.Fprintf(&sb, "**Entry Points:** %d  \n", mc.EntryFunctionCount)
	fmt.Fprintf(&sb, "**State Variables:** %d  \n", mc.StateVariableCount)
	sb.WriteString("\n")

	// Findings landing in this contract.
	sb.WriteString("## Findings in this contract\n\n")
	cf := findingsForContract(findings, mc)
	if len(cf) == 0 {
		sb.WriteString("_No findings._\n\n")
	} else {
		sort.SliceStable(cf, func(i, j int) bool {
			ri, rj := SeverityRank(normalizeSeverity(cf[i].Severity)), SeverityRank(normalizeSeverity(cf[j].Severity))
			if ri != rj {
				return ri < rj
			}
			return cf[i].Location.Line < cf[j].Location.Line
		})
		sb.WriteString("| Severity | Finding | Function | Line |\n")
		sb.WriteString("|----------|---------|----------|------|\n")
		for _, f := range cf {
			fn := f.Location.Function
			if fn == "" {
				fn = "—"
			}
			title := f.Title
			if title == "" {
				title = f.TemplateID
			}
			fmt.Fprintf(&sb, "| %s | %s | `%s` | %d |\n",
				sevTitle(normalizeSeverity(f.Severity)), title, fn, f.Location.Line)
		}
		fmt.Fprintf(&sb, "\nSee [findings.md](%sfindings.md) for full detail.\n\n", rootPrefix)
	}

	// Detail file links.
	sb.WriteString("## Detail\n\n")
	sb.WriteString("- [state-changes.md](state-changes.md) — state-variable write matrix\n")
	if len(mc.EntryFunctions) > 0 {
		sb.WriteString("- [workflows/](workflows/) — per-entry-point context (auth, guards, effects, call graph)\n")
	}
	sb.WriteString("\n")

	// Architectural detail (inheritance, functions, state variables).
	sb.WriteString(mc.renderRestOfContract())

	return sb.String()
}
