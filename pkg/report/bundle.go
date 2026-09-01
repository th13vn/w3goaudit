package report

import (
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/th13vn/w3goaudit/pkg/engine"
	"github.com/th13vn/w3goaudit/pkg/types"
)

// BundleOptions controls optional artifacts in a result folder.
type BundleOptions struct {
	// HTML additionally emits the consolidated audit.html report.
	HTML bool
	// Now supplies the one UTC timestamp shared by every generated artifact in
	// this bundle. Nil uses time.Now.
	Now func() time.Time
}

func bundleNow(opts BundleOptions) time.Time {
	if opts.Now != nil {
		return opts.Now().UTC()
	}
	return time.Now().UTC()
}

// WriteBundle renders a complete result folder for a scan:
//
//	<dir>/
//	├── README.md          # bounded landing page
//	├── audit.md           # consolidated human-readable audit
//	├── audit.html         # optional offline mirror
//	├── results.sarif
//	├── data/{manifest.json,findings.json,overview.json,diagnostics.json,database.json,nav.json,explorer.json,xref.json}
//	└── contracts/<relative-source-path>__<ContractName>.md
//
// run.log is written separately because it is open for the whole CLI scan. The
// canonical database lives only under data/ and remains reusable via --db.
func WriteBundle(dir string, db *types.Database, summary *SummaryReport, findings []*engine.Finding, tool ToolMeta, opts BundleOptions) error {
	if db == nil {
		return fmt.Errorf("writing report bundle: nil database")
	}
	if summary == nil {
		return fmt.Errorf("writing report bundle: nil summary")
	}
	now := bundleNow(opts)
	summary, diagnostics := prepareBundleSummary(db, summary, now)
	index, err := buildContractReportIndex(summary, findings)
	if err != nil {
		return err
	}
	if _, err := planFindingAnchors(findings, findingIdentityDigest); err != nil {
		return err
	}

	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("creating output folder %s: %w", dir, err)
	}
	if err := resetManagedBundlePaths(dir); err != nil {
		return err
	}
	if err := cleanLegacyBundleArtifacts(dir); err != nil {
		return err
	}
	if err := writeBundleReports(dir, db, summary, findings, tool); err != nil {
		return err
	}
	if err := writeBundleContractReports(dir, db, summary, findings, index); err != nil {
		return err
	}
	if err := writeBundleHTML(dir, db, summary, findings, tool, opts.HTML); err != nil {
		return err
	}
	if err := writeBundleData(dir, db, summary, findings, index.refs, diagnostics, tool, now, opts); err != nil {
		return err
	}

	return nil
}

func cleanLegacyBundleArtifacts(dir string) error {
	for _, rel := range []string{
		"summary.md",
		"overview.md",
		"findings.md",
		"overview.html",
		"findings.html",
		"audit.html",
		"contracts",
		"corpus",
		filepath.Join("data", "ai-triage.json"),
		filepath.Join("data", "manifest.json"),
	} {
		if err := os.RemoveAll(filepath.Join(dir, rel)); err != nil {
			return fmt.Errorf("removing stale report artifact %s: %w", rel, err)
		}
	}
	return nil
}

func resetManagedBundlePaths(dir string) error {
	for _, rel := range []string{
		"README.md",
		"audit.md",
		"results.sarif",
		"data",
	} {
		if err := os.RemoveAll(filepath.Join(dir, rel)); err != nil {
			return fmt.Errorf("resetting managed report artifact %s: %w", rel, err)
		}
	}
	return nil
}

func prepareBundleSummary(db *types.Database, summary *SummaryReport, now time.Time) (*SummaryReport, []types.Diagnostic) {
	diagnostics := diagnosticSnapshot(db)
	bundleSummary := *summary
	bundleSummary.GeneratedAt = now
	if db.ProjectRoot != "" || bundleSummary.ProjectRoot == "" {
		bundleSummary.ProjectRoot = db.ProjectRoot
	}
	bundleSummary.ScanTarget = scanTarget(bundleSummary.ProjectRoot, db.ScanTarget)
	bundleSummary.AnalysisComplete = analysisComplete(diagnostics, true)
	bundleSummary.DiagnosticCounts = countDiagnostics(diagnostics)
	if bundleSummary.Stats == nil {
		bundleSummary.Stats = db.GetStats()
	}
	return &bundleSummary, diagnostics
}

func writeBundleReports(dir string, db *types.Database, summary *SummaryReport, findings []*engine.Finding, tool ToolMeta) error {
	if err := writeFile(filepath.Join(dir, "README.md"), FormatFolderReadme(tool, summary, findings)); err != nil {
		return err
	}
	if err := writeFile(filepath.Join(dir, "audit.md"), FormatAuditMarkdown(tool, summary, findings, db)); err != nil {
		return err
	}
	sarif, err := FormatFindingsAsSARIF(findings, tool, summary.ProjectRoot)
	if err != nil {
		return fmt.Errorf("encoding SARIF: %w", err)
	}
	return writeFile(filepath.Join(dir, "results.sarif"), sarif)
}

func writeBundleData(dir string, db *types.Database, summary *SummaryReport, findings []*engine.Finding, refs []ContractRef, diagnostics []types.Diagnostic, tool ToolMeta, now time.Time, opts BundleOptions) error {
	dataDir := filepath.Join(dir, "data")
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return fmt.Errorf("creating data folder: %w", err)
	}
	databaseForOutput := *db
	databaseForOutput.Diagnostics = diagnostics
	if err := writeJSONFile(filepath.Join(dataDir, "database.json"), &databaseForOutput, "database"); err != nil {
		return err
	}
	if err := writeJSONFile(filepath.Join(dataDir, "overview.json"), BuildOverviewJSONAt(now, tool, summary, summary.Stats), "overview"); err != nil {
		return err
	}
	if err := writeJSONFile(filepath.Join(dataDir, "findings.json"), BuildFindingsJSONAt(now, tool, findings), "findings"); err != nil {
		return err
	}
	if err := writeJSONFile(filepath.Join(dataDir, "diagnostics.json"), BuildDiagnosticsJSONAt(now, db), "diagnostics"); err != nil {
		return err
	}
	if err := writeJSONFile(filepath.Join(dataDir, "nav.json"), BuildNavJSON(db), "nav"); err != nil {
		return err
	}
	if err := writeJSONFile(filepath.Join(dataDir, "xref.json"), BuildXrefJSON(db), "xref"); err != nil {
		return err
	}
	if err := writeJSONFile(filepath.Join(dataDir, "explorer.json"), BuildExplorerJSON(db), "explorer"); err != nil {
		return err
	}
	manifest := BuildManifestAt(now, tool, summary, findings, refs, db, opts.HTML)
	return writeJSONFile(filepath.Join(dataDir, "manifest.json"), manifest, "manifest")
}

func writeJSONFile(path string, value interface{}, context string) error {
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding %s JSON: %w", context, err)
	}
	return writeFile(path, string(encoded))
}

func writeBundleHTML(dir string, db *types.Database, summary *SummaryReport, findings []*engine.Finding, tool ToolMeta, enabled bool) error {
	if !enabled {
		return nil
	}
	return writeFile(filepath.Join(dir, "audit.html"), FormatAuditHTML(tool, summary, findings, db))
}

func writeBundleContractReports(dir string, db *types.Database, summary *SummaryReport, findings []*engine.Finding, index contractReportIndex) error {
	for _, contract := range summary.MainContracts {
		if contract == nil {
			continue
		}
		reportPath, ok := index.reports[contractIdentityKey(contract)]
		if !ok {
			return fmt.Errorf("missing planned report path for %s#%s", contract.SourceFile, contract.Name)
		}
		rootPrefix := rootPrefixFor(path.Dir(reportPath))
		content := FormatContractReportMarkdown(contract, findings, db, summary.GitInfo, summary.ProjectRoot, rootPrefix, reportPath)
		if err := writeFile(filepath.Join(dir, filepath.FromSlash(reportPath)), content); err != nil {
			return err
		}
	}
	return nil
}

// rootPrefixFor returns the "../" chain that walks from a contract folder (given
// as a slash path relative to the result root) back up to the root, so links to
// top-level files resolve at any nesting depth.
func rootPrefixFor(relDir string) string {
	depth := strings.Count(relDir, "/") + 1
	return strings.Repeat("../", depth)
}

// renderStateChanges renders the per-contract state-change matrix: each state
// variable, the functions that write it, and the entry points that reach a
// writer (reachability-aware). Falls back to a plain variable list when the
// matrix could not be computed.
func renderStateChanges(mc *ContractSummary, rows []StateRow) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "# %s — State Changes\n\n", mc.Name)
	if mc.Version != "" {
		fmt.Fprintf(&sb, "**Version:** `%s`  \n", mc.Version)
	}
	fmt.Fprintf(&sb, "**State Variables:** %d\n\n", mc.StateVariableCount)

	if len(mc.StateVariables) == 0 {
		sb.WriteString("_No state variables._\n")
		return sb.String()
	}

	if len(rows) == 0 {
		// Fallback: variable list only.
		sb.WriteString("| State Var | Type | Defined In |\n")
		sb.WriteString("|-----------|------|------------|\n")
		for _, sv := range mc.StateVariables {
			fmt.Fprintf(&sb, "| `%s` | `%s` | %s |\n", sv.Name, sv.TypeName, definedInLabel(sv.DefinedIn, mc.Name))
		}
		return sb.String()
	}

	sb.WriteString("Which functions write each state variable, and which entry points reach a writer.\n\n")
	sb.WriteString("| State Var | Type | Defined In | Written By | Reachable From (entry) |\n")
	sb.WriteString("|-----------|------|------------|------------|------------------------|\n")
	for _, r := range rows {
		writers := "—"
		if len(r.Writers) > 0 {
			writers = "`" + strings.Join(r.Writers, "`, `") + "`"
		}
		entries := "—"
		if len(r.Entries) > 0 {
			entries = "`" + strings.Join(r.Entries, "`, `") + "`"
		}
		fmt.Fprintf(&sb, "| `%s` | `%s` | %s | %s | %s |\n",
			r.Var, r.TypeName, definedInLabel(r.DefinedIn, mc.Name), writers, entries)
	}
	return sb.String()
}

func definedInLabel(definedIn, main string) string {
	if definedIn == main || definedIn == "" {
		return "*self*"
	}
	return definedIn
}

// renderWorkflow renders a single entry-function workflow file: signature,
// access control, guards/checks, branch conditions, state effects, and the call
// workflow — the context block an auditor (or an AI) reasons over per entry.
func renderWorkflow(mc *ContractSummary, fn *FunctionSummary, fe *types.FunctionEffects, stateWrites []string) string {
	var sb strings.Builder

	name := fn.Selector
	if name == "" {
		name = fn.Name
	}
	fmt.Fprintf(&sb, "# %s · %s\n\n", mc.Name, name)

	// Signature
	sb.WriteString("## Signature\n\n")
	if fn.Selector != "" {
		fmt.Fprintf(&sb, "- **Selector:** `%s`\n", fn.Selector)
	}
	if fn.Signature != "" {
		fmt.Fprintf(&sb, "- **4-byte:** `%s`\n", fn.Signature)
	}
	if fn.IsPayable {
		sb.WriteString("- **Payable:** yes 💰\n")
	}
	if mc.Version != "" {
		fmt.Fprintf(&sb, "- **Version:** `%s`\n", mc.Version)
	}
	sb.WriteString("\n")

	// Access control / auth
	sb.WriteString("## Auth / Access Control\n\n")
	controlled := fn.IsAccessControlled || len(fn.Modifiers) > 0
	if fe != nil {
		controlled = controlled || fe.Auth.Controlled
	}
	if controlled {
		if len(fn.Modifiers) > 0 {
			fmt.Fprintf(&sb, "- **Modifiers:** %s\n", strings.Join(fn.Modifiers, ", "))
		}
		if fe != nil {
			for _, c := range fe.Auth.SenderChecks {
				fmt.Fprintf(&sb, "- **msg.sender check:** `%s`\n", c)
			}
		}
		if fn.IsAccessControlled {
			sb.WriteString("- Access controlled 🔒\n")
		}
	} else {
		sb.WriteString("- ⚠ **Unprotected** — no access-control modifier or msg.sender check detected\n")
	}
	if fe != nil && fe.Auth.UsesTxOrigin {
		sb.WriteString("- ⚠ Uses `tx.origin` for authorization (phishing-prone)\n")
	}
	sb.WriteString("\n")

	// Guards / checks
	sb.WriteString("## Guards / Checks\n\n")
	guards := filterGuards(fe, "require", "assert", "revert")
	if len(guards) > 0 {
		for _, g := range guards {
			fmt.Fprintf(&sb, "- `%s` — %s\n", g.Kind, codeOrText(g.Expr))
		}
	} else {
		sb.WriteString("_No require/assert/revert guards._\n")
	}
	sb.WriteString("\n")

	// Branch conditions
	branches := filterGuards(fe, "if")
	if len(branches) > 0 {
		sb.WriteString("## Branch Conditions\n\n")
		for _, g := range branches {
			fmt.Fprintf(&sb, "- %s\n", codeOrText(g.Expr))
		}
		sb.WriteString("\n")
	}

	// State effects (transitive)
	sb.WriteString("## State Effects\n\n")
	if len(stateWrites) > 0 {
		sb.WriteString("State variables written by this entry (directly or via internal calls):\n\n")
		for _, v := range stateWrites {
			fmt.Fprintf(&sb, "- `%s`\n", v)
		}
	} else {
		sb.WriteString("_No state variables written._\n")
	}
	sb.WriteString("\n")

	// Call workflow
	sb.WriteString("## Call Workflow\n\n")
	if fn.CallGraphMermaid != "" && strings.Contains(fn.CallGraphMermaid, "-->") {
		sb.WriteString("```mermaid\n")
		sb.WriteString(fn.CallGraphMermaid)
		if !strings.HasSuffix(fn.CallGraphMermaid, "\n") {
			sb.WriteString("\n")
		}
		sb.WriteString("```\n")
	} else {
		sb.WriteString("_No internal or external calls._\n")
	}

	return sb.String()
}

// filterGuards returns the guards whose kind is in the allowed set.
func filterGuards(fe *types.FunctionEffects, kinds ...string) []types.Guard {
	if fe == nil {
		return nil
	}
	allow := make(map[string]bool, len(kinds))
	for _, k := range kinds {
		allow[k] = true
	}
	var out []types.Guard
	for _, g := range fe.Guards {
		if allow[g.Kind] {
			out = append(out, g)
		}
	}
	return out
}

// codeOrText wraps a non-empty expression in backticks, else a placeholder.
func codeOrText(expr string) string {
	if strings.TrimSpace(expr) == "" {
		return "_(condition)_"
	}
	return "`" + expr + "`"
}

// --- naming / dedup helpers ---

var unsafeNameChars = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

// sanitizeName makes a string safe to use as a single path component.
func sanitizeName(s string) string {
	s = unsafeNameChars.ReplaceAllString(s, "_")
	s = strings.Trim(s, "._-")
	if s == "" {
		s = "unnamed"
	}
	return s
}

// writeFile writes content to path, creating parent dirs.
func writeFile(path, content string) error {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("creating directory %s: %w", dir, err)
		}
	}
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	return nil
}
