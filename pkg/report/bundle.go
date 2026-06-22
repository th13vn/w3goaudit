package report

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/th13vn/w3goaudit/pkg/engine"
	"github.com/th13vn/w3goaudit/pkg/types"
)

// BundleOptions controls optional artifacts in a result folder.
type BundleOptions struct {
	// HTML additionally emits overview.html + findings.html mirrors.
	HTML bool
}

// WriteBundle renders a complete result folder for a scan:
//
//	<dir>/
//	├── overview.md
//	├── findings.md
//	├── results.sarif
//	├── corpus/{database.json,findings.json,overview.json}
//	└── <MainContract>/
//	    ├── state-changes.md
//	    └── workflows/<entryFn>.md
//
// run.log is written separately (it is open for the whole scan), and HTML
// mirrors are added when opts.HTML is set. The canonical database lives only
// under corpus/ (reusable via --db).
func WriteBundle(dir string, db *types.Database, summary *SummaryReport, findings []*engine.Finding, tool ToolMeta, opts BundleOptions) error {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("creating output folder %s: %w", dir, err)
	}

	// Top-level human reports.
	if err := writeFile(filepath.Join(dir, "overview.md"), summary.ToMarkdown()); err != nil {
		return err
	}
	if err := writeFile(filepath.Join(dir, "findings.md"), FormatFindingsAsMarkdown(findings, db)); err != nil {
		return err
	}

	// SARIF (always).
	sarifStr, err := FormatFindingsAsSARIF(findings, tool, db.ProjectRoot)
	if err != nil {
		return fmt.Errorf("encoding SARIF: %w", err)
	}
	if err := writeFile(filepath.Join(dir, "results.sarif"), sarifStr); err != nil {
		return err
	}

	// Machine-readable corpus (canonical DB + JSON report mirror).
	corpus := filepath.Join(dir, "corpus")
	if err := os.MkdirAll(corpus, 0755); err != nil {
		return fmt.Errorf("creating corpus folder: %w", err)
	}
	if dbJSON, err := json.MarshalIndent(db, "", "  "); err != nil {
		return fmt.Errorf("encoding database JSON: %w", err)
	} else if err := writeFile(filepath.Join(corpus, "database.json"), string(dbJSON)); err != nil {
		return err
	}
	if ovJSON, err := json.MarshalIndent(BuildOverviewJSON(tool, summary, summary.Stats), "", "  "); err != nil {
		return fmt.Errorf("encoding overview JSON: %w", err)
	} else if err := writeFile(filepath.Join(corpus, "overview.json"), string(ovJSON)); err != nil {
		return err
	}
	if fdJSON, err := json.MarshalIndent(BuildFindingsJSON(tool, findings), "", "  "); err != nil {
		return fmt.Errorf("encoding findings JSON: %w", err)
	} else if err := writeFile(filepath.Join(corpus, "findings.json"), string(fdJSON)); err != nil {
		return err
	}

	// Optional HTML mirror.
	if opts.HTML {
		if err := writeFile(filepath.Join(dir, "overview.html"), summary.ToHTML()); err != nil {
			return err
		}
		if err := writeFile(filepath.Join(dir, "findings.html"), FormatFindingsAsHTML(findings, db)); err != nil {
			return err
		}
	}

	// Per-main-contract folders. Prune any stale contract dirs from a prior run
	// so a re-scan doesn't leave deleted contracts behind.
	dirNames := contractDirNames(summary.MainContracts)
	if err := pruneStaleContractDirs(dir, dirNames); err != nil {
		return err
	}
	for i, mc := range summary.MainContracts {
		// Resolve the summary back to its database contract so we can attach the
		// reachability-aware state matrix and per-function effects. When it can't
		// be resolved we still emit the folder with the basic (effects-free) view.
		var smb *stateMatrixBuilder
		if c := db.GetContract(types.MakeContractID(mc.SourceFile, mc.Name)); c != nil {
			smb = newStateMatrixBuilder(db, c)
		}
		if err := writeContractFolder(filepath.Join(dir, dirNames[i]), db, mc, smb); err != nil {
			return err
		}
	}

	return nil
}

// writeContractFolder writes state-changes.md and workflows/<entry>.md for one
// main contract. smb may be nil when the contract could not be resolved.
func writeContractFolder(cdir string, db *types.Database, mc *ContractSummary, smb *stateMatrixBuilder) error {
	if err := os.MkdirAll(cdir, 0755); err != nil {
		return fmt.Errorf("creating contract folder %s: %w", cdir, err)
	}

	var rows []StateRow
	if smb != nil {
		rows = BuildStateMatrix(db, smb.main, mc.StateVariables)
	}
	if err := writeFile(filepath.Join(cdir, "state-changes.md"), renderStateChanges(mc, rows)); err != nil {
		return err
	}

	wdir := filepath.Join(cdir, "workflows")
	if err := os.MkdirAll(wdir, 0755); err != nil {
		return fmt.Errorf("creating workflows folder %s: %w", wdir, err)
	}
	fileNames := workflowFileNames(mc.EntryFunctions)
	for i, fn := range mc.EntryFunctions {
		var fe *types.FunctionEffects
		var writes []string
		if smb != nil {
			if rf, ok := smb.resolveEntry(fn.Selector, fn.Name); ok {
				fe = smb.effects(rf)
				for v := range smb.transitiveWrites(rf) {
					writes = append(writes, v)
				}
				sort.Strings(writes)
			}
		}
		if err := writeFile(filepath.Join(wdir, fileNames[i]), renderWorkflow(mc, fn, fe, writes)); err != nil {
			return err
		}
	}
	return nil
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

// contractDirNames assigns a folder name to each main contract, disambiguating
// duplicate contract names (across files) by appending the source file stem.
func contractDirNames(contracts []*ContractSummary) []string {
	counts := make(map[string]int)
	for _, c := range contracts {
		counts[c.Name]++
	}
	names := make([]string, len(contracts))
	used := make(map[string]bool)
	for i, c := range contracts {
		base := sanitizeName(c.Name)
		if counts[c.Name] > 1 {
			stem := fileStem(c.SourceFile)
			base = sanitizeName(c.Name + "__" + stem)
		}
		name := base
		for n := 2; used[name]; n++ {
			name = fmt.Sprintf("%s__%d", base, n)
		}
		used[name] = true
		names[i] = name
	}
	return names
}

// workflowFileNames assigns "<entryFn>.md" to each entry function, appending the
// 4-byte selector hash to disambiguate overloaded names within one contract.
func workflowFileNames(fns []*FunctionSummary) []string {
	counts := make(map[string]int)
	for _, fn := range fns {
		counts[fn.Name]++
	}
	names := make([]string, len(fns))
	used := make(map[string]bool)
	for i, fn := range fns {
		base := sanitizeName(fn.Name)
		if counts[fn.Name] > 1 && fn.Signature != "" {
			base = sanitizeName(fn.Name + "__" + fn.Signature)
		}
		name := base + ".md"
		for n := 2; used[name]; n++ {
			name = fmt.Sprintf("%s__%d.md", base, n)
		}
		used[name] = true
		names[i] = name
	}
	return names
}

// fileStem returns the base filename without its extension.
func fileStem(path string) string {
	b := filepath.Base(path)
	return strings.TrimSuffix(b, filepath.Ext(b))
}

// pruneStaleContractDirs removes contract folders left by a previous scan that
// are not part of the current set. It only touches directories containing a
// workflows/ subdir or state-changes.md so it never deletes unrelated files a
// user may have placed in the output folder.
func pruneStaleContractDirs(dir string, keep []string) error {
	keepSet := make(map[string]bool, len(keep))
	for _, k := range keep {
		keepSet[k] = true
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil // folder is new; nothing to prune
	}
	reserved := map[string]bool{"corpus": true}
	for _, e := range entries {
		if !e.IsDir() || keepSet[e.Name()] || reserved[e.Name()] {
			continue
		}
		cdir := filepath.Join(dir, e.Name())
		_, scErr := os.Stat(filepath.Join(cdir, "state-changes.md"))
		_, wfErr := os.Stat(filepath.Join(cdir, "workflows"))
		if scErr == nil || wfErr == nil {
			if err := os.RemoveAll(cdir); err != nil {
				return fmt.Errorf("pruning stale contract folder %s: %w", cdir, err)
			}
		}
	}
	return nil
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
