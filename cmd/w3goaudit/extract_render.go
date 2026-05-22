package main

// extract_render.go — output-format helpers for the `extract` subcommands.
//
// Two consumers drive the design:
//
//   1. AI agents / LLMs feeding extract output back as context. They prefer
//      markdown (compact, headers, fenced code blocks, tables) over deeply
//      nested JSON, which is token-heavy and hard to summarize.
//
//   2. Humans running `w3goaudit extract …` at the terminal or in scripts.
//      JSON stays the default for scripting; markdown via `--format=md` (or
//      inferred from `-o report.md`) for paste-into-doc workflows.
//
// Every subcommand routes through writeExtract(), which picks JSON or
// markdown based on the resolved format and writes via writeOutput().

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/th13vn/w3goaudit-engine/pkg/types"
)

// ExtractSchemaVersion is the schema version embedded in every extract JSON
// output. Bumped on any breaking shape change so downstream tools can
// refuse to parse mismatched majors.
const ExtractSchemaVersion = "1.0.0"

// ExtractFormat selects the output format for an extract subcommand.
type ExtractFormat string

const (
	FormatJSON ExtractFormat = "json"
	FormatMD   ExtractFormat = "md"
)

// resolveExtractFormat picks the output format from the `--format` flag,
// falling back to inferring from the `-o` extension, then JSON as the
// machine-friendly default.
func resolveExtractFormat(cmd *cobra.Command) ExtractFormat {
	if fmtFlag, _ := cmd.Flags().GetString("format"); fmtFlag != "" {
		switch strings.ToLower(fmtFlag) {
		case "md", "markdown":
			return FormatMD
		case "json":
			return FormatJSON
		}
	}
	outPath, _ := cmd.Flags().GetString("output")
	if outPath != "" {
		switch strings.ToLower(filepath.Ext(outPath)) {
		case ".md", ".markdown":
			return FormatMD
		}
	}
	return FormatJSON
}

// addExtractFormatFlag registers `--format` consistently across all extract
// subcommands so the flag name and help text stay aligned.
func addExtractFormatFlag(cmd *cobra.Command) {
	cmd.Flags().String("format", "", "Output format: json (default) or md (LLM/human-friendly markdown). Inferred from -o extension if unset.")
}

// writeExtract is the single sink every extract subcommand uses. It picks
// JSON or markdown based on `format`, runs the matching renderer, and
// writes through writeOutput so the overwrite-warning + EISDIR check
// behavior is shared with the scan path.
//
// `mdRender` should return ready-to-print markdown when invoked.
func writeExtract(v interface{}, mdRender func() string, outPath string, format ExtractFormat) error {
	if format == FormatMD {
		return writeOutput(mdRender(), outPath)
	}
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding JSON: %w", err)
	}
	return writeOutput(string(data), outPath)
}

// relPathFromDB renders an absolute file path as relative to the project
// root when possible, so extract output stays portable across machines and
// short enough to grep. Falls back to basename outside the project root.
func relPathFromDB(db *types.Database, absFile string) string {
	if db == nil || db.ProjectRoot == "" || absFile == "" {
		return absFile
	}
	if rel, err := filepath.Rel(db.ProjectRoot, absFile); err == nil && !strings.HasPrefix(rel, "..") {
		return rel
	}
	return filepath.Base(absFile)
}

// ─────────────────────────────────────────────────────────────────────────────
// Renderers
// ─────────────────────────────────────────────────────────────────────────────

// renderEntryMarkdown lays the entry-point summary as a markdown table
// followed by per-function detail lines — compact for LLMs, readable for
// humans pasting into PR descriptions.
func renderEntryMarkdown(o EntryOutput, db *types.Database) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "# Entry Functions: %s\n\n", o.Contract)
	fmt.Fprintf(&sb, "**Source:** `%s`\n", relPathFromDB(db, o.SourceFile))
	fmt.Fprintf(&sb, "**Entry count:** %d\n\n", o.EntryCount)
	if len(o.EntryFunctions) == 0 {
		sb.WriteString("_(no entry functions)_\n")
		return sb.String()
	}
	sb.WriteString("| Function | Selector | Visibility | Mutability | Modifiers | Lines |\n")
	sb.WriteString("|---|---|---|---|---|---|\n")
	for _, fn := range o.EntryFunctions {
		mods := "—"
		if len(fn.Modifiers) > 0 {
			mods = strings.Join(fn.Modifiers, ", ")
		}
		fmt.Fprintf(&sb, "| `%s` | `%s` | %s | %s | %s | %d–%d |\n",
			fn.Name, fn.Selector, fn.Visibility, defaultStr(fn.Mutability, "nonpayable"),
			mods, fn.StartLine, fn.EndLine)
	}
	return sb.String()
}

// renderMainMarkdown produces a project overview suitable for "tell the LLM
// what contracts exist".
func renderMainMarkdown(o MainOutput, db *types.Database) string {
	var sb strings.Builder
	sb.WriteString("# Main Contracts\n\n")
	if len(o.MainContracts) == 0 {
		sb.WriteString("_(no deployable main contracts detected)_\n")
		return sb.String()
	}
	sb.WriteString("| Contract | Source | Entry Funcs | Functions | State Vars | Inheritance |\n")
	sb.WriteString("|---|---|---|---|---|---|\n")
	for _, mc := range o.MainContracts {
		inh := strings.Join(mc.InheritanceChain, " → ")
		if inh == "" {
			inh = "—"
		}
		fmt.Fprintf(&sb, "| `%s` | `%s` | %d | %d | %d | %s |\n",
			mc.Name, relPathFromDB(db, mc.SourceFile),
			mc.EntryFuncCount, mc.FunctionCount, mc.StateVarCount, inh)
	}
	return sb.String()
}

// (Call-graph rendering moved to the `extract involve` subcommand —
// see extract_involve.go for the per-entry workflow Mermaid charts.)

// renderInheritanceMarkdown renders the C3 linearization chain.
func renderInheritanceMarkdown(o InheritanceOutput) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "# C3 Linearization: %s\n\n", o.Contract)
	fmt.Fprintf(&sb, "**Depth:** %d\n\n", o.InheritanceWeight)
	if len(o.BaseContracts) > 0 {
		fmt.Fprintf(&sb, "**Direct parents (`is` clause):** %s\n\n",
			strings.Join(o.BaseContracts, ", "))
	}
	if len(o.Chain) == 0 {
		sb.WriteString("_(no chain)_\n")
		return sb.String()
	}
	sb.WriteString("**MRO** (derived → base):\n\n")
	sb.WriteString("| # | Contract | Kind |\n|---|---|---|\n")
	for _, e := range o.Chain {
		fmt.Fprintf(&sb, "| %d | `%s` | %s |\n", e.Order, e.Name, e.Kind)
	}
	return sb.String()
}

// renderStatevarMarkdown lists state variables in storage order.
func renderStatevarMarkdown(o StatevarOutput) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "# State Variables: %s\n\n", o.Contract)
	fmt.Fprintf(&sb, "**Total:** %d (including inherited, in storage order)\n\n", o.TotalCount)
	if len(o.Variables) == 0 {
		sb.WriteString("_(no state variables)_\n")
		return sb.String()
	}
	sb.WriteString("| # | Name | Type | Visibility | Defined In | Const | Imm |\n")
	sb.WriteString("|---|---|---|---|---|---|---|\n")
	for i, v := range o.Variables {
		fmt.Fprintf(&sb, "| %d | `%s` | `%s` | %s | `%s` | %s | %s |\n",
			i+1, v.Name, v.TypeName, v.Visibility, v.DefinedIn,
			yesNo(v.IsConstant), yesNo(v.IsImmutable))
	}
	return sb.String()
}

// renderSelectorMarkdown lists 4-byte selectors.
func renderSelectorMarkdown(o SelectorOutput) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "# Selectors: %s\n\n", o.Contract)
	fmt.Fprintf(&sb, "**Count:** %d\n\n", o.Count)
	if len(o.Selectors) == 0 {
		sb.WriteString("_(no selectors)_\n")
		return sb.String()
	}
	sb.WriteString("| Function | Selector | Signature | Visibility | Mutability |\n")
	sb.WriteString("|---|---|---|---|---|\n")
	for _, s := range o.Selectors {
		fmt.Fprintf(&sb, "| `%s` | `%s` | `%s` | %s | %s |\n",
			s.Name, s.Selector, s.Signature, s.Visibility, defaultStr(s.Mutability, "nonpayable"))
	}
	return sb.String()
}

// renderDiffMarkdown renders a database diff in a way reviewers can scan
// quickly — added/removed contracts first, per-contract function deltas
// rolled into expandable sections.
func renderDiffMarkdown(o DiffOutput) string {
	var sb strings.Builder
	sb.WriteString("# Database Diff\n\n")
	fmt.Fprintf(&sb, "**Old:** `%s`\n", o.Db1Path)
	fmt.Fprintf(&sb, "**New:** `%s`\n\n", o.Db2Path)
	fmt.Fprintf(&sb, "- **Contracts added:** %d\n", len(o.Added.Contracts))
	fmt.Fprintf(&sb, "- **Contracts removed:** %d\n", len(o.Removed.Contracts))
	fmt.Fprintf(&sb, "- **Contracts changed:** %d\n\n", len(o.Changed))

	if len(o.Added.Contracts) > 0 {
		sb.WriteString("## Added\n\n")
		for _, c := range o.Added.Contracts {
			fmt.Fprintf(&sb, "- `%s`\n", c)
		}
		sb.WriteString("\n")
	}
	if len(o.Removed.Contracts) > 0 {
		sb.WriteString("## Removed\n\n")
		for _, c := range o.Removed.Contracts {
			fmt.Fprintf(&sb, "- `%s`\n", c)
		}
		sb.WriteString("\n")
	}
	if len(o.Changed) > 0 {
		sb.WriteString("## Changed\n\n")
		for _, c := range o.Changed {
			fmt.Fprintf(&sb, "### `%s`\n\n", c.Contract)
			if len(c.AddedFuncs) > 0 {
				fmt.Fprintf(&sb, "- **Functions added:** %s\n", strings.Join(c.AddedFuncs, ", "))
			}
			if len(c.RemovedFuncs) > 0 {
				fmt.Fprintf(&sb, "- **Functions removed:** %s\n", strings.Join(c.RemovedFuncs, ", "))
			}
			if len(c.AddedStateVars) > 0 {
				fmt.Fprintf(&sb, "- **State vars added:** %s\n", strings.Join(c.AddedStateVars, ", "))
			}
			if len(c.RemovedStateVars) > 0 {
				fmt.Fprintf(&sb, "- **State vars removed:** %s\n", strings.Join(c.RemovedStateVars, ", "))
			}
			sb.WriteString("\n")
		}
	}
	return sb.String()
}

// renderSourceMarkdown wraps a single function's source in a fenced code
// block prefixed with a stable header LLMs can key on.
func renderSourceMarkdown(o SourceOutput, db *types.Database) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "# `%s.%s`\n\n", o.Contract, o.Function)
	fmt.Fprintf(&sb, "**File:** `%s` (lines %d–%d)\n\n",
		relPathFromDB(db, o.File), o.StartLine, o.EndLine)
	sb.WriteString("```solidity\n")
	sb.WriteString(strings.TrimRight(o.SourceCode, "\n"))
	sb.WriteString("\n```\n")
	return sb.String()
}

// renderContextMarkdown renders the "everything about this function in one
// document" output — the older `extract context`. The new `extract bundle`
// adds inheritance and selectors on top of this.
func renderContextMarkdown(o ContextOutput, db *types.Database) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "# Context: `%s.%s`\n\n", o.Contract.Name, o.Function.Name)
	fmt.Fprintf(&sb, "**Contract:** `%s` (%s) — `%s`\n",
		o.Contract.Name, o.Contract.Kind, relPathFromDB(db, o.Contract.SourceFile))
	if len(o.Contract.LinearizedBases) > 0 {
		fmt.Fprintf(&sb, "**Inheritance:** %s\n", strings.Join(o.Contract.LinearizedBases, " → "))
	}
	sb.WriteString("\n## Function Signature\n\n")
	fmt.Fprintf(&sb, "- **Selector:** `%s`\n", o.Function.Selector)
	fmt.Fprintf(&sb, "- **Signature:** `%s`\n", o.Function.Signature)
	fmt.Fprintf(&sb, "- **Visibility / Mutability:** %s / %s\n",
		o.Function.Visibility, defaultStr(o.Function.Mutability, "nonpayable"))
	if len(o.Function.Modifiers) > 0 {
		fmt.Fprintf(&sb, "- **Modifiers:** %s\n", strings.Join(o.Function.Modifiers, ", "))
	}
	fmt.Fprintf(&sb, "- **Lines:** %d–%d\n\n", o.Function.StartLine, o.Function.EndLine)

	sb.WriteString("## Source\n\n```solidity\n")
	sb.WriteString(strings.TrimRight(o.Function.SourceCode, "\n"))
	sb.WriteString("\n```\n\n")

	if len(o.Callees) > 0 {
		sb.WriteString("## Callees\n\n")
		for _, e := range o.Callees {
			fmt.Fprintf(&sb, "- `%s` (%s)\n", shortFuncName(e.To), e.Type)
		}
		sb.WriteString("\n")
	}
	if len(o.Callers) > 0 {
		sb.WriteString("## Callers\n\n")
		for _, e := range o.Callers {
			fmt.Fprintf(&sb, "- `%s` (%s)\n", shortFuncName(e.From), e.Type)
		}
		sb.WriteString("\n")
	}
	if len(o.StateVars) > 0 {
		sb.WriteString("## State Variables (storage order)\n\n")
		sb.WriteString("| Name | Type | Visibility | Defined In |\n|---|---|---|---|\n")
		for _, v := range o.StateVars {
			fmt.Fprintf(&sb, "| `%s` | `%s` | %s | `%s` |\n",
				v.Name, v.TypeName, v.Visibility, v.DefinedIn)
		}
		sb.WriteString("\n")
	}
	return sb.String()
}

// renderWorkflowMarkdown renders the transitive-source dump.
func renderWorkflowMarkdown(o WorkflowOutput, db *types.Database) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "# Workflow: `%s.%s`\n\n", o.EntryContract, o.EntryFunction)
	fmt.Fprintf(&sb, "**Functions collected:** %d (BFS over internal/library/super edges)\n\n",
		o.TotalFuncs)
	for _, fn := range o.Functions {
		fmt.Fprintf(&sb, "## depth %d — `%s.%s`\n\n", fn.CallDepth, fn.Contract, fn.Function)
		fmt.Fprintf(&sb, "`%s` (lines %d–%d, visibility=%s)\n\n",
			relPathFromDB(db, fn.File), fn.StartLine, fn.EndLine, fn.Visibility)
		sb.WriteString("```solidity\n")
		sb.WriteString(strings.TrimRight(fn.SourceCode, "\n"))
		sb.WriteString("\n```\n\n")
	}
	return sb.String()
}

// ─────────────────────────────────────────────────────────────────────────────
// Small helpers
// ─────────────────────────────────────────────────────────────────────────────

// defaultStr returns s if non-empty, otherwise the fallback. Used for
// rendering optional metadata without leaving empty cells in markdown
// tables.
func defaultStr(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

// yesNo renders a bool as a short markdown-table-friendly string.
func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "—"
}
