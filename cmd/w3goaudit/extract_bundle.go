package main

// extract_bundle.go — the "feed one document to an LLM" extract.
//
// `extract bundle <function>` returns everything an AI agent needs to reason
// about a function: signature, modifiers, source, callers, callees, state
// variables (storage order), inheritance chain, and the contract's selector
// table. Markdown is the default format because that's what LLMs consume
// best; `--format=json` keeps the same structure for scripts.
//
// This subcommand subsumes the older `extract context` (which only included
// callers + callees + state vars). Use `bundle` for AI workflows; the
// narrower `context` / `source` commands remain available for targeted CLI
// queries.

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/th13vn/w3goaudit/pkg/types"
)

// BundleOutput is the JSON shape of `extract bundle`. SchemaVersion lets
// downstream tools refuse to parse on a major-version mismatch.
type BundleOutput struct {
	SchemaVersion string             `json:"schemaVersion"`
	Function      ContextFunction    `json:"function"`
	Contract      BundleContract     `json:"contract"`
	Callees       []CallEdgeInfo     `json:"callees,omitempty"`
	Callers       []CallEdgeInfo     `json:"callers,omitempty"`
	StateVars     []StateVarInfo     `json:"stateVars,omitempty"`
	Inheritance   []InheritanceEntry `json:"inheritance,omitempty"`
	Selectors     []SelectorInfo     `json:"selectors,omitempty"`
}

// BundleContract is a slimmed-down ContextContract that also carries the
// path relative to the project root — useful both as JSON metadata and as
// markdown rendering input.
type BundleContract struct {
	Name            string   `json:"name"`
	Kind            string   `json:"kind"`
	SourceFile      string   `json:"sourceFile"`
	SourceFileRel   string   `json:"sourceFileRel,omitempty"`
	LinearizedBases []string `json:"linearizedBases,omitempty"`
}

var extractBundleCmd = &cobra.Command{
	Use:   "bundle <function-name>",
	Short: "Combined LLM-ready bundle: function source + callers + callees + state vars + inheritance + selectors",
	Long: `Produce a single self-contained document about a function, designed
for feeding to an AI agent / LLM as conversation context (markdown by default)
or for any tool that wants one structured blob (JSON via --format=json).

Includes:
  - Function signature, modifiers, visibility, mutability, line range
  - Function source code
  - Callees (functions this function calls)
  - Callers (functions that call this function)
  - State variables in storage order (including inherited)
  - Full C3 linearization
  - Contract's selector table

Examples:
  w3goaudit extract bundle withdraw ./contracts/
  w3goaudit extract bundle withdraw --db database.json
  w3goaudit extract bundle withdraw --db database.json --contract DeFiVault -o bundle.md
  w3goaudit extract bundle transfer --db database.json --format=json -o bundle.json`,
	Args: cobra.RangeArgs(1, 2),
	RunE: func(cmd *cobra.Command, args []string) error {
		outPath, _ := cmd.Flags().GetString("output")
		contractFilter, _ := cmd.Flags().GetString("contract")

		db, err := resolveExtractDB(cmd, args)
		if err != nil {
			return err
		}

		fn, contract := findFunction(db, args[0], contractFilter)
		if fn == nil {
			return fmt.Errorf("function %q not found%s", args[0], contractHint(contractFilter))
		}

		bundle := buildBundle(db, contract, fn)

		// Bundle is markdown-native (the LLM-friendly form), which is also the
		// tool-wide default; --format=json or -o file.json opts into JSON.
		return writeExtract(bundle,
			func() string { return renderBundleMarkdown(bundle, db) },
			outPath, resolveExtractFormat(cmd))
	},
}

func init() {
	extractBundleCmd.Flags().String("db", "", "Path to a pre-built database JSON (optional; or pass a source path)")
	extractBundleCmd.Flags().StringP("output", "o", "", "Output file path (default: stdout)")
	extractBundleCmd.Flags().String("contract", "", "Restrict search to a specific contract name")
	addExtractFormatFlag(extractBundleCmd)
}

// buildBundle assembles the BundleOutput for a function. Shared with any
// future SDK callers that want the same combined structure.
func buildBundle(db *types.Database, contract *types.Contract, fn *types.Function) BundleOutput {
	funcID := fmt.Sprintf("%s#%s.%s", contract.SourceFile, contract.Name, fn.Name)

	var callees, callers []CallEdgeInfo
	if db.CallGraph != nil {
		for _, edge := range db.CallGraph.GetCallees(funcID) {
			callees = append(callees, edgeToInfo(edge))
		}
		for _, edge := range db.CallGraph.GetCallers(funcID) {
			callers = append(callers, edgeToInfo(edge))
		}
	}

	// State vars in storage order: base contracts first (reverse-iterate the
	// derived-first LinearizedBases).
	var stateVars []StateVarInfo
	for i := len(contract.LinearizedBases) - 1; i >= 0; i-- {
		base := db.GetContractByName(contract.LinearizedBases[i])
		if base == nil {
			continue
		}
		for _, sv := range base.StateVariables {
			stateVars = append(stateVars, StateVarInfo{
				Name: sv.Name, TypeName: sv.TypeName, Visibility: sv.Visibility,
				IsConstant: sv.IsConstant, IsImmutable: sv.IsImmutable,
				DefinedIn: base.Name,
			})
		}
	}

	// Full C3 chain — same shape as `extract inheritance` output.
	var chain []InheritanceEntry
	for i, baseName := range contract.LinearizedBases {
		kind := "unknown"
		if base := db.GetContractByName(baseName); base != nil {
			kind = string(base.Kind)
		}
		chain = append(chain, InheritanceEntry{Order: i + 1, Name: baseName, Kind: kind})
	}

	// Selector table for the focal contract only — context for the LLM but
	// not the full project graph.
	var sels []SelectorInfo
	for _, ff := range contract.Functions {
		if ff.Selector == "" && ff.Signature == "" {
			continue
		}
		sels = append(sels, SelectorInfo{
			Name: ff.Name, Selector: ff.Selector, Signature: ff.Signature,
			Visibility: string(ff.Visibility), Mutability: string(ff.StateMutability),
		})
	}

	return BundleOutput{
		SchemaVersion: ExtractSchemaVersion,
		Function: ContextFunction{
			Name: fn.Name, Signature: fn.Signature, Selector: fn.Selector,
			Visibility: string(fn.Visibility), Mutability: string(fn.StateMutability),
			Modifiers: fn.Modifiers,
			StartLine: fn.StartLine, EndLine: fn.EndLine,
			SourceCode: db.GetFunctionSource(fn),
		},
		Contract: BundleContract{
			Name: contract.Name, Kind: string(contract.Kind),
			SourceFile:      contract.SourceFile,
			SourceFileRel:   relPathFromDB(db, contract.SourceFile),
			LinearizedBases: contract.LinearizedBases,
		},
		Callees:     callees,
		Callers:     callers,
		StateVars:   stateVars,
		Inheritance: chain,
		Selectors:   sels,
	}
}

// renderBundleMarkdown is the LLM-facing format. Section order is chosen so
// the LLM sees identity → signature → source → call graph → state → catalog,
// matching how a human auditor reasons about a function.
func renderBundleMarkdown(b BundleOutput, db *types.Database) string {
	var sb strings.Builder

	fmt.Fprintf(&sb, "# Bundle: `%s.%s`\n\n", b.Contract.Name, b.Function.Name)
	fmt.Fprintf(&sb, "_Schema version: %s — generated by w3goaudit_\n\n", b.SchemaVersion)

	// 1. Contract identity
	sb.WriteString("## Contract\n\n")
	fmt.Fprintf(&sb, "- **Name:** `%s` (%s)\n", b.Contract.Name, b.Contract.Kind)
	if b.Contract.SourceFileRel != "" {
		fmt.Fprintf(&sb, "- **Source:** `%s`\n", b.Contract.SourceFileRel)
	} else {
		fmt.Fprintf(&sb, "- **Source:** `%s`\n", relPathFromDB(db, b.Contract.SourceFile))
	}
	if len(b.Contract.LinearizedBases) > 0 {
		fmt.Fprintf(&sb, "- **MRO:** %s\n", strings.Join(b.Contract.LinearizedBases, " → "))
	}
	sb.WriteString("\n")

	// 2. Function signature
	sb.WriteString("## Function\n\n")
	fmt.Fprintf(&sb, "- **Signature:** `%s`\n", b.Function.Signature)
	fmt.Fprintf(&sb, "- **Selector:** `%s`\n", b.Function.Selector)
	fmt.Fprintf(&sb, "- **Visibility / Mutability:** %s / %s\n",
		b.Function.Visibility, defaultStr(b.Function.Mutability, "nonpayable"))
	if len(b.Function.Modifiers) > 0 {
		fmt.Fprintf(&sb, "- **Modifiers:** %s\n", strings.Join(b.Function.Modifiers, ", "))
	}
	fmt.Fprintf(&sb, "- **Lines:** %d–%d\n\n", b.Function.StartLine, b.Function.EndLine)

	// 3. Source — the core artifact
	sb.WriteString("## Source\n\n```solidity\n")
	sb.WriteString(strings.TrimRight(b.Function.SourceCode, "\n"))
	sb.WriteString("\n```\n\n")

	// 4. Call graph context — what this function reaches, what reaches it
	if len(b.Callees) > 0 {
		sb.WriteString("## Callees\n\n")
		sb.WriteString("| Target | Type | Line | Resolved |\n|---|---|---|---|\n")
		for _, e := range b.Callees {
			line := "—"
			if e.Line > 0 {
				line = fmt.Sprintf("%d", e.Line)
			}
			fmt.Fprintf(&sb, "| `%s` | %s | %s | %s |\n",
				shortFuncName(e.To), e.Type, line, yesNo(e.Resolved))
		}
		sb.WriteString("\n")
	}
	if len(b.Callers) > 0 {
		sb.WriteString("## Callers\n\n")
		sb.WriteString("| From | Type | Line | Resolved |\n|---|---|---|---|\n")
		for _, e := range b.Callers {
			line := "—"
			if e.Line > 0 {
				line = fmt.Sprintf("%d", e.Line)
			}
			fmt.Fprintf(&sb, "| `%s` | %s | %s | %s |\n",
				shortFuncName(e.From), e.Type, line, yesNo(e.Resolved))
		}
		sb.WriteString("\n")
	}

	// 5. State variables in storage order
	if len(b.StateVars) > 0 {
		sb.WriteString("## State Variables (storage order)\n\n")
		sb.WriteString("| # | Name | Type | Visibility | Defined In | Const | Imm |\n")
		sb.WriteString("|---|---|---|---|---|---|---|\n")
		for i, v := range b.StateVars {
			fmt.Fprintf(&sb, "| %d | `%s` | `%s` | %s | `%s` | %s | %s |\n",
				i+1, v.Name, v.TypeName, v.Visibility, v.DefinedIn,
				yesNo(v.IsConstant), yesNo(v.IsImmutable))
		}
		sb.WriteString("\n")
	}

	// 6. Inheritance chain (full MRO with kinds)
	if len(b.Inheritance) > 0 {
		sb.WriteString("## Inheritance (C3 MRO, derived → base)\n\n")
		sb.WriteString("| # | Contract | Kind |\n|---|---|---|\n")
		for _, e := range b.Inheritance {
			fmt.Fprintf(&sb, "| %d | `%s` | %s |\n", e.Order, e.Name, e.Kind)
		}
		sb.WriteString("\n")
	}

	// 7. Selector table — last because it's reference data, not reasoning input
	if len(b.Selectors) > 0 {
		sb.WriteString("## Contract Selectors\n\n")
		sb.WriteString("<details>\n<summary>All function selectors in this contract</summary>\n\n")
		sb.WriteString("| Function | Selector | Signature | Visibility |\n|---|---|---|---|\n")
		for _, s := range b.Selectors {
			fmt.Fprintf(&sb, "| `%s` | `%s` | `%s` | %s |\n",
				s.Name, s.Selector, s.Signature, s.Visibility)
		}
		sb.WriteString("\n</details>\n")
	}

	return sb.String()
}
