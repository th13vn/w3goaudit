package main

import (
	"fmt"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"github.com/th13vn/w3goaudit/pkg/types"
)

// ── Parent command ──────────────────────────────────────────────────────────

var extractCmd = &cobra.Command{
	Use:   "extract",
	Short: "Extract information from a contract database",
	Long: `Extract specific information from a pre-built contract database.

Every subcommand supports --format=json (default, machine-readable) and
--format=md (markdown, optimized for feeding to an AI agent / LLM as
conversation context). The format is also inferred from the -o file
extension (.md → markdown, .json → json).

Use the subcommands below to query different aspects of the database:
  entry       — Entry point functions for a contract
  main        — Main (deployable) contracts in a project (path or --db)
  inheritance — C3 linearization for a main contract (derived → base)
  involve     — All entry-point workflows that involve a given function (Mermaid charts)
  statevar    — State variables (including inherited)
  selector    — Function selectors for a contract
  diff        — Compare two databases
  source      — Raw Solidity source for a function
  context     — Combined context package for a function
  bundle      — One LLM-ready document: source + callers + callees + state + inheritance + selectors
  workflow    — Full transitive source for an entry function (report-ready)`,
}

func init() {
	// Subcommands
	extractCmd.AddCommand(extractEntryCmd)
	extractCmd.AddCommand(extractMainCmd)
	extractCmd.AddCommand(extractInheritanceCmd)
	extractCmd.AddCommand(extractInvolveCmd)
	extractCmd.AddCommand(extractStatevarCmd)
	extractCmd.AddCommand(extractSelectorCmd)
	extractCmd.AddCommand(extractDiffCmd)
	extractCmd.AddCommand(extractSourceCmd)
	extractCmd.AddCommand(extractContextCmd)
	extractCmd.AddCommand(extractBundleCmd)
	extractCmd.AddCommand(extractWorkflowCmd)
}

// ── Helper ──────────────────────────────────────────────────────────────────

// All extract subcommands route through writeExtract() in extract_render.go,
// which handles JSON vs markdown format selection. JSON encoding for the
// json branch happens inside that helper.

func findContract(db *types.Database, name string) *types.Contract {
	// Try exact name match first
	c := db.GetContractByName(name)
	if c != nil {
		return c
	}
	// Try case-insensitive
	for _, contract := range db.Contracts {
		if strings.EqualFold(contract.Name, name) {
			return contract
		}
	}
	return nil
}

// ── extract entry ───────────────────────────────────────────────────────────

type EntryOutput struct {
	SchemaVersion  string          `json:"schemaVersion"`
	Contract       string          `json:"contract"`
	SourceFile     string          `json:"sourceFile"`
	EntryCount     int             `json:"entryCount"`
	EntryFunctions []EntryFuncInfo `json:"entryFunctions"`
}

type EntryFuncInfo struct {
	Name           string   `json:"name"`
	Selector       string   `json:"selector"`
	Signature      string   `json:"signature"`
	Visibility     string   `json:"visibility"`
	Mutability     string   `json:"mutability"`
	Modifiers      []string `json:"modifiers,omitempty"`
	StartLine      int      `json:"startLine"`
	EndLine        int      `json:"endLine"`
}

var extractEntryCmd = &cobra.Command{
	Use:   "entry <contract-name>",
	Short: "Extract entry point functions for a contract",
	Long: `Extract all public/external entry point functions for a named contract.
Requires a pre-built database (--db flag).

Example:
  w3goaudit extract entry MyToken --db database.json
  w3goaudit extract entry MyToken --db database.json -o entry.json`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		dbPath, _ := cmd.Flags().GetString("db")
		outPath, _ := cmd.Flags().GetString("output")

		db, err := loadDatabaseRequired(dbPath, false)
		if err != nil { return err }
		contract := findContract(db, args[0])
		if contract == nil {
			return fmt.Errorf("contract %q not found in database", args[0])
		}

		var funcs []EntryFuncInfo
		for _, fn := range contract.Functions {
			if fn.IsEntrypoint() {
				funcs = append(funcs, EntryFuncInfo{
					Name:       fn.Name,
					Selector:   fn.Selector,
					Signature:  fn.Signature,
					Visibility: string(fn.Visibility),
					Mutability: string(fn.StateMutability),
					Modifiers:  fn.Modifiers,
					StartLine:  fn.StartLine,
					EndLine:    fn.EndLine,
				})
			}
		}

		output := EntryOutput{
			SchemaVersion:  ExtractSchemaVersion,
			Contract:       contract.Name,
			SourceFile:     contract.SourceFile,
			EntryCount:     len(funcs),
			EntryFunctions: funcs,
		}

		return writeExtract(output,
			func() string { return renderEntryMarkdown(output, db) },
			outPath, resolveExtractFormat(cmd))
	},
}

func init() {
	extractEntryCmd.Flags().String("db", "", "Path to database JSON file (required)")
	extractEntryCmd.Flags().StringP("output", "o", "", "Output file path (default: stdout)")
	addExtractFormatFlag(extractEntryCmd)
	extractEntryCmd.MarkFlagRequired("db")
}

// ── extract main ────────────────────────────────────────────────────────────

type MainOutput struct {
	SchemaVersion string             `json:"schemaVersion"`
	MainContracts []MainContractInfo `json:"mainContracts"`
	Stats         interface{}        `json:"stats"`
}

type MainContractInfo struct {
	Name             string   `json:"name"`
	SourceFile       string   `json:"sourceFile"`
	InheritanceChain []string `json:"inheritanceChain"`
	EntryFuncCount   int      `json:"entryFuncCount"`
	FunctionCount    int      `json:"functionCount"`
	StateVarCount    int      `json:"stateVarCount"`
}

var extractMainCmd = &cobra.Command{
	Use:   "main [path]",
	Short: "Extract main (deployable) contracts",
	Long: `Extract main contracts from a project. Can build from source path or use pre-built database.

Examples:
  w3goaudit extract main ./contracts/
  w3goaudit extract main --db database.json
  w3goaudit extract main ./contracts/ -o main.json`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		dbPath, _ := cmd.Flags().GetString("db")
		outPath, _ := cmd.Flags().GetString("output")

		inputPath := ""
		if len(args) > 0 {
			inputPath = args[0]
		}

		if inputPath == "" && dbPath == "" {
			return fmt.Errorf("provide a source path or use --db to load a database")
		}

		db, err := loadOrBuildDatabase(inputPath, dbPath, false)
		if err != nil { return err }

		var mains []MainContractInfo
		for contractID, entry := range db.MainContracts {
			contract := db.Contracts[contractID]
			if contract == nil {
				continue
			}
			mains = append(mains, MainContractInfo{
				Name:             contract.Name,
				SourceFile:       contract.SourceFile,
				InheritanceChain: entry.LinearizedBases,
				EntryFuncCount:   len(entry.EntryFunctions),
				FunctionCount:    len(contract.Functions),
				StateVarCount:    len(contract.StateVariables),
			})
		}

		output := MainOutput{
			SchemaVersion: ExtractSchemaVersion,
			MainContracts: mains,
			Stats:         db.GetStats(),
		}

		return writeExtract(output,
			func() string { return renderMainMarkdown(output, db) },
			outPath, resolveExtractFormat(cmd))
	},
}

func init() {
	extractMainCmd.Flags().String("db", "", "Path to database JSON file (optional)")
	extractMainCmd.Flags().StringP("output", "o", "", "Output file path (default: stdout)")
	addExtractFormatFlag(extractMainCmd)
}

// CallEdgeInfo is the shared call-edge shape used by `extract context`,
// `extract bundle`, and `extract involve` JSON outputs.
type CallEdgeInfo struct {
	From     string `json:"from"`
	To       string `json:"to"`
	Type     string `json:"type"`
	Line     int    `json:"line,omitempty"`
	Resolved bool   `json:"resolved"`
}

// shortFuncName extracts "Contract.func" from "path#Contract.func"
func shortFuncName(fullID string) string {
	if idx := strings.LastIndex(fullID, "#"); idx >= 0 {
		return fullID[idx+1:]
	}
	return fullID
}

// ── extract inheritance ─────────────────────────────────────────────────────

type InheritanceOutput struct {
	SchemaVersion     string             `json:"schemaVersion"`
	Contract          string             `json:"contract"`
	LinearizedBases   []string           `json:"linearizedBases"`
	InheritanceWeight int                `json:"inheritanceWeight"`
	BaseContracts     []string           `json:"baseContracts"`
	Chain             []InheritanceEntry `json:"chain"`
}

type InheritanceEntry struct {
	Order int    `json:"order"`
	Name  string `json:"name"`
	Kind  string `json:"kind"`
}

var extractInheritanceCmd = &cobra.Command{
	Use:   "inheritance <main-contract-name>",
	Short: "Extract C3 linearization for a main (deployable) contract",
	Long: `Show the full C3 linearization (most-derived → most-base) for a main
contract. The argument MUST resolve to a contract marked as deployable —
interfaces, libraries, abstract contracts, and contracts that are never
deployed are rejected with the list of valid main contracts.

This restriction reflects how auditors actually use the data: linearization
matters for the contracts you can call from the outside, not for utility
mixins that compose into them.

Example:
  w3goaudit extract inheritance MyToken --db database.json`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		dbPath, _ := cmd.Flags().GetString("db")
		outPath, _ := cmd.Flags().GetString("output")

		db, err := loadDatabaseRequired(dbPath, false)
		if err != nil {
			return err
		}
		contract := findContract(db, args[0])
		if contract == nil {
			return fmt.Errorf("contract %q not found in database", args[0])
		}

		// Validate the contract is a main (deployable) contract — surface a
		// helpful list of valid choices when it isn't.
		contractID := contract.SourceFile + "#" + contract.Name
		if _, isMain := db.MainContracts[contractID]; !isMain {
			mainNames := make([]string, 0, len(db.MainContracts))
			for id := range db.MainContracts {
				if c := db.Contracts[id]; c != nil {
					mainNames = append(mainNames, c.Name)
				}
			}
			sort.Strings(mainNames)
			hint := "no main contracts in this database"
			if len(mainNames) > 0 {
				preview := mainNames
				if len(preview) > 10 {
					preview = append(preview[:10], "…")
				}
				hint = "valid main contracts: " + strings.Join(preview, ", ")
			}
			return fmt.Errorf("contract %q is not a main (deployable) contract — %s",
				contract.Name, hint)
		}

		var chain []InheritanceEntry
		for i, baseName := range contract.LinearizedBases {
			kind := "unknown"
			if base := db.GetContractByName(baseName); base != nil {
				kind = string(base.Kind)
			}
			chain = append(chain, InheritanceEntry{
				Order: i + 1,
				Name:  baseName,
				Kind:  kind,
			})
		}

		output := InheritanceOutput{
			SchemaVersion:     ExtractSchemaVersion,
			Contract:          contract.Name,
			LinearizedBases:   contract.LinearizedBases,
			InheritanceWeight: contract.InheritanceWeight,
			BaseContracts:     contract.BaseContracts,
			Chain:             chain,
		}

		return writeExtract(output,
			func() string { return renderInheritanceMarkdown(output) },
			outPath, resolveExtractFormat(cmd))
	},
}

func init() {
	extractInheritanceCmd.Flags().String("db", "", "Path to database JSON file (required)")
	extractInheritanceCmd.Flags().StringP("output", "o", "", "Output file path (default: stdout)")
	addExtractFormatFlag(extractInheritanceCmd)
	extractInheritanceCmd.MarkFlagRequired("db")
}

// ── extract statevar ────────────────────────────────────────────────────────

type StatevarOutput struct {
	SchemaVersion string         `json:"schemaVersion"`
	Contract      string         `json:"contract"`
	TotalCount    int            `json:"totalCount"`
	Variables     []StateVarInfo `json:"variables"`
}

type StateVarInfo struct {
	Name        string `json:"name"`
	TypeName    string `json:"typeName"`
	Visibility  string `json:"visibility"`
	IsConstant  bool   `json:"isConstant,omitempty"`
	IsImmutable bool   `json:"isImmutable,omitempty"`
	DefinedIn   string `json:"definedIn"`
}

var extractStatevarCmd = &cobra.Command{
	Use:   "statevar <contract-name>",
	Short: "List all state variables (including inherited)",
	Long: `List all state variables for a contract, including those inherited from base contracts.
Variables are listed in inheritance order (base first).

Example:
  w3goaudit extract statevar MyToken --db database.json`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		dbPath, _ := cmd.Flags().GetString("db")
		outPath, _ := cmd.Flags().GetString("output")

		db, err := loadDatabaseRequired(dbPath, false)
		if err != nil { return err }
		contract := findContract(db, args[0])
		if contract == nil {
			return fmt.Errorf("contract %q not found in database", args[0])
		}

		var vars []StateVarInfo

		// Walk inheritance chain in reverse (base first) to get storage order
		bases := contract.LinearizedBases
		for i := len(bases) - 1; i >= 0; i-- {
			baseName := bases[i]
			base := db.GetContractByName(baseName)
			if base == nil {
				continue
			}
			for _, sv := range base.StateVariables {
				vars = append(vars, StateVarInfo{
					Name:        sv.Name,
					TypeName:    sv.TypeName,
					Visibility:  sv.Visibility,
					IsConstant:  sv.IsConstant,
					IsImmutable: sv.IsImmutable,
					DefinedIn:   baseName,
				})
			}
		}

		output := StatevarOutput{
			SchemaVersion: ExtractSchemaVersion,
			Contract:      contract.Name,
			TotalCount:    len(vars),
			Variables:     vars,
		}

		return writeExtract(output,
			func() string { return renderStatevarMarkdown(output) },
			outPath, resolveExtractFormat(cmd))
	},
}

func init() {
	extractStatevarCmd.Flags().String("db", "", "Path to database JSON file (required)")
	extractStatevarCmd.Flags().StringP("output", "o", "", "Output file path (default: stdout)")
	addExtractFormatFlag(extractStatevarCmd)
	extractStatevarCmd.MarkFlagRequired("db")
}

// ── extract selector ────────────────────────────────────────────────────────

type SelectorOutput struct {
	SchemaVersion string         `json:"schemaVersion"`
	Contract      string         `json:"contract"`
	Count         int            `json:"count"`
	Selectors     []SelectorInfo `json:"selectors"`
}

type SelectorInfo struct {
	Name       string `json:"name"`
	Selector   string `json:"selector"`
	Signature  string `json:"signature"`
	Visibility string `json:"visibility"`
	Mutability string `json:"mutability"`
}

var extractSelectorCmd = &cobra.Command{
	Use:   "selector <contract-name>",
	Short: "List function selectors for a contract",
	Long: `List all function selectors (4-byte keccak256 hashes) for a contract.

Example:
  w3goaudit extract selector MyToken --db database.json`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		dbPath, _ := cmd.Flags().GetString("db")
		outPath, _ := cmd.Flags().GetString("output")

		db, err := loadDatabaseRequired(dbPath, false)
		if err != nil { return err }
		contract := findContract(db, args[0])
		if contract == nil {
			return fmt.Errorf("contract %q not found in database", args[0])
		}

		var sels []SelectorInfo
		for _, fn := range contract.Functions {
			if fn.Selector == "" && fn.Signature == "" {
				continue // skip constructors, fallback etc.
			}
			sels = append(sels, SelectorInfo{
				Name:       fn.Name,
				Selector:   fn.Selector,
				Signature:  fn.Signature,
				Visibility: string(fn.Visibility),
				Mutability: string(fn.StateMutability),
			})
		}

		output := SelectorOutput{
			SchemaVersion: ExtractSchemaVersion,
			Contract:      contract.Name,
			Count:         len(sels),
			Selectors:     sels,
		}

		return writeExtract(output,
			func() string { return renderSelectorMarkdown(output) },
			outPath, resolveExtractFormat(cmd))
	},
}

func init() {
	extractSelectorCmd.Flags().String("db", "", "Path to database JSON file (required)")
	extractSelectorCmd.Flags().StringP("output", "o", "", "Output file path (default: stdout)")
	addExtractFormatFlag(extractSelectorCmd)
	extractSelectorCmd.MarkFlagRequired("db")
}

// ── extract diff ────────────────────────────────────────────────────────────

type DiffOutput struct {
	SchemaVersion string           `json:"schemaVersion"`
	Db1Path       string           `json:"db1Path"`
	Db2Path       string           `json:"db2Path"`
	Added         DiffContractList `json:"added"`
	Removed       DiffContractList `json:"removed"`
	Changed       []ContractDiff   `json:"changed,omitempty"`
}

type DiffContractList struct {
	Contracts []string `json:"contracts"`
	Functions []string `json:"functions,omitempty"`
}

type ContractDiff struct {
	Contract       string   `json:"contract"`
	AddedFuncs     []string `json:"addedFunctions,omitempty"`
	RemovedFuncs   []string `json:"removedFunctions,omitempty"`
	AddedStateVars []string `json:"addedStateVars,omitempty"`
	RemovedStateVars []string `json:"removedStateVars,omitempty"`
}

var extractDiffCmd = &cobra.Command{
	Use:   "diff",
	Short: "Compare two databases",
	Long: `Compare two pre-built databases and show added, removed, and changed contracts/functions.

Example:
  w3goaudit extract diff --db1 old.json --db2 new.json
  w3goaudit extract diff --db1 old.json --db2 new.json -o diff.json`,
	RunE: func(cmd *cobra.Command, args []string) error {
		db1Path, _ := cmd.Flags().GetString("db1")
		db2Path, _ := cmd.Flags().GetString("db2")
		outPath, _ := cmd.Flags().GetString("output")

		if db1Path == "" || db2Path == "" {
			return fmt.Errorf("both --db1 and --db2 are required")
		}

		db1, err := types.LoadFromJSON(db1Path)
		if err != nil {
			return fmt.Errorf("error loading db1: %w", err)
		}
		db2, err := types.LoadFromJSON(db2Path)
		if err != nil {
			return fmt.Errorf("error loading db2: %w", err)
		}

		// Build contract name sets
		names1 := make(map[string]bool)
		names2 := make(map[string]bool)
		for _, c := range db1.Contracts {
			names1[c.Name] = true
		}
		for _, c := range db2.Contracts {
			names2[c.Name] = true
		}

		// Added contracts (in db2 not in db1)
		var addedContracts []string
		for name := range names2 {
			if !names1[name] {
				addedContracts = append(addedContracts, name)
			}
		}

		// Removed contracts (in db1 not in db2)
		var removedContracts []string
		for name := range names1 {
			if !names2[name] {
				removedContracts = append(removedContracts, name)
			}
		}

		// Changed contracts (in both, but different functions/state)
		var changed []ContractDiff
		for name := range names1 {
			if !names2[name] {
				continue
			}
			c1 := db1.GetContractByName(name)
			c2 := db2.GetContractByName(name)
			if c1 == nil || c2 == nil {
				continue
			}

			// Compare functions
			funcs1 := make(map[string]bool)
			funcs2 := make(map[string]bool)
			for _, f := range c1.Functions {
				funcs1[f.Name] = true
			}
			for _, f := range c2.Functions {
				funcs2[f.Name] = true
			}

			var addedFuncs, removedFuncs []string
			for fn := range funcs2 {
				if !funcs1[fn] {
					addedFuncs = append(addedFuncs, fn)
				}
			}
			for fn := range funcs1 {
				if !funcs2[fn] {
					removedFuncs = append(removedFuncs, fn)
				}
			}

			// Compare state variables
			vars1 := make(map[string]bool)
			vars2 := make(map[string]bool)
			for _, v := range c1.StateVariables {
				vars1[v.Name] = true
			}
			for _, v := range c2.StateVariables {
				vars2[v.Name] = true
			}

			var addedVars, removedVars []string
			for v := range vars2 {
				if !vars1[v] {
					addedVars = append(addedVars, v)
				}
			}
			for v := range vars1 {
				if !vars2[v] {
					removedVars = append(removedVars, v)
				}
			}

			if len(addedFuncs) > 0 || len(removedFuncs) > 0 || len(addedVars) > 0 || len(removedVars) > 0 {
				changed = append(changed, ContractDiff{
					Contract:         name,
					AddedFuncs:       addedFuncs,
					RemovedFuncs:     removedFuncs,
					AddedStateVars:   addedVars,
					RemovedStateVars: removedVars,
				})
			}
		}

		output := DiffOutput{
			SchemaVersion: ExtractSchemaVersion,
			Db1Path:       db1Path,
			Db2Path:       db2Path,
			Added: DiffContractList{
				Contracts: addedContracts,
			},
			Removed: DiffContractList{
				Contracts: removedContracts,
			},
			Changed: changed,
		}

		return writeExtract(output,
			func() string { return renderDiffMarkdown(output) },
			outPath, resolveExtractFormat(cmd))
	},
}

func init() {
	extractDiffCmd.Flags().String("db1", "", "Path to first (old) database JSON")
	extractDiffCmd.Flags().String("db2", "", "Path to second (new) database JSON")
	extractDiffCmd.Flags().StringP("output", "o", "", "Output file path (default: stdout)")
	addExtractFormatFlag(extractDiffCmd)
	extractDiffCmd.MarkFlagRequired("db1")
	extractDiffCmd.MarkFlagRequired("db2")
}

// ── extract source ──────────────────────────────────────────────────────────

// SourceOutput is the JSON result of extract source.
type SourceOutput struct {
	SchemaVersion string `json:"schemaVersion"`
	Contract      string `json:"contract"`
	Function      string `json:"function"`
	File          string `json:"file"`
	StartLine     int    `json:"startLine"`
	EndLine       int    `json:"endLine"`
	SourceCode    string `json:"sourceCode"`
}

var extractSourceCmd = &cobra.Command{
	Use:   "source <function-name>",
	Short: "Extract raw Solidity source code for a function",
	Long: `Extract the raw Solidity source lines for a named function.
Searches all contracts; use --contract to disambiguate when multiple match.

Examples:
  w3goaudit extract source withdraw --db database.json
  w3goaudit extract source withdraw --db database.json --contract DeFiVault -o src.json`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		dbPath, _ := cmd.Flags().GetString("db")
		outPath, _ := cmd.Flags().GetString("output")
		contractFilter, _ := cmd.Flags().GetString("contract")

		db, err := loadDatabaseRequired(dbPath, false)
		if err != nil { return err }
		funcName := args[0]

		fn, contract := findFunction(db, funcName, contractFilter)
		if fn == nil {
			return fmt.Errorf("function %q not found%s", funcName, contractHint(contractFilter))
		}

		output := SourceOutput{
			SchemaVersion: ExtractSchemaVersion,
			Contract:      contract.Name,
			Function:      fn.Name,
			File:          contract.SourceFile,
			StartLine:     fn.StartLine,
			EndLine:       fn.EndLine,
			SourceCode:    db.GetFunctionSource(fn),
		}
		return writeExtract(output,
			func() string { return renderSourceMarkdown(output, db) },
			outPath, resolveExtractFormat(cmd))
	},
}

func init() {
	extractSourceCmd.Flags().String("db", "", "Path to database JSON file (required)")
	extractSourceCmd.Flags().StringP("output", "o", "", "Output file path (default: stdout)")
	extractSourceCmd.Flags().String("contract", "", "Restrict search to a specific contract name")
	addExtractFormatFlag(extractSourceCmd)
	extractSourceCmd.MarkFlagRequired("db")
}

// ── extract context ─────────────────────────────────────────────────────────

// ContextOutput is the JSON result of extract context.
type ContextOutput struct {
	SchemaVersion string          `json:"schemaVersion"`
	Function      ContextFunction `json:"function"`
	Contract      ContextContract `json:"contract"`
	Callees       []CallEdgeInfo  `json:"callees,omitempty"`
	Callers       []CallEdgeInfo  `json:"callers,omitempty"`
	StateVars     []StateVarInfo  `json:"stateVars,omitempty"`
}

// ContextFunction mirrors function metadata + source.
type ContextFunction struct {
	Name       string   `json:"name"`
	Signature  string   `json:"signature"`
	Selector   string   `json:"selector"`
	Visibility string   `json:"visibility"`
	Mutability string   `json:"mutability"`
	Modifiers  []string `json:"modifiers,omitempty"`
	StartLine  int      `json:"startLine"`
	EndLine    int      `json:"endLine"`
	SourceCode string   `json:"sourceCode"`
}

// ContextContract contains contract metadata.
type ContextContract struct {
	Name            string   `json:"name"`
	Kind            string   `json:"kind"`
	SourceFile      string   `json:"sourceFile"`
	LinearizedBases []string `json:"linearizedBases"`
}

var extractContextCmd = &cobra.Command{
	Use:   "context <function-name>",
	Short: "Extract combined context package for a function",
	Long: `Extract a comprehensive context package for a function: source + call edges + state vars + inheritance.
Suitable as input for analysis or report writing.

Examples:
  w3goaudit extract context withdraw --db database.json
  w3goaudit extract context withdraw --db database.json --contract DeFiVault -o ctx.json`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		dbPath, _ := cmd.Flags().GetString("db")
		outPath, _ := cmd.Flags().GetString("output")
		contractFilter, _ := cmd.Flags().GetString("contract")

		db, err := loadDatabaseRequired(dbPath, false)
		if err != nil { return err }
		funcName := args[0]

		fn, contract := findFunction(db, funcName, contractFilter)
		if fn == nil {
			return fmt.Errorf("function %q not found%s", funcName, contractHint(contractFilter))
		}

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

		// State vars — inheritance order: base-first (storage order)
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

		output := ContextOutput{
			SchemaVersion: ExtractSchemaVersion,
			Function: ContextFunction{
				Name: fn.Name, Signature: fn.Signature, Selector: fn.Selector,
				Visibility: string(fn.Visibility), Mutability: string(fn.StateMutability),
				Modifiers: fn.Modifiers,
				StartLine: fn.StartLine, EndLine: fn.EndLine,
				SourceCode: db.GetFunctionSource(fn),
			},
			Contract: ContextContract{
				Name: contract.Name, Kind: string(contract.Kind),
				SourceFile:      contract.SourceFile,
				LinearizedBases: contract.LinearizedBases,
			},
			Callees:   callees,
			Callers:   callers,
			StateVars: stateVars,
		}
		return writeExtract(output,
			func() string { return renderContextMarkdown(output, db) },
			outPath, resolveExtractFormat(cmd))
	},
}

func init() {
	extractContextCmd.Flags().String("db", "", "Path to database JSON file (required)")
	extractContextCmd.Flags().StringP("output", "o", "", "Output file path (default: stdout)")
	extractContextCmd.Flags().String("contract", "", "Restrict search to a specific contract name")
	addExtractFormatFlag(extractContextCmd)
	extractContextCmd.MarkFlagRequired("db")
}

// ── extract workflow ─────────────────────────────────────────────────────────

// WorkflowFunction represents one function in the workflow bundle.
type WorkflowFunction struct {
	Contract   string `json:"contract"`
	Function   string `json:"function"`
	File       string `json:"file"`
	Visibility string `json:"visibility"`
	StartLine  int    `json:"startLine"`
	EndLine    int    `json:"endLine"`
	SourceCode string `json:"sourceCode"`
	CallDepth  int    `json:"callDepth"` // 0 = entry, 1 = direct callee, …
}

// WorkflowOutput is the JSON result of extract workflow.
type WorkflowOutput struct {
	SchemaVersion string             `json:"schemaVersion"`
	EntryFunction string             `json:"entryFunction"`
	EntryContract string             `json:"entryContract"`
	TotalFuncs    int                `json:"totalFunctions"`
	Functions     []WorkflowFunction `json:"functions"`
	// CombinedSource is a ready-to-paste concatenation for copy-pasting into a report.
	CombinedSource string `json:"combinedSource"`
}

var extractWorkflowCmd = &cobra.Command{
	Use:   "workflow <entry-function-name>",
	Short: "Extract full transitive source for an entry function (report-ready)",
	Long: `Extract the complete source code workflow for an entry function:
  - The entry function itself
  - All internal/inherited functions it calls (transitively)
  - Modifiers used along the call path

This gives auditors a self-contained, scrollable code bundle for writing finding reports
without needing to manually track down every helper function.

Options:
  --contract  Restrict entry function search to a named contract
  --depth     Maximum call depth to recurse (default: 10)

Examples:
  w3goaudit extract workflow withdraw --db database.json
  w3goaudit extract workflow withdraw --db database.json --contract DeFiVault -o workflow.json
  w3goaudit extract workflow transfer --db database.json --depth 5`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		dbPath, _ := cmd.Flags().GetString("db")
		outPath, _ := cmd.Flags().GetString("output")
		contractFilter, _ := cmd.Flags().GetString("contract")
		maxDepth, _ := cmd.Flags().GetInt("depth")

		db, err := loadDatabaseRequired(dbPath, false)
		if err != nil { return err }
		entryFuncName := args[0]

		fn, contract := findFunction(db, entryFuncName, contractFilter)
		if fn == nil {
			return fmt.Errorf("entry function %q not found%s", entryFuncName, contractHint(contractFilter))
		}

		// BFS over call graph, collecting internal/library/super callees
		type queueItem struct {
			funcID string
			depth  int
		}

		visited := make(map[string]bool)
		var collected []WorkflowFunction
		var combined strings.Builder

		entryFuncID := fmt.Sprintf("%s#%s.%s", contract.SourceFile, contract.Name, fn.Name)
		queue := []queueItem{{entryFuncID, 0}}

		for len(queue) > 0 {
			item := queue[0]
			queue = queue[1:]

			if visited[item.funcID] || item.depth > maxDepth {
				continue
			}
			visited[item.funcID] = true

			// Resolve function from ID
			_, cName, fSelector := parseWorkflowFuncID(item.funcID)
			c := db.GetContractByName(cName)
			if c == nil {
				continue
			}
			resolvedFn := findFunctionBySelector(c, fSelector)
			if resolvedFn == nil {
				continue
			}

			src := db.GetFunctionSource(resolvedFn)
			wf := WorkflowFunction{
				Contract:   c.Name,
				Function:   resolvedFn.Name,
				File:       c.SourceFile,
				Visibility: string(resolvedFn.Visibility),
				StartLine:  resolvedFn.StartLine,
				EndLine:    resolvedFn.EndLine,
				SourceCode: src,
				CallDepth:  item.depth,
			}
			collected = append(collected, wf)

			// Append to combined source with a section header
			combined.WriteString(fmt.Sprintf("\n// ─── %s.%s (depth %d, %s:%d-%d) ───\n",
				c.Name, resolvedFn.Name, item.depth, shortPath(c.SourceFile), resolvedFn.StartLine, resolvedFn.EndLine))
			combined.WriteString(src)
			combined.WriteString("\n")

			// Enqueue callees using the actual edge.To IDs from the call graph
			if db.CallGraph != nil {
				for _, edge := range db.CallGraph.GetCallees(item.funcID) {
					callType := string(edge.Type)
					isInternal := callType == "internal" || callType == "inherited" ||
						callType == "library" || callType == "super" || callType == "modifier"
					if !isInternal {
						continue // always skip external — they're in other contracts
					}
					if !visited[edge.To] && item.depth+1 <= maxDepth {
						queue = append(queue, queueItem{edge.To, item.depth + 1})
					}
				}
			}
		}

		output := WorkflowOutput{
			SchemaVersion:  ExtractSchemaVersion,
			EntryFunction:  fn.Name,
			EntryContract:  contract.Name,
			TotalFuncs:     len(collected),
			Functions:      collected,
			CombinedSource: combined.String(),
		}
		return writeExtract(output,
			func() string { return renderWorkflowMarkdown(output, db) },
			outPath, resolveExtractFormat(cmd))
	},
}

func init() {
	extractWorkflowCmd.Flags().String("db", "", "Path to database JSON file (required)")
	extractWorkflowCmd.Flags().StringP("output", "o", "", "Output file path (default: stdout)")
	extractWorkflowCmd.Flags().String("contract", "", "Restrict entry function search to a named contract")
	extractWorkflowCmd.Flags().Int("depth", 10, "Maximum call depth to recurse")
	addExtractFormatFlag(extractWorkflowCmd)
	extractWorkflowCmd.MarkFlagRequired("db")
}

// ── shared helpers ────────────────────────────────────────────────────────────

// findFunction locates a function by name, optionally filtered by contract name.
// Returns (nil, nil) if not found.
func findFunction(db *types.Database, funcName, contractFilter string) (*types.Function, *types.Contract) {
	for _, c := range db.Contracts {
		if contractFilter != "" && !strings.EqualFold(c.Name, contractFilter) {
			continue
		}
		for _, f := range c.Functions {
			if f.Name == funcName {
				return f, c
			}
		}
	}
	return nil, nil
}

// findFunctionBySelector finds a function in a contract by name, 4-byte selector, or full signature.
func findFunctionBySelector(c *types.Contract, nameOrSelector string) *types.Function {
	for _, f := range c.Functions {
		if f.Name == nameOrSelector || f.Selector == nameOrSelector || f.Signature == nameOrSelector {
			return f
		}
	}
	return nil
}

// contractHint returns a disambiguation hint when contractFilter is set.
func contractHint(contractFilter string) string {
	if contractFilter != "" {
		return fmt.Sprintf(" in contract %q", contractFilter)
	}
	return " in any contract (use --contract to disambiguate)"
}

// edgeToInfo converts a CallEdge to a CallEdgeInfo.
func edgeToInfo(edge *types.CallEdge) CallEdgeInfo {
	return CallEdgeInfo{
		From: edge.From, To: edge.To,
		Type: string(edge.Type), Line: edge.Line, Resolved: edge.Resolved,
	}
}

// parseWorkflowFuncID cracks "absPath#ContractName.selector" into its parts.
func parseWorkflowFuncID(id string) (filePath, contractName, selector string) {
	hashIdx := strings.LastIndex(id, "#")
	if hashIdx < 0 {
		return "", id, ""
	}
	filePath = id[:hashIdx]
	rest := id[hashIdx+1:]
	dotIdx := strings.Index(rest, ".")
	if dotIdx < 0 {
		return filePath, rest, ""
	}
	return filePath, rest[:dotIdx], rest[dotIdx+1:]
}

// shortPath returns just the filename for display.
func shortPath(p string) string {
	idx := strings.LastIndexAny(p, "/\\")
	if idx >= 0 {
		return p[idx+1:]
	}
	return p
}
