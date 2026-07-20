// Package builder constructs the contract database from parsed AST.
package builder

import (
	"fmt"
	"sort"

	"github.com/th13vn/solast-go/pkg/ast"
	"github.com/th13vn/solast-go/pkg/parser"
	"github.com/th13vn/w3goaudit/pkg/logging"
	"github.com/th13vn/w3goaudit/pkg/types"
)

// Options configures one Builder instance.
type Options struct {
	Logger      *logging.Logger
	ProjectRoot string
	ScanTarget  string
	Diagnostics []types.Diagnostic
}

// Builder constructs the contract database
type Builder struct {
	db           *types.Database
	functionASTs map[*types.Function]*ast.FunctionDefinition // Store raw AST nodes for processing
	modifierASTs map[*types.Modifier]*ast.ModifierDefinition // Store modifier AST nodes for processing
	locators     map[string]*sourceLocator
	logger       *logging.Logger
	legacy       bool
}

// New creates a Builder that preserves the legacy package-global verbose
// configuration. New code should use NewWithOptions for scan-local logging.
func New() *Builder {
	return newBuilder(Options{}, true)
}

// NewWithOptions creates a Builder with scan-local configuration. A nil logger
// is treated as disabled and never falls back to package globals.
func NewWithOptions(opts Options) *Builder {
	return newBuilder(opts, false)
}

func newBuilder(opts Options, legacy bool) *Builder {
	logger := opts.Logger
	if logger == nil && !legacy {
		logger = logging.Disabled()
	}
	var db *types.Database
	if legacy {
		db = types.NewDatabase()
	} else {
		db = types.NewDatabaseWithOptions(types.DatabaseOptions{Logger: logger})
	}
	db.ProjectRoot = opts.ProjectRoot
	db.ScanTarget = opts.ScanTarget
	db.Diagnostics = append(db.Diagnostics, opts.Diagnostics...)
	return &Builder{
		db:           db,
		functionASTs: make(map[*types.Function]*ast.FunctionDefinition),
		modifierASTs: make(map[*types.Modifier]*ast.ModifierDefinition),
		locators:     make(map[string]*sourceLocator),
		logger:       logger,
		legacy:       legacy,
	}
}

func (b *Builder) logf(format string, args ...any) {
	if b != nil && b.legacy {
		VerboseLog(format, args...)
		return
	}
	if b != nil {
		b.logger.Printf(format, args...)
	}
}

// Build constructs the database from source files
func (b *Builder) Build(sources []*types.SourceFile) (*types.Database, error) {
	defer b.db.NormalizeDiagnostics()
	b.logf("Starting database build process with %d source files", len(sources))

	// Phase 1: Parse all files and extract contracts.
	// Tolerant: a single unparseable file is logged and skipped rather than
	// aborting the whole build — an audit target with one broken file should
	// still yield findings for the rest (matches the call-graph phase's policy).
	b.logf("Phase 1: Parsing files and extracting contracts")
	for _, sf := range sources {
		if err := b.parseFile(sf); err != nil {
			b.logf("Phase 1: parsing %s failed: %v (skipping)", sf.Path, err)
			b.db.AddDiagnostic(types.Diagnostic{
				Code:       types.DiagnosticParseSkipped,
				Severity:   types.DiagnosticError,
				Phase:      "builder",
				Message:    err.Error(),
				File:       sf.Path,
				Line:       parseFailureLine(err),
				Incomplete: true,
			})
			continue
		}
	}
	b.logf("Phase 1 complete: Extracted %d contracts", len(b.db.Contracts))

	// Phase 2: Build AST trees, data flow, and semantic type facts for all functions
	b.logf("Phase 2: Building AST trees, data flow, and semantic type facts")
	if err := b.buildASTs(); err != nil {
		return nil, fmt.Errorf("building ASTs: %w", err)
	}
	b.logf("Phase 2 complete")

	// Phase 3: Calculate function selectors/signatures with struct resolution
	b.logf("Phase 3: Calculating function selectors and signatures")
	b.calculateFunctionSelectors()
	b.logf("Phase 3 complete")

	// Phase 4: Build inheritance tree and calculate weights
	b.logf("Phase 4: Building inheritance tree")
	if err := b.buildInheritance(); err != nil {
		return nil, fmt.Errorf("building inheritance: %w", err)
	}
	b.recordUnresolvedBaseDiagnostics()
	b.logf("Phase 4 complete")

	// Phase 5: Build call graph
	b.logf("Phase 5: Building call graph")
	if err := b.buildCallGraph(); err != nil {
		return nil, fmt.Errorf("building call graph: %w", err)
	}
	b.logf("Phase 5 complete")

	// Phase 6: Calculate main contracts and entry functions
	b.logf("Phase 6: Calculating main contracts and entry functions")
	b.db.CalculateMainContracts()
	b.logf("Phase 6 complete: Found %d main contracts", len(b.db.MainContracts))

	// Phase 7: Per-function effects (state writes, guards, access control)
	b.logf("Phase 7: Analyzing per-function effects")
	b.analyzeEffects()
	b.logf("Phase 7 complete")

	b.logf("Database build complete")
	return b.db, nil
}

// parseFile parses a single source file and extracts contracts
func (b *Builder) parseFile(sf *types.SourceFile) error {
	b.logf("Parsing file: %s", sf.Path)
	// ParseWithErrors surfaces the errors that tolerant parsing recovers from but
	// would otherwise discard. A recovered error means the parser desynced and may
	// have dropped part of a contract body (functions, state) WITHOUT failing the
	// build — a silent false-negative source for every downstream detector. We
	// keep the tolerant policy (build the rest of the project) but make the loss
	// loud via a verbose warning so it is diagnosable instead of invisible.
	result, parseErrs, err := parser.ParseWithErrors(normalizeYulAssignmentsForParser(sf.Content), &parser.Options{
		Tolerant: true,
		Loc:      true,
		Range:    true,
	})
	if err != nil {
		return err
	}
	if len(parseErrs) > 0 {
		b.logf("⚠️  %s: %d parse error(s) recovered in tolerant mode — extracted contracts may be INCOMPLETE (functions/state silently dropped). First: %q at line %d",
			sf.Path, len(parseErrs), parseErrs[0].Message, parseErrs[0].Line)
		for _, parseErr := range parseErrs {
			b.db.AddDiagnostic(types.Diagnostic{
				Code:       types.DiagnosticParseRecovered,
				Severity:   types.DiagnosticWarning,
				Phase:      "builder",
				Message:    parseErr.Message,
				File:       sf.Path,
				Line:       parseErr.Line,
				Incomplete: true,
			})
		}
	}

	// Stash the parsed tree so the call-graph phase can reuse it instead of
	// re-parsing every file (parsing is the most expensive phase; on large
	// codebases this halves it). Not serialized — see SourceFile.AST.
	sf.AST = result

	// Add source file to database
	b.db.AddSourceFile(sf)
	locator := newSourceLocator(sf, b.db)
	b.locators[sf.Path] = locator

	// Extract contracts by manually walking AST (avoid visitor nil pointer issues)
	extractor := &ContractExtractor{
		sourceFile: sf.Path,
		locator:    locator,
		contracts:  make([]*types.Contract, 0),
	}

	// Manually iterate over children instead of using visitor
	importIndex := 0
	for _, child := range result.Children {
		switch n := child.(type) {
		case *ast.ContractDefinition:
			extractor.visitContract(n)
		case *ast.ImportDirective:
			sf.Imports = append(sf.Imports, n.Path)
			enrichImportBinding(sf, n, importIndex)
			importIndex++
		case *ast.PragmaDirective:
			if n.Name == "solidity" {
				sf.PragmaVersion = n.Value
			}
		}
	}

	// Add extracted contracts to database
	for _, contract := range extractor.contracts {
		b.db.AddContract(contract)
		sf.Contracts = append(sf.Contracts, contract.Name)
		b.logf("  Found contract: %s (type: %s, functions: %d)", contract.Name, contract.Kind, len(contract.Functions))
	}

	// Transfer function AST mappings to builder for later processing
	for fn, astNode := range extractor.functionASTs {
		b.functionASTs[fn] = astNode
	}

	// Transfer modifier AST mappings to builder for later processing
	for mod, astNode := range extractor.modifierASTs {
		b.modifierASTs[mod] = astNode
	}

	return nil
}

func enrichImportBinding(sf *types.SourceFile, directive *ast.ImportDirective, index int) {
	if sf == nil || directive == nil || index < 0 {
		return
	}
	for len(sf.ImportBindings) <= index {
		sf.ImportBindings = append(sf.ImportBindings, types.ImportBinding{})
	}
	binding := &sf.ImportBindings[index]
	if binding.ImportPath == "" {
		binding.ImportPath = directive.Path
	}
	binding.UnitAlias = directive.UnitAlias
	binding.Symbols = make([]types.ImportSymbolBinding, 0, len(directive.SymbolAliases))
	for _, symbol := range directive.SymbolAliases {
		if symbol == nil || symbol.Symbol == "" {
			continue
		}
		binding.Symbols = append(binding.Symbols, types.ImportSymbolBinding{
			Symbol: symbol.Symbol,
			Alias:  symbol.Alias,
		})
	}
}

func parseFailureLine(err error) int {
	parseErr, ok := err.(*parser.ParserError)
	if !ok || len(parseErr.Errors) == 0 || parseErr.Errors[0] == nil {
		return 0
	}
	return parseErr.Errors[0].Line
}

func (b *Builder) recordUnresolvedBaseDiagnostics() {
	contractIDs := make([]string, 0, len(b.db.Contracts))
	for id := range b.db.Contracts {
		contractIDs = append(contractIDs, id)
	}
	sort.Strings(contractIDs)

	for _, id := range contractIDs {
		contract := b.db.Contracts[id]
		for _, baseName := range contract.BaseContracts {
			if baseName == "" {
				continue
			}
			if _, status := b.db.ResolveContractNameExactWithStatus(baseName, contract.SourceFile); status == types.ExactResolutionResolved {
				continue
			}
			b.db.AddDiagnostic(types.Diagnostic{
				Code:       types.DiagnosticUnresolvedBase,
				Severity:   types.DiagnosticWarning,
				Phase:      "builder",
				Message:    fmt.Sprintf("base contract %q referenced by %q could not be resolved", baseName, contract.Name),
				File:       contract.SourceFile,
				Symbol:     baseName,
				Incomplete: true,
			})
		}
	}
}

// buildASTs builds AST trees for all functions and modifiers
func (b *Builder) buildASTs() error {
	b.logf("Building AST trees for %d functions and %d modifiers", len(b.functionASTs), len(b.modifierASTs))
	structDefs := b.structDefinitions()
	for fn := range b.functionASTs {
		fn.Selector = fn.GetSelector(structDefs)
	}

	// Building a function AST appends DataFlow edges to the shared graph, so the
	// order we visit functions becomes the order of db.DataFlow.Edges in the
	// serialized output. Map iteration order is randomized per run, which made
	// the exported database non-reproducible. Visit in a stable key order
	// (exact source/contract, source position, name) so edges are emitted
	// identically across runs. Selectors are intentionally computed above before
	// AST construction, but are unnecessary in this visit key because exact
	// ownership, source position, and declaration data already determine order.
	fns := make([]*types.Function, 0, len(b.functionASTs))
	for fn := range b.functionASTs {
		fns = append(fns, fn)
	}
	sort.Slice(fns, func(i, j int) bool {
		a, c := fns[i], fns[j]
		if a.SourceFile != c.SourceFile {
			return a.SourceFile < c.SourceFile
		}
		if a.ContractName != c.ContractName {
			return a.ContractName < c.ContractName
		}
		if a.StartLine != c.StartLine {
			return a.StartLine < c.StartLine
		}
		if a.EndLine != c.EndLine {
			return a.EndLine < c.EndLine
		}
		return a.Name < c.Name
	})

	// Iterate through function->AST mappings and build AST trees
	for _, fn := range fns {
		astNode := b.functionASTs[fn]
		// Find the contract this function belongs to. Use the exact ID
		// (file#name) so a function isn't built against a same-named contract's
		// state variables / semantic context in another file; fall back to
		// name resolution only when SourceFile is unset.
		var contract *types.Contract
		if fn.SourceFile != "" {
			contract = b.db.GetContractByID(types.MakeContractID(fn.SourceFile, fn.ContractName))
		}
		if contract == nil {
			contract = b.db.GetContractByName(fn.ContractName)
		}
		if contract == nil {
			continue // Skip if contract not found
		}

		// Build AST tree and store in function
		fn.AST = buildFunctionASTWithLocator(astNode, fn, contract, b.db, b.locatorForFile(fn.SourceFile))
	}

	// Build AST trees for modifiers in the same stable order. Modifier bodies can
	// also produce DataFlow edges (assignments inside a modifier), so this loop
	// must be deterministic too. Modifier has no file/contract field, so order by
	// exact owning contract, source position, then name.
	// Map each modifier back to its owning contract so its AST can be built with
	// state-variable context (Modifier itself carries no contract reference).
	modContract := make(map[*types.Modifier]*types.Contract)
	for _, c := range b.db.Contracts {
		for _, mod := range c.Modifiers {
			modContract[mod] = c
		}
	}

	mods := make([]*types.Modifier, 0, len(b.modifierASTs))
	for mod := range b.modifierASTs {
		mods = append(mods, mod)
	}
	sort.Slice(mods, func(i, j int) bool {
		a, c := mods[i], mods[j]
		aOwner, cOwner := modContract[a], modContract[c]
		aID, cID := "", ""
		if aOwner != nil {
			aID = aOwner.ID
		}
		if cOwner != nil {
			cID = cOwner.ID
		}
		if aID != cID {
			return aID < cID
		}
		if a.StartLine != c.StartLine {
			return a.StartLine < c.StartLine
		}
		if a.EndLine != c.EndLine {
			return a.EndLine < c.EndLine
		}
		return a.Name < c.Name
	})
	for _, mod := range mods {
		// Build AST tree and store in modifier, with the owning contract's
		// state-variable context so modifier-body references resolve.
		contract := modContract[mod]
		file := ""
		if contract != nil {
			file = contract.SourceFile
		}
		mod.AST = buildModifierASTWithLocator(b.modifierASTs[mod], contract, b.db, b.locatorForFile(file))
	}

	// Clear the mappings to free memory
	b.functionASTs = nil
	b.modifierASTs = nil

	return nil
}

// buildInheritance builds the inheritance tree for all contracts
func (b *Builder) buildInheritance() error {
	ih := newInheritanceBuilder(b.db, b.logf)
	return ih.Build()
}

// buildCallGraph builds the call graph for all contracts
func (b *Builder) buildCallGraph() error {
	cg := newCallGraphBuilderWithLocators(b.db, b.logf, b.locators)
	if err := cg.Build(); err != nil {
		return err
	}
	// Make `super` resolution context-aware: bind each super call to the next
	// definition in EVERY instantiation leaf's MRO, not just the textual
	// contract's own MRO. Sound union; additive and deduplicated.
	cg.ResolveSuperAcrossLeaves()
	return nil
}

func (b *Builder) locatorForFile(file string) *sourceLocator {
	if b == nil || file == "" {
		return nil
	}
	if locator := b.locators[file]; locator != nil {
		return locator
	}
	locator := sourceLocatorFromDatabase(b.db, file)
	if locator != nil {
		b.locators[file] = locator
	}
	return locator
}

// calculateFunctionSelectors calculates selectors and signatures for all functions
// with proper struct resolution to tuple format
func (b *Builder) calculateFunctionSelectors() {
	// Build a global map of struct definitions from all contracts.
	// This allows resolving structs that might be defined in parent contracts.
	// Iterate contracts in sorted ID order so that when two contracts define a
	// struct with the same short name, the short-name winner is deterministic
	// across runs (previously map-iteration order made selectors non-reproducible).
	// The qualified `Contract.Struct` key is always unambiguous.
	structDefs := b.structDefinitions()

	// Calculate selectors and signatures for all functions
	for _, contract := range b.db.Contracts {
		for _, fn := range contract.Functions {
			fn.Selector = fn.GetSelector(structDefs)
			fn.Signature = fn.GetSignature(structDefs)
		}
	}
}

func (b *Builder) structDefinitions() map[string]*types.Struct {
	structDefs := make(map[string]*types.Struct)
	contractIDs := make([]string, 0, len(b.db.Contracts))
	for id := range b.db.Contracts {
		contractIDs = append(contractIDs, id)
	}
	sort.Strings(contractIDs)
	for _, id := range contractIDs {
		contract := b.db.Contracts[id]
		for _, st := range contract.Structs {
			structDefs[contract.Name+"."+st.Name] = st
			// Only set the short-name key if unclaimed, so the lexicographically
			// first contract wins deterministically instead of the last iterated.
			if _, exists := structDefs[st.Name]; !exists {
				structDefs[st.Name] = st
			}
		}
	}

	return structDefs
}

// GetDatabase returns the built database
func (b *Builder) GetDatabase() *types.Database {
	return b.db
}
