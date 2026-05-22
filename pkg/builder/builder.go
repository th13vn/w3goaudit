// Package builder constructs the contract database from parsed AST.
package builder

import (
	"fmt"

	"github.com/th13vn/solast-go/pkg/ast"
	"github.com/th13vn/solast-go/pkg/parser"
	"github.com/th13vn/w3goaudit-engine/pkg/types"
)

// Builder constructs the contract database
type Builder struct {
	db           *types.Database
	functionASTs map[*types.Function]*ast.FunctionDefinition // Store raw AST nodes for processing
	modifierASTs map[*types.Modifier]*ast.ModifierDefinition // Store modifier AST nodes for processing
}

// New creates a new Builder
func New() *Builder {
	return &Builder{
		db:           types.NewDatabase(),
		functionASTs: make(map[*types.Function]*ast.FunctionDefinition),
		modifierASTs: make(map[*types.Modifier]*ast.ModifierDefinition),
	}
}

// Build constructs the database from source files
func (b *Builder) Build(sources []*types.SourceFile) (*types.Database, error) {
	VerboseLog("Starting database build process with %d source files", len(sources))

	// Phase 1: Parse all files and extract contracts
	VerboseLog("Phase 1: Parsing files and extracting contracts")
	for _, sf := range sources {
		if err := b.parseFile(sf); err != nil {
			return nil, fmt.Errorf("parsing %s: %w", sf.Path, err)
		}
	}
	VerboseLog("Phase 1 complete: Extracted %d contracts", len(b.db.Contracts))

	// Phase 2: Build AST trees for all functions
	VerboseLog("Phase 2: Building AST trees")
	if err := b.buildASTs(); err != nil {
		return nil, fmt.Errorf("building ASTs: %w", err)
	}
	VerboseLog("Phase 2 complete")

	// Phase 3: Calculate function selectors/signatures with struct resolution
	VerboseLog("Phase 3: Calculating function selectors and signatures")
	b.calculateFunctionSelectors()
	VerboseLog("Phase 3 complete")

	// Phase 4: Build inheritance tree and calculate weights
	VerboseLog("Phase 4: Building inheritance tree")
	if err := b.buildInheritance(); err != nil {
		return nil, fmt.Errorf("building inheritance: %w", err)
	}
	VerboseLog("Phase 4 complete")

	// Phase 5: Build call graph
	VerboseLog("Phase 5: Building call graph")
	if err := b.buildCallGraph(); err != nil {
		return nil, fmt.Errorf("building call graph: %w", err)
	}
	VerboseLog("Phase 5 complete")

	// Phase 6: Calculate main contracts and entry functions
	VerboseLog("Phase 6: Calculating main contracts and entry functions")
	b.db.CalculateMainContracts()
	VerboseLog("Phase 6 complete: Found %d main contracts", len(b.db.MainContracts))

	VerboseLog("Database build complete")
	return b.db, nil
}

// parseFile parses a single source file and extracts contracts
func (b *Builder) parseFile(sf *types.SourceFile) error {
	VerboseLog("Parsing file: %s", sf.Path)
	result, err := parser.Parse(sf.Content, &parser.Options{
		Tolerant: true,
		Loc:      true,
		Range:    true,
	})
	if err != nil {
		return err
	}

	// Add source file to database
	b.db.AddSourceFile(sf)

	// Extract contracts by manually walking AST (avoid visitor nil pointer issues)
	extractor := &ContractExtractor{
		sourceFile: sf.Path,
		contracts:  make([]*types.Contract, 0),
	}

	// Manually iterate over children instead of using visitor
	for _, child := range result.Children {
		switch n := child.(type) {
		case *ast.ContractDefinition:
			extractor.visitContract(n)
		case *ast.ImportDirective:
			sf.Imports = append(sf.Imports, n.Path)
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
		VerboseLog("  Found contract: %s (type: %s, functions: %d)", contract.Name, contract.Kind, len(contract.Functions))
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

// buildASTs builds AST trees for all functions and modifiers
func (b *Builder) buildASTs() error {
	VerboseLog("Building AST trees for %d functions and %d modifiers", len(b.functionASTs), len(b.modifierASTs))
	// Iterate through function->AST mappings and build AST trees
	for fn, astNode := range b.functionASTs {
		// Find the contract this function belongs to
		contract := b.db.GetContractByName(fn.ContractName)
		if contract == nil {
			continue // Skip if contract not found
		}

		// Build AST tree and store in function
		fn.AST = BuildFunctionAST(astNode, fn, contract, b.db)
	}

	// Build AST trees for modifiers
	for mod, astNode := range b.modifierASTs {
		// Build AST tree and store in modifier
		mod.AST = BuildModifierAST(astNode)
	}

	// Clear the mappings to free memory
	b.functionASTs = nil
	b.modifierASTs = nil

	return nil
}

// buildInheritance builds the inheritance tree for all contracts
func (b *Builder) buildInheritance() error {
	ih := NewInheritanceBuilder(b.db)
	return ih.Build()
}

// buildCallGraph builds the call graph for all contracts
func (b *Builder) buildCallGraph() error {
	cg := NewCallGraphBuilder(b.db)
	return cg.Build()
}

// calculateFunctionSelectors calculates selectors and signatures for all functions
// with proper struct resolution to tuple format
func (b *Builder) calculateFunctionSelectors() {
	// Build a global map of struct definitions from all contracts
	// This allows resolving structs that might be defined in parent contracts
	structDefs := make(map[string]*types.Struct)
	for _, contract := range b.db.Contracts {
		for _, st := range contract.Structs {
			// Use both short name and qualified name for lookup
			structDefs[st.Name] = st
			structDefs[contract.Name+"."+st.Name] = st
		}
	}

	// Calculate selectors and signatures for all functions
	for _, contract := range b.db.Contracts {
		for _, fn := range contract.Functions {
			fn.Selector = fn.GetSelector(structDefs)
			fn.Signature = fn.GetSignature(structDefs)
		}
	}
}

// GetDatabase returns the built database
func (b *Builder) GetDatabase() *types.Database {
	return b.db
}
