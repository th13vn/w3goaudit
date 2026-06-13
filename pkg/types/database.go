package types

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// SourceFile represents a parsed Solidity source file
type SourceFile struct {
	// Path is the file path
	Path string `json:"path"`

	// Content is the file content.
	//
	// Serialized so a `build → JSON → scan --db` round-trip is self-contained:
	// source-text predicates (`source_regex`, `scope: source`) reproduce the
	// same findings without depending on the original files still being present
	// at their absolute paths. The engine still falls back to reading the file
	// from disk when Content is empty (e.g. a database produced before this
	// field was serialized), and warns when neither is available.
	Content string `json:"content,omitempty"`

	// AST is the raw parsed AST tree (stored for deep analysis).
	//
	// Deliberately not serialized (`json:"-"`): it holds a solast-go node tree
	// behind an interface{} that does not round-trip cleanly through JSON, and
	// no current operator walks the file-level tree — source-scope matching uses
	// Content (above), and function-level matching uses Function.AST (which does
	// round-trip). If a future operator needs to walk this tree from a reloaded
	// database, it must be rebuilt from source rather than relied upon here.
	AST interface{} `json:"-"`

	// Contracts defined in this file
	Contracts []string `json:"contracts,omitempty"`

	// Imports in this file
	Imports []string `json:"imports,omitempty"`

	// PragmaVersion from the file
	PragmaVersion string `json:"pragmaVersion,omitempty"`

	// Checksum is the SHA256 hash of the file content
	Checksum string `json:"checksum,omitempty"`
}

// Database represents the complete project database
type Database struct {
	// ProjectRoot is the root directory of the project
	ProjectRoot string `json:"projectRoot"`

	// SourceFiles maps file path to source file info
	SourceFiles map[string]*SourceFile `json:"sourceFiles"`

	// Contracts maps contract ID (absPath#Name) to contract definition
	Contracts map[string]*Contract `json:"contracts"`

	// MainContracts maps main contract ID to its entry with resolved functions and linearized inheritance
	// Keys are deployable contract IDs ranked by inheritance weight
	MainContracts map[string]*MainContractEntry `json:"mainContracts"`

	// CallGraph for the entire project
	CallGraph *CallGraph `json:"callGraph"`

	// DataFlow tracks intra-procedural operations and assignments
	DataFlow *DataFlowGraph `json:"dataFlow"`

	// Semantics stores lightweight inferred type/symbol facts used by WQL and
	// later analysis phases. It is serialized with the database so build-cache
	// scans retain the same facts.
	Semantics *SemanticFacts `json:"semantics"`

	// Framework detected for the project
	Framework string `json:"framework"`
}

// MainContractEntry represents a main contract with its resolved entry functions and inheritance
type MainContractEntry struct {
	// EntryFunctions are the resolved entry function IDs (format: absPath#ContractName.functionName)
	EntryFunctions []string `json:"entryFunctions"`

	// LinearizedBases is the C3 linearization order (method resolution order)
	// Most derived (current contract) first, most base contract last
	LinearizedBases []string `json:"linearizedBases"`
}

// MakeFunctionID creates a unique function ID: absPath#ContractName.selector
// Note: funcSelector should be the full function selector (e.g. "transfer(address,uint256)")
// to ensure overloaded functions are uniquely identified.
func MakeFunctionID(filePath, contractName, funcSelector string) string {
	return filePath + "#" + contractName + "." + funcSelector
}

// MakeModifierID creates a unique modifier ID: absPath#ContractName.modifierName
// Modifiers are named entities within contracts similar to functions
func MakeModifierID(filePath, contractName, modifierName string) string {
	return filePath + "#" + contractName + "." + modifierName
}

// ParseFunctionID extracts file path, contract name, and function selector from ID
func ParseFunctionID(id string) (filePath, contractName, funcSelector string) {
	parts := strings.SplitN(id, "#", 2)
	if len(parts) < 2 {
		return id, "", ""
	}
	filePath = parts[0]
	rest := parts[1]

	dotParts := strings.SplitN(rest, ".", 2)
	contractName = dotParts[0]
	if len(dotParts) > 1 {
		funcSelector = dotParts[1]
	}
	return
}

// NewDatabase creates a new empty database
func NewDatabase() *Database {
	return &Database{
		SourceFiles:   make(map[string]*SourceFile),
		Contracts:     make(map[string]*Contract),
		CallGraph:     NewCallGraph(),
		DataFlow:      NewDataFlowGraph(),
		Semantics:     NewSemanticFacts(),
		MainContracts: make(map[string]*MainContractEntry),
	}
}

// LoadFromJSON loads a database from a JSON file
// This enables database caching - build once, reuse multiple times
func LoadFromJSON(path string) (*Database, error) {
	VerboseLog("Loading database from JSON file: %s", path)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var db Database
	if err := json.Unmarshal(data, &db); err != nil {
		return nil, err
	}

	// Initialize maps if nil (defensive)
	if db.SourceFiles == nil {
		db.SourceFiles = make(map[string]*SourceFile)
	}
	if db.Contracts == nil {
		db.Contracts = make(map[string]*Contract)
	}
	if db.MainContracts == nil {
		db.MainContracts = make(map[string]*MainContractEntry)
	}
	if db.CallGraph == nil {
		db.CallGraph = NewCallGraph()
	}
	if db.DataFlow == nil {
		db.DataFlow = NewDataFlowGraph()
	}
	if db.Semantics == nil {
		db.Semantics = NewSemanticFacts()
	}
	db.RestoreASTParents()

	return &db, nil
}

// RestoreASTParents rebuilds AST parent links lost during JSON round-trips.
func (db *Database) RestoreASTParents() {
	if db == nil {
		return
	}
	for _, contract := range db.Contracts {
		if contract == nil {
			continue
		}
		for _, fn := range contract.Functions {
			if fn != nil && fn.AST != nil {
				fn.AST.RestoreParents()
			}
		}
		for _, modifier := range contract.Modifiers {
			if modifier != nil && modifier.AST != nil {
				modifier.AST.RestoreParents()
			}
		}
	}
}

// AddContract adds a contract to the database using its ID
func (db *Database) AddContract(contract *Contract) {
	if contract.ID == "" {
		contract.ID = MakeContractID(contract.SourceFile, contract.Name)
	}
	db.Contracts[contract.ID] = contract
}

// AddSourceFile adds a source file to the database
func (db *Database) AddSourceFile(sf *SourceFile) {
	db.SourceFiles[sf.Path] = sf
}

// GetContract returns a contract by ID
func (db *Database) GetContract(id string) *Contract {
	return db.Contracts[id]
}

// GetContractByName finds a contract by unqualified name.
//
// IMPORTANT: name collisions are common (e.g. a `Token` in `/src/Token.sol`
// AND a `Token` in `/test/mocks/Token.sol`). Go map iteration is randomized,
// so a naive "return first match" produces non-deterministic analysis.
//
// This implementation collects every candidate and returns the one with the
// lexicographically smallest ID. Behaviour is therefore deterministic across
// runs, but if you have a true ambiguity, prefer GetContractByID with the
// fully-qualified ID (`absPath#ContractName`).
func (db *Database) GetContractByName(name string) *Contract {
	var candidates []*Contract
	for _, c := range db.Contracts {
		if c.Name == name {
			candidates = append(candidates, c)
		}
	}
	if len(candidates) == 0 {
		return nil
	}
	if len(candidates) == 1 {
		return candidates[0]
	}
	sort.Slice(candidates, func(i, j int) bool {
		return MakeContractID(candidates[i].SourceFile, candidates[i].Name) <
			MakeContractID(candidates[j].SourceFile, candidates[j].Name)
	})
	VerboseLog("GetContractByName(%q): %d candidates, returning %s (lex-min)",
		name, len(candidates),
		MakeContractID(candidates[0].SourceFile, candidates[0].Name))
	return candidates[0]
}

// GetContractByID returns the contract with the exact fully-qualified ID
// (`absPath#ContractName`). Prefer this over GetContractByName whenever the
// caller already has an ID — it's O(1) and unambiguous.
func (db *Database) GetContractByID(id string) *Contract {
	return db.Contracts[id]
}

// FindContractsByName returns every contract sharing the given unqualified
// name. Useful when the caller needs to handle collisions explicitly.
func (db *Database) FindContractsByName(name string) []*Contract {
	var out []*Contract
	for _, c := range db.Contracts {
		if c.Name == name {
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return MakeContractID(out[i].SourceFile, out[i].Name) <
			MakeContractID(out[j].SourceFile, out[j].Name)
	})
	return out
}

// ResolveContractName resolves an unqualified contract name to a concrete
// contract, preferring the candidate "closest" to fromFile when the name is
// ambiguous (the same name defined in more than one file — e.g. a real `Token`
// and a `test/mocks/Token`). Resolution order:
//
//  1. exactly one contract has the name → return it (the overwhelmingly common
//     case — zero behaviour change versus a plain lookup);
//  2. a contract defined in fromFile itself (an intra-file reference is
//     unambiguous);
//  3. a contract in the same directory as fromFile;
//  4. a contract whose file a relative import in fromFile resolves to exactly;
//  5. otherwise the lexicographically-smallest ID (GetContractByName's default).
//
// This is a deterministic heuristic, not full import-scope resolution (which
// would require the resolved absolute path of every import — imports are stored
// as raw strings). It is never worse than the bare lex-min pick and strictly
// more precise when a collision exists and fromFile gives a usable scope. Pass
// fromFile = "" (or a path with no contracts) to get the plain lex-min result.
func (db *Database) ResolveContractName(name, fromFile string) *Contract {
	candidates := db.FindContractsByName(name) // sorted lex-min by ID
	switch len(candidates) {
	case 0:
		return nil
	case 1:
		return candidates[0]
	}

	if fromFile != "" {
		// 2. Defined in the same file.
		for _, c := range candidates {
			if c.SourceFile == fromFile {
				return c
			}
		}
		// 3. Defined in the same directory (candidates are lex-min sorted, so the
		// first match is deterministic).
		fromDir := filepath.Dir(fromFile)
		for _, c := range candidates {
			if filepath.Dir(c.SourceFile) == fromDir {
				return c
			}
		}
		// 4. A relative import in fromFile resolves exactly to a candidate's
		// file. (Remapped imports like `@openzeppelin/...` cannot be resolved
		// here without the project remappings, so they fall through.)
		if sf := db.SourceFiles[fromFile]; sf != nil {
			fromDir := filepath.Dir(fromFile)
			for _, imp := range sf.Imports {
				resolved := imp
				if !filepath.IsAbs(resolved) {
					resolved = filepath.Join(fromDir, imp)
				}
				resolved = filepath.Clean(resolved)
				for _, c := range candidates {
					if filepath.Clean(c.SourceFile) == resolved {
						return c
					}
				}
			}
		}
	}

	// 5. Deterministic lex-min fallback (matches GetContractByName).
	VerboseLog("ResolveContractName(%q, from=%q): %d candidates, lex-min fallback %s",
		name, fromFile, len(candidates), candidates[0].ID)
	return candidates[0]
}

// MakeContractID creates a unique contract ID: absPath#ContractName
func MakeContractID(filePath, contractName string) string {
	return filePath + "#" + contractName
}

// ParseContractID extracts file path and contract name from ID
func ParseContractID(id string) (filePath, contractName string) {
	parts := strings.SplitN(id, "#", 2)
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	return "", id
}

// CalculateMainContracts identifies main contracts and builds their entry functions
// A main contract is a deployable contract that is NOT inherited by any other contract
// Entry functions are resolved from the inheritance chain
func (db *Database) CalculateMainContracts() {
	// Build set of contracts that are inherited by others
	inheritedContracts := make(map[string]bool)
	for _, contract := range db.Contracts {
		for _, baseName := range contract.BaseContracts {
			// Mark base contract as inherited
			inheritedContracts[baseName] = true
		}
	}

	var candidates []*Contract
	for _, contract := range db.Contracts {
		// Only consider deployable contracts that are NOT inherited by others
		if contract.IsMainCandidate() && !inheritedContracts[contract.Name] {
			candidates = append(candidates, contract)
		}
	}

	// Sort by inheritance weight (descending)
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].InheritanceWeight > candidates[j].InheritanceWeight
	})

	// Build MainContracts map with entry functions and linearized inheritance
	db.MainContracts = make(map[string]*MainContractEntry)
	for _, c := range candidates {
		db.MainContracts[c.ID] = &MainContractEntry{
			EntryFunctions:  db.buildEntryFunctionsForContract(c),
			LinearizedBases: c.LinearizedBases,
		}
	}
}

// buildEntryFunctionsForContract builds the resolved entry functions for a contract
// Creates a list of function IDs from the inheritance chain
func (db *Database) buildEntryFunctionsForContract(contract *Contract) []string {
	// Collect resolved entry functions (by signature to handle overrides)
	// Map signature -> function ID
	resolvedBySignature := make(map[string]string)

	// LinearizedBases is derived-first: [MostDerived, ..., MostBase]
	// Iterate forward - first signature encountered is the most derived (overridden) version
	for _, baseName := range contract.LinearizedBases {
		baseContract := db.GetContractByName(baseName)
		if baseContract == nil {
			continue
		}

		for _, fn := range baseContract.Functions {
			if fn.IsEntrypoint() {
				signature := fn.GetSignature(nil)
				if signature != "" {
					// Only add if not already seen - first occurrence is most derived
					if _, exists := resolvedBySignature[signature]; !exists {
						selector := fn.Selector
						if selector == "" {
							selector = fn.Name
						}
						funcID := MakeFunctionID(baseContract.SourceFile, baseContract.Name, selector)
						resolvedBySignature[signature] = funcID
					}
				}
			}
		}
	}

	// Convert map to slice of function IDs, sorted for deterministic output.
	// MainContractEntry.EntryFunctions is serialized into the cached database;
	// a random map order made the cache non-reproducible across runs.
	ids := make([]string, 0, len(resolvedBySignature))
	for _, funcID := range resolvedBySignature {
		ids = append(ids, funcID)
	}
	sort.Strings(ids)

	return ids
}

// GetAllFunctions returns all functions across all contracts
func (db *Database) GetAllFunctions() []*Function {
	var result []*Function
	for _, contract := range db.Contracts {
		result = append(result, contract.Functions...)
	}
	return result
}

// GetContractByFile returns contracts defined in a specific file
func (db *Database) GetContractByFile(path string) []*Contract {
	var result []*Contract
	for _, contract := range db.Contracts {
		if contract.SourceFile == path {
			result = append(result, contract)
		}
	}
	return result
}

// Stats returns database statistics
type DatabaseStats struct {
	TotalFiles          int    `json:"totalFiles"`
	TotalContracts      int    `json:"totalContracts"`
	TotalInterfaces     int    `json:"totalInterfaces"`
	TotalLibraries      int    `json:"totalLibraries"`
	TotalFunctions      int    `json:"totalFunctions"`
	TotalEntryFunctions int    `json:"totalEntryFunctions"`
	MainContractsCount  int    `json:"mainContractsCount"`
	NSLOC               int    `json:"nsloc"`
	Framework           string `json:"framework"`
}

func (db *Database) GetStats() *DatabaseStats {
	stats := &DatabaseStats{
		TotalFiles:          len(db.SourceFiles),
		TotalContracts:      0,
		MainContractsCount:  len(db.MainContracts),
		TotalEntryFunctions: db.countEntryFunctions(),
		Framework:           db.Framework,
	}

	for _, contract := range db.Contracts {
		switch contract.Kind {
		case ContractKindContract, ContractKindAbstract:
			stats.TotalContracts++
		case ContractKindInterface:
			stats.TotalInterfaces++
		case ContractKindLibrary:
			stats.TotalLibraries++
		}
		stats.TotalFunctions += len(contract.Functions)
	}

	// Calculate nSLOC
	for _, sf := range db.SourceFiles {
		lines := strings.Split(sf.Content, "\n")
		for _, line := range lines {
			trimmed := strings.TrimSpace(line)
			if trimmed != "" && !strings.HasPrefix(trimmed, "//") && !strings.HasPrefix(trimmed, "*") && !strings.HasPrefix(trimmed, "/*") && !strings.HasSuffix(trimmed, "*/") {
				stats.NSLOC++
			}
		}
	}

	return stats
}

// countEntryFunctions counts all entry functions across main contracts
func (db *Database) countEntryFunctions() int {
	count := 0
	for _, entry := range db.MainContracts {
		count += len(entry.EntryFunctions)
	}
	return count
}
