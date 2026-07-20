package report

import (
	"sort"

	"github.com/th13vn/w3goaudit/pkg/types"
)

// NavJSON is the semantic navigation index consumed by the VSCode extension.
type NavJSON struct {
	SchemaVersion string              `json:"schemaVersion"`
	Symbols       []*NavSymbol        `json:"symbols"`
	Callers       []*NavCaller        `json:"callers,omitempty"`
	InterfaceImpl []*NavInterfaceImpl `json:"interfaceImpl,omitempty"`
}

// NavSymbol is a navigable definition (contract, function, or state variable).
type NavSymbol struct {
	ID       string   `json:"id"`
	Kind     string   `json:"kind"` // "contract" | "function" | "stateVar"
	Name     string   `json:"name"`
	Selector string   `json:"selector,omitempty"`
	Range    SrcRange `json:"range"`
}

// NavCaller is a reverse call edge: Callee is called by Caller at Site.
type NavCaller struct {
	Callee string   `json:"callee"` // function ID being called
	Caller string   `json:"caller"` // function ID of the calling function
	Site   SrcRange `json:"site"`   // the call-site location
}

// NavInterfaceImpl maps an interface method to its concrete implementation.
type NavInterfaceImpl struct {
	Interface      string `json:"interface"`
	Method         string `json:"method"`
	Implementation string `json:"implementation"`
}

// BuildNavJSON produces the navigation index from the database.
func BuildNavJSON(db *types.Database) *NavJSON {
	nav := &NavJSON{SchemaVersion: SchemaVersion, Symbols: []*NavSymbol{}}
	if db == nil {
		return nav
	}
	for _, c := range db.Contracts {
		if c == nil {
			continue
		}
		nav.Symbols = append(nav.Symbols, &NavSymbol{
			ID: c.ID, Kind: "contract", Name: c.Name,
			Range: declRange(c.SourceFile, c.StartLine, c.StartCol, c.EndLine, c.EndCol, c.StartByte, c.EndByte),
		})
		for _, fn := range c.Functions {
			// fallback/receive/constructor have an empty Selector, so keying the
			// symbol ID on selector alone collapses them all to `file#Contract.`
			// — a contract with both fallback and receive would emit two symbols
			// with the same id. Fall back to the function name to disambiguate.
			idSel := fn.Selector
			if idSel == "" {
				idSel = fn.Name
			}
			nav.Symbols = append(nav.Symbols, &NavSymbol{
				ID: types.MakeFunctionID(c.SourceFile, c.Name, idSel), Kind: "function",
				Name: fn.Name, Selector: fn.Selector,
				Range: declRange(c.SourceFile, fn.StartLine, fn.StartCol, fn.EndLine, fn.EndCol, fn.StartByte, fn.EndByte),
			})
		}
		for _, sv := range c.StateVariables {
			nav.Symbols = append(nav.Symbols, &NavSymbol{
				ID: c.ID + "." + sv.Name, Kind: "stateVar", Name: sv.Name,
				Range: declRange(c.SourceFile, sv.StartLine, sv.StartCol, sv.EndLine, sv.EndCol, sv.StartByte, sv.EndByte),
			})
		}
	}
	for _, e := range db.CallGraph.Edges {
		if e == nil || e.From == "" || !e.Resolved || !exactNavFunctionTarget(db, e.To) {
			continue
		}
		file, _, _ := types.ParseFunctionID(e.From) // caller's file for the call-site range
		nav.Callers = append(nav.Callers, &NavCaller{
			Callee: e.To, Caller: e.From,
			Site: SrcRange{File: file, StartLine: e.Line, StartCol: e.Col, StartByte: e.Byte},
		})
	}
	nav.InterfaceImpl = resolveInterfaceImpls(db)

	// Deterministic ordering so the emitted nav.json is stable across runs
	// (map iteration over db.Contracts is unordered).
	sort.Slice(nav.Symbols, func(i, j int) bool {
		if nav.Symbols[i].ID != nav.Symbols[j].ID {
			return nav.Symbols[i].ID < nav.Symbols[j].ID
		}
		if nav.Symbols[i].Kind != nav.Symbols[j].Kind {
			return nav.Symbols[i].Kind < nav.Symbols[j].Kind
		}
		if nav.Symbols[i].Name != nav.Symbols[j].Name {
			return nav.Symbols[i].Name < nav.Symbols[j].Name
		}
		return nav.Symbols[i].Range.StartLine < nav.Symbols[j].Range.StartLine
	})
	sort.Slice(nav.Callers, func(i, j int) bool {
		if nav.Callers[i].Callee != nav.Callers[j].Callee {
			return nav.Callers[i].Callee < nav.Callers[j].Callee
		}
		if nav.Callers[i].Caller != nav.Callers[j].Caller {
			return nav.Callers[i].Caller < nav.Callers[j].Caller
		}
		if nav.Callers[i].Site.StartLine != nav.Callers[j].Site.StartLine {
			return nav.Callers[i].Site.StartLine < nav.Callers[j].Site.StartLine
		}
		if nav.Callers[i].Site.StartCol != nav.Callers[j].Site.StartCol {
			return nav.Callers[i].Site.StartCol < nav.Callers[j].Site.StartCol
		}
		return nav.Callers[i].Site.StartByte < nav.Callers[j].Site.StartByte
	})
	sort.Slice(nav.InterfaceImpl, func(i, j int) bool {
		if nav.InterfaceImpl[i].Interface != nav.InterfaceImpl[j].Interface {
			return nav.InterfaceImpl[i].Interface < nav.InterfaceImpl[j].Interface
		}
		if nav.InterfaceImpl[i].Method != nav.InterfaceImpl[j].Method {
			return nav.InterfaceImpl[i].Method < nav.InterfaceImpl[j].Method
		}
		// Multiple contracts can implement the same interface method; without
		// this tiebreaker their relative order is map-iteration random.
		return nav.InterfaceImpl[i].Implementation < nav.InterfaceImpl[j].Implementation
	})
	return nav
}

func exactNavFunctionTarget(db *types.Database, id string) bool {
	file, contractName, selector := types.ParseFunctionID(id)
	if file == "" || contractName == "" || selector == "" {
		return false
	}
	contract := db.GetContractByID(types.MakeContractID(file, contractName))
	if contract == nil {
		return false
	}
	for _, fn := range contract.Functions {
		if fn == nil {
			continue
		}
		functionKey := fn.Selector
		if functionKey == "" {
			functionKey = fn.Name
		}
		if functionKey == selector {
			return true
		}
	}
	return false
}

// resolveInterfaceImpls materializes interface-method -> concrete-implementation
// edges. For each interface method, find non-interface contracts that inherit the
// interface and take the most-derived function with a matching selector.
func resolveInterfaceImpls(db *types.Database) []*NavInterfaceImpl {
	var out []*NavInterfaceImpl
	for _, iface := range db.Contracts {
		if iface == nil || iface.Kind != types.ContractKindInterface {
			continue
		}
		for _, m := range iface.Functions {
			if m.Selector == "" {
				continue
			}
			for _, impl := range db.Contracts {
				if impl == nil || impl.Kind == types.ContractKindInterface {
					continue
				}
				if !inheritsInterface(db, impl, iface.ID) {
					continue
				}
				if implFn := findImpl(db, impl, m.Selector); implFn != nil {
					out = append(out, &NavInterfaceImpl{
						Interface:      iface.ID,
						Method:         m.Selector,
						Implementation: types.MakeFunctionID(implFn.contractFile, implFn.contractName, m.Selector),
					})
				}
			}
		}
	}
	return out
}

func inheritsInterface(db *types.Database, c *types.Contract, ifaceID string) bool {
	for _, base := range db.LinearizedContracts(c) {
		if base != nil && base.ID == ifaceID {
			return true
		}
	}
	return false
}

// implRef is the located concrete function for a selector along an MRO.
type implRef struct {
	contractFile string
	contractName string
}

// findImpl walks c's MRO derived-first and returns the first non-interface
// function with a real body whose selector matches (most-derived override
// wins). LinearizedContracts supplies exact file#Contract objects, including
// for legacy databases whose display-name MRO contains collisions.
func findImpl(db *types.Database, c *types.Contract, selector string) *implRef {
	for _, base := range db.LinearizedContracts(c) {
		if base == nil || base.Kind == types.ContractKindInterface {
			continue
		}
		for _, fn := range base.Functions {
			// fn.AST == nil means the function has no body (an interface
			// declaration or an abstract/virtual re-declaration) and does
			// not count as an implementation.
			if fn.Selector == selector && fn.AST != nil {
				return &implRef{contractFile: base.SourceFile, contractName: base.Name}
			}
		}
	}
	return nil
}
