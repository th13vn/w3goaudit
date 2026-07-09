package report

import "github.com/th13vn/w3goaudit/pkg/types"

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
			nav.Symbols = append(nav.Symbols, &NavSymbol{
				ID: types.MakeFunctionID(c.SourceFile, c.Name, fn.Selector), Kind: "function",
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
		if e == nil || e.From == "" || e.To == "" {
			continue
		}
		file, _, _ := types.ParseFunctionID(e.From) // caller's file for the call-site range
		nav.Callers = append(nav.Callers, &NavCaller{
			Callee: e.To, Caller: e.From,
			Site: SrcRange{File: file, StartLine: e.Line, StartCol: e.Col, StartByte: e.Byte},
		})
	}
	nav.InterfaceImpl = resolveInterfaceImpls(db)
	return nav
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
				if !inheritsInterface(impl, iface.Name) {
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

func inheritsInterface(c *types.Contract, ifaceName string) bool {
	for _, b := range c.LinearizedBases {
		if b == ifaceName {
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
// function whose selector matches (most-derived override wins).
func findImpl(db *types.Database, c *types.Contract, selector string) *implRef {
	for _, baseName := range c.LinearizedBases {
		base := db.GetContractByName(baseName)
		if base == nil || base.Kind == types.ContractKindInterface {
			continue
		}
		for _, fn := range base.Functions {
			if fn.Selector == selector {
				return &implRef{contractFile: base.SourceFile, contractName: base.Name}
			}
		}
	}
	return nil
}
