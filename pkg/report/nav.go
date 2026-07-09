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
// Populated by the resolver added in a later task; the type is defined here
// so NavJSON compiles and the field can be wired up incrementally.
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
	return nav
}
