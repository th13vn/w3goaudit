package report

import (
	"sort"

	"github.com/th13vn/w3goaudit/pkg/types"
)

// SrcRange is a precise source span for the extension: 1-based line/column plus
// character byte offsets. Shared by explorer.json and nav.json. Zero fields are
// omitted so location-less/synthetic decls stay compact.
type SrcRange struct {
	File      string `json:"file,omitempty"`
	StartLine int    `json:"startLine,omitempty"`
	StartCol  int    `json:"startCol,omitempty"`
	EndLine   int    `json:"endLine,omitempty"`
	EndCol    int    `json:"endCol,omitempty"`
	StartByte int    `json:"startByte,omitempty"`
	EndByte   int    `json:"endByte,omitempty"`
}

// ExplorerJSON is the explorer-tab model: one entry per deployable (main) contract.
type ExplorerJSON struct {
	SchemaVersion string              `json:"schemaVersion"`
	Contracts     []*ExplorerContract `json:"contracts"`
}

type ExplorerContract struct {
	ID             string              `json:"id"`
	Name           string              `json:"name"`
	Kind           string              `json:"kind"`
	Range          SrcRange            `json:"range"`
	Constants      []*ExplorerStateVar `json:"constants,omitempty"`      // constant + immutable
	Storage        []*ExplorerStateVar `json:"storage,omitempty"`        // mutable storage, slot order
	EntryFunctions []*ExplorerFunc     `json:"entryFunctions,omitempty"` // state-mutating public/external
	Getters        []*ExplorerFunc     `json:"getters,omitempty"`        // public/external view/pure
}

type ExplorerStateVar struct {
	Name       string   `json:"name"`
	TypeName   string   `json:"typeName,omitempty"`
	Visibility string   `json:"visibility,omitempty"`
	Constant   bool     `json:"constant,omitempty"`
	Immutable  bool     `json:"immutable,omitempty"`
	Range      SrcRange `json:"range"`
}

type ExplorerFunc struct {
	Name       string   `json:"name"`
	Selector   string   `json:"selector,omitempty"`
	Signature  string   `json:"signature,omitempty"`
	Visibility string   `json:"visibility,omitempty"`
	Mutability string   `json:"mutability,omitempty"`
	Modifiers  []string `json:"modifiers,omitempty"`
	Range      SrcRange `json:"range"`
}

// declRange builds a SrcRange from a declaration's location fields.
func declRange(file string, sl, sc, el, ec, sb, eb int) SrcRange {
	return SrcRange{File: file, StartLine: sl, StartCol: sc, EndLine: el, EndCol: ec, StartByte: sb, EndByte: eb}
}

func isGetter(f *types.Function) bool {
	return (f.Visibility == types.VisibilityPublic || f.Visibility == types.VisibilityExternal) &&
		(f.StateMutability == types.StateMutabilityView || f.StateMutability == types.StateMutabilityPure)
}

// BuildExplorerJSON produces the explorer model for every deployable (main) contract.
func BuildExplorerJSON(db *types.Database) *ExplorerJSON {
	out := &ExplorerJSON{SchemaVersion: SchemaVersion, Contracts: []*ExplorerContract{}}
	if db == nil {
		return out
	}
	for id := range db.MainContracts {
		c := db.Contracts[id]
		if c == nil {
			continue
		}
		ec := &ExplorerContract{
			ID: c.ID, Name: c.Name, Kind: string(c.Kind),
			Range: declRange(c.SourceFile, c.StartLine, c.StartCol, c.EndLine, c.EndCol, c.StartByte, c.EndByte),
		}
		// State: walk MRO most-base-first (storage-slot order), preserving each
		// contract's declared order. LinearizedBases is derived-first, so reverse it.
		for i := len(c.LinearizedBases) - 1; i >= 0; i-- {
			base := db.GetContractByName(c.LinearizedBases[i])
			if base == nil {
				continue
			}
			for _, sv := range base.StateVariables {
				esv := &ExplorerStateVar{
					Name: sv.Name, TypeName: sv.TypeName, Visibility: sv.Visibility,
					Constant: sv.IsConstant, Immutable: sv.IsImmutable,
					Range: declRange(base.SourceFile, sv.StartLine, sv.StartCol, sv.EndLine, sv.EndCol, sv.StartByte, sv.EndByte),
				}
				if sv.IsConstant || sv.IsImmutable {
					ec.Constants = append(ec.Constants, esv)
				} else {
					ec.Storage = append(ec.Storage, esv)
				}
			}
		}
		// Functions: walk MRO derived-first, first selector wins (most-derived override).
		seen := map[string]bool{}
		for _, baseName := range c.LinearizedBases {
			base := db.GetContractByName(baseName)
			if base == nil {
				continue
			}
			for _, fn := range base.Functions {
				if fn.IsConstructor || fn.Selector == "" || seen[fn.Selector] {
					continue
				}
				ef := &ExplorerFunc{
					Name: fn.Name, Selector: fn.Selector, Signature: fn.Signature,
					Visibility: string(fn.Visibility), Mutability: string(fn.StateMutability),
					Modifiers: fn.Modifiers,
					Range:     declRange(base.SourceFile, fn.StartLine, fn.StartCol, fn.EndLine, fn.EndCol, fn.StartByte, fn.EndByte),
				}
				switch {
				case fn.IsEntrypoint():
					seen[fn.Selector] = true
					ec.EntryFunctions = append(ec.EntryFunctions, ef)
				case isGetter(fn):
					seen[fn.Selector] = true
					ec.Getters = append(ec.Getters, ef)
				}
			}
		}
		out.Contracts = append(out.Contracts, ec)
	}
	// Deterministic ordering (map iteration over db.MainContracts is unordered).
	sort.Slice(out.Contracts, func(i, j int) bool { return out.Contracts[i].ID < out.Contracts[j].ID })
	return out
}
