package report

import (
	"sort"

	"github.com/th13vn/w3goaudit/pkg/types"
)

// XrefJSON is the precise, type-resolved cross-reference index consumed by the
// editor extension for go-to-definition and find-references without regex.
//
// It is purely additive to the schema-2.0.0 data layer: two flat, deterministic
// tables. `declarations[]` are jump targets (each keyed by its canonical id),
// and `references[]` are occurrences that carry the declaration id they resolve
// to. Go-to-definition maps a cursor to the covering reference, then to the
// declaration by id; find-references groups references by id.
type XrefJSON struct {
	SchemaVersion string      `json:"schemaVersion"`
	Declarations  []*XrefDecl `json:"declarations"`
	References    []*XrefRef  `json:"references,omitempty"`
}

// XrefDecl is a navigable declaration (jump target). Range is the NAME token
// span where available, otherwise the declaration span.
type XrefDecl struct {
	ID    string   `json:"id"`
	Kind  string   `json:"kind"`
	Name  string   `json:"name"`
	Range SrcRange `json:"range"`
}

// XrefRef is a resolved occurrence: the source span plus the declaration id it
// binds to. File is carried on the entry; Range omits its own file to stay
// compact (the reference file is authoritative).
type XrefRef struct {
	File    string   `json:"file"`
	Range   SrcRange `json:"range"`
	RefID   string   `json:"refId"`
	RefKind string   `json:"refKind,omitempty"`
}

// BuildXrefJSON produces the cross-reference index from the database. All
// emitted slices are sorted with total-order tiebreakers so the artifact is
// byte-stable across runs (map iteration over db.Contracts is unordered).
func BuildXrefJSON(db *types.Database) *XrefJSON {
	out := &XrefJSON{SchemaVersion: SchemaVersion, Declarations: []*XrefDecl{}}
	if db == nil {
		return out
	}

	seen := make(map[string]bool)
	addDecl := func(id, kind, name string, r SrcRange) {
		if id == "" || seen[id] {
			return
		}
		seen[id] = true
		out.Declarations = append(out.Declarations, &XrefDecl{ID: id, Kind: kind, Name: name, Range: r})
	}

	// Deterministic contract iteration so first-wins dedup is stable.
	contractIDs := make([]string, 0, len(db.Contracts))
	for id := range db.Contracts {
		contractIDs = append(contractIDs, id)
	}
	sort.Strings(contractIDs)

	for _, cid := range contractIDs {
		c := db.Contracts[cid]
		if c == nil {
			continue
		}
		file := c.SourceFile
		addDecl(c.ID, contractKindLabel(c.Kind), c.Name,
			declRange(file, c.StartLine, c.StartCol, c.EndLine, c.EndCol, c.StartByte, c.EndByte))

		for _, fn := range c.Functions {
			if fn == nil {
				continue
			}
			fnID := functionDeclID(c, fn)
			addDecl(fnID, "function", fn.Name,
				declRange(file, fn.StartLine, fn.StartCol, fn.EndLine, fn.EndCol, fn.StartByte, fn.EndByte))
			for _, p := range fn.Parameters {
				if p == nil || p.Name == "" {
					continue
				}
				addDecl(fnID+"."+p.Name, "parameter", p.Name,
					declRange(file, p.StartLine, p.StartCol, p.EndLine, p.EndCol, p.StartByte, p.EndByte))
			}
		}
		for _, sv := range c.StateVariables {
			if sv == nil {
				continue
			}
			addDecl(c.ID+"."+sv.Name, "stateVar", sv.Name,
				declRange(file, sv.StartLine, sv.StartCol, sv.EndLine, sv.EndCol, sv.StartByte, sv.EndByte))
		}
		for _, ev := range c.Events {
			if ev == nil {
				continue
			}
			addDecl(c.ID+"."+ev.Name, "event", ev.Name,
				declRange(file, ev.StartLine, ev.StartCol, ev.EndLine, ev.EndCol, ev.StartByte, ev.EndByte))
		}
		for _, er := range c.Errors {
			if er == nil {
				continue
			}
			addDecl(c.ID+"."+er.Name, "error", er.Name,
				declRange(file, er.StartLine, er.StartCol, er.EndLine, er.EndCol, er.StartByte, er.EndByte))
		}
		for _, st := range c.Structs {
			if st == nil {
				continue
			}
			addDecl(c.ID+"."+st.Name, "struct", st.Name,
				declRange(file, st.StartLine, st.StartCol, st.EndLine, st.EndCol, st.StartByte, st.EndByte))
		}
		for _, en := range c.Enums {
			if en == nil {
				continue
			}
			addDecl(c.ID+"."+en.Name, "enum", en.Name,
				declRange(file, en.StartLine, en.StartCol, en.EndLine, en.EndCol, en.StartByte, en.EndByte))
		}
		for _, md := range c.Modifiers {
			if md == nil {
				continue
			}
			addDecl(c.ID+"."+md.Name, "modifier", md.Name,
				declRange(file, md.StartLine, md.StartCol, md.EndLine, md.EndCol, md.StartByte, md.EndByte))
		}

		// References + local-variable declarations, from every function and
		// modifier AST that hangs off this contract.
		for _, fn := range c.Functions {
			if fn == nil || fn.AST == nil {
				continue
			}
			collectXrefFromAST(fn.AST, refFile(file, fn.SourceFile), addDecl, &out.References)
		}
		for _, md := range c.Modifiers {
			if md == nil || md.AST == nil {
				continue
			}
			collectXrefFromAST(md.AST, file, addDecl, &out.References)
		}
	}

	sortXrefDecls(out.Declarations)
	sortXrefRefs(out.References)
	return out
}

// collectXrefFromAST walks an AST recording every resolved occurrence as a
// reference and every located local-variable declaration as a declaration.
func collectXrefFromAST(root *types.ASTNode, file string, addDecl func(id, kind, name string, r SrcRange), refs *[]*XrefRef) {
	if root == nil {
		return
	}
	visit := func(n *types.ASTNode) {
		if n == nil || n.StartLine == 0 {
			return // synthetic node with no source counterpart
		}
		r := nodeRange(n)
		// A local-variable declaration with a resolved id is a jump target.
		if n.Kind == types.KindDeclVariable && n.RefID != "" {
			addDecl(n.RefID, "local", n.Name, declRange(file, n.StartLine, n.StartCol, n.EndLine, n.EndCol, n.StartByte, n.EndByte))
		}
		if n.RefID != "" {
			*refs = append(*refs, &XrefRef{File: file, Range: r, RefID: n.RefID, RefKind: n.RefKind})
		}
	}
	visit(root)
	root.WalkDescendants(func(n *types.ASTNode) bool {
		visit(n)
		return true
	})
}

// functionDeclID mirrors nav.go: key selector-less functions
// (fallback/receive/constructor) on the function name so they don't collapse.
func functionDeclID(c *types.Contract, fn *types.Function) string {
	idSel := fn.Selector
	if idSel == "" {
		idSel = fn.Name
	}
	return types.MakeFunctionID(c.SourceFile, c.Name, idSel)
}

// refFile prefers the function's own SourceFile, falling back to the contract's.
func refFile(contractFile, fnFile string) string {
	if fnFile != "" {
		return fnFile
	}
	return contractFile
}

// nodeRange builds a SrcRange for a reference occurrence. The file is carried on
// the XrefRef entry, so the range itself omits it.
func nodeRange(n *types.ASTNode) SrcRange {
	return SrcRange{
		StartLine: n.StartLine, StartCol: n.StartCol,
		EndLine: n.EndLine, EndCol: n.EndCol,
		StartByte: n.StartByte, EndByte: n.EndByte,
	}
}

// contractKindLabel maps a ContractKind to an xref declaration kind. Abstract
// contracts are surfaced as "contract" (the extension treats them alike).
func contractKindLabel(k types.ContractKind) string {
	switch k {
	case types.ContractKindInterface:
		return "interface"
	case types.ContractKindLibrary:
		return "library"
	default:
		return "contract"
	}
}

func sortXrefDecls(decls []*XrefDecl) {
	sort.Slice(decls, func(i, j int) bool {
		if decls[i].ID != decls[j].ID {
			return decls[i].ID < decls[j].ID
		}
		if decls[i].Kind != decls[j].Kind {
			return decls[i].Kind < decls[j].Kind
		}
		if decls[i].Name != decls[j].Name {
			return decls[i].Name < decls[j].Name
		}
		return decls[i].Range.StartLine < decls[j].Range.StartLine
	})
}

func sortXrefRefs(refs []*XrefRef) {
	sort.Slice(refs, func(i, j int) bool {
		if refs[i].File != refs[j].File {
			return refs[i].File < refs[j].File
		}
		if refs[i].Range.StartLine != refs[j].Range.StartLine {
			return refs[i].Range.StartLine < refs[j].Range.StartLine
		}
		if refs[i].Range.StartCol != refs[j].Range.StartCol {
			return refs[i].Range.StartCol < refs[j].Range.StartCol
		}
		if refs[i].Range.StartByte != refs[j].Range.StartByte {
			return refs[i].Range.StartByte < refs[j].Range.StartByte
		}
		return refs[i].RefID < refs[j].RefID
	})
}
