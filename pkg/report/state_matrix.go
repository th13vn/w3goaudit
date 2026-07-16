package report

import (
	"sort"
	"strings"

	"github.com/th13vn/w3goaudit/pkg/types"
)

// StateRow is one row of the state-change matrix: a state variable, the
// functions that write it directly, and the entry points that reach a writer.
type StateRow struct {
	Var       string
	TypeName  string
	DefinedIn string
	Writers   []string // "fn" or "Base.fn"
	Entries   []string // entry points (transitively) reaching a writer
}

// resolvedFn pairs a function with the contract (and file) it is defined in.
type resolvedFn struct {
	fn         *types.Function
	contract   string
	sourceFile string
}

func (r resolvedFn) selector() string {
	if r.fn.Selector != "" {
		return r.fn.Selector
	}
	return r.fn.Name
}

func (r resolvedFn) key() string {
	return types.MakeFunctionID(r.sourceFile, r.contract, r.selector())
}

func (r resolvedFn) label(main string) string {
	if r.contract != "" && r.contract != main {
		return r.contract + "." + r.fn.Name
	}
	return r.fn.Name
}

// stateMatrixBuilder resolves functions across a contract's linearized bases
// and answers reachability/write questions.
type stateMatrixBuilder struct {
	db         *types.Database
	main       *types.Contract
	bySelector map[string]resolvedFn
	byName     map[string]resolvedFn
	allByID    map[string]resolvedFn
}

func newStateMatrixBuilder(db *types.Database, main *types.Contract) *stateMatrixBuilder {
	b := &stateMatrixBuilder{
		db:         db,
		main:       main,
		bySelector: make(map[string]resolvedFn),
		byName:     make(map[string]resolvedFn),
		allByID:    make(map[string]resolvedFn),
	}
	mro := db.LinearizedContracts(main)
	// The exact MRO is derived-first; iterate in REVERSE so the most-derived
	// implementation wins on name/selector collisions (matches dispatch).
	for i := len(mro) - 1; i >= 0; i-- {
		bc := mro[i]
		for _, fn := range bc.Functions {
			rf := resolvedFn{fn: fn, contract: bc.Name, sourceFile: bc.SourceFile}
			b.allByID[rf.key()] = rf
			if fn.Selector != "" {
				b.bySelector[fn.Selector] = rf
			}
			if fn.Name != "" {
				b.byName[fn.Name] = rf
			}
		}
	}
	return b
}

// effects returns the recorded effects for a resolved function.
func (b *stateMatrixBuilder) effects(rf resolvedFn) *types.FunctionEffects {
	id := types.MakeFunctionID(rf.sourceFile, rf.contract, rf.selector())
	return b.db.Semantics.GetFunctionEffects(id)
}

// resolveCall maps a recorded call to a known function. Explicit super/library
// targets use their exact resolved contract ID; virtual internal/self calls use
// the most-derived selector map for the deployment hierarchy.
func (b *stateMatrixBuilder) resolveCall(call *types.FunctionCall) (resolvedFn, bool) {
	if call == nil {
		return resolvedFn{}, false
	}
	target := call.ResolvedFunction
	if target == "" {
		target = call.Target
	}
	if call.CallType == types.CallTypeSuper || call.CallType == types.CallTypeLibrary {
		if rf, ok := b.resolveExactTarget(call, target); ok {
			return rf, true
		}
	}
	if rf, ok := b.bySelector[target]; ok {
		return rf, true
	}
	name := target
	if i := strings.IndexByte(name, '('); i >= 0 {
		name = name[:i]
	}
	if rf, ok := b.byName[name]; ok {
		return rf, true
	}
	return b.resolveExactTarget(call, target)
}

func (b *stateMatrixBuilder) resolveExactTarget(call *types.FunctionCall, target string) (resolvedFn, bool) {
	if call == nil || call.ResolvedContractID == "" {
		return resolvedFn{}, false
	}
	contract := b.db.GetContractByID(call.ResolvedContractID)
	if contract == nil {
		return resolvedFn{}, false
	}
	name := target
	if i := strings.IndexByte(name, '('); i >= 0 {
		name = name[:i]
	}
	for _, fn := range contract.Functions {
		if target != "" && strings.Contains(target, "(") && fn.Selector != target {
			continue
		}
		if !strings.Contains(target, "(") && fn.Name != name {
			continue
		}
		if call.ArgCount >= 0 && !strings.Contains(target, "(") && len(fn.Parameters) != call.ArgCount {
			continue
		}
		rf := resolvedFn{fn: fn, contract: contract.Name, sourceFile: contract.SourceFile}
		return rf, true
	}
	return resolvedFn{}, false
}

// resolveEntry finds a resolved function by selector (preferred) or name.
func (b *stateMatrixBuilder) resolveEntry(selector, name string) (resolvedFn, bool) {
	if selector != "" {
		if rf, ok := b.bySelector[selector]; ok {
			return rf, true
		}
	}
	if rf, ok := b.byName[name]; ok {
		return rf, true
	}
	return resolvedFn{}, false
}

// reachable returns every function reachable from entry via intra-contract calls
// (internal/self/inherited/super/library/modifier), including entry itself.
func (b *stateMatrixBuilder) reachable(entry resolvedFn) []resolvedFn {
	visited := make(map[string]bool)
	var out []resolvedFn
	var visit func(rf resolvedFn)
	visit = func(rf resolvedFn) {
		if visited[rf.key()] {
			return
		}
		visited[rf.key()] = true
		out = append(out, rf)
		for _, call := range rf.fn.Calls {
			if !isIntraContractCall(call.CallType) {
				continue
			}
			if next, ok := b.resolveCall(call); ok {
				visit(next)
			}
		}
	}
	visit(entry)
	return out
}

func isIntraContractCall(ct types.CallType) bool {
	switch ct {
	case types.CallTypeInternal, types.CallTypeSelf, types.CallTypeInherited,
		types.CallTypeSuper, types.CallTypeLibrary, types.CallTypeModifier:
		return true
	}
	return false
}

// entryFns returns the contract's entry-point functions, resolved.
func (b *stateMatrixBuilder) entryFns() []resolvedFn {
	var out []resolvedFn
	seen := make(map[string]bool)
	// Derived-first, first selector wins: inherited overrides stay attached to
	// the exact contract that supplies the runtime implementation.
	for _, bc := range b.db.LinearizedContracts(b.main) {
		for _, fn := range bc.Functions {
			if !fn.IsEntrypoint() {
				continue
			}
			rf := resolvedFn{fn: fn, contract: bc.Name, sourceFile: bc.SourceFile}
			key := fn.Selector
			if key == "" {
				key = fn.Name
			}
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, rf)
		}
	}
	return out
}

// transitiveWrites returns the set of state variables an entry writes directly
// or via any reachable function.
func (b *stateMatrixBuilder) transitiveWrites(entry resolvedFn) map[string]bool {
	writes := make(map[string]bool)
	for _, rf := range b.reachable(entry) {
		if fe := b.effects(rf); fe != nil {
			for _, w := range fe.StateWrites {
				writes[w.Var] = true
			}
		}
	}
	return writes
}

// BuildStateMatrix computes the per-contract state-change matrix.
func BuildStateMatrix(db *types.Database, main *types.Contract, states []*StateSummary) []StateRow {
	if db == nil || main == nil || db.Semantics == nil {
		return nil
	}
	b := newStateMatrixBuilder(db, main)

	// Direct writers per state var.
	writers := make(map[string][]string)
	writerSeen := make(map[string]bool)
	for _, rf := range allResolved(b) {
		fe := b.effects(rf)
		if fe == nil {
			continue
		}
		for _, w := range fe.StateWrites {
			k := w.Var + "|" + rf.label(main.Name)
			if writerSeen[k] {
				continue
			}
			writerSeen[k] = true
			writers[w.Var] = append(writers[w.Var], rf.label(main.Name))
		}
	}

	// Entry points reaching each state var (transitive).
	entryReach := make(map[string][]string)
	for _, e := range b.entryFns() {
		label := e.label(main.Name)
		for v := range b.transitiveWrites(e) {
			entryReach[v] = append(entryReach[v], label)
		}
	}

	rows := make([]StateRow, 0, len(states))
	for _, sv := range states {
		w := writers[sv.Name]
		en := entryReach[sv.Name]
		sort.Strings(w)
		sort.Strings(en)
		rows = append(rows, StateRow{
			Var:       sv.Name,
			TypeName:  sv.TypeName,
			DefinedIn: sv.DefinedIn,
			Writers:   w,
			Entries:   en,
		})
	}
	return rows
}

// allResolved returns the deduped set of functions across the hierarchy.
func allResolved(b *stateMatrixBuilder) []resolvedFn {
	keys := make([]string, 0, len(b.allByID))
	for key := range b.allByID {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]resolvedFn, 0, len(keys))
	for _, key := range keys {
		out = append(out, b.allByID[key])
	}
	return out
}
