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
	owner      *types.Contract
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

type reportCallTarget struct {
	contract *types.Contract
	fn       *types.Function
}

func (target reportCallTarget) selector() string {
	if target.fn == nil {
		return ""
	}
	if target.fn.Selector != "" {
		return target.fn.Selector
	}
	return target.fn.Name
}

func (target reportCallTarget) key() string {
	if target.contract == nil {
		return ""
	}
	return types.MakeFunctionID(target.contract.SourceFile, target.contract.Name, target.selector())
}

// resolveReportCall is the single exact call-target resolver used by report
// call graphs, state matrices, and workflow reachability. Exact recorded
// contract IDs constrain the lookup immediately. Legacy metadata may search
// only source-exact runtime MRO objects and succeeds only when one distinct
// selector remains after applying the known arity.
func resolveReportCall(db *types.Database, runtime, caller *types.Contract, call *types.FunctionCall) (reportCallTarget, bool) {
	if db == nil || call == nil {
		return reportCallTarget{}, false
	}
	target := call.ResolvedFunction
	if target == "" {
		target = call.Target
	}
	if target == "" {
		return reportCallTarget{}, false
	}

	contracts, ok := reportCallContracts(db, runtime, caller, call)
	if !ok {
		return reportCallTarget{}, false
	}
	return resolveReportFunction(contracts, target, call.ArgCount)
}

func reportCallContracts(db *types.Database, runtime, caller *types.Contract, call *types.FunctionCall) ([]*types.Contract, bool) {
	if call.ResolvedContractID != "" {
		exact := db.GetContractByID(call.ResolvedContractID)
		if exact == nil {
			return nil, false
		}
		return []*types.Contract{exact}, true
	}
	if reportCallUsesRuntimeMRO(call.CallType) {
		contracts := db.LinearizedContracts(runtime)
		if len(contracts) == 0 && caller != nil {
			contracts = []*types.Contract{caller}
		}
		if call.CallType == types.CallTypeSuper && caller != nil {
			for i, contract := range contracts {
				if contract != nil && contract.ID == caller.ID {
					contracts = contracts[i+1:]
					break
				}
			}
		}
		return contracts, len(contracts) > 0
	}
	if call.ResolvedContract != "" {
		fromFile := ""
		if caller != nil {
			fromFile = caller.SourceFile
		}
		exact, status := db.ResolveContractNameExactWithStatus(call.ResolvedContract, fromFile)
		if status != types.ExactResolutionResolved || exact == nil {
			return nil, false
		}
		return []*types.Contract{exact}, true
	}
	return nil, false
}

func reportCallUsesRuntimeMRO(callType types.CallType) bool {
	switch callType {
	case types.CallTypeInternal, types.CallTypeInherited, types.CallTypeSelf,
		types.CallTypeSuper, types.CallTypeModifier:
		return true
	default:
		return false
	}
}

func resolveReportFunction(contracts []*types.Contract, target string, argCount int) (reportCallTarget, bool) {
	if target == "" {
		return reportCallTarget{}, false
	}
	fullSelector := strings.Contains(target, "(")
	name := target
	if i := strings.IndexByte(name, '('); i >= 0 {
		name = name[:i]
	}
	bySelector := make(map[string]reportCallTarget)
	order := make([]string, 0)
	for _, contract := range contracts {
		if contract == nil {
			continue
		}
		for _, fn := range contract.Functions {
			if fn == nil {
				continue
			}
			if fullSelector {
				if fn.Selector != target {
					continue
				}
			} else if fn.Name != name {
				continue
			}
			if argCount >= 0 && len(fn.Parameters) != argCount {
				continue
			}
			selector := fn.Selector
			if selector == "" {
				selector = fn.Name
			}
			if _, exists := bySelector[selector]; exists {
				continue
			}
			bySelector[selector] = reportCallTarget{contract: contract, fn: fn}
			order = append(order, selector)
		}
	}
	if len(order) != 1 {
		return reportCallTarget{}, false
	}
	return bySelector[order[0]], true
}

// stateMatrixBuilder resolves functions across a contract's linearized bases
// and answers reachability/write questions.
type stateMatrixBuilder struct {
	db      *types.Database
	main    *types.Contract
	allByID map[string]resolvedFn
}

func newStateMatrixBuilder(db *types.Database, main *types.Contract) *stateMatrixBuilder {
	b := &stateMatrixBuilder{
		db:      db,
		main:    main,
		allByID: make(map[string]resolvedFn),
	}
	mro := db.LinearizedContracts(main)
	// The exact MRO is derived-first; iterate in REVERSE so the most-derived
	// implementation wins on name/selector collisions (matches dispatch).
	for i := len(mro) - 1; i >= 0; i-- {
		bc := mro[i]
		for _, fn := range bc.Functions {
			rf := resolvedFn{fn: fn, contract: bc.Name, sourceFile: bc.SourceFile, owner: bc}
			b.allByID[rf.key()] = rf
		}
	}
	return b
}

// effects returns the recorded effects for a resolved function.
func (b *stateMatrixBuilder) effects(rf resolvedFn) *types.FunctionEffects {
	id := types.MakeFunctionID(rf.sourceFile, rf.contract, rf.selector())
	return b.db.Semantics.GetFunctionEffects(id)
}

// resolveCall maps a recorded call through the package-wide exact report
// resolver, using the current function owner as source context and main as the
// runtime MRO.
func (b *stateMatrixBuilder) resolveCall(caller resolvedFn, call *types.FunctionCall) (resolvedFn, bool) {
	target, ok := resolveReportCall(b.db, b.main, caller.owner, call)
	if !ok {
		return resolvedFn{}, false
	}
	return resolvedFn{
		fn:         target.fn,
		contract:   target.contract.Name,
		sourceFile: target.contract.SourceFile,
		owner:      target.contract,
	}, true
}

// resolveEntry finds a resolved function by selector (preferred) or name.
func (b *stateMatrixBuilder) resolveEntry(selector, name string) (resolvedFn, bool) {
	target := selector
	if target == "" {
		target = name
	}
	resolved, ok := resolveReportFunction(b.db.LinearizedContracts(b.main), target, -1)
	if !ok {
		return resolvedFn{}, false
	}
	return resolvedFn{
		fn:         resolved.fn,
		contract:   resolved.contract.Name,
		sourceFile: resolved.contract.SourceFile,
		owner:      resolved.contract,
	}, true
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
			if next, ok := b.resolveCall(rf, call); ok {
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
			rf := resolvedFn{fn: fn, contract: bc.Name, sourceFile: bc.SourceFile, owner: bc}
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
