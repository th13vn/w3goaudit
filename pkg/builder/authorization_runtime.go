package builder

import (
	"encoding/json"
	"sort"

	"github.com/th13vn/w3goaudit/pkg/types"
)

func resolveAuthorizationRuntime(fn *types.Function, declared *types.Contract, db *types.Database) (runtime *types.Contract, selected *types.Function, ambiguous bool) {
	if fn == nil || declared == nil || db == nil {
		return declared, fn, false
	}
	candidates := authorizationRuntimeCandidates(declared, db)
	switch len(candidates) {
	case 0:
		return declared, fn, false
	case 1:
		runtime = candidates[0]
	default:
		return nil, nil, true
	}
	return runtime, selectRuntimeFunction(fn, runtime, db), false
}

// authorizationRuntimeCandidates returns, sorted by ID, every main contract
// whose linearized hierarchy contains the declaring contract.
func authorizationRuntimeCandidates(declared *types.Contract, db *types.Database) []*types.Contract {
	ids := make([]string, 0, len(db.MainContracts))
	for id := range db.MainContracts {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	var candidates []*types.Contract
	for _, id := range ids {
		main := db.GetContractByID(id)
		if hierarchyContainsContract(db, main, declared.ID) {
			candidates = append(candidates, main)
		}
	}
	return candidates
}

// agreedAuthorizationAcrossRuntimes analyzes a function shared by several
// main contracts once per runtime. When every runtime reaches the same result
// through the same selected implementation and the same evidence, that result
// holds whichever contract the function runs in, so it is returned. Any
// disagreement returns ok=false and the fact stays fail-closed.
func agreedAuthorizationAcrossRuntimes(fn *types.Function, declared *types.Contract, db *types.Database) (authorizationResult, *types.Function, bool) {
	var agreed authorizationResult
	var agreedSelected *types.Function
	signature := ""
	for i, runtime := range authorizationRuntimeCandidates(declared, db) {
		selected := selectRuntimeFunction(fn, runtime, db)
		result := analyzeAuthorizationTarget(selected, runtime, db, make(map[string]bool))
		current := authorizationResultSignature(result, selected)
		if i == 0 {
			agreed, agreedSelected, signature = result, selected, current
			continue
		}
		if current != signature {
			return authorizationResult{}, nil, false
		}
	}
	return agreed, agreedSelected, agreedSelected != nil
}

func authorizationResultSignature(result authorizationResult, selected *types.Function) string {
	encoded, err := json.Marshal(struct {
		Verdict     types.AuthorizationVerdict
		Selected    string
		Chosen      string
		Evidence    []types.AuthorizationEvidence
		Reasons     []string
		Limitations []string
	}{result.verdict, authorizationFunctionID(selected, nil), result.selectedFunctionID, result.evidence, result.reasons, result.limitations})
	if err != nil {
		return ""
	}
	return string(encoded)
}

func hierarchyContainsContract(db *types.Database, runtime *types.Contract, contractID string) bool {
	if db == nil || runtime == nil || contractID == "" {
		return false
	}
	for _, candidate := range db.LinearizedContracts(runtime) {
		if candidate != nil && candidate.ID == contractID {
			return true
		}
	}
	return false
}

func selectRuntimeFunction(fn *types.Function, runtime *types.Contract, db *types.Database) *types.Function {
	if fn == nil || runtime == nil || db == nil || fn.Selector == "" {
		return fn
	}
	for _, contract := range db.LinearizedContracts(runtime) {
		for _, candidate := range contract.Functions {
			if candidate != nil && candidate.Selector == fn.Selector {
				return candidate
			}
		}
	}
	return fn
}

func resolveAuthorizationCallee(call *types.FunctionCall, runtime *types.Contract, db *types.Database) (*types.Function, string) {
	if call == nil || db == nil || !call.Resolved || call.ResolvedContractID == "" || call.ResolvedFunction == "" {
		return nil, ""
	}
	owner := db.GetContractByID(call.ResolvedContractID)
	if owner == nil {
		return nil, ""
	}
	var resolved *types.Function
	for _, candidate := range owner.Functions {
		if candidate == nil {
			continue
		}
		if candidate.Selector == call.ResolvedFunction || (candidate.Selector == "" && candidate.Name == call.ResolvedFunction) {
			resolved = candidate
			break
		}
	}
	if resolved == nil {
		return nil, ""
	}
	if call.CallType == types.CallTypeSuper {
		return resolved, "super"
	}
	selected := selectRuntimeFunction(resolved, runtime, db)
	if selected != resolved {
		return selected, "virtual_override"
	}
	if runtime != nil && resolved.ContractName != runtime.Name {
		return resolved, "inherited"
	}
	return resolved, "helper"
}
