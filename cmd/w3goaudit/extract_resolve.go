package main

import (
	"fmt"
	"sort"
	"strings"

	"github.com/th13vn/w3goaudit/pkg/types"
)

type contractCandidate struct {
	id       string
	contract *types.Contract
}

type functionCandidate struct {
	id       string
	contract *types.Contract
	function *types.Function
}

func resolveContractQuery(db *types.Database, query string) (*types.Contract, error) {
	if db == nil {
		return nil, fmt.Errorf("contract %q not found: database is nil", query)
	}
	if contract := db.GetContractByID(query); contract != nil {
		return contract, nil
	}

	candidates := make([]contractCandidate, 0)
	for id, contract := range db.Contracts {
		if contract != nil && strings.EqualFold(contract.Name, query) {
			candidates = append(candidates, contractCandidate{id: id, contract: contract})
		}
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].id < candidates[j].id })

	switch len(candidates) {
	case 0:
		return nil, fmt.Errorf("contract %q not found in database", query)
	case 1:
		return candidates[0].contract, nil
	default:
		ids := make([]string, len(candidates))
		for i := range candidates {
			ids[i] = candidates[i].id
		}
		return nil, fmt.Errorf("ambiguous contract %q; use an exact file#Contract ID:\n  %s", query, strings.Join(ids, "\n  "))
	}
}

func resolveFunctionQuery(db *types.Database, query, contractFilter string) (*types.Function, *types.Contract, error) {
	if db == nil {
		return nil, nil, fmt.Errorf("function %q not found: database is nil", query)
	}
	if strings.Contains(query, "#") {
		fn, contract := resolveFunctionID(db, query)
		if fn == nil {
			return nil, nil, fmt.Errorf("function ID %q not found in database", query)
		}
		if contractFilter != "" {
			filtered, err := resolveContractQuery(db, contractFilter)
			if err != nil {
				return nil, nil, err
			}
			if filtered.ID != contract.ID {
				return nil, nil, fmt.Errorf("function %q is not defined in contract %q", query, contractFilter)
			}
		}
		return fn, contract, nil
	}

	functionQuery := query
	var contract *types.Contract
	if contractFilter != "" {
		resolved, err := resolveContractQuery(db, contractFilter)
		if err != nil {
			return nil, nil, err
		}
		contract = resolved
	}
	if qualifier, remainder, ok := splitQualifiedFunctionQuery(query); ok {
		qualifiedContract := contract
		if qualifiedContract == nil || !strings.EqualFold(qualifiedContract.Name, qualifier) {
			resolved, err := resolveContractQuery(db, qualifier)
			if err != nil {
				return nil, nil, err
			}
			qualifiedContract = resolved
		}
		if contract != nil && contract.ID != qualifiedContract.ID {
			return nil, nil, fmt.Errorf("function qualifier %q does not match contract filter %q", qualifier, contractFilter)
		}
		contract = qualifiedContract
		functionQuery = remainder
	}

	candidates := make([]functionCandidate, 0)
	for _, candidateContract := range db.Contracts {
		if candidateContract == nil || (contract != nil && candidateContract.ID != contract.ID) {
			continue
		}
		for _, fn := range candidateContract.Functions {
			if fn == nil || !functionMatchesQuery(fn, functionQuery) {
				continue
			}
			candidates = append(candidates, functionCandidate{
				id:       exactFunctionID(candidateContract, fn),
				contract: candidateContract,
				function: fn,
			})
		}
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].id < candidates[j].id })

	switch len(candidates) {
	case 0:
		if contract != nil {
			return nil, nil, fmt.Errorf("function %q not found in contract %q", functionQuery, contract.ID)
		}
		return nil, nil, fmt.Errorf("function %q not found in any contract", functionQuery)
	case 1:
		return candidates[0].function, candidates[0].contract, nil
	default:
		ids := make([]string, len(candidates))
		for i := range candidates {
			ids[i] = candidates[i].id
		}
		return nil, nil, fmt.Errorf("ambiguous function %q; use an exact function ID or --contract file#Contract:\n  %s", query, strings.Join(ids, "\n  "))
	}
}

func exactFunctionID(contract *types.Contract, fn *types.Function) string {
	key := fn.Selector
	if key == "" {
		key = fn.Name
	}
	return types.MakeFunctionID(contract.SourceFile, contract.Name, key)
}

// linearizedContractsBaseFirst returns the selected contract's exact C3 chain
// in storage-layout order. Using Database.LinearizedContracts is essential:
// resolving the display-only LinearizedBases names with GetContractByName can
// cross-wire an exact extract query to an unrelated same-named base contract.
func linearizedContractsBaseFirst(db *types.Database, contract *types.Contract) []*types.Contract {
	if db == nil || contract == nil {
		return nil
	}
	derivedFirst := db.LinearizedContracts(contract)
	baseFirst := make([]*types.Contract, 0, len(derivedFirst))
	for i := len(derivedFirst) - 1; i >= 0; i-- {
		baseFirst = append(baseFirst, derivedFirst[i])
	}
	return baseFirst
}

// linearizedContractAt returns the exact object corresponding to one
// display-name MRO entry. LinearizedBases may retain unresolved names while
// LinearizedBaseIDs is compact, so the slices must never be zipped by index.
func linearizedContractAt(db *types.Database, contract *types.Contract, index int) *types.Contract {
	if db == nil || contract == nil || index < 0 || index >= len(contract.LinearizedBases) {
		return nil
	}
	if index == 0 && contract.LinearizedBases[index] == contract.Name {
		return contract
	}
	displayName := contract.LinearizedBases[index]
	var match *types.Contract
	for _, candidate := range db.LinearizedContracts(contract) {
		if candidate == nil || candidate.Name != displayName {
			continue
		}
		if match != nil && match.ID != candidate.ID {
			return nil
		}
		match = candidate
	}
	return match
}

func resolveFunctionID(db *types.Database, id string) (*types.Function, *types.Contract) {
	filePath, contractName, selector := types.ParseFunctionID(id)
	if contractName == "" || selector == "" {
		return nil, nil
	}
	contract := db.GetContractByID(types.MakeContractID(filePath, contractName))
	if contract == nil {
		return nil, nil
	}
	for _, fn := range contract.Functions {
		if fn != nil && functionMatchesQuery(fn, selector) {
			return fn, contract
		}
	}
	return nil, nil
}

func functionMatchesQuery(fn *types.Function, query string) bool {
	return fn.Name == query || fn.Selector == query || fn.Signature == query
}

func splitQualifiedFunctionQuery(query string) (contract, function string, ok bool) {
	limit := len(query)
	if paren := strings.IndexByte(query, '('); paren >= 0 {
		limit = paren
	}
	dot := strings.LastIndex(query[:limit], ".")
	if dot <= 0 || dot == len(query)-1 {
		return "", query, false
	}
	return query[:dot], query[dot+1:], true
}
