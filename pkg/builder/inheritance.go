package builder

import (
	"fmt"

	"github.com/th13vn/w3goaudit-engine/pkg/types"
)

// InheritanceBuilder builds the inheritance tree for contracts
type InheritanceBuilder struct {
	db *types.Database
	// inProgress tracks contracts currently being linearized so cyclic
	// inheritance (A is B; B is A) returns an error instead of recursing
	// until the Go stack overflows.
	inProgress map[string]bool
}

// NewInheritanceBuilder creates a new inheritance builder
func NewInheritanceBuilder(db *types.Database) *InheritanceBuilder {
	return &InheritanceBuilder{db: db, inProgress: make(map[string]bool)}
}

// Build constructs the inheritance tree for all contracts
func (ib *InheritanceBuilder) Build() error {
	for _, contract := range ib.db.Contracts {
		// Reset cycle tracking per top-level contract so independent contracts
		// don't poison each other.
		ib.inProgress = make(map[string]bool)
		// Perform C3 linearization
		linearized, err := ib.c3Linearize(contract.Name)
		if err != nil {
			// Fall back to "just this contract" so downstream phases don't crash.
			// Surface the reason via verbose so the user can see what failed.
			VerboseLog("C3 linearization failed for %s: %v (falling back to self-only)", contract.Name, err)
			linearized = []string{contract.Name}
		}
		contract.LinearizedBases = linearized

		// Calculate inheritance weight (depth of inheritance)
		contract.InheritanceWeight = len(linearized)
	}

	return nil
}

// c3Linearize performs C3 linearization (Method Resolution Order)
// This is the same algorithm used by Solidity for inheritance
// In Solidity's "is" clause, left-to-right is most base-like to most derived-like
// The result is stored in derived-to-base order (most derived first, most base last)
// This matches Python's MRO and is useful for method resolution (search from derived to base)
func (ib *InheritanceBuilder) c3Linearize(contractName string) ([]string, error) {
	if ib.inProgress[contractName] {
		return nil, fmt.Errorf("cyclic inheritance detected at %s", contractName)
	}
	ib.inProgress[contractName] = true
	defer delete(ib.inProgress, contractName)

	contract := ib.db.GetContractByName(contractName)
	if contract == nil {
		return nil, fmt.Errorf("contract not found: %s", contractName)
	}

	// Base case: no parents
	if len(contract.BaseContracts) == 0 {
		return []string{contractName}, nil
	}

	// Collect parent linearizations in REVERSE order (right-to-left)
	// Rightmost parent (most derived-like) first - this ensures each parent's
	// chain is fully drained before moving to the next parent
	parentLinearizations := make([][]string, 0)
	for i := len(contract.BaseContracts) - 1; i >= 0; i-- {
		baseName := contract.BaseContracts[i]
		parentLin, err := ib.c3LinearizeInternal(baseName)
		if err != nil {
			// Parent not found OR cyclic — skip and continue with the rest.
			VerboseLog("C3 parent linearization skipped (%s -> %s): %v", contractName, baseName, err)
			continue
		}
		parentLinearizations = append(parentLinearizations, parentLin)
	}

	// Add the list of direct parents in REVERSE order (right-to-left)
	// This is used for blocking: rightmost parent blocks leftmost
	reversedBases := make([]string, len(contract.BaseContracts))
	for i, base := range contract.BaseContracts {
		reversedBases[len(contract.BaseContracts)-1-i] = base
	}
	parentLinearizations = append(parentLinearizations, reversedBases)

	// Merge using C3 algorithm
	merged, err := ib.c3Merge(parentLinearizations)
	if err != nil {
		return nil, err
	}

	// Prepend current contract (most derived) at the start
	result := append([]string{contractName}, merged...)

	return result, nil
}

// c3LinearizeInternal computes C3 linearization in base-first order (for internal recursion)
func (ib *InheritanceBuilder) c3LinearizeInternal(contractName string) ([]string, error) {
	if ib.inProgress[contractName] {
		return nil, fmt.Errorf("cyclic inheritance detected at %s", contractName)
	}
	ib.inProgress[contractName] = true
	defer delete(ib.inProgress, contractName)

	contract := ib.db.GetContractByName(contractName)
	if contract == nil {
		return nil, fmt.Errorf("contract not found: %s", contractName)
	}

	// Base case: no parents
	if len(contract.BaseContracts) == 0 {
		return []string{contractName}, nil
	}

	// Collect parent linearizations in REVERSE order (right-to-left)
	parentLinearizations := make([][]string, 0)
	for i := len(contract.BaseContracts) - 1; i >= 0; i-- {
		baseName := contract.BaseContracts[i]
		parentLin, err := ib.c3LinearizeInternal(baseName)
		if err != nil {
			// Parent not found, skip
			continue
		}
		parentLinearizations = append(parentLinearizations, parentLin)
	}

	// Add the list of direct parents in REVERSE order (right-to-left)
	reversedBases := make([]string, len(contract.BaseContracts))
	for i, base := range contract.BaseContracts {
		reversedBases[len(contract.BaseContracts)-1-i] = base
	}
	parentLinearizations = append(parentLinearizations, reversedBases)

	// Merge using C3 algorithm
	merged, err := ib.c3Merge(parentLinearizations)
	if err != nil {
		return nil, err
	}

	// Prepend current contract (most derived) at the start
	// With right-to-left processing, merge already produces derived-first order
	result := append([]string{contractName}, merged...)
	return result, nil
}

// c3Merge merges multiple linearizations using C3 algorithm
// Lists are ordered: rightmost parent first (most derived-like), last list is direct parents
// Algorithm: Chain draining - pick from same list until blocked, then move to next
//
// TODO(stage-3): the chain-draining variant here picks heads in reverse list
// order; canonical C3 (Solidity, CPython) picks in forward order with strict
// "no candidate in any other list's tail" semantics. Output is correct on
// non-diamond inheritance but can diverge from solc on complex diamonds.
// Port the canonical algorithm once we have diamond-inheritance fixtures.
// Tracked in .vscode/2026-05-08-invariant-audit.md §1.4.
func (ib *InheritanceBuilder) c3Merge(lists [][]string) ([]string, error) {
	var result []string
	lastPickedListHead := "" // Track the head we picked from

	for {
		// Count non-empty lists
		nonEmptyCount := 0
		for _, list := range lists {
			if len(list) > 0 {
				nonEmptyCount++
			}
		}
		if nonEmptyCount == 0 {
			break
		}

		var head string
		found := false
		pickedFromListIdx := -1

		// CHAIN DRAINING: If we picked something before, try to continue from same list
		if lastPickedListHead != "" {
			for listIdx := 0; listIdx < len(lists); listIdx++ {
				if len(lists[listIdx]) == 0 {
					continue
				}
				// Check if this list's head was the one we picked before
				// (meaning this is the list we were draining)
				if len(lists[listIdx]) > 0 {
					candidate := lists[listIdx][0]
					if ib.isGoodHeadFromSpecificList(candidate, lists, listIdx) {
						// Continue picking from any unblocked list
						head = candidate
						found = true
						pickedFromListIdx = listIdx
						break
					}
				}
			}
		}

		// If chain draining didn't work or first iteration, do normal selection
		if !found {
			// Try parent linearizations in REVERSE (n-2 to 0), then direct parent list
			for listIdx := len(lists) - 2; listIdx >= 0; listIdx-- {
				if len(lists[listIdx]) == 0 {
					continue
				}
				candidate := lists[listIdx][0]
				if ib.isGoodHeadFromSpecificList(candidate, lists, listIdx) {
					head = candidate
					found = true
					pickedFromListIdx = listIdx
					break
				}
			}

			// Try direct parent list as fallback
			if !found {
				directParentIdx := len(lists) - 1
				if len(lists[directParentIdx]) > 0 {
					candidate := lists[directParentIdx][0]
					if ib.isGoodHeadFromSpecificList(candidate, lists, directParentIdx) {
						head = candidate
						found = true
						pickedFromListIdx = directParentIdx
					}
				}
			}
		}

		if !found {
			return result, nil
		}

		result = append(result, head)

		// Track what we picked for chain draining
		if pickedFromListIdx >= 0 && len(lists[pickedFromListIdx]) > 1 {
			// Next head after removing current
			lastPickedListHead = lists[pickedFromListIdx][1]
		} else {
			lastPickedListHead = ""
		}

		// Remove head from all lists
		for i := range lists {
			lists[i] = removeElement(lists[i], head)
		}
	}

	return result, nil
}

// isGoodHeadFromSpecificList checks if a candidate from a specific list can be picked
func (ib *InheritanceBuilder) isGoodHeadFromSpecificList(candidate string, lists [][]string, sourceIdx int) bool {
	for listIdx, list := range lists {
		if listIdx == sourceIdx {
			continue
		}
		// Check if candidate is in the TAIL of this list
		if len(list) > 1 {
			for _, item := range list[1:] {
				if item == candidate {
					return false
				}
			}
		}
	}
	return true
}



// removeElement removes an element from a slice
func removeElement(list []string, element string) []string {
	result := make([]string, 0, len(list))
	for _, item := range list {
		if item != element {
			result = append(result, item)
		}
	}
	return result
}

// GetInheritedFunctions returns all functions from base contracts
func (ib *InheritanceBuilder) GetInheritedFunctions(contractName string) []*types.Function {
	contract := ib.db.GetContractByName(contractName)
	if contract == nil {
		return nil
	}

	var functions []*types.Function
	seen := make(map[string]bool)

	// Traverse in order (most derived first, which is the MRO order)
	// Skip index 0 since that's the contract itself
	for i := 1; i < len(contract.LinearizedBases); i++ {
		baseName := contract.LinearizedBases[i]
		baseContract := ib.db.GetContractByName(baseName)
		if baseContract == nil {
			continue
		}

		for _, fn := range baseContract.Functions {
			signature := fn.GetSignature(nil)
			if signature != "" && !seen[signature] {
				seen[signature] = true
				functions = append(functions, fn)
			}
		}
	}

	return functions
}
