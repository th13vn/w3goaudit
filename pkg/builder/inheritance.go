package builder

import (
	"fmt"

	"github.com/th13vn/w3goaudit/pkg/types"
)

// InheritanceBuilder builds the inheritance tree for contracts
type InheritanceBuilder struct {
	db *types.Database
	// inProgress tracks contracts currently being linearized so cyclic
	// inheritance (A is B; B is A) returns an error instead of recursing
	// until the Go stack overflows.
	inProgress map[string]bool
	// memo caches each contract's completed C3 linearization, keyed by contract
	// ID. A contract's MRO is context-independent, so this is shared across all
	// top-level contracts and avoids the previous superlinear re-computation of
	// shared ancestors on deep (OpenZeppelin-style) hierarchies.
	memo map[string][]string
}

// NewInheritanceBuilder creates a new inheritance builder
func NewInheritanceBuilder(db *types.Database) *InheritanceBuilder {
	return &InheritanceBuilder{
		db:         db,
		inProgress: make(map[string]bool),
		memo:       make(map[string][]string),
	}
}

// Build constructs the inheritance tree for all contracts
func (ib *InheritanceBuilder) Build() error {
	for _, contract := range ib.db.Contracts {
		// Reset cycle tracking per top-level contract so independent contracts
		// don't poison each other.
		ib.inProgress = make(map[string]bool)
		// Perform C3 linearization
		linearized, err := ib.c3Linearize(contract)
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

// c3Linearize performs canonical C3 linearization (Solidity's Method Resolution
// Order), the same algorithm used by Solidity and CPython.
//
// Solidity reads the `is` base list left-to-right but treats the LAST-listed
// base as the most derived. Equivalently, C3 is computed over the direct base
// list in reverse:
//
//	L[C] = C + merge( L[B_n], …, L[B_1], [B_n, …, B_1] )
//
// where B_1..B_n are the bases in written order. The `merge` step uses the
// canonical forward-order rule (select the first head that appears in no other
// list's tail), so the result is provably the same MRO solc computes — not a
// heuristic that can diverge on deep diamonds.
//
// The output is derived-first (most derived contract at index 0, most-base
// last), which is both the method-resolution scan order and an easy-to-read
// display order.
//
// It operates on the resolved *Contract (not just a name) and resolves each base
// name relative to that contract's source file via db.ResolveContractName, so a
// duplicate contract name (e.g. a real `Token` and a mock `Token`) resolves to
// the right base instead of an arbitrary global pick. Cycle tracking is keyed by
// contract ID so two same-named contracts are linearized independently.
func (ib *InheritanceBuilder) c3Linearize(contract *types.Contract) ([]string, error) {
	if contract == nil {
		return nil, fmt.Errorf("nil contract")
	}
	if cached, ok := ib.memo[contract.ID]; ok {
		return append([]string(nil), cached...), nil // copy so callers can't mutate the cache
	}
	if ib.inProgress[contract.ID] {
		return nil, fmt.Errorf("cyclic inheritance detected at %s", contract.Name)
	}
	ib.inProgress[contract.ID] = true
	defer delete(ib.inProgress, contract.ID)

	// Base case: no parents.
	if len(contract.BaseContracts) == 0 {
		result := []string{contract.Name}
		ib.memo[contract.ID] = append([]string(nil), result...)
		return result, nil
	}

	// Reverse the direct base list: Solidity's most-derived base is the one
	// written last, so C3 is computed right-to-left.
	revBases := make([]string, len(contract.BaseContracts))
	for i, base := range contract.BaseContracts {
		revBases[len(contract.BaseContracts)-1-i] = base
	}

	// Build the merge input: each reversed parent's full linearization, followed
	// by the reversed direct-base list itself (which enforces local precedence).
	lists := make([][]string, 0, len(revBases)+1)
	degraded := false
	for _, baseName := range revBases {
		base := ib.db.ResolveContractName(baseName, contract.SourceFile)
		if base == nil {
			// Unknown base (e.g. an interface from an unresolved import): keep its
			// name in the direct-base list below, but we cannot recurse into it.
			VerboseLog("C3 parent not found (%s -> %s); using name only", contract.Name, baseName)
			continue
		}
		parentLin, err := ib.c3Linearize(base)
		if err != nil {
			// Cyclic parent: skip recursion but keep linearizing the rest so
			// downstream phases still receive a usable (if partial) MRO. The
			// partial result is context-sensitive, so don't memoize it.
			VerboseLog("C3 parent linearization skipped (%s -> %s): %v", contract.Name, baseName, err)
			degraded = true
			continue
		}
		lists = append(lists, parentLin)
	}
	lists = append(lists, append([]string{}, revBases...))

	merged := ib.c3Merge(lists)
	result := append([]string{contract.Name}, merged...)
	if !degraded {
		ib.memo[contract.ID] = append([]string(nil), result...)
	}
	return result, nil
}

// c3Merge implements the canonical forward-order C3 merge. At each step it scans
// the lists left-to-right for a "good head" — a head that appears in no other
// list's tail — and selects it. Selecting heads in forward order with the
// no-tail rule is what makes C3 deterministic and consistent with solc.
//
// If the hierarchy is genuinely inconsistent (no good head exists, which
// Solidity would reject at compile time), c3Merge degrades gracefully: it takes
// the first remaining head and logs, so a single malformed contract cannot abort
// the whole build. Operates on private copies so the caller's slices are intact.
func (ib *InheritanceBuilder) c3Merge(lists [][]string) []string {
	work := make([][]string, len(lists))
	for i, l := range lists {
		work[i] = append([]string{}, l...)
	}

	var result []string
	for {
		anyNonEmpty := false
		for _, l := range work {
			if len(l) > 0 {
				anyNonEmpty = true
				break
			}
		}
		if !anyNonEmpty {
			break
		}

		head := ""
		found := false
		for _, l := range work {
			if len(l) == 0 {
				continue
			}
			candidate := l[0]
			if !inAnyTail(candidate, work) {
				head = candidate
				found = true
				break
			}
		}

		if !found {
			// Inconsistent linearization — pick the first available head to make
			// progress rather than loop forever or drop the contract entirely.
			for _, l := range work {
				if len(l) > 0 {
					head = l[0]
					break
				}
			}
			VerboseLog("C3 merge: inconsistent linearization, forcing head %q", head)
		}

		result = append(result, head)
		for i := range work {
			work[i] = removeElement(work[i], head)
		}
	}

	return result
}

// inAnyTail reports whether candidate appears in the tail (every element after
// the head) of any list — the canonical C3 "blocking" check.
func inAnyTail(candidate string, lists [][]string) bool {
	for _, l := range lists {
		for i := 1; i < len(l); i++ {
			if l[i] == candidate {
				return true
			}
		}
	}
	return false
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
