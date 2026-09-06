package types

import (
	"errors"
	"sort"
)

const TransactionContextFactsVersion = "1.0.0"

const (
	TransactionContextSourceMsgValue = "msg_value"

	TransactionContextUseStateWrite           = "state_write"
	TransactionContextUseCallValue            = "call_value"
	TransactionContextUseStatefulInternalCall = "stateful_internal_call"

	TransactionContextRepeatabilityPossible        = "possible"
	TransactionContextRepeatabilitySingleIteration = "single_iteration"
)

var ErrTransactionContextFactsUnavailable = errors.New("transaction-context facts unavailable; rebuild the database from source")

// TransactionContextFact records one proven transaction-level msg.value flow
// from an exact source occurrence to an effect hosted by an enclosing loop.
// Facts describe evidence only; they do not declare a vulnerability.
type TransactionContextFact struct {
	ID               string              `json:"id"`
	ContractID       string              `json:"contractId"`
	ScopeID          string              `json:"scopeId"`
	FunctionID       string              `json:"functionId"`
	Source           string              `json:"source"`
	Use              string              `json:"use"`
	Repeatability    string              `json:"repeatability"`
	SourceRange      SemanticSourceRange `json:"sourceRange"`
	EffectRange      SemanticSourceRange `json:"effectRange"`
	LoopPath         string              `json:"loopPath"`
	ResolvedCalleeID string              `json:"resolvedCalleeId,omitempty"`
}

// NormalizeTransactionContextFacts returns a sorted, deduplicated deep copy.
// A fact ID is the exact semantic occurrence identity, so repeated IDs collapse
// to one record after deterministic ordering.
func NormalizeTransactionContextFacts(facts []*TransactionContextFact) []*TransactionContextFact {
	out := make([]*TransactionContextFact, 0, len(facts))
	for _, fact := range facts {
		if fact == nil {
			continue
		}
		copy := *fact
		out = append(out, &copy)
	}
	sort.Slice(out, func(i, j int) bool {
		return transactionContextFactLess(out[i], out[j])
	})
	write := 0
	for _, fact := range out {
		if write > 0 && out[write-1].ID == fact.ID {
			continue
		}
		out[write] = fact
		write++
	}
	return out[:write]
}

func transactionContextFactLess(left, right *TransactionContextFact) bool {
	if left.ID != right.ID {
		return left.ID < right.ID
	}
	if left.ContractID != right.ContractID {
		return left.ContractID < right.ContractID
	}
	if left.ScopeID != right.ScopeID {
		return left.ScopeID < right.ScopeID
	}
	if left.SourceRange.File != right.SourceRange.File {
		return left.SourceRange.File < right.SourceRange.File
	}
	if left.SourceRange.StartByte != right.SourceRange.StartByte {
		return left.SourceRange.StartByte < right.SourceRange.StartByte
	}
	if left.EffectRange.StartByte != right.EffectRange.StartByte {
		return left.EffectRange.StartByte < right.EffectRange.StartByte
	}
	return left.Use < right.Use
}

// TransactionContextFactsSnapshot returns deterministic caller-owned facts.
// Legacy databases fail closed instead of synthesizing weaker evidence.
func (db *Database) TransactionContextFactsSnapshot() ([]*TransactionContextFact, error) {
	if db == nil || db.Semantics == nil || db.Semantics.TransactionContextVersion != TransactionContextFactsVersion {
		return nil, ErrTransactionContextFactsUnavailable
	}
	return NormalizeTransactionContextFacts(db.Semantics.TransactionContextFacts), nil
}
