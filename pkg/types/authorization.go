package types

import (
	"errors"
	"fmt"
	"sort"
)

const AuthorizationFactsVersion = "1.0.0"

const MaxAuthorizationQueryLimit = 200

const AuthorizationLimitationCallerSelected = "authorization.binding.caller_selected"

var ErrAuthorizationFactsUnavailable = errors.New("authorization facts unavailable; rebuild the database from source")

type AuthorizationVerdict string

const (
	AuthorizationProtected   AuthorizationVerdict = "protected"
	AuthorizationSelfScoped  AuthorizationVerdict = "self_scoped"
	AuthorizationUnprotected AuthorizationVerdict = "unprotected"
	AuthorizationUnknown     AuthorizationVerdict = "unknown"
)

type AuthorizationPrincipalKind string

const (
	PrincipalOwner            AuthorizationPrincipalKind = "owner"
	PrincipalRole             AuthorizationPrincipalKind = "role"
	PrincipalFixedAddress     AuthorizationPrincipalKind = "fixed_address"
	PrincipalExpectedExternal AuthorizationPrincipalKind = "expected_external"
	PrincipalCallerSelfScope  AuthorizationPrincipalKind = "caller_self_scope"
	PrincipalUnknown          AuthorizationPrincipalKind = "unknown"
)

type AuthorizationDominance string

const (
	AuthorizationDominates  AuthorizationDominance = "dominates"
	AuthorizationPartial    AuthorizationDominance = "partial"
	AuthorizationAfterSite  AuthorizationDominance = "after_site"
	AuthorizationUnknownDom AuthorizationDominance = "unknown"
)

type AuthorizationEvidence struct {
	GuardKind       string                     `json:"guardKind,omitempty"`
	GuardExpression string                     `json:"guardExpression,omitempty"`
	GuardRange      SemanticSourceRange        `json:"guardRange"`
	PrincipalKind   AuthorizationPrincipalKind `json:"principalKind"`
	Principal       string                     `json:"principal,omitempty"`
	RefIDs          []string                   `json:"refIds"`
	Dominance       AuthorizationDominance     `json:"dominance"`
}

type AuthorizationFact struct {
	ID                      string                     `json:"id"`
	ContractID              string                     `json:"contractId"`
	ScopeID                 string                     `json:"scopeId"`
	ScopeKind               string                     `json:"scopeKind"`
	FunctionID              string                     `json:"functionId,omitempty"`
	RuntimeContractID       string                     `json:"runtimeContractId,omitempty"`
	SelectedFunctionID      string                     `json:"selectedFunctionId,omitempty"`
	Evidence                []AuthorizationEvidence    `json:"evidence"`
	Verdict                 AuthorizationVerdict       `json:"verdict"`
	PrincipalKind           AuthorizationPrincipalKind `json:"principalKind"`
	Principal               string                     `json:"principal,omitempty"`
	ExpectedPrincipal       string                     `json:"expectedPrincipal,omitempty"`
	ExpectedPrincipalRefIDs []string                   `json:"expectedPrincipalRefIds,omitempty"`
	Dominance               AuthorizationDominance     `json:"dominance"`
	Reasons                 []string                   `json:"reasons"`
	Limitations             []string                   `json:"limitations"`
	InitializerEntry        bool                       `json:"initializerEntry,omitempty"`
	OneTimeMutex            bool                       `json:"oneTimeMutex,omitempty"`
	ConstructorDisable      bool                       `json:"constructorDisable,omitempty"`
	ProxyContext            string                     `json:"proxyContext,omitempty"`
	FirstCallTakeover       string                     `json:"firstCallTakeover,omitempty"`
	AtomicInitialization    string                     `json:"atomicInitialization,omitempty"`
	ProxyImplementationID   string                     `json:"proxyImplementationId,omitempty"`
	ProxyLinkage            string                     `json:"proxyLinkage,omitempty"`
}

type AuthorizationQuery struct {
	ContractID        string
	ScopeID           string
	FunctionID        string
	RuntimeContractID string
	Verdict           AuthorizationVerdict
	PrincipalKind     AuthorizationPrincipalKind
	Offset            int
	Limit             int
}
type AuthorizationPage struct {
	Items     []*AuthorizationFact `json:"items"`
	Total     int                  `json:"total"`
	Offset    int                  `json:"offset"`
	Limit     int                  `json:"limit"`
	Truncated bool                 `json:"truncated"`
}

func NormalizeAuthorizationFacts(facts []*AuthorizationFact) []*AuthorizationFact {
	out := make([]*AuthorizationFact, 0, len(facts))
	for _, fact := range facts {
		if fact == nil {
			continue
		}
		c := *fact
		c.Evidence = append([]AuthorizationEvidence(nil), fact.Evidence...)
		for i := range c.Evidence {
			c.Evidence[i].RefIDs = normalizedStrings(fact.Evidence[i].RefIDs)
		}
		c.Reasons = normalizedStrings(fact.Reasons)
		c.Limitations = normalizedStrings(fact.Limitations)
		c.ExpectedPrincipalRefIDs = normalizedStrings(fact.ExpectedPrincipalRefIDs)
		if c.Evidence == nil {
			c.Evidence = []AuthorizationEvidence{}
		}
		if c.Reasons == nil {
			c.Reasons = []string{}
		}
		if c.Limitations == nil {
			c.Limitations = []string{}
		}
		if c.Verdict == "" {
			c.Verdict = AuthorizationUnknown
		}
		if c.PrincipalKind == "" {
			c.PrincipalKind = PrincipalUnknown
		}
		if c.Dominance == "" {
			c.Dominance = AuthorizationUnknownDom
		}
		out = append(out, &c)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ID != out[j].ID {
			return out[i].ID < out[j].ID
		}
		if out[i].ScopeID != out[j].ScopeID {
			return out[i].ScopeID < out[j].ScopeID
		}
		return out[i].RuntimeContractID < out[j].RuntimeContractID
	})
	return out
}

func (db *Database) AuthorizationFactsSnapshot() ([]*AuthorizationFact, error) {
	if db == nil || db.Semantics == nil || db.Semantics.AuthorizationFactsVersion != AuthorizationFactsVersion {
		return nil, ErrAuthorizationFactsUnavailable
	}
	return NormalizeAuthorizationFacts(db.Semantics.AuthorizationFacts), nil
}
func (db *Database) GetAuthorizationFactByID(id string) (*AuthorizationFact, bool) {
	facts, err := db.AuthorizationFactsSnapshot()
	if err != nil {
		return nil, false
	}
	i := sort.Search(len(facts), func(i int) bool { return facts[i].ID >= id })
	if i >= len(facts) || facts[i].ID != id {
		return nil, false
	}
	return facts[i], true
}
func (db *Database) QueryAuthorizationFacts(q AuthorizationQuery) (*AuthorizationPage, error) {
	facts, err := db.AuthorizationFactsSnapshot()
	if err != nil {
		return nil, err
	}
	if q.Limit < 1 || q.Limit > MaxAuthorizationQueryLimit {
		return nil, fmt.Errorf("authorization query limit must be between 1 and %d", MaxAuthorizationQueryLimit)
	}
	if q.Offset < 0 {
		return nil, fmt.Errorf("authorization query offset must be non-negative")
	}
	matches := make([]*AuthorizationFact, 0, len(facts))
	for _, f := range facts {
		if q.ContractID != "" && f.ContractID != q.ContractID {
			continue
		}
		if q.ScopeID != "" && f.ScopeID != q.ScopeID {
			continue
		}
		if q.FunctionID != "" && f.FunctionID != q.FunctionID {
			continue
		}
		if q.RuntimeContractID != "" && f.RuntimeContractID != q.RuntimeContractID {
			continue
		}
		if q.Verdict != "" && f.Verdict != q.Verdict {
			continue
		}
		if q.PrincipalKind != "" && f.PrincipalKind != q.PrincipalKind {
			continue
		}
		matches = append(matches, f)
	}
	total := len(matches)
	start := q.Offset
	if start > total {
		start = total
	}
	end := start + q.Limit
	if end > total {
		end = total
	}
	items := append([]*AuthorizationFact(nil), matches[start:end]...)
	return &AuthorizationPage{Items: items, Total: total, Offset: q.Offset, Limit: q.Limit, Truncated: end < total}, nil
}
