package types

import (
	"errors"
	"sort"
	"strings"
)

const (
	TypeKindUnknown   = "unknown"
	TypeKindPrimitive = "primitive"
	TypeKindContract  = "contract"
	TypeKindInterface = "interface"
	TypeKindLibrary   = "library"
	TypeKindAbstract  = "abstract"
	TypeKindStruct    = "struct"
	TypeKindArray     = "array"
	TypeKindMapping   = "mapping"
)

const (
	ExternalBoundaryFactsVersion  = "1.0.0"
	MaxExternalBoundaryQueryLimit = 200
)

var ErrExternalBoundaryFactsUnavailable = errors.New("external-boundary facts unavailable; rebuild the database from source")

type ExternalBoundaryScopeKind string

const (
	ExternalBoundaryScopeFunction ExternalBoundaryScopeKind = "function"
	ExternalBoundaryScopeModifier ExternalBoundaryScopeKind = "modifier"
)

type BoundaryValueControl string

const (
	BoundaryValueUnknown          BoundaryValueControl = "unknown"
	BoundaryValueCallerControlled BoundaryValueControl = "caller_controlled"
	BoundaryValueStateDerived     BoundaryValueControl = "state_derived"
	BoundaryValueFixed            BoundaryValueControl = "fixed"
)

const (
	BoundaryValueRoleReceiver = "receiver"
	BoundaryValueRoleValue    = "value"
	BoundaryValueRoleGas      = "gas"
	BoundaryValueRoleArgument = "argument"
	BoundaryValueRoleResult   = "result"

	BoundaryTargetResolved      = "resolved"
	BoundaryTargetUnresolved    = "unresolved"
	BoundaryTargetNotApplicable = "not_applicable"

	BoundaryResultYes     = "yes"
	BoundaryResultNo      = "no"
	BoundaryResultUnknown = "unknown"

	BoundaryResultNone      = "none"
	BoundaryResultDiscarded = "discarded"
	BoundaryResultCaptured  = "captured"
	BoundaryResultReturned  = "returned"
	BoundaryResultCondition = "condition"
	BoundaryResultConsumed  = "consumed"

	BoundaryStateBefore       = "before"
	BoundaryStateAfter        = "after"
	BoundaryStateUnordered    = "unordered"
	BoundaryStateIncompatible = "incompatible"
	BoundaryStateUnknown      = "unknown"

	BoundaryReentryPossible            = "possible"
	BoundaryReentryDelegateContext     = "delegate_context"
	BoundaryReentryReadOnlyPossible    = "read_only_possible"
	BoundaryReentryStipendLimited      = "stipend_limited"
	BoundaryReentrySameContract        = "same_contract"
	BoundaryReentryConstructorPossible = "constructor_possible"
	BoundaryReentryUnknown             = "unknown"
)

// SemanticSourceRange is an exact source span owned by one semantic fact.
type SemanticSourceRange struct {
	File      string `json:"file,omitempty"`
	StartLine int    `json:"startLine,omitempty"`
	StartCol  int    `json:"startCol,omitempty"`
	EndLine   int    `json:"endLine,omitempty"`
	EndCol    int    `json:"endCol,omitempty"`
	StartByte int    `json:"startByte,omitempty"`
	EndByte   int    `json:"endByte,omitempty"`
}

// BoundaryValue records bounded value provenance at an external boundary.
type BoundaryValue struct {
	Role         string               `json:"role"`
	Index        int                  `json:"index"`
	Expression   string               `json:"expression,omitempty"`
	Range        SemanticSourceRange  `json:"range"`
	Type         TypeInfo             `json:"type"`
	Control      BoundaryValueControl `json:"control"`
	RefIDs       []string             `json:"refIds"`
	TaintSources []string             `json:"taintSources"`
}

// BoundaryTarget records target identity without guessing unresolved calls.
type BoundaryTarget struct {
	Resolution       string       `json:"resolution"`
	CalledName       string       `json:"calledName,omitempty"`
	CalledSignature  string       `json:"calledSignature,omitempty"`
	ContractID       string       `json:"contractId,omitempty"`
	ContractName     string       `json:"contractName,omitempty"`
	FunctionID       string       `json:"functionId,omitempty"`
	FunctionSelector string       `json:"functionSelector,omitempty"`
	Kind             ContractKind `json:"kind,omitempty"`
}

// BoundaryResult describes direct handling of a call result.
type BoundaryResult struct {
	Availability string                `json:"availability"`
	Disposition  string                `json:"disposition"`
	DirectCheck  string                `json:"directCheck"`
	Targets      []BoundaryValue       `json:"targets"`
	CheckSites   []SemanticSourceRange `json:"checkSites"`
}

// BoundaryStateEffect relates one direct state write to a boundary occurrence.
type BoundaryStateEffect struct {
	Relation string              `json:"relation"`
	RefID    string              `json:"refId,omitempty"`
	Name     string              `json:"name,omitempty"`
	Kind     string              `json:"kind,omitempty"`
	Range    SemanticSourceRange `json:"range"`
}

// ExternalBoundaryFact is the stable public evidence record for one external
// control boundary. It is descriptive and does not declare a vulnerability.
type ExternalBoundaryFact struct {
	ID            string                    `json:"id"`
	ASTPath       string                    `json:"astPath"`
	ContractID    string                    `json:"contractId"`
	ScopeID       string                    `json:"scopeId"`
	ScopeKind     ExternalBoundaryScopeKind `json:"scopeKind"`
	FunctionID    string                    `json:"functionId,omitempty"`
	Kind          string                    `json:"kind"`
	CallType      CallType                  `json:"callType"`
	Range         SemanticSourceRange       `json:"range"`
	Target        BoundaryTarget            `json:"target"`
	Receiver      *BoundaryValue            `json:"receiver,omitempty"`
	Value         *BoundaryValue            `json:"value,omitempty"`
	Gas           *BoundaryValue            `json:"gas,omitempty"`
	Arguments     []BoundaryValue           `json:"arguments"`
	Result        BoundaryResult            `json:"result"`
	ReentryClass  string                    `json:"reentryClass"`
	ReachableFrom []string                  `json:"reachableFrom"`
	StateEffects  []BoundaryStateEffect     `json:"stateEffects"`
	Limitations   []string                  `json:"limitations"`
}

type ExternalBoundaryQuery struct {
	ContractID      string
	ScopeID         string
	FunctionID      string
	EntryFunctionID string
	Kinds           []string
	Offset          int
	Limit           int
}

type ExternalBoundaryPage struct {
	Items     []*ExternalBoundaryFact `json:"items"`
	Total     int                     `json:"total"`
	Offset    int                     `json:"offset"`
	Limit     int                     `json:"limit"`
	Truncated bool                    `json:"truncated"`
}

// TypeInfo is the normalized semantic type attached to symbols and AST nodes.
// It is intentionally lightweight: enough to improve call classification and
// WQL facts without requiring a solc-grade type checker.
type TypeInfo struct {
	Name        string `json:"name,omitempty"`
	BaseName    string `json:"baseName,omitempty"`
	Kind        string `json:"kind,omitempty"`
	ContractID  string `json:"contractId,omitempty"`
	IsAddress   bool   `json:"isAddress,omitempty"`
	IsPayable   bool   `json:"isPayable,omitempty"`
	Confidence  string `json:"confidence,omitempty"`
	Source      string `json:"source,omitempty"`
	ElementType string `json:"elementType,omitempty"`
	KeyType     string `json:"keyType,omitempty"`
	ValueType   string `json:"valueType,omitempty"`
}

// IsKnown returns true when the fact carries a meaningful inferred type.
func (ti TypeInfo) IsKnown() bool {
	return ti.Name != "" && ti.Kind != "" && ti.Kind != TypeKindUnknown
}

// IsPrimitiveAddress returns true for Solidity address/address payable values.
func (ti TypeInfo) IsPrimitiveAddress() bool {
	return ti.Kind == TypeKindPrimitive && ti.IsAddress
}

// SemanticSymbol records a named program symbol and its inferred type.
type SemanticSymbol struct {
	RefID        string   `json:"refId"`
	Name         string   `json:"name"`
	Kind         string   `json:"kind"`
	ContractID   string   `json:"contractId,omitempty"`
	FunctionID   string   `json:"functionId,omitempty"`
	StorageClass string   `json:"storageClass,omitempty"`
	Type         TypeInfo `json:"type"`
}

// SemanticFacts is the database-level semantic layer consumed by WQL.
type SemanticFacts struct {
	Symbols map[string]*SemanticSymbol `json:"symbols,omitempty"`

	// FunctionEffects holds per-function analysis facts (state writes, guards,
	// access control) keyed by function ID. Populated by the builder's effects
	// pass and consumed by the report layer (per-entry workflow files and the
	// state-change matrix).
	FunctionEffects map[string]*FunctionEffects `json:"functionEffects,omitempty"`

	ExternalBoundaryVersion string                  `json:"externalBoundaryVersion,omitempty"`
	ExternalBoundaries      []*ExternalBoundaryFact `json:"externalBoundaries,omitempty"`
}

// FunctionEffects captures what a single function does that an auditor needs to
// reason about: which state it writes, what it checks, and how it is guarded.
type FunctionEffects struct {
	// StateWrites are the state variables this function writes directly.
	StateWrites []StateWrite `json:"stateWrites,omitempty"`
	// Guards are require/assert/revert and branch conditions, in source order.
	Guards []Guard `json:"guards,omitempty"`
	// Auth summarizes access control on this function.
	Auth AuthInfo `json:"auth"`
}

// StateWrite records a write to a state variable.
type StateWrite struct {
	Var  string `json:"var"`            // state variable name
	Kind string `json:"kind,omitempty"` // assign | compound | push | pop | delete | increment | decrement | sstore
	Line int    `json:"line,omitempty"`
}

// Guard records a precondition or branch condition.
type Guard struct {
	Kind string `json:"kind"`           // require | assert | revert | if
	Expr string `json:"expr,omitempty"` // condition source text (best effort)
	Line int    `json:"line,omitempty"`
}

// AuthInfo summarizes a function's access control.
type AuthInfo struct {
	Modifiers    []string `json:"modifiers,omitempty"`
	SenderChecks []string `json:"senderChecks,omitempty"` // conditions referencing msg.sender
	UsesTxOrigin bool     `json:"usesTxOrigin,omitempty"`
	// Controlled is true only when enforcement-positive exact modifier bodies
	// and call-site authorization/fixed-operand bindings, inline caller checks,
	// or recursively resolved internal auth helpers prove privileged access.
	Controlled bool `json:"controlled,omitempty"`
}

// NewSemanticFacts creates an empty semantic index.
func NewSemanticFacts() *SemanticFacts {
	return &SemanticFacts{
		Symbols:            make(map[string]*SemanticSymbol),
		FunctionEffects:    make(map[string]*FunctionEffects),
		ExternalBoundaries: make([]*ExternalBoundaryFact, 0),
	}
}

// IsExternalBoundaryKind reports whether an AST kind belongs to the stable
// boundary-fact coverage set.
func IsExternalBoundaryKind(kind string) bool {
	switch kind {
	case KindCallExternal, KindCallLowlevelCall, KindCallLowlevelDelegate,
		KindCallLowlevelStatic, KindCallBuiltinTransfer, KindCallBuiltinSend,
		KindCallCreate, KindAsmCall, KindAsmDelegatecall, KindAsmStaticcall,
		KindAsmCreate, KindAsmCreate2:
		return true
	default:
		return false
	}
}

// NormalizeExternalBoundaryFacts returns a deterministic deep-copy snapshot.
func NormalizeExternalBoundaryFacts(facts []*ExternalBoundaryFact) []*ExternalBoundaryFact {
	out := make([]*ExternalBoundaryFact, 0, len(facts))
	for _, fact := range facts {
		if fact == nil {
			continue
		}
		copy := cloneExternalBoundaryFact(fact)
		normalizeExternalBoundaryFact(copy)
		out = append(out, copy)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ID != out[j].ID {
			return out[i].ID < out[j].ID
		}
		if out[i].ScopeID != out[j].ScopeID {
			return out[i].ScopeID < out[j].ScopeID
		}
		return out[i].ASTPath < out[j].ASTPath
	})
	return out
}

func normalizeExternalBoundaryFact(fact *ExternalBoundaryFact) {
	if fact.ScopeID == "" && fact.FunctionID != "" {
		fact.ScopeID = fact.FunctionID
	}
	if fact.ScopeKind == "" && fact.FunctionID != "" && fact.ScopeID == fact.FunctionID {
		fact.ScopeKind = ExternalBoundaryScopeFunction
	}
	fact.Arguments = normalizeBoundaryValues(fact.Arguments)
	fact.Result.Targets = normalizeBoundaryValues(fact.Result.Targets)
	fact.Result.CheckSites = normalizeSemanticRanges(fact.Result.CheckSites)
	fact.ReachableFrom = normalizedStrings(fact.ReachableFrom)
	fact.Limitations = normalizedStrings(fact.Limitations)
	if fact.Receiver != nil {
		normalizeBoundaryValue(fact.Receiver)
	}
	if fact.Value != nil {
		normalizeBoundaryValue(fact.Value)
	}
	if fact.Gas != nil {
		normalizeBoundaryValue(fact.Gas)
	}
	if fact.StateEffects == nil {
		fact.StateEffects = []BoundaryStateEffect{}
	}
	sort.Slice(fact.StateEffects, func(i, j int) bool {
		a, b := fact.StateEffects[i], fact.StateEffects[j]
		if a.Relation != b.Relation {
			return a.Relation < b.Relation
		}
		if a.Range.File != b.Range.File {
			return a.Range.File < b.Range.File
		}
		if a.Range.StartByte != b.Range.StartByte {
			return a.Range.StartByte < b.Range.StartByte
		}
		if a.RefID != b.RefID {
			return a.RefID < b.RefID
		}
		return a.Name < b.Name
	})
}

func normalizeBoundaryValues(values []BoundaryValue) []BoundaryValue {
	if values == nil {
		return []BoundaryValue{}
	}
	out := append([]BoundaryValue(nil), values...)
	for index := range out {
		normalizeBoundaryValue(&out[index])
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Role != out[j].Role {
			return out[i].Role < out[j].Role
		}
		if out[i].Index != out[j].Index {
			return out[i].Index < out[j].Index
		}
		return out[i].Expression < out[j].Expression
	})
	return out
}

func normalizeBoundaryValue(value *BoundaryValue) {
	value.RefIDs = normalizedStrings(value.RefIDs)
	value.TaintSources = normalizedStrings(value.TaintSources)
}

func normalizeSemanticRanges(ranges []SemanticSourceRange) []SemanticSourceRange {
	if ranges == nil {
		return []SemanticSourceRange{}
	}
	out := append([]SemanticSourceRange(nil), ranges...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].File != out[j].File {
			return out[i].File < out[j].File
		}
		if out[i].StartByte != out[j].StartByte {
			return out[i].StartByte < out[j].StartByte
		}
		return out[i].EndByte < out[j].EndByte
	})
	return out
}

func normalizedStrings(values []string) []string {
	if values == nil {
		return []string{}
	}
	out := append([]string(nil), values...)
	sort.Strings(out)
	write := 0
	for _, value := range out {
		if value == "" || write > 0 && out[write-1] == value {
			continue
		}
		out[write] = value
		write++
	}
	return out[:write]
}

func cloneExternalBoundaryFact(fact *ExternalBoundaryFact) *ExternalBoundaryFact {
	if fact == nil {
		return nil
	}
	copy := *fact
	if fact.Receiver != nil {
		receiver := *fact.Receiver
		copy.Receiver = &receiver
	}
	if fact.Value != nil {
		value := *fact.Value
		copy.Value = &value
	}
	if fact.Gas != nil {
		gas := *fact.Gas
		copy.Gas = &gas
	}
	copy.Arguments = append([]BoundaryValue(nil), fact.Arguments...)
	copy.Result.Targets = append([]BoundaryValue(nil), fact.Result.Targets...)
	copy.Result.CheckSites = append([]SemanticSourceRange(nil), fact.Result.CheckSites...)
	copy.ReachableFrom = append([]string(nil), fact.ReachableFrom...)
	copy.StateEffects = append([]BoundaryStateEffect(nil), fact.StateEffects...)
	copy.Limitations = append([]string(nil), fact.Limitations...)
	return &copy
}

// SetFunctionEffects stores effects for a function ID.
func (sf *SemanticFacts) SetFunctionEffects(funcID string, fe *FunctionEffects) {
	if sf == nil || funcID == "" || fe == nil {
		return
	}
	if sf.FunctionEffects == nil {
		sf.FunctionEffects = make(map[string]*FunctionEffects)
	}
	sf.FunctionEffects[funcID] = fe
}

// GetFunctionEffects returns effects for a function ID (nil when absent).
func (sf *SemanticFacts) GetFunctionEffects(funcID string) *FunctionEffects {
	if sf == nil || sf.FunctionEffects == nil {
		return nil
	}
	return sf.FunctionEffects[funcID]
}

// AddSymbol inserts or replaces a semantic symbol by RefID.
func (sf *SemanticFacts) AddSymbol(sym *SemanticSymbol) {
	if sf == nil || sym == nil || sym.RefID == "" {
		return
	}
	if sf.Symbols == nil {
		sf.Symbols = make(map[string]*SemanticSymbol)
	}
	sf.Symbols[sym.RefID] = sym
}

// GetSymbol returns a semantic symbol by RefID.
func (sf *SemanticFacts) GetSymbol(refID string) *SemanticSymbol {
	if sf == nil || sf.Symbols == nil || refID == "" {
		return nil
	}
	return sf.Symbols[refID]
}

// CleanTypeName removes storage-location and whitespace noise from Solidity
// type names while preserving array/mapping syntax.
func CleanTypeName(typeName string) string {
	typeName = strings.TrimSpace(typeName)
	for _, storage := range []string{" memory", " storage", " calldata"} {
		typeName = strings.ReplaceAll(typeName, storage, "")
	}
	return strings.TrimSpace(typeName)
}
