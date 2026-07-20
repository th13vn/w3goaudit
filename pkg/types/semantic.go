package types

import "strings"

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
		Symbols:         make(map[string]*SemanticSymbol),
		FunctionEffects: make(map[string]*FunctionEffects),
	}
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
