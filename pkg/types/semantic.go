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
}

// NewSemanticFacts creates an empty semantic index.
func NewSemanticFacts() *SemanticFacts {
	return &SemanticFacts{
		Symbols: make(map[string]*SemanticSymbol),
	}
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
