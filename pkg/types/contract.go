// Package types defines core data structures for the w3goaudit engine.
package types

// ContractKind represents the type of contract definition
type ContractKind string

const (
	ContractKindContract  ContractKind = "contract"
	ContractKindInterface ContractKind = "interface"
	ContractKindLibrary   ContractKind = "library"
	ContractKindAbstract  ContractKind = "abstract"
)

// Contract represents a Solidity contract with its metadata
type Contract struct {
	// ID is the unique identifier: absPath#ContractName
	ID string `json:"id"`

	// Name of the contract
	Name string `json:"name"`

	// Kind of contract (contract, interface, library, abstract)
	Kind ContractKind `json:"kind"`

	// SourceFile where the contract is defined
	SourceFile string `json:"sourceFile"`

	// BaseContracts are direct parent contracts (names only)
	BaseContracts []string `json:"baseContracts,omitempty"`

	// LinearizedBases is the C3 linearization order (method resolution order)
	// Most derived (current contract) first, most base contract last
	LinearizedBases []string `json:"linearizedBases,omitempty"`

	// LinearizedBaseIDs is the exact file#Contract identity for each entry in
	// LinearizedBases. It is additive to preserve schema-2.0.0 readers that use
	// the display-name slice, while new consumers avoid short-name collisions.
	LinearizedBaseIDs []string `json:"linearizedBaseIds,omitempty"`

	// InheritanceWeight is used to score main contract candidates
	// Higher weight = more derived = more likely to be main contract
	InheritanceWeight int `json:"inheritanceWeight"`

	// Functions defined in this contract
	Functions []*Function `json:"functions,omitempty"`

	// StateVariables defined in this contract
	StateVariables []*StateVariable `json:"stateVariables,omitempty"`

	// Events defined in this contract
	Events []*Event `json:"events,omitempty"`

	// Modifiers defined in this contract
	Modifiers []*Modifier `json:"modifiers,omitempty"`

	// Structs defined in this contract
	Structs []*Struct `json:"structs,omitempty"`

	// Enums defined in this contract
	Enums []*Enum `json:"enums,omitempty"`

	// IsAbstract indicates if contract has unimplemented functions
	IsAbstract bool `json:"isAbstract,omitempty"`

	// UsingDirectives for library function resolution
	// e.g., 'using SafeMath for uint256'
	UsingDirectives []*UsingDirective `json:"usingDirectives,omitempty"`

	// SourceLocation for debugging / click-to-jump
	StartLine int `json:"startLine,omitempty"`
	EndLine   int `json:"endLine,omitempty"`
	StartCol  int `json:"startCol,omitempty"`
	EndCol    int `json:"endCol,omitempty"`
	StartByte int `json:"startByte,omitempty"`
	EndByte   int `json:"endByte,omitempty"`
}

// StateVariable represents a contract state variable
type StateVariable struct {
	Name        string `json:"name"`
	TypeName    string `json:"typeName"`
	Visibility  string `json:"visibility"`
	IsConstant  bool   `json:"isConstant,omitempty"`
	IsImmutable bool   `json:"isImmutable,omitempty"`

	// SourceLocation for debugging / click-to-jump
	StartLine int `json:"startLine,omitempty"`
	EndLine   int `json:"endLine,omitempty"`
	StartCol  int `json:"startCol,omitempty"`
	EndCol    int `json:"endCol,omitempty"`
	StartByte int `json:"startByte,omitempty"`
	EndByte   int `json:"endByte,omitempty"`
}

// Event represents a Solidity event
type Event struct {
	Name       string       `json:"name"`
	Parameters []*Parameter `json:"parameters,omitempty"`

	// SourceLocation for debugging / click-to-jump
	StartLine int `json:"startLine,omitempty"`
	EndLine   int `json:"endLine,omitempty"`
	StartCol  int `json:"startCol,omitempty"`
	EndCol    int `json:"endCol,omitempty"`
	StartByte int `json:"startByte,omitempty"`
	EndByte   int `json:"endByte,omitempty"`
}

// Modifier represents a Solidity modifier
type Modifier struct {
	Name       string          `json:"name"`
	Parameters []*Parameter    `json:"parameters,omitempty"`
	AST        *ASTNode        `json:"ast,omitempty"`       // AST of modifier body
	Calls      []*FunctionCall `json:"calls,omitempty"`     // Calls made within modifier
	StartLine  int             `json:"startLine,omitempty"` // Source location
	EndLine    int             `json:"endLine,omitempty"`   // Source location
	StartCol   int             `json:"startCol,omitempty"`
	EndCol     int             `json:"endCol,omitempty"`
	StartByte  int             `json:"startByte,omitempty"`
	EndByte    int             `json:"endByte,omitempty"`
}

// Struct represents a Solidity struct
type Struct struct {
	Name    string    `json:"name"`
	Members []*Member `json:"members,omitempty"`

	// SourceLocation for debugging / click-to-jump
	StartLine int `json:"startLine,omitempty"`
	EndLine   int `json:"endLine,omitempty"`
	StartCol  int `json:"startCol,omitempty"`
	EndCol    int `json:"endCol,omitempty"`
	StartByte int `json:"startByte,omitempty"`
	EndByte   int `json:"endByte,omitempty"`
}

// Member represents a struct member
type Member struct {
	Name     string `json:"name"`
	TypeName string `json:"typeName"`
}

// Enum represents a Solidity enum
type Enum struct {
	Name   string   `json:"name"`
	Values []string `json:"values,omitempty"`

	// SourceLocation for debugging / click-to-jump
	StartLine int `json:"startLine,omitempty"`
	EndLine   int `json:"endLine,omitempty"`
	StartCol  int `json:"startCol,omitempty"`
	EndCol    int `json:"endCol,omitempty"`
	StartByte int `json:"startByte,omitempty"`
	EndByte   int `json:"endByte,omitempty"`
}

// UsingDirective represents a 'using Library for Type' directive
type UsingDirective struct {
	// Library is the library name (e.g., "SafeMath")
	Library string `json:"library"`

	// ForType is the type the library is applied to (e.g., "uint256", "*" for all)
	ForType string `json:"forType"`

	// IsGlobal indicates file-level using directive
	IsGlobal bool `json:"isGlobal,omitempty"`
}

// IsDeployable returns true if the contract can be deployed
func (c *Contract) IsDeployable() bool {
	return c.Kind == ContractKindContract && !c.IsAbstract
}

// IsMainCandidate returns true if contract is a candidate for main contract
func (c *Contract) IsMainCandidate() bool {
	return c.Kind == ContractKindContract && !c.IsAbstract
}
