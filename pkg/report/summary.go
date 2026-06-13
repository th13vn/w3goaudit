// Package report provides report generation functionality for Solidity projects.
package report

import (
	"time"

	"github.com/th13vn/w3goaudit/pkg/types"
)

// SummaryReport represents a full project summary
type SummaryReport struct {
	// ProjectRoot is the root directory of the project
	ProjectRoot string `json:"projectRoot"`

	// GitInfo contains git repository information (nil if not a git repo)
	GitInfo *GitInfo `json:"gitInfo,omitempty"`

	// MainContracts contains summaries for each main contract
	MainContracts []*ContractSummary `json:"mainContracts"`

	// GeneratedAt is when the report was generated
	GeneratedAt time.Time `json:"generatedAt"`

	// Stats contains project statistics
	Stats *types.DatabaseStats `json:"stats"`
}

// GitInfo contains detected git repository information
type GitInfo struct {
	// RemoteURL is the web URL of the repository (e.g., https://github.com/user/repo)
	RemoteURL string `json:"remoteUrl,omitempty"`
	// Branch is the current or default branch (e.g., main, master)
	Branch string `json:"branch,omitempty"`
}

// ContractSummary represents a summary of a main contract
type ContractSummary struct {
	// Name of the contract
	Name string `json:"name"`

	// SourceFile where the contract is defined (full path)
	SourceFile string `json:"sourceFile"`

	// EntryFunctionCount is the number of entry point functions
	EntryFunctionCount int `json:"entryFunctionCount"`

	// StateVariableCount is the total number of state variables (including inherited)
	StateVariableCount int `json:"stateVariableCount"`

	// StateVariables lists all state variables (including inherited)
	StateVariables []*StateSummary `json:"stateVariables"`

	// InheritanceChain is the flattened inheritance sequence (derived first)
	InheritanceChain []*InheritedContract `json:"inheritanceChain"`

	// InheritanceMermaid is the Mermaid diagram for inheritance
	InheritanceMermaid string `json:"inheritanceMermaid"`

	// EntryFunctions are public/external functions that can modify state
	EntryFunctions []*FunctionSummary `json:"entryFunctions"`

	// ViewFunctions are public/external view/pure functions
	ViewFunctions []*FunctionSummary `json:"viewFunctions"`

	// InternalFunctions are internal/private functions
	InternalFunctions []*FunctionSummary `json:"internalFunctions"`

	// CallGraphMermaid is the Mermaid diagram for function calls
	CallGraphMermaid string `json:"callGraphMermaid"`
}

// StateSummary represents a state variable
type StateSummary struct {
	// Name of the variable
	Name string `json:"name"`

	// TypeName is the type of the variable
	TypeName string `json:"typeName"`

	// DefinedIn is the contract where the variable is defined
	DefinedIn string `json:"definedIn"`
}

// InheritedContract represents a contract in the inheritance chain
type InheritedContract struct {
	// Order in the inheritance chain (1 = most derived)
	Order int `json:"order"`

	// Name of the contract
	Name string `json:"name"`

	// Kind of contract
	Kind string `json:"kind"`
}

// FunctionSummary represents a function summary
type FunctionSummary struct {
	// Name of the function
	Name string `json:"name"`

	// Selector is the function selector: name(params)
	Selector string `json:"selector"`

	// Signature is the 4-byte hash
	Signature string `json:"signature"`

	// IsPayable indicates if function can receive ETH
	IsPayable bool `json:"isPayable,omitempty"`

	// DefinedIn is the contract where the function is actually defined
	DefinedIn string `json:"definedIn,omitempty"`

	// CallGraphMermaid is the Mermaid diagram for this function's call graph
	CallGraphMermaid string `json:"callGraphMermaid,omitempty"`

	// Modifiers list for the function
	Modifiers []string `json:"modifiers,omitempty"`

	// IsAccessControlled indicates if the function has access control modifiers
	IsAccessControlled bool `json:"isAccessControlled,omitempty"`
}
