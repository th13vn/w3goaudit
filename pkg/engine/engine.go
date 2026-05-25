package engine

import (
	"github.com/th13vn/w3goaudit/pkg/types"
)

// MaxRuleRecursionDepth caps how deep Verify is allowed to recurse into a
// single rule (not/all/any/contains/inside/sequence). Real templates rarely
// nest more than 6 levels; this guards against pathological or attacker-
// supplied templates that would blow the Go stack.
const MaxRuleRecursionDepth = 64

// MaxInterproceduralTaintDepth caps recursive internal-call tracing for
// context-sensitive taint matching. This keeps cyclic call graphs bounded while
// still covering ordinary entrypoint -> helper -> helper flows.
const MaxInterproceduralTaintDepth = 12

// Engine executes WQL templates against the project database.
//
// NOTE: Engine is NOT safe for concurrent use. The execution-context fields
// below (currentFunction, currentContract, currentSourceFile, recursionDepth)
// are mutated during a scan. Callers that want parallelism must allocate one
// Engine per goroutine.
type Engine struct {
	db                *types.Database
	currentFunction   *types.Function   // Context for recursive call checking
	currentContract   *types.Contract   // Context for recursive call checking
	currentSourceFile *types.SourceFile // Context for version checking
	currentTaintEnv   map[string][]string
	recursionDepth    int // Guards Verify against unbounded recursion.
}

// New creates a new Engine
func New(db *types.Database) *Engine {
	return &Engine{db: db}
}

// Finding represents a vulnerability finding
type Finding struct {
	TemplateID     string                 `json:"template_id"`
	Severity       string                 `json:"severity"`
	Confidence     string                 `json:"confidence"`
	Title          string                 `json:"title,omitempty"`
	Message        string                 `json:"message,omitempty"`
	Recommendation string                 `json:"recommendation,omitempty"`
	Location       Location               `json:"location"`
	Context        map[string]interface{} `json:"context,omitempty"`

	// Optional metadata propagated from TemplateMeta.
	CWE        []int    `json:"cwe,omitempty"`
	OWASP      []string `json:"owasp,omitempty"`
	References []string `json:"references,omitempty"`
	Fix        string   `json:"fix,omitempty"`
}

// Location identifies where a finding was detected
type Location struct {
	File     string `json:"file"`
	Contract string `json:"contract,omitempty"`
	Function string `json:"function,omitempty"`
	Line     int    `json:"line,omitempty"`
}

// newFinding constructs a Finding with all metadata propagated from tmpl.Meta.
// All Engine.executeOn* methods route through this helper so optional fields
// (CWE, OWASP, References, Fix, Recommendation) are populated consistently.
func newFinding(tmpl *Template, loc Location) *Finding {
	return &Finding{
		TemplateID:     tmpl.Meta.ID,
		Severity:       tmpl.Meta.Severity,
		Confidence:     tmpl.Meta.Confidence,
		Title:          tmpl.Meta.Title,
		Message:        tmpl.Meta.Description,
		Recommendation: tmpl.Meta.Recommendation,
		Location:       loc,
		CWE:            tmpl.Meta.CWE,
		OWASP:          tmpl.Meta.OWASP,
		References:     tmpl.Meta.References,
		Fix:            tmpl.Meta.Fix,
	}
}

// Execute runs a template and returns findings
func (e *Engine) Execute(tmpl *Template) []*Finding {
	VerboseLog("Executing template: %s (ID: %s, Scope: %s)", tmpl.Meta.Title, tmpl.Meta.ID, tmpl.Query.Scope)
	var findings []*Finding

	switch tmpl.Query.Scope {
	case ScopeAllContract:
		findings = e.executeOnAllContracts(tmpl)
	case ScopeMainContract:
		findings = e.executeOnMainContracts(tmpl)
	case ScopeFunction:
		findings = e.executeOnAllFunctions(tmpl)
	case ScopeEntrypoint:
		findings = e.executeOnEntryFunctions(tmpl)
	default:
		// Default to entrypoint for security scanning
		findings = e.executeOnEntryFunctions(tmpl)
	}

	VerboseLog("Template %s completed: Found %d findings", tmpl.Meta.ID, len(findings))
	return findings
}

// ExecuteAll runs all templates
func (e *Engine) ExecuteAll(templates []*Template) []*Finding {
	VerboseLog("Executing %d templates", len(templates))
	var findings []*Finding
	for _, tmpl := range templates {
		findings = append(findings, e.Execute(tmpl)...)
	}
	VerboseLog("All templates executed: Total %d findings", len(findings))
	return findings
}

// executeOnAllContracts runs template on every contract
func (e *Engine) executeOnAllContracts(tmpl *Template) []*Finding {
	var findings []*Finding

	for _, contract := range e.db.Contracts {
		// Apply filter if present
		if tmpl.Query.Filter != nil {
			if !e.VerifyAtContract(contract, *tmpl.Query.Filter) {
				continue
			}
		}
		if e.VerifyAtContract(contract, tmpl.Query.Match) {
			findings = append(findings, newFinding(tmpl, Location{
				File:     contract.SourceFile,
				Contract: contract.Name,
			}))
		}
	}

	return findings
}

// executeOnMainContracts runs template only on main contracts
func (e *Engine) executeOnMainContracts(tmpl *Template) []*Finding {
	var findings []*Finding

	for contractID := range e.db.MainContracts {
		contract := e.db.Contracts[contractID]
		if contract == nil {
			continue
		}

		if e.VerifyAtContract(contract, tmpl.Query.Match) {
			findings = append(findings, newFinding(tmpl, Location{
				File:     contract.SourceFile,
				Contract: contract.Name,
			}))
		}
	}

	return findings
}

// executeOnAllFunctions runs template on all functions
func (e *Engine) executeOnAllFunctions(tmpl *Template) []*Finding {
	var findings []*Finding

	for _, contract := range e.db.Contracts {
		// Set source file context for version checking
		e.currentSourceFile = e.db.SourceFiles[contract.SourceFile]

		for _, fn := range contract.Functions {
			// Apply filter if present
			if tmpl.Query.Filter != nil {
				if !e.VerifyAtFunction(fn, *tmpl.Query.Filter, contract) {
					continue
				}
			}
			if e.VerifyAtFunction(fn, tmpl.Query.Match, contract) {
				findings = append(findings, newFinding(tmpl, Location{
					File:     contract.SourceFile,
					Contract: fn.ContractName,
					Function: fn.Name,
					Line:     fn.StartLine,
				}))
			}
		}

		e.currentSourceFile = nil
	}

	return findings
}

// executeOnEntryFunctions runs template on resolved entry functions
func (e *Engine) executeOnEntryFunctions(tmpl *Template) []*Finding {
	var findings []*Finding

	// Iterate over main contracts and their entry function IDs
	for contractID, entry := range e.db.MainContracts {
		contract := e.db.Contracts[contractID]
		if contract == nil {
			continue
		}

		// Set source file context for version checking
		e.currentSourceFile = e.db.SourceFiles[contract.SourceFile]

		for _, funcID := range entry.EntryFunctions {
			// Lookup the actual function from source by ID
			fn, fnContract := e.lookupFunctionWithContractByID(funcID)
			if fn == nil {
				continue
			}
			locationFile := contract.SourceFile
			if fnContract != nil {
				locationFile = fnContract.SourceFile
			}

			// Apply filter if present
			if tmpl.Query.Filter != nil {
				if !e.VerifyAtFunction(fn, *tmpl.Query.Filter, contract) {
					continue
				}
			}
			if e.VerifyAtFunctionWithCallees(fn, tmpl.Query.Match, contract) {
				findings = append(findings, newFinding(tmpl, Location{
					File:     locationFile,
					Contract: fn.ContractName,
					Function: fn.Name,
					Line:     fn.StartLine,
				}))
			}
		}

		e.currentSourceFile = nil
	}

	return findings
}

// lookupFunctionByID looks up a function by its ID: absPath#Contract.selector
func (e *Engine) lookupFunctionByID(funcID string) *types.Function {
	fn, _ := e.lookupFunctionWithContractByID(funcID)
	return fn
}

func (e *Engine) lookupFunctionWithContractByID(funcID string) (*types.Function, *types.Contract) {
	filePath, contractName, funcSelector := types.ParseFunctionID(funcID)

	// Find the contract
	contract := e.db.GetContractByID(filePath + "#" + contractName)
	if contract == nil {
		contract = e.db.GetContractByName(contractName)
	}
	if contract == nil {
		return nil, nil
	}

	// Find the function matching the selector (or name as fallback)
	for _, fn := range contract.Functions {
		key := fn.Selector
		if key == "" {
			key = fn.Name
		}
		if key == funcSelector {
			return fn, contract
		}
	}
	return nil, contract
}
