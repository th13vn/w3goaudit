package engine

import (
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"

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

// MaxTaintFixpointPasses bounds the intra-function taint dataflow fixpoint
// (buildFunctionTaintEnv). Each pass re-applies every assignment using the taint
// computed so far, so chained and loop-carried aliases converge. Straight-line
// code stabilizes in one or two passes; the cap stops pathological or cyclic
// definitions (`a = b; b = a;`) from iterating forever.
const MaxTaintFixpointPasses = 8

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

	// match, when non-nil, captures matched-node provenance during Verify
	// so the calling executeOn* function can build Finding.Location from the
	// matched AST node (the dangerous statement) instead of the enclosing
	// verifier function. nil by default — Engine.Verify() callers that don't
	// want this capture pay zero cost.
	match *matchTrace

	// ipChains, when non-nil, maps an inlined-callee AST node back to the
	// call chain the interprocedural walker followed to reach it
	// ([entryFn, ..., hostFn]). Populated by interproceduralDescendants for
	// the lifetime of a single match attempt; nil otherwise.
	ipChains map[*types.ASTNode]ipPath

	// locationOverride is set by SetLocationSource and consulted via
	// locationSource(); the env var WGAUDIT_LOCATION_FROM_MATCHED_NODE takes
	// precedence so CI/scripts can opt in without touching code.
	locationOverride LocationSource

	// contractASTContract / contractASTRoot are a SINGLE-slot memo of the
	// synthetic `decl.contract` AST for the contract currently being processed.
	// The execute loop handles one contract end-to-end (filter → match → related-
	// site enrichment) before moving on, so this lets verifyAtContract build the
	// tree once and the enrichment reuse the SAME tree — without holding every
	// contract's tree for the whole scan (a map would grow unbounded since each
	// contract is visited only once). Reset at the top of Execute.
	contractASTContract *types.Contract
	contractASTRoot     *types.ASTNode
}

// matchTrace accumulates the metadata needed to build a Finding with
// matched-node provenance. Populated by Verify and its helpers as they
// descend; the outer call site reads it back on success.
type matchTrace struct {
	// Primary is the deepest atomic-match node — the dangerous statement
	// the rule was anchored on. Set once, on the first atomic match that
	// fires; subsequent matches don't overwrite it.
	Primary *types.ASTNode

	// Chain, when populated by the interprocedural matcher, lists the
	// functions the walker traversed to reach Primary: [entry, ..., host].
	// Length 1 (or 0) means the match was found in the entry function
	// directly and the host == entry.
	Chain []*types.Function

	// ChainContracts parallels Chain — the contract each function lives in
	// (an internal call into an inherited base picks up the base's contract).
	ChainContracts []*types.Contract
}

// ipPath is what interproceduralDescendants stores in Engine.ipChains for
// each inlined node so the caller can reconstruct the full reachability path
// when a sequence/has rule eventually matches that node.
type ipPath struct {
	Functions []*types.Function
	Contracts []*types.Contract
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
	Related        []RelatedLocation      `json:"related,omitempty"`
	Context        map[string]interface{} `json:"context,omitempty"`

	// Reachability records the call chain from an externally-callable entry
	// down to the function that hosts the dangerous statement. Step[0] is the
	// entry; Step[len-1] is the host (== Location.Function when location
	// provenance is matched-node mode). Populated for interprocedural matches.
	// Single-step paths are omitted via omitempty.
	Reachability *ReachabilityPath `json:"reachability,omitempty"`

	// PrimaryAST identifies the AST node the rule matched on — i.e. the
	// dangerous statement itself. Useful for IDE jumps and source extraction.
	PrimaryAST *NodeRef `json:"primaryAst,omitempty"`

	// EntryPoint names the auditor-actionable fix-here function: the highest
	// hop on Reachability that lacks verified access control. Nil when every
	// hop already has Verified access control (the bug is somewhere else).
	EntryPoint *EntryRef `json:"entryPoint,omitempty"`

	// Optional metadata propagated from TemplateMeta.
	References []string `json:"references,omitempty"`
	Fix        string   `json:"fix,omitempty"`
}

// Location identifies where a finding was detected.
//
// Provenance depends on the LocationSource setting. With
// LocationSourceMatchedNode (set via WGAUDIT_LOCATION_FROM_MATCHED_NODE=1 or
// --location-source matched), every field is derived from the matched AST
// node — the dangerous statement. With LocationSourceVerifier (the default
// today, preserved for backward compatibility), Function/Contract come from
// the verifier-function context while Line comes from the matched node, which
// can be inconsistent across interprocedural matches.
type Location struct {
	File     string `json:"file"`
	Contract string `json:"contract,omitempty"`
	Function string `json:"function,omitempty"`
	Line     int    `json:"line,omitempty"`
}

// RelatedLocation identifies an additional source site that contributes to a
// multi-condition finding. Contract-scope combination rules use this to show
// every exploitable site instead of only the first matched node.
type RelatedLocation struct {
	Label    string `json:"label,omitempty"`
	File     string `json:"file"`
	Contract string `json:"contract,omitempty"`
	Function string `json:"function,omitempty"`
	Line     int    `json:"line,omitempty"`
	Kind     string `json:"kind,omitempty"`
	Name     string `json:"name,omitempty"`
}

// ReachabilityPath records the call chain a finding traversed from an entry
// point to the dangerous statement.
type ReachabilityPath struct {
	Steps []ReachStep `json:"steps"`
}

// ReachStep is one hop on a ReachabilityPath.
type ReachStep struct {
	Contract   string `json:"contract"`
	Function   string `json:"function"`
	Visibility string `json:"visibility,omitempty"` // public/external/internal/private
	Line       int    `json:"line,omitempty"`       // line of the call into the NEXT step (last step: line of the dangerous statement)
	// AuthVerdict and AuthReasons are populated once the semantic access-
	// control analyzer (Section 2 of the design spec) ships. Left empty by
	// the current implementation.
	AuthVerdict string   `json:"authVerdict,omitempty"`
	AuthReasons []string `json:"authReasons,omitempty"`
}

// NodeRef identifies the AST node a rule matched on.
type NodeRef struct {
	Kind  string `json:"kind"`
	Name  string `json:"name,omitempty"`
	Start int    `json:"startLine"`
	End   int    `json:"endLine,omitempty"`
}

// EntryRef points at the auditor-actionable fix site.
type EntryRef struct {
	Contract    string   `json:"contract"`
	Function    string   `json:"function"`
	AuthVerdict string   `json:"authVerdict,omitempty"`
	AuthReasons []string `json:"authReasons,omitempty"`
}

// LocationSource selects how Finding.Location is computed.
type LocationSource int

const (
	// LocationSourceVerifier (default) preserves today's behavior:
	// Function/Contract come from the verifier-function context while Line
	// comes from the matched AST node. Maintained for backward compatibility.
	LocationSourceVerifier LocationSource = iota

	// LocationSourceMatchedNode points every field of Location at the matched
	// AST node — the dangerous statement. Aligns w3goaudit with SARIF /
	// Slither / Semgrep conventions. Selected via the env var
	// WGAUDIT_LOCATION_FROM_MATCHED_NODE=1 or the --location-source matched
	// CLI flag. Will become the default in a future major version.
	LocationSourceMatchedNode
)

// locationSource returns the effective provenance for this scan.
func (e *Engine) locationSource() LocationSource {
	// Primary env var matches the tool name; the older WGAUDIT_* name is kept as
	// a backward-compatible alias.
	envVal := os.Getenv("W3GOAUDIT_LOCATION_FROM_MATCHED_NODE")
	if envVal == "" {
		envVal = os.Getenv("WGAUDIT_LOCATION_FROM_MATCHED_NODE")
	}
	if envVal == "1" || strings.EqualFold(envVal, "true") || strings.EqualFold(envVal, "matched") {
		return LocationSourceMatchedNode
	}
	if e.locationOverride == LocationSourceMatchedNode {
		return LocationSourceMatchedNode
	}
	return LocationSourceVerifier
}

// SetLocationSource overrides the location provenance for this Engine
// instance. The CLI uses this when --location-source is passed; tests use it
// directly. The env var still takes precedence so it can be set in CI without
// touching code.
func (e *Engine) SetLocationSource(src LocationSource) { e.locationOverride = src }

// newFinding constructs a Finding with metadata propagated from tmpl.Meta.
// All Engine.executeOn* methods route through this helper so optional fields
// (References, Fix, Recommendation) are populated consistently.
func newFinding(tmpl *Template, loc Location) *Finding {
	return &Finding{
		TemplateID:     tmpl.Meta.ID,
		Severity:       tmpl.Meta.Severity,
		Confidence:     tmpl.Meta.Confidence,
		Title:          tmpl.Meta.Title,
		Message:        tmpl.Meta.Description,
		Recommendation: tmpl.Meta.Recommendation,
		Location:       loc,
		References:     tmpl.Meta.References,
		Fix:            tmpl.Meta.Fix,
	}
}

// Execute runs a template and returns findings
func (e *Engine) Execute(tmpl *Template) []*Finding {
	VerboseLog("Executing template: %s (ID: %s, Scope: %s)", tmpl.Meta.Title, tmpl.Meta.ID, tmpl.Query.Scope)
	e.contractASTContract, e.contractASTRoot = nil, nil // fresh per Execute
	var findings []*Finding

	switch tmpl.Query.Scope {
	case ScopeSource:
		findings = e.executeOnSourceFiles(tmpl)
	case ScopeAllContract:
		findings = e.executeOnAllContracts(tmpl)
	case ScopeMainContract:
		findings = e.executeOnMainContracts(tmpl)
	case ScopeContract:
		findings = e.executeOnContractsByKind(tmpl, types.ContractKindContract)
	case ScopeLibrary:
		findings = e.executeOnContractsByKind(tmpl, types.ContractKindLibrary)
	case ScopeAbstract:
		findings = e.executeOnContractsByKind(tmpl, types.ContractKindAbstract)
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

// executeOnSourceFiles runs raw source-text templates. This is deliberately
// small and regex-only; AST-aware rules should continue to use function or
// entrypoint scopes.
func (e *Engine) executeOnSourceFiles(tmpl *Template) []*Finding {
	if tmpl.Query.Match.Regex == "" {
		return nil
	}
	re, err := compileRegexCached(tmpl.Query.Match.Regex)
	if err != nil || re == nil {
		return nil
	}

	var findings []*Finding
	paths := make([]string, 0, len(e.db.SourceFiles))
	for path := range e.db.SourceFiles {
		paths = append(paths, path)
	}
	sort.Strings(paths)

	for _, path := range paths {
		sf := e.db.SourceFiles[path]
		if sf == nil {
			continue
		}
		content := sf.Content
		if content == "" {
			if data, err := os.ReadFile(path); err == nil {
				content = string(data)
			}
		}
		if content == "" {
			// Neither the serialized Content nor the on-disk file is available.
			// Don't fail silently: a source-text template that matches nothing
			// here is a false negative, not a clean result. This typically means
			// the database was built elsewhere (or the files moved) and predates
			// Content serialization.
			VerboseLog("WARN: source-scope template %q: no content for %s (not serialized and file not readable); skipping — results may be incomplete", tmpl.Meta.ID, path)
			continue
		}
		for _, match := range re.FindAllStringIndex(content, -1) {
			line := 1 + strings.Count(content[:match[0]], "\n")
			contract, fn := e.lookupSourceLine(path, line)
			findings = append(findings, newFinding(tmpl, Location{
				File:     path,
				Contract: contract,
				Function: fn,
				Line:     line,
			}))
		}
	}
	return findings
}

func (e *Engine) lookupSourceLine(path string, line int) (string, string) {
	if line <= 0 {
		return "", ""
	}
	contracts := make([]*types.Contract, 0)
	for _, contract := range e.db.Contracts {
		if contract != nil && contract.SourceFile == path {
			contracts = append(contracts, contract)
		}
	}
	sort.Slice(contracts, func(i, j int) bool { return contracts[i].ID < contracts[j].ID })
	for _, contract := range contracts {
		for _, fn := range contract.Functions {
			if fn != nil && fn.StartLine <= line && line <= fn.EndLine {
				return contract.Name, fn.Name
			}
		}
	}
	if content := e.sourceContent(path); content != "" {
		for _, contract := range contracts {
			start, end := sourceContractRange(content, contract.Name)
			if start <= line && line <= end {
				return contract.Name, ""
			}
		}
	}
	return "", ""
}

func (e *Engine) sourceContent(path string) string {
	if sf := e.db.SourceFiles[path]; sf != nil && sf.Content != "" {
		return sf.Content
	}
	if data, err := os.ReadFile(path); err == nil {
		return string(data)
	}
	return ""
}

func (e *Engine) sourceSnippet(path string, startLine, endLine int) string {
	content := e.sourceContent(path)
	if content == "" || startLine <= 0 || endLine <= 0 {
		return ""
	}
	lines := strings.Split(content, "\n")
	start := startLine - 1
	end := endLine
	if start < 0 {
		start = 0
	}
	if end > len(lines) {
		end = len(lines)
	}
	if start >= end {
		return ""
	}
	return strings.Join(lines[start:end], "\n")
}

func (e *Engine) functionSource(fn *types.Function, contract *types.Contract) string {
	if fn == nil {
		return ""
	}
	if contract != nil && contract.SourceFile != "" &&
		(fn.ContractName == "" || contract.Name == fn.ContractName) {
		if snippet := e.sourceSnippet(contract.SourceFile, fn.StartLine, fn.EndLine); snippet != "" {
			return snippet
		}
	}
	if source := e.db.GetFunctionSource(fn); source != "" {
		return source
	}
	return ""
}

func (e *Engine) contractSource(contract *types.Contract) string {
	if contract == nil || contract.SourceFile == "" {
		return ""
	}
	content := e.sourceContent(contract.SourceFile)
	if content == "" {
		return ""
	}
	start, end := sourceContractRange(content, contract.Name)
	return e.sourceSnippet(contract.SourceFile, start, end)
}

func (e *Engine) astNodeSource(node *types.ASTNode) string {
	if node == nil || node.StartLine <= 0 || node.EndLine <= 0 {
		return ""
	}
	if sourceFile := node.GetAttributeString("source_file"); sourceFile != "" {
		if snippet := e.sourceSnippet(sourceFile, node.StartLine, node.EndLine); snippet != "" {
			return snippet
		}
	}
	if e.currentContract != nil && e.currentContract.SourceFile != "" {
		if snippet := e.sourceSnippet(e.currentContract.SourceFile, node.StartLine, node.EndLine); snippet != "" {
			return snippet
		}
	}
	if e.currentFunction != nil {
		if contract := e.db.GetContractByName(e.currentFunction.ContractName); contract != nil {
			return e.sourceSnippet(contract.SourceFile, node.StartLine, node.EndLine)
		}
	}
	return ""
}

func sourceContractRange(content, name string) (int, int) {
	pattern := regexp.MustCompile(`\b(contract|interface|library)\s+` + regexp.QuoteMeta(name) + `\b`)
	lines := strings.Split(content, "\n")
	for idx, line := range lines {
		if !pattern.MatchString(stripLineComment(line)) {
			continue
		}
		return idx + 1, sourceBlockEnd(lines, idx)
	}
	return 0, 0
}

func sourceBlockEnd(lines []string, startIdx int) int {
	depth := 0
	seenOpen := false
	for idx := startIdx; idx < len(lines); idx++ {
		for _, ch := range stripLineComment(lines[idx]) {
			switch ch {
			case '{':
				depth++
				seenOpen = true
			case '}':
				if seenOpen {
					depth--
				}
			}
		}
		if seenOpen && depth <= 0 {
			return idx + 1
		}
	}
	return len(lines)
}

func stripLineComment(line string) string {
	if idx := strings.Index(line, "//"); idx >= 0 {
		return line[:idx]
	}
	return line
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
		trace := &matchTrace{}
		e.match = trace
		matched := e.VerifyAtContract(contract, tmpl.Query.Match)
		e.match = nil
		if matched {
			f := newFinding(tmpl, e.buildContractLocation(trace, contract))
			e.enrichFindingFromTrace(f, trace, nil, contract)
			e.enrichContractRelatedLocations(f, contract, tmpl.Query.Match)
			findings = append(findings, f)
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

		if tmpl.Query.Filter != nil {
			if !e.VerifyAtContract(contract, *tmpl.Query.Filter) {
				continue
			}
		}
		trace := &matchTrace{}
		e.match = trace
		matched := e.VerifyAtContract(contract, tmpl.Query.Match)
		e.match = nil
		if matched {
			f := newFinding(tmpl, e.buildContractLocation(trace, contract))
			e.enrichFindingFromTrace(f, trace, nil, contract)
			e.enrichContractRelatedLocations(f, contract, tmpl.Query.Match)
			findings = append(findings, f)
		}
	}

	return findings
}

func (e *Engine) executeOnContractsByKind(tmpl *Template, kind types.ContractKind) []*Finding {
	var findings []*Finding

	for _, contract := range e.db.Contracts {
		if contract == nil || contract.Kind != kind {
			continue
		}
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
			// Set up the per-attempt match trace so Verify can capture the
			// primary AST node + (for IP matches) the call chain.
			trace := &matchTrace{}
			e.match = trace
			matched := e.VerifyAtFunctionWithCallees(fn, tmpl.Query.Match, contract)
			e.match = nil
			if !matched {
				continue
			}
			loc := e.buildLocation(trace, fn, fnContract, locationFile)
			f := newFinding(tmpl, loc)
			e.enrichFindingFromTrace(f, trace, fn, fnContract)
			findings = append(findings, f)
		}

		e.currentSourceFile = nil
	}

	return findings
}

// buildLocation chooses the Finding.Location fields based on the active
// LocationSource. With LocationSourceMatchedNode, every field comes from the
// matched AST node (the dangerous statement); with LocationSourceVerifier
// (the default today) the function/contract come from the verifier-function
// context — preserving today's behavior for callers that haven't opted in.
func (e *Engine) buildLocation(trace *matchTrace, verifierFn *types.Function, verifierContract *types.Contract, fallbackFile string) Location {
	if trace != nil && trace.Primary != nil && e.locationSource() == LocationSourceMatchedNode {
		hostName, hostContract, hostFile, hostLine := e.hostFunctionFor(trace.Primary)
		if hostFile == "" {
			hostFile = fallbackFile
		}
		if hostContract == "" && verifierContract != nil {
			hostContract = verifierContract.Name
		}
		if hostName == "" && verifierFn != nil {
			hostName = verifierFn.Name
		}
		if hostLine == 0 {
			// Interior AST nodes now carry precise source spans (v0.4), so
			// the primary node's StartLine is the normal precise-anchor
			// path here, not a fallback; only drop to the host function's
			// StartLine when the primary node genuinely lacks one (e.g. a
			// synthetic node).
			if trace.Primary.StartLine > 0 {
				hostLine = trace.Primary.StartLine
			} else if len(trace.Chain) > 0 {
				if last := trace.Chain[len(trace.Chain)-1]; last != nil {
					hostLine = last.StartLine
				}
			} else if verifierFn != nil {
				hostLine = verifierFn.StartLine
			}
		}
		return Location{File: hostFile, Contract: hostContract, Function: hostName, Line: hostLine}
	}
	// Default (today's behavior): verifier function/contract; matched-node line if available.
	loc := Location{File: fallbackFile, Line: verifierFn.StartLine}
	if verifierFn != nil {
		loc.Function = verifierFn.Name
		loc.Contract = verifierFn.ContractName
	}
	if trace != nil && trace.Primary != nil && trace.Primary.StartLine > 0 {
		loc.Line = trace.Primary.StartLine
	}
	return loc
}

func (e *Engine) buildContractLocation(trace *matchTrace, contract *types.Contract) Location {
	loc := Location{}
	if contract != nil {
		loc.File = contract.SourceFile
		loc.Contract = contract.Name
	}
	if trace == nil || trace.Primary == nil {
		return loc
	}

	hostName, hostContract, hostFile, hostLine := e.hostFunctionFor(trace.Primary)
	if hostFile != "" {
		loc.File = hostFile
	}
	if hostContract != "" {
		loc.Contract = hostContract
	}
	if hostName != "" {
		loc.Function = hostName
	}
	if hostLine > 0 {
		loc.Line = hostLine
	} else if trace.Primary.StartLine > 0 {
		loc.Line = trace.Primary.StartLine
	}
	return loc
}

// enrichFindingFromTrace populates the new optional fields (Reachability,
// PrimaryAST, EntryPoint) from the captured trace. Always additive — these
// fields are populated regardless of LocationSource so consumers can read
// the structured context independently of the legacy Location provenance.
func (e *Engine) enrichFindingFromTrace(f *Finding, trace *matchTrace, verifierFn *types.Function, verifierContract *types.Contract) {
	if f == nil || trace == nil {
		return
	}
	if trace.Primary != nil {
		f.PrimaryAST = &NodeRef{
			Kind:  trace.Primary.Kind,
			Name:  trace.Primary.Name,
			Start: trace.Primary.StartLine,
			End:   trace.Primary.EndLine,
		}
	}
	// Reachability path. For non-IP matches Chain is empty — synthesize a
	// single-step path so reports always have something to render.
	chainFns := trace.Chain
	chainContracts := trace.ChainContracts
	if len(chainFns) == 0 && verifierFn != nil {
		chainFns = []*types.Function{verifierFn}
		chainContracts = []*types.Contract{verifierContract}
	}
	if len(chainFns) > 0 {
		steps := make([]ReachStep, 0, len(chainFns))
		for i, fn := range chainFns {
			if fn == nil {
				continue
			}
			step := ReachStep{
				Contract:   fn.ContractName,
				Function:   fn.Name,
				Visibility: string(fn.Visibility),
				// The function's StartLine is the anchor for intermediate
				// hops in the chain, where we only have the function-level
				// context. Interior AST nodes carry precise source spans
				// (v0.4), so for the final hop we prefer the primary node's
				// line when it's non-zero so reports point at the dangerous
				// statement rather than the function header.
				Line: fn.StartLine,
			}
			if i == len(chainFns)-1 && trace.Primary != nil && trace.Primary.StartLine > 0 {
				step.Line = trace.Primary.StartLine
			}
			_ = chainContracts // contracts available for future enrichment
			steps = append(steps, step)
		}
		f.Reachability = &ReachabilityPath{Steps: steps}
	}
	// EntryPoint: until the semantic access-control analyzer ships, the entry
	// point is just step[0] of the chain (the externally-callable function
	// the walker started from). AuthVerdict left empty.
	if f.Reachability != nil && len(f.Reachability.Steps) > 0 {
		s := f.Reachability.Steps[0]
		f.EntryPoint = &EntryRef{Contract: s.Contract, Function: s.Function}
	}
}

func (e *Engine) enrichContractRelatedLocations(f *Finding, contract *types.Contract, r Rule) {
	if f == nil || contract == nil || !ruleHasASTFields(r) {
		return
	}
	root := e.contractAST(contract)
	if root == nil {
		return
	}
	rules := r.All
	if len(rules) == 0 {
		rules = []Rule{r}
	}
	seen := make(map[string]bool)
	for i, branch := range rules {
		label := contractBranchLabel(branch, i)
		for _, related := range e.collectContractRelatedLocations(root, branch, label) {
			key := related.File + "|" + related.Contract + "|" + related.Function + "|" + related.Label + "|" + strconv.Itoa(related.Line)
			if seen[key] {
				continue
			}
			seen[key] = true
			f.Related = append(f.Related, related)
		}
	}
}

func (e *Engine) collectContractRelatedLocations(root *types.ASTNode, r Rule, label string) []RelatedLocation {
	// The function-targeting sub-rule(s) of this branch. A branch like
	// `contains: { kind: decl.function, ... }` matches a function as a
	// descendant of the contract root; we re-identify which function(s) satisfy
	// it by matching each decl.function/modifier node against those sub-rules.
	// Collecting ALL of them (not just the first) keeps `any:` branches with
	// several function shapes faithful. Falls back to the branch itself when it
	// has no explicit function sub-rule.
	fnRules := containedFunctionRules(r)
	if len(fnRules) == 0 {
		fnRules = []Rule{r}
	}
	var out []RelatedLocation
	root.WalkDescendants(func(n *types.ASTNode) bool {
		if n.Kind != types.KindDeclFunction && n.Kind != types.KindDeclModifier {
			return true
		}
		for i := range fnRules {
			if e.Verify(n, fnRules[i]) {
				out = append(out, e.relatedLocationForNode(n, label))
				break
			}
		}
		return true
	})
	return out
}

func (e *Engine) relatedLocationForNode(node *types.ASTNode, label string) RelatedLocation {
	hostName, hostContract, hostFile, hostLine := e.hostFunctionFor(node)
	return RelatedLocation{
		Label:    label,
		File:     hostFile,
		Contract: hostContract,
		Function: hostName,
		Line:     hostLine,
		Kind:     node.Kind,
		Name:     node.Name,
	}
}

// contractBranchLabel names a matched branch for the related-site list. The
// name comes from the template's `label:` field on that branch; templates that
// omit it fall back to a positional "condition N". The engine deliberately
// holds no per-detector knowledge — labels live in the WQL template.
func contractBranchLabel(r Rule, idx int) string {
	if r.Label != "" {
		return r.Label
	}
	return "condition " + strconv.Itoa(idx+1)
}

// containedFunctionRules returns every decl.function / decl.modifier rule
// reachable in a branch through `contains` / `all` / `any` (positive paths
// only). A function-kind rule is returned as-is, with its own sub-structure
// intact, and recursion stops there. `not:` is skipped — a negated branch
// describes the ABSENCE of a function, which has no positive related site.
func containedFunctionRules(r Rule) []Rule {
	if r.Kind == types.KindDeclFunction || r.Kind == types.KindDeclModifier {
		return []Rule{r}
	}
	var out []Rule
	if r.Contains != nil {
		out = append(out, containedFunctionRules(*r.Contains)...)
	}
	for i := range r.All {
		out = append(out, containedFunctionRules(r.All[i])...)
	}
	for i := range r.Any {
		out = append(out, containedFunctionRules(r.Any[i])...)
	}
	return out
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
