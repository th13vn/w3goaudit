package engine

import (
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/th13vn/w3goaudit/pkg/logging"
	"github.com/th13vn/w3goaudit/pkg/types"
)

// Options configures one Engine instance.
type Options struct {
	Logger *logging.Logger
}

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
	logger            *logging.Logger
	legacy            bool
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

	// modifierDeclContract / modifierDeclByName are a separate SINGLE-slot
	// memo for guarded_by. It clones only modifier declarations from one exact
	// contract MRO, avoiding full function/variable contract-AST construction.
	// A new contract evicts the previous map; Execute resets both slots.
	modifierDeclContract *types.Contract
	modifierDeclByName   map[string]*types.ASTNode
}

// matchTrace accumulates the metadata needed to build a Finding with
// matched-node provenance. Populated by Verify and its helpers as they
// descend; the outer call site reads it back on success.
type matchTrace struct {
	// Primary is the dangerous statement the rule was anchored on. The first
	// equal-priority atomic match wins, while traceable AST evidence may replace
	// an earlier coarse regex/root fallback.
	Primary *types.ASTNode
	// primaryPriority lets exact AST evidence supersede a coarse regex/root
	// fallback while preserving first-match behavior among equal-priority sites.
	primaryPriority uint8

	// Chain, when populated by the interprocedural matcher, lists the
	// functions the walker traversed to reach Primary: [entry, ..., host].
	// Length 1 (or 0) means the match was found in the entry function
	// directly and the host == entry.
	Chain []*types.Function

	// ChainContracts parallels Chain — the contract each function lives in
	// (an internal call into an inherited base picks up the base's contract).
	ChainContracts []*types.Contract
}

// ipPath is stored on each interprocedural sequence-event occurrence so reused
// callee AST pointers retain the exact entry-to-host path for that occurrence.
type ipPath struct {
	Functions []*types.Function
	Contracts []*types.Contract
}

// New creates an Engine that preserves the legacy package-global verbose
// configuration. New code should use NewWithOptions for scan-local logging.
func New(db *types.Database) *Engine {
	return &Engine{db: db, legacy: true}
}

// NewWithOptions creates an Engine with scan-local configuration. A nil logger
// is treated as disabled and never falls back to package globals.
func NewWithOptions(db *types.Database, opts Options) *Engine {
	logger := opts.Logger
	if logger == nil {
		logger = logging.Disabled()
	}
	return &Engine{db: db, logger: logger}
}

func (e *Engine) logf(format string, args ...any) {
	if e != nil && e.legacy {
		VerboseLog(format, args...)
		return
	}
	if e != nil {
		e.logger.Printf(format, args...)
	}
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
	// Precise source span of the matched node (v0.4). Col/EndLine/EndCol are
	// 1-based; StartByte/EndByte are 0-based UTF-8 byte offsets. Zero/omitted for
	// synthetic nodes or verifier-derived locations that lack a matched node.
	Col       int `json:"col,omitempty"`
	EndLine   int `json:"endLine,omitempty"`
	EndCol    int `json:"endCol,omitempty"`
	StartByte int `json:"startByte,omitempty"`
	EndByte   int `json:"endByte,omitempty"`
}

// RelatedLocation identifies an additional source site that contributes to a
// multi-condition finding. Function and contract joins use this to show each
// branch's exact matched node instead of only the first site.
type RelatedLocation struct {
	Label     string `json:"label,omitempty"`
	File      string `json:"file"`
	Contract  string `json:"contract,omitempty"`
	Function  string `json:"function,omitempty"`
	Line      int    `json:"line,omitempty"`
	Col       int    `json:"col,omitempty"`
	EndLine   int    `json:"endLine,omitempty"`
	EndCol    int    `json:"endCol,omitempty"`
	StartByte int    `json:"startByte,omitempty"`
	EndByte   int    `json:"endByte,omitempty"`
	Kind      string `json:"kind,omitempty"`
	Name      string `json:"name,omitempty"`
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
	File       string `json:"file,omitempty"`       // source file hosting this hop (may differ from the primary file on cross-contract chains)
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
	// Precise source span (v0.4): 1-based columns, 0-based byte offsets.
	// Omitted for synthetic nodes that lack a span.
	StartCol  int `json:"startCol,omitempty"`
	EndCol    int `json:"endCol,omitempty"`
	StartByte int `json:"startByte,omitempty"`
	EndByte   int `json:"endByte,omitempty"`
}

// applyNodeSpan copies the matched node's precise span onto a Location. Line is
// left to the caller (it may come from the host function for interprocedural
// matches); the sub-line fields (Col/EndLine/EndCol/bytes) only make sense when
// they belong to the same node the Line was taken from, so callers apply this
// only when Line == n.StartLine.
func applyNodeSpan(loc *Location, n *types.ASTNode) {
	if n == nil {
		return
	}
	loc.Col = n.StartCol
	loc.EndLine = n.EndLine
	loc.EndCol = n.EndCol
	loc.StartByte = n.StartByte
	loc.EndByte = n.EndByte
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

	// LocationSourceMatchedNode takes the precise range from the matched AST
	// node and host identity from the final trace hop or enclosing declaration.
	// Aligns w3goaudit with SARIF / Slither / Semgrep conventions. Selected via the env var
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

// Execute runs a template. Single-query templates execute their one
// QueryBlock; or:-composed templates (len(Queries) > 1) execute every block
// and union the findings under this template's meta. Only the same precise
// matched site from an earlier branch is deduplicated; duplicates within one
// branch and imprecise legacy findings remain. Branch order is deterministic.
func (e *Engine) Execute(tmpl *Template) []*Finding {
	normalized, err := normalizedTemplateCompatibilityCopy(tmpl)
	if err != nil {
		e.logf("Template compatibility normalization failed: %v", err)
		return nil
	}
	tmpl = normalized
	if len(tmpl.Queries) <= 1 {
		return e.executeQuery(tmpl)
	}

	var findings []*Finding
	seenEarlier := make(map[matchedSiteSpan]*matchedSiteKinds)
	for _, q := range tmpl.Queries {
		branch := *tmpl
		branch.Query = q
		branch.Queries = nil
		var branchIdentities []matchedSiteOccurrence
		replacedUnknown := make(map[matchedSiteSpan]bool)
		for _, f := range e.executeQuery(&branch) {
			identity, precise := findingMatchedSiteIdentity(f)
			if precise && matchedSiteSeen(seenEarlier, identity) {
				continue
			}
			if precise && identity.Kind != "" {
				kinds := seenEarlier[identity.Span]
				if kinds != nil && kinds.Unknown && !replacedUnknown[identity.Span] {
					findings[kinds.UnknownIndex] = f
					replacedUnknown[identity.Span] = true
					branchIdentities = append(branchIdentities, matchedSiteOccurrence{
						Identity: identity, FindingIndex: kinds.UnknownIndex,
					})
					continue
				}
			}
			findings = append(findings, f)
			if precise {
				branchIdentities = append(branchIdentities, matchedSiteOccurrence{
					Identity: identity, FindingIndex: len(findings) - 1,
				})
			}
		}
		for _, occurrence := range branchIdentities {
			rememberMatchedSite(seenEarlier, occurrence.Identity, occurrence.FindingIndex)
		}
	}
	return findings
}

type matchedSiteSpan struct {
	File                string
	ByByte              bool
	StartByte, EndByte  int
	StartLine, StartCol int
	EndLine, EndCol     int
}

type matchedSiteIdentity struct {
	Span matchedSiteSpan
	Kind string
}

type matchedSiteOccurrence struct {
	Identity     matchedSiteIdentity
	FindingIndex int
}

type matchedSiteKinds struct {
	Unknown      bool
	UnknownIndex int
	Known        map[string]bool
}

func matchedSiteSeen(seen map[matchedSiteSpan]*matchedSiteKinds, identity matchedSiteIdentity) bool {
	kinds := seen[identity.Span]
	if kinds == nil {
		return false
	}
	if identity.Kind == "" {
		return kinds.Unknown || len(kinds.Known) > 0
	}
	return kinds.Known[identity.Kind]
}

func rememberMatchedSite(seen map[matchedSiteSpan]*matchedSiteKinds, identity matchedSiteIdentity, findingIndex int) {
	kinds := seen[identity.Span]
	if kinds == nil {
		kinds = &matchedSiteKinds{UnknownIndex: -1}
		seen[identity.Span] = kinds
	}
	if identity.Kind == "" {
		if !kinds.Unknown && len(kinds.Known) == 0 {
			kinds.Unknown = true
			kinds.UnknownIndex = findingIndex
		}
		return
	}
	kinds.Unknown = false
	kinds.UnknownIndex = -1
	if kinds.Known == nil {
		kinds.Known = make(map[string]bool)
	}
	kinds.Known[identity.Kind] = true
}

// findingMatchedSiteIdentity returns the canonical precise source identity of
// a finding. Kind is optional provenance: an unknown kind matches the same span
// with a known kind in either branch order, while two different known kinds at
// one span remain distinct. Coarse declaration/function locations deliberately
// return false so legacy or synthetic findings are retained.
func findingMatchedSiteIdentity(f *Finding) (matchedSiteIdentity, bool) {
	if f == nil {
		return matchedSiteIdentity{}, false
	}
	kind := ""
	if f.PrimaryAST != nil {
		kind = f.PrimaryAST.Kind
		file := finalReachabilityFile(f)
		if file == "" {
			// Contract matches have no call path. For a real-span primary,
			// buildContractLocation supplies the exact owning file needed for a
			// canonical identity. A location-less primary remains imprecise, so
			// its zero span returns no canonical identity below.
			file = f.Location.File
		}
		if file != "" {
			if f.PrimaryAST.EndByte > f.PrimaryAST.StartByte {
				return matchedSiteIdentity{Span: matchedSiteSpan{
					File: file, ByByte: true, StartByte: f.PrimaryAST.StartByte, EndByte: f.PrimaryAST.EndByte,
				}, Kind: kind}, true
			}
			if preciseLineSpan(f.PrimaryAST.Start, f.PrimaryAST.StartCol, f.PrimaryAST.End, f.PrimaryAST.EndCol) {
				return matchedSiteIdentity{Span: matchedSiteSpan{
					File: file, StartLine: f.PrimaryAST.Start, StartCol: f.PrimaryAST.StartCol,
					EndLine: f.PrimaryAST.End, EndCol: f.PrimaryAST.EndCol,
				}, Kind: kind}, true
			}
		}
	}

	loc := f.Location
	if loc.File != "" && loc.EndByte > loc.StartByte {
		return matchedSiteIdentity{Span: matchedSiteSpan{
			File: loc.File, ByByte: true, StartByte: loc.StartByte, EndByte: loc.EndByte,
		}, Kind: kind}, true
	}
	if loc.File != "" && preciseLineSpan(loc.Line, loc.Col, loc.EndLine, loc.EndCol) {
		return matchedSiteIdentity{Span: matchedSiteSpan{
			File: loc.File, StartLine: loc.Line, StartCol: loc.Col, EndLine: loc.EndLine, EndCol: loc.EndCol,
		}, Kind: kind}, true
	}
	return matchedSiteIdentity{}, false
}

func finalReachabilityFile(f *Finding) string {
	if f == nil || f.Reachability == nil || len(f.Reachability.Steps) == 0 {
		return ""
	}
	return f.Reachability.Steps[len(f.Reachability.Steps)-1].File
}

func preciseLineSpan(startLine, startCol, endLine, endCol int) bool {
	return startLine > 0 && startCol > 0 && endLine > 0 && endCol > 0
}

func (e *Engine) executeQuery(tmpl *Template) []*Finding {
	e.logf("Executing template: %s (ID: %s, Scope: %s)", tmpl.Meta.Title, tmpl.Meta.ID, tmpl.Query.Scope)
	e.contractASTContract, e.contractASTRoot = nil, nil // fresh per Execute
	e.modifierDeclContract, e.modifierDeclByName = nil, nil
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

	e.logf("Template %s completed: Found %d findings", tmpl.Meta.ID, len(findings))
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
			e.logf("WARN: source-scope template %q: no content for %s (not serialized and file not readable); skipping — results may be incomplete", tmpl.Meta.ID, path)
			continue
		}
		for _, match := range re.FindAllStringIndex(content, -1) {
			loc := sourceMatchLocation(path, content, match[0], match[1])
			loc.Contract, loc.Function = e.lookupSourceLine(path, loc.Line)
			findings = append(findings, newFinding(tmpl, loc))
		}
	}
	return findings
}

// sourceMatchLocation converts a regexp's UTF-8 byte range into the source
// units used by findings: zero-based half-open bytes and one-based half-open
// Unicode-code-point columns.
func sourceMatchLocation(path, content string, startByte, endByte int) Location {
	if startByte < 0 {
		startByte = 0
	}
	if startByte > len(content) {
		startByte = len(content)
	}
	if endByte < startByte {
		endByte = startByte
	}
	if endByte > len(content) {
		endByte = len(content)
	}
	startLine, startCol := sourceEndpoint(content, startByte)
	endLine, endCol := sourceEndpoint(content, endByte)
	return Location{
		File:      path,
		Line:      startLine,
		Col:       startCol,
		EndLine:   endLine,
		EndCol:    endCol,
		StartByte: startByte,
		EndByte:   endByte,
	}
}

func sourceEndpoint(content string, byteOffset int) (line, col int) {
	prefix := content[:byteOffset]
	line = 1 + strings.Count(prefix, "\n")
	lineStart := strings.LastIndex(prefix, "\n") + 1
	col = utf8.RuneCountInString(content[lineStart:byteOffset]) + 1
	return line, col
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
			start, end := contractLineRange(contract, content)
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
	start, end := contractLineRange(contract, content)
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
		if e.currentFunction.SourceFile != "" {
			return e.sourceSnippet(e.currentFunction.SourceFile, node.StartLine, node.EndLine)
		}
		// Compatibility for schema-2.0.0 caches written before Function.SourceFile.
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

func contractLineRange(contract *types.Contract, content string) (int, int) {
	if contract != nil && contract.StartLine > 0 &&
		contract.EndLine >= contract.StartLine {
		return contract.StartLine, contract.EndLine
	}
	if contract == nil {
		return 0, 0
	}
	return sourceContractRange(content, contract.Name)
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
	e.logf("Executing %d templates", len(templates))
	var findings []*Finding
	for _, tmpl := range templates {
		findings = append(findings, e.Execute(tmpl)...)
	}
	SortFindings(findings)
	e.logf("All templates executed: Total %d findings", len(findings))
	return findings
}

// SortFindings imposes a deterministic total order on findings. Per-scope
// execution iterates Go maps (Database.Contracts/MainContracts) in randomized
// order, so without this the same scan emits the same finding set in a
// different order every run — producing noisy diffs and unstable
// findings.json/results.sarif. The key covers every field that distinguishes
// two findings; any pair that ties on all of them serializes identically, so
// their relative order cannot affect the output bytes.
func SortFindings(findings []*Finding) {
	astStart := func(f *Finding) int {
		if f.PrimaryAST != nil {
			return f.PrimaryAST.Start
		}
		return 0
	}
	astKind := func(f *Finding) string {
		if f.PrimaryAST != nil {
			return f.PrimaryAST.Kind
		}
		return ""
	}
	astName := func(f *Finding) string {
		if f.PrimaryAST != nil {
			return f.PrimaryAST.Name
		}
		return ""
	}
	// entryKey disambiguates findings for the same dangerous statement reached
	// via different entry points, and — via the full reachability signature —
	// two same-named contracts in different files that resolve to the same
	// display location. Without the per-hop file, those two distinct findings
	// tie and swap with map order.
	entryKey := func(f *Finding) string {
		var b strings.Builder
		if f.EntryPoint != nil {
			b.WriteString(f.EntryPoint.Contract)
			b.WriteByte('.')
			b.WriteString(f.EntryPoint.Function)
		}
		if f.Reachability != nil {
			for _, s := range f.Reachability.Steps {
				b.WriteByte('|')
				b.WriteString(s.File)
				b.WriteByte(':')
				b.WriteString(s.Contract)
				b.WriteByte('.')
				b.WriteString(s.Function)
				b.WriteByte('@')
				b.WriteString(strconv.Itoa(s.Line))
			}
		}
		return b.String()
	}
	sort.SliceStable(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if a.Location.File != b.Location.File {
			return a.Location.File < b.Location.File
		}
		if a.Location.Line != b.Location.Line {
			return a.Location.Line < b.Location.Line
		}
		if a.Location.Col != b.Location.Col {
			return a.Location.Col < b.Location.Col
		}
		if as, bs := astStart(a), astStart(b); as != bs {
			return as < bs
		}
		if a.TemplateID != b.TemplateID {
			return a.TemplateID < b.TemplateID
		}
		if a.Location.Contract != b.Location.Contract {
			return a.Location.Contract < b.Location.Contract
		}
		if a.Location.Function != b.Location.Function {
			return a.Location.Function < b.Location.Function
		}
		if ak, bk := astKind(a), astKind(b); ak != bk {
			return ak < bk
		}
		if an, bn := astName(a), astName(b); an != bn {
			return an < bn
		}
		if ea, eb := entryKey(a), entryKey(b); ea != eb {
			return ea < eb
		}
		return a.Message < b.Message
	})
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
		trace, matched := e.matchContractWithTrace(contract, tmpl.Query.Match)
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
		trace, matched := e.matchContractWithTrace(contract, tmpl.Query.Match)
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
		trace, matched := e.matchContractWithTrace(contract, tmpl.Query.Match)
		if matched {
			f := newFinding(tmpl, e.buildContractLocation(trace, contract))
			e.enrichFindingFromTrace(f, trace, nil, contract)
			e.enrichContractRelatedLocations(f, contract, tmpl.Query.Match)
			findings = append(findings, f)
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
			if fn == nil {
				continue
			}
			// Apply filter if present
			if tmpl.Query.Filter != nil {
				if !e.VerifyAtFunction(fn, *tmpl.Query.Filter, contract) {
					continue
				}
			}
			trace, matched := e.matchFunctionWithTrace(fn, contract, tmpl.Query.Match, false)
			if matched {
				locationFile := fn.SourceFile
				if locationFile == "" {
					locationFile = contract.SourceFile
				}
				f := newFinding(tmpl, e.buildLocation(trace, fn, contract, locationFile))
				e.enrichFindingFromTrace(f, trace, fn, contract)
				e.enrichFunctionRelatedLocations(f, fn, contract, tmpl.Query.Match, false)
				findings = append(findings, f)
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
			trace, matched := e.matchFunctionWithTrace(fn, contract, tmpl.Query.Match, true)
			if !matched {
				continue
			}
			loc := e.buildLocation(trace, fn, fnContract, locationFile)
			f := newFinding(tmpl, loc)
			e.enrichFindingFromTrace(f, trace, fn, fnContract)
			e.enrichFunctionRelatedLocations(f, fn, contract, tmpl.Query.Match, true)
			findings = append(findings, f)
		}

		e.currentSourceFile = nil
	}

	return findings
}

// matchFunctionWithTrace executes one function verifier path with an isolated
// provenance trace. The prior trace is always restored so nested enrichment
// attempts cannot leak state into the surrounding match.
func (e *Engine) matchFunctionWithTrace(fn *types.Function, contract *types.Contract, rule Rule, withCallees bool) (*matchTrace, bool) {
	trace := &matchTrace{}
	prior := e.match
	e.match = trace
	defer func() { e.match = prior }()

	matched := false
	if withCallees {
		matched = e.VerifyAtFunctionWithCallees(fn, rule, contract)
	} else {
		matched = e.VerifyAtFunction(fn, rule, contract)
	}
	if !matched {
		return nil, false
	}
	return trace, true
}

// matchContractWithTrace executes contract verification with an isolated
// provenance trace and restores any surrounding trace on return.
func (e *Engine) matchContractWithTrace(contract *types.Contract, rule Rule) (*matchTrace, bool) {
	trace := &matchTrace{}
	prior := e.match
	e.match = trace
	defer func() { e.match = prior }()

	if !e.VerifyAtContract(contract, rule) {
		return nil, false
	}
	return trace, true
}

// buildLocation chooses the Finding.Location fields based on the active
// LocationSource. With LocationSourceMatchedNode, the precise range comes from
// the matched AST node and host identity prefers the final trace hop; with
// LocationSourceVerifier (the default today) the function/contract come from
// the verifier-function context — preserving today's behavior for callers that
// haven't opted in.
func (e *Engine) buildLocation(trace *matchTrace, verifierFn *types.Function, verifierContract *types.Contract, fallbackFile string) Location {
	if trace != nil && trace.Primary != nil && e.locationSource() == LocationSourceMatchedNode {
		var hostName, hostContract, hostFile string
		if len(trace.Chain) > 0 {
			idx := len(trace.Chain) - 1
			if fn := trace.Chain[idx]; fn != nil {
				hostName = fn.Name
				hostContract = fn.ContractName
				hostFile = fn.SourceFile
			}
			if idx < len(trace.ChainContracts) && trace.ChainContracts[idx] != nil {
				if hostContract == "" {
					hostContract = trace.ChainContracts[idx].Name
				}
				if hostFile == "" {
					hostFile = trace.ChainContracts[idx].SourceFile
				}
			}
		}
		declName, declContract, declFile, _ := e.hostFunctionFor(trace.Primary)
		if hostName == "" {
			hostName = declName
		}
		if hostContract == "" {
			hostContract = declContract
		}
		if hostFile == "" {
			hostFile = declFile
		}
		if verifierFn != nil {
			if hostName == "" {
				hostName = verifierFn.Name
			}
			if hostContract == "" {
				hostContract = verifierFn.ContractName
			}
			if hostFile == "" {
				hostFile = verifierFn.SourceFile
			}
		}
		if verifierContract != nil {
			if hostContract == "" {
				hostContract = verifierContract.Name
			}
			if hostFile == "" {
				hostFile = verifierContract.SourceFile
			}
		}
		if hostFile == "" {
			hostFile = fallbackFile
		}
		loc := Location{File: hostFile, Contract: hostContract, Function: hostName, Line: trace.Primary.StartLine}
		applyNodeSpan(&loc, trace.Primary)
		return loc
	}
	// Default (today's behavior): verifier function/contract; matched-node line if available.
	loc := Location{File: fallbackFile}
	if verifierFn != nil {
		loc.Line = verifierFn.StartLine
		loc.Function = verifierFn.Name
		loc.Contract = verifierFn.ContractName
	}
	if trace != nil && trace.Primary != nil && trace.Primary.StartLine > 0 {
		loc.Line = trace.Primary.StartLine
		applyNodeSpan(&loc, trace.Primary)
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
	if trace.Primary.StartLine <= 0 {
		return loc
	}

	hostName, hostContract, hostFile, _ := e.hostFunctionFor(trace.Primary)
	if hostFile != "" {
		loc.File = hostFile
	}
	if hostContract != "" {
		loc.Contract = hostContract
	}
	if hostName != "" {
		loc.Function = hostName
	}
	loc.Line = trace.Primary.StartLine
	applyNodeSpan(&loc, trace.Primary)
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
			Kind:      trace.Primary.Kind,
			Name:      trace.Primary.Name,
			Start:     trace.Primary.StartLine,
			End:       trace.Primary.EndLine,
			StartCol:  trace.Primary.StartCol,
			EndCol:    trace.Primary.EndCol,
			StartByte: trace.Primary.StartByte,
			EndByte:   trace.Primary.EndByte,
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
				File:       stepFile(fn, chainContracts, i),
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

// stepFile returns the source file of the contract hosting hop i, or "" when
// the contract is unknown. Used so a cross-contract reachability chain can
// render each hop at its own file rather than the primary file.
func stepFile(fn *types.Function, chainContracts []*types.Contract, i int) string {
	if fn != nil && fn.SourceFile != "" {
		return fn.SourceFile
	}
	if i >= 0 && i < len(chainContracts) && chainContracts[i] != nil {
		return chainContracts[i].SourceFile
	}
	return ""
}

func (e *Engine) enrichFunctionRelatedLocations(f *Finding, fn *types.Function, contract *types.Contract, r Rule, withCallees bool) {
	if f == nil || fn == nil || len(r.All) == 0 {
		return
	}
	for i, branch := range r.All {
		trace, matched := e.matchFunctionWithTrace(fn, contract, branch, withCallees)
		if !matched || trace.Primary == nil {
			continue
		}
		f.Related = append(f.Related, e.relatedLocationFromTrace(trace, fn, contract, contractBranchLabel(branch, i)))
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
		for _, related := range e.collectContractRelatedLocations(root, contract, branch, label) {
			key := fmt.Sprintf("%s|%s|%s|%s|%s|%s|%d|%d|%d|%d|%d|%d",
				related.File, related.Contract, related.Function, related.Label, related.Kind, related.Name,
				related.Line, related.Col, related.EndLine, related.EndCol, related.StartByte, related.EndByte)
			if seen[key] {
				continue
			}
			seen[key] = true
			f.Related = append(f.Related, related)
		}
	}
}

func (e *Engine) collectContractRelatedLocations(root *types.ASTNode, contract *types.Contract, r Rule, label string) []RelatedLocation {
	rootTrace, rootMatched := e.matchASTWithTrace(root, r)
	if rootMatched && rootTrace.Primary == root {
		return []RelatedLocation{{
			Label:     label,
			File:      contract.SourceFile,
			Contract:  contract.Name,
			Line:      root.StartLine,
			Col:       root.StartCol,
			EndLine:   root.EndLine,
			EndCol:    root.EndCol,
			StartByte: root.StartByte,
			EndByte:   root.EndByte,
			Kind:      root.Kind,
			Name:      root.Name,
		}}
	}

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
			trace, matched := e.matchASTWithTrace(n, fnRules[i])
			if matched && trace.Primary != nil {
				out = append(out, e.relatedLocationFromTrace(trace, nil, nil, label))
				break
			}
		}
		return true
	})
	if len(out) == 0 && rootMatched && rootTrace.Primary != nil {
		return []RelatedLocation{e.relatedLocationFromTrace(rootTrace, nil, contract, label)}
	}
	return out
}

func (e *Engine) matchASTWithTrace(node *types.ASTNode, rule Rule) (*matchTrace, bool) {
	trace := &matchTrace{}
	prior := e.match
	e.match = trace
	defer func() { e.match = prior }()
	if !e.verify(node, rule) {
		return nil, false
	}
	return trace, true
}

func (e *Engine) relatedLocationFromTrace(trace *matchTrace, verifierFn *types.Function, verifierContract *types.Contract, label string) RelatedLocation {
	if trace == nil || trace.Primary == nil {
		return RelatedLocation{Label: label}
	}
	node := trace.Primary
	hostName, hostContract, hostFile, _ := e.hostFunctionFor(node)
	if len(trace.Chain) > 0 {
		idx := len(trace.Chain) - 1
		if fn := trace.Chain[idx]; fn != nil {
			hostName = fn.Name
			hostContract = fn.ContractName
			if fn.SourceFile != "" {
				hostFile = fn.SourceFile
			}
		}
		if idx < len(trace.ChainContracts) && trace.ChainContracts[idx] != nil {
			if hostContract == "" {
				hostContract = trace.ChainContracts[idx].Name
			}
			if hostFile == "" {
				hostFile = trace.ChainContracts[idx].SourceFile
			}
		}
	}
	if verifierFn != nil {
		if hostName == "" {
			hostName = verifierFn.Name
		}
		if hostContract == "" {
			hostContract = verifierFn.ContractName
		}
		if hostFile == "" {
			hostFile = verifierFn.SourceFile
		}
	}
	if verifierContract != nil {
		if hostContract == "" {
			hostContract = verifierContract.Name
		}
		if hostFile == "" {
			hostFile = verifierContract.SourceFile
		}
	}
	return RelatedLocation{
		Label:     label,
		File:      hostFile,
		Contract:  hostContract,
		Function:  hostName,
		Line:      node.StartLine,
		Col:       node.StartCol,
		EndLine:   node.EndLine,
		EndCol:    node.EndCol,
		StartByte: node.StartByte,
		EndByte:   node.EndByte,
		Kind:      node.Kind,
		Name:      node.Name,
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
	contract := e.db.GetContractByID(types.MakeContractID(filePath, contractName))
	if contract == nil && filePath == "" {
		// Compatibility for legacy/non-qualified IDs only. A qualified ID that
		// misses must not silently bind to a same-named contract in another file.
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
