package report

import (
	"sort"

	"github.com/th13vn/w3goaudit/pkg/types"
)

const (
	unavailableHunterBoundaryLimitation = "external-boundary facts unavailable; rebuild the database from source"
	unavailableHunterAuthLimitation     = "authorization facts unavailable; rebuild the database from source"
	hunterAmbiguousAuthorization        = "hunter.authorization.ambiguous"
	hunterMissingAuthorization          = "hunter.authorization.missing"
	hunterUnresolvedEntry               = "hunter.entry.unresolved"
)

// HunterFactsVersions records the version of every fact family the ranking
// consumed, so a consumer can tell a model change from an evidence change.
type HunterFactsVersions struct {
	ExternalBoundary string `json:"externalBoundary,omitempty"`
	Authorization    string `json:"authorization,omitempty"`
}

// HunterEntry is one ranked (main contract, entry function) pair. The pair is
// the unit because an entry ID names the contract that DECLARES the function:
// keying by entry ID alone would collapse one inherited entry across several
// deployed contracts into a single wrong row.
type HunterEntry struct {
	Rank               int                       `json:"rank"`
	Tier               int                       `json:"tier"`
	TierName           string                    `json:"tierName"`
	EntryID            string                    `json:"entryId"`
	ContractID         string                    `json:"contractId"`
	ContractName       string                    `json:"contractName"`
	DeclaredContractID string                    `json:"declaredContractId"`
	FunctionSelector   string                    `json:"functionSelector"`
	Range              types.SemanticSourceRange `json:"range"`
	Payable            bool                      `json:"payable"`
	Signals            HunterSignals             `json:"signals"`
	BoundaryIDs        []string                  `json:"boundaryIds"`
	EvidenceComplete   bool                      `json:"evidenceComplete"`
	Limitations        []string                  `json:"limitations"`
}

// HunterJSON is the entry-point reading order. It is a projection of facts the
// scanner already computed, not a finding list: a high rank means "read this
// first", never "this is a vulnerability".
type HunterJSON struct {
	SchemaVersion    string              `json:"schemaVersion"`
	ModelVersion     string              `json:"modelVersion"`
	FactsVersions    HunterFactsVersions `json:"factsVersions"`
	Available        bool                `json:"available"`
	AnalysisComplete bool                `json:"analysisComplete"`
	DiagnosticCounts DiagnosticCounts    `json:"diagnosticCounts"`
	Count            int                 `json:"count"`
	Limitations      []string            `json:"limitations"`
	Entries          []*HunterEntry      `json:"entries"`
}

// BuildHunterJSON ranks every entry point from the versioned external-boundary
// and authorization facts without retaining aliases to the database. It is
// fail-closed: when either fact family is unavailable the artifact reports no
// entries and says why, rather than ranking from partial evidence.
func BuildHunterJSON(db *types.Database) *HunterJSON {
	diagnostics := diagnosticSnapshot(db)
	doc := &HunterJSON{
		SchemaVersion:    SchemaVersion,
		ModelVersion:     HunterModelVersion,
		AnalysisComplete: analysisComplete(diagnostics, db != nil),
		DiagnosticCounts: countDiagnostics(diagnostics),
		Limitations:      []string{},
		Entries:          []*HunterEntry{},
	}
	if db == nil {
		doc.Limitations = []string{unavailableHunterBoundaryLimitation, unavailableHunterAuthLimitation}
		return doc
	}
	boundaries, boundaryErr := db.ExternalBoundarySnapshot()
	if boundaryErr != nil {
		doc.Limitations = append(doc.Limitations, unavailableHunterBoundaryLimitation)
	}
	facts, authErr := db.AuthorizationFactsSnapshot()
	if authErr != nil {
		doc.Limitations = append(doc.Limitations, unavailableHunterAuthLimitation)
	}
	if boundaryErr != nil || authErr != nil {
		return doc
	}

	doc.Available = true
	doc.FactsVersions = HunterFactsVersions{
		ExternalBoundary: types.ExternalBoundaryFactsVersion,
		Authorization:    types.AuthorizationFactsVersion,
	}
	doc.Entries = newHunterIndex(boundaries, facts, diagnostics).rank(db)
	doc.Count = len(doc.Entries)
	return doc
}

// hunterIndex holds the join tables, built once per artifact.
type hunterIndex struct {
	byEntry   map[string][]*types.ExternalBoundaryFact
	byRuntime map[string][]*types.AuthorizationFact
	// agreed holds facts for declarations shared by several deployed
	// contracts whose runtimes all reached the same result. They carry no
	// RuntimeContractID and hold for every deployed contract that inherits
	// the declaration, which every row's contract does.
	agreed    map[string][]*types.AuthorizationFact
	lossyFile map[string]bool
}

func newHunterIndex(boundaries []*types.ExternalBoundaryFact, facts []*types.AuthorizationFact, diagnostics []types.Diagnostic) *hunterIndex {
	index := &hunterIndex{
		byEntry:   make(map[string][]*types.ExternalBoundaryFact),
		byRuntime: make(map[string][]*types.AuthorizationFact),
		agreed:    make(map[string][]*types.AuthorizationFact),
		lossyFile: make(map[string]bool),
	}
	for _, fact := range boundaries {
		if fact == nil {
			continue
		}
		for _, entryID := range fact.ReachableFrom {
			index.byEntry[entryID] = append(index.byEntry[entryID], fact)
		}
	}
	for _, fact := range facts {
		if fact == nil || fact.FunctionID == "" {
			continue
		}
		if fact.RuntimeContractID == "" && hunterContains(fact.Reasons, hunterAgreedRuntimes) {
			index.agreed[fact.FunctionID] = append(index.agreed[fact.FunctionID], fact)
			continue
		}
		key := hunterAuthorizationKey(fact.FunctionID, fact.RuntimeContractID)
		index.byRuntime[key] = append(index.byRuntime[key], fact)
	}
	for _, diagnostic := range diagnostics {
		if diagnostic.File != "" && (diagnostic.Incomplete || types.IsParseLoss(diagnostic.Code)) {
			index.lossyFile[diagnostic.File] = true
		}
	}
	return index
}

// hunterAgreedRuntimes is the authorization reason recorded when every runtime
// of a shared declaration reached the same result.
const hunterAgreedRuntimes = "runtime.alternatives.agree"

func hunterContains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func hunterAuthorizationKey(functionID, runtimeContractID string) string {
	return functionID + "\x00" + runtimeContractID
}

// rank builds one row per (main contract, entry function) pair and applies the
// model's total order.
func (index *hunterIndex) rank(db *types.Database) []*HunterEntry {
	contractIDs := make([]string, 0, len(db.MainContracts))
	for contractID := range db.MainContracts {
		contractIDs = append(contractIDs, contractID)
	}
	sort.Strings(contractIDs)

	entries := make([]*HunterEntry, 0, len(contractIDs))
	for _, contractID := range contractIDs {
		main := db.MainContracts[contractID]
		if main == nil {
			continue
		}
		entryIDs := append([]string(nil), main.EntryFunctions...)
		sort.Strings(entryIDs)
		for _, entryID := range entryIDs {
			entries = append(entries, index.row(db, contractID, entryID))
		}
	}

	sort.SliceStable(entries, func(i, j int) bool { return hunterLess(entries[i], entries[j]) })
	for position, entry := range entries {
		entry.Rank = position + 1
	}
	return entries
}

// hunterLess is the total order: tier ascending, then the signal tuple
// descending, then the row's own identity.
func hunterLess(a, b *HunterEntry) bool {
	if a.Tier != b.Tier {
		return a.Tier < b.Tier
	}
	left, right := hunterSignalTuple(a.Signals), hunterSignalTuple(b.Signals)
	for dimension := range left {
		if left[dimension] != right[dimension] {
			return left[dimension] > right[dimension]
		}
	}
	if a.EntryID != b.EntryID {
		return a.EntryID < b.EntryID
	}
	return a.ContractID < b.ContractID
}

// row projects one entry point. Every unproven input becomes a limitation plus
// a high ordinal, never a silent safe default.
func (index *hunterIndex) row(db *types.Database, contractID, entryID string) *HunterEntry {
	declaredFile, declaredContract, selector := types.ParseFunctionID(entryID)
	entry := &HunterEntry{
		EntryID:            entryID,
		ContractID:         contractID,
		DeclaredContractID: types.MakeContractID(declaredFile, declaredContract),
		FunctionSelector:   selector,
		BoundaryIDs:        []string{},
		Limitations:        []string{},
	}
	if contract := db.Contracts[contractID]; contract != nil {
		entry.ContractName = contract.Name
	} else {
		_, entry.ContractName = types.ParseContractID(contractID)
	}

	limitations := make(map[string]bool)
	if fn, ok := db.GetFunctionByID(entryID); ok && fn != nil {
		entry.Payable = fn.StateMutability == types.StateMutabilityPayable
		entry.Range = types.SemanticSourceRange{
			File:      fn.SourceFile,
			StartLine: fn.StartLine,
			StartCol:  fn.StartCol,
			EndLine:   fn.EndLine,
			EndCol:    fn.EndCol,
			StartByte: fn.StartByte,
			EndByte:   fn.EndByte,
		}
	} else {
		entry.Range = types.SemanticSourceRange{File: declaredFile}
		limitations[hunterUnresolvedEntry] = true
	}
	if index.lossyFile[entry.Range.File] || index.lossyFile[declaredFile] {
		limitations[types.DiagnosticParseRecovered] = true
	}

	boundaries := index.byEntry[entryID]
	entry.Signals = index.signals(entryID, contractID, boundaries, limitations)
	for _, fact := range boundaries {
		entry.BoundaryIDs = appendHunterFactID(entry.BoundaryIDs, fact.ID)
		for _, limitation := range fact.Limitations {
			limitations[limitation] = true
		}
	}

	entry.Tier, entry.TierName = hunterTier(entry.Signals, entry.Payable, len(boundaries) > 0)
	entry.Limitations = sortedHunterKeys(limitations)
	entry.EvidenceComplete = len(entry.Limitations) == 0
	return entry
}

// signals reduces the joined facts to the six ranked dimensions, keeping the
// strongest observation of each and citing the facts that produced it.
func (index *hunterIndex) signals(entryID, contractID string, boundaries []*types.ExternalBoundaryFact, limitations map[string]bool) HunterSignals {
	signals := HunterSignals{
		Authorization:    index.authorization(entryID, contractID, limitations),
		ValueReach:       newHunterSignal(),
		Reentry:          newHunterSignal(),
		StateAfterCall:   newHunterSignal(),
		TargetResolution: newHunterSignal(),
		ResultHandling:   newHunterSignal(),
	}

	for _, fact := range boundaries {
		if fact.Value != nil {
			raiseHunterSignal(&signals.ValueReach, string(fact.Value.Control), hunterValueOrdinal(fact.Value.Control), fact.ID)
		}
		raiseHunterSignal(&signals.Reentry, fact.ReentryClass, hunterReentryOrdinal(fact.ReentryClass), fact.ID)
		for _, effect := range fact.StateEffects {
			raiseHunterSignal(&signals.StateAfterCall, effect.Relation, hunterStateOrdinal(effect.Relation), fact.ID)
		}
		if fact.Target.Resolution == types.BoundaryTargetUnresolved {
			raiseHunterSignal(&signals.TargetResolution, types.BoundaryTargetUnresolved, 1, fact.ID)
		}
		if fact.Result.Availability == types.BoundaryResultYes &&
			(fact.Result.Disposition == types.BoundaryResultDiscarded || fact.Result.Disposition == types.BoundaryResultNone) {
			raiseHunterSignal(&signals.ResultHandling, fact.Result.Disposition, 1, fact.ID)
		}
	}
	return signals
}

// authorization resolves the verdict for this entry in this deployed contract.
// A missing or ambiguous binding is recorded as unknown, which ranks high.
func (index *hunterIndex) authorization(entryID, contractID string, limitations map[string]bool) HunterAuthorizationSignal {
	signal := HunterAuthorizationSignal{HunterSignal: HunterSignal{
		Value:   string(types.AuthorizationUnknown),
		Ordinal: hunterAuthorizationOrdinal(types.AuthorizationUnknown),
		FactIDs: []string{},
	}}
	matches := index.byRuntime[hunterAuthorizationKey(entryID, contractID)]
	if len(matches) == 0 {
		matches = index.agreed[entryID]
	}
	switch len(matches) {
	case 0:
		limitations[hunterMissingAuthorization] = true
	case 1:
		fact := matches[0]
		signal.Value = string(fact.Verdict)
		signal.Ordinal = hunterAuthorizationOrdinal(fact.Verdict)
		signal.Dominance = string(fact.Dominance)
		signal.PrincipalKind = string(fact.PrincipalKind)
		signal.FactIDs = appendHunterFactID(signal.FactIDs, fact.ID)
		for _, limitation := range fact.Limitations {
			limitations[limitation] = true
		}
	default:
		limitations[hunterAmbiguousAuthorization] = true
		for _, fact := range matches {
			signal.FactIDs = appendHunterFactID(signal.FactIDs, fact.ID)
		}
	}
	return signal
}

func sortedHunterKeys(set map[string]bool) []string {
	keys := make([]string, 0, len(set))
	for key := range set {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
