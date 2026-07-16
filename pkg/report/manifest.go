package report

import (
	"time"

	"github.com/th13vn/w3goaudit/pkg/engine"
	"github.com/th13vn/w3goaudit/pkg/types"
)

// ManifestJSON is the machine-readable index of a result folder. A consumer
// reads this one file (data/manifest.json) to discover the tool, the scan
// scope, the finding tally, and the relative path of every other artifact —
// without having to walk the tree.
type ManifestJSON struct {
	SchemaVersion    string           `json:"schemaVersion"`
	Tool             ToolMeta         `json:"tool"`
	GeneratedAt      time.Time        `json:"generatedAt"`
	Target           string           `json:"target,omitempty"`
	ProjectRoot      string           `json:"projectRoot,omitempty"`
	ScanTarget       string           `json:"scanTarget,omitempty"`
	AnalysisComplete bool             `json:"analysisComplete"`
	DiagnosticCounts DiagnosticCounts `json:"diagnosticCounts"`
	Counts           FindingsCounts   `json:"counts"`
	Stats            ManifestStats    `json:"stats"`
	Files            ManifestFiles    `json:"files"`
	Contracts        []ContractRef    `json:"contracts"`
}

// ManifestStats is a compact project tally (the full stats live in overview.json).
type ManifestStats struct {
	Files         int `json:"files"`
	Contracts     int `json:"contracts"`
	Interfaces    int `json:"interfaces"`
	Libraries     int `json:"libraries"`
	Declarations  int `json:"declarations"`
	Functions     int `json:"functions"`
	MainContracts int `json:"mainContracts"`
}

// ManifestFiles lists the result-folder artifacts by relative path.
type ManifestFiles struct {
	Readme   string `json:"readme"`
	Summary  string `json:"summary"`
	Findings string `json:"findings"`
	Overview string `json:"overview"`
	Sarif    string `json:"sarif"`
	Log      string `json:"log"`
	// OverviewHTML and FindingsHTML are present only when BundleOptions.HTML
	// caused those optional artifacts to be emitted.
	OverviewHTML string `json:"overviewHtml,omitempty"`
	FindingsHTML string `json:"findingsHtml,omitempty"`
	Data         struct {
		Findings    string `json:"findings"`
		Overview    string `json:"overview"`
		Diagnostics string `json:"diagnostics"`
		Database    string `json:"database"`
		Nav         string `json:"nav,omitempty"`
		Explorer    string `json:"explorer,omitempty"`
	} `json:"data"`
}

// ContractRef indexes one in-scope main contract: its name, source file, folder,
// and per-severity finding tally.
type ContractRef struct {
	Name     string `json:"name"`
	Source   string `json:"source"`
	Dir      string `json:"dir"`
	Findings int    `json:"findings"`
}

// BuildManifest assembles a compatibility manifest using the current UTC time.
// Use BuildManifestAt with the database when exact scan scope, diagnostics,
// declaration categories, and optional artifact indexing are required.
func BuildManifest(tool ToolMeta, summary *SummaryReport, findings []*engine.Finding, contracts []ContractRef) *ManifestJSON {
	return BuildManifestAt(time.Now().UTC(), tool, summary, findings, contracts, nil, false)
}

// BuildManifestAt assembles the manifest from the summary, findings, database,
// and pre-computed per-contract folder references at a caller-supplied time.
func BuildManifestAt(now time.Time, tool ToolMeta, summary *SummaryReport, findings []*engine.Finding, contracts []ContractRef, db *types.Database, html bool) *ManifestJSON {
	if contracts == nil {
		contracts = []ContractRef{}
	}
	projectRoot, selectedTarget := "", ""
	complete := false
	var diagnosticCounts DiagnosticCounts
	var stats *types.DatabaseStats
	mainContracts := 0
	if summary != nil {
		projectRoot = summary.ProjectRoot
		selectedTarget = scanTarget(projectRoot, summary.ScanTarget)
		complete = summaryAnalysisComplete(summary)
		diagnosticCounts = summary.DiagnosticCounts
		stats = summary.Stats
		mainContracts = len(summary.MainContracts)
	}
	if db != nil {
		if db.ProjectRoot != "" || projectRoot == "" {
			projectRoot = db.ProjectRoot
		}
		selectedTarget = scanTarget(projectRoot, db.ScanTarget)
		diagnostics := diagnosticSnapshot(db)
		complete = analysisComplete(diagnostics, true)
		diagnosticCounts = countDiagnostics(diagnostics)
		stats = db.GetStats()
		mainContracts = len(db.MainContracts)
	}

	m := &ManifestJSON{
		SchemaVersion:    SchemaVersion,
		Tool:             tool,
		GeneratedAt:      now.UTC(),
		Target:           selectedTarget,
		ProjectRoot:      projectRoot,
		ScanTarget:       selectedTarget,
		AnalysisComplete: complete,
		DiagnosticCounts: diagnosticCounts,
		Counts:           buildFindingsCounts(findings),
		Contracts:        contracts,
	}
	if stats != nil {
		m.Stats = ManifestStats{
			Files:         stats.TotalFiles,
			Contracts:     stats.TotalContracts,
			Interfaces:    stats.TotalInterfaces,
			Libraries:     stats.TotalLibraries,
			Declarations:  stats.TotalContracts + stats.TotalInterfaces + stats.TotalLibraries,
			Functions:     stats.TotalFunctions,
			MainContracts: mainContracts,
		}
	}
	m.Files.Readme = "README.md"
	m.Files.Summary = "summary.md"
	m.Files.Findings = "findings.md"
	m.Files.Overview = "overview.md"
	m.Files.Sarif = "results.sarif"
	m.Files.Log = "run.log"
	m.Files.Data.Findings = "data/findings.json"
	m.Files.Data.Overview = "data/overview.json"
	m.Files.Data.Diagnostics = "data/diagnostics.json"
	m.Files.Data.Database = "data/database.json"
	m.Files.Data.Nav = "data/nav.json"
	m.Files.Data.Explorer = "data/explorer.json"
	if html {
		m.Files.OverviewHTML = "overview.html"
		m.Files.FindingsHTML = "findings.html"
	}
	return m
}
