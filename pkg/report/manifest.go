package report

import (
	"time"

	"github.com/th13vn/w3goaudit/pkg/engine"
)

// ManifestJSON is the machine-readable index of a result folder. A consumer
// reads this one file (data/manifest.json) to discover the tool, the scan
// scope, the finding tally, and the relative path of every other artifact —
// without having to walk the tree.
type ManifestJSON struct {
	SchemaVersion string         `json:"schemaVersion"`
	Tool          ToolMeta       `json:"tool"`
	GeneratedAt   time.Time      `json:"generatedAt"`
	Target        string         `json:"target,omitempty"`
	Counts        FindingsCounts `json:"counts"`
	Stats         ManifestStats  `json:"stats"`
	Files         ManifestFiles  `json:"files"`
	Contracts     []ContractRef  `json:"contracts"`
}

// ManifestStats is a compact project tally (the full stats live in overview.json).
type ManifestStats struct {
	Files         int `json:"files"`
	Contracts     int `json:"contracts"`
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
	Data     struct {
		Findings string `json:"findings"`
		Overview string `json:"overview"`
		Database string `json:"database"`
		Nav      string `json:"nav,omitempty"`
		Explorer string `json:"explorer,omitempty"`
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

// BuildManifest assembles the manifest from the summary, findings, and the
// pre-computed per-contract folder references.
func BuildManifest(tool ToolMeta, summary *SummaryReport, findings []*engine.Finding, contracts []ContractRef) *ManifestJSON {
	fj := BuildFindingsJSON(tool, findings)

	m := &ManifestJSON{
		SchemaVersion: SchemaVersion,
		Tool:          tool,
		GeneratedAt:   time.Now().UTC(),
		Target:        summary.ProjectRoot,
		Counts:        fj.Counts,
		Contracts:     contracts,
	}
	if summary.Stats != nil {
		m.Stats = ManifestStats{
			Files:         summary.Stats.TotalFiles,
			Contracts:     summary.Stats.TotalContracts + summary.Stats.TotalInterfaces + summary.Stats.TotalLibraries,
			Functions:     summary.Stats.TotalFunctions,
			MainContracts: len(summary.MainContracts),
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
	m.Files.Data.Database = "data/database.json"
	m.Files.Data.Nav = "data/nav.json"
	m.Files.Data.Explorer = "data/explorer.json"
	return m
}
