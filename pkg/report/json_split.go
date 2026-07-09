package report

import (
	"time"

	"github.com/th13vn/w3goaudit/pkg/engine"
	"github.com/th13vn/w3goaudit/pkg/types"
)

// SchemaVersion is the version of the JSON output schema. Incremented on
// any breaking change to OverviewJSON or FindingsJSON. Consumers should
// check this and refuse to parse on a major-version mismatch.
const SchemaVersion = "2.0.0"

// OverviewJSON is the schema-stable shape of the overview half of the report.
// Mirrors the markdown/HTML overview: project stats, contracts, inheritance,
// call graphs — no findings.
type OverviewJSON struct {
	SchemaVersion string               `json:"schemaVersion"`
	Tool          ToolMeta             `json:"tool"`
	GeneratedAt   time.Time            `json:"generatedAt"`
	Stats         *types.DatabaseStats `json:"stats"`
	Overview      *SummaryReport       `json:"overview"`
}

// FindingsJSON is the schema-stable shape of the findings half of the report.
// Includes per-severity counts and an enriched finding list (refs/fix).
type FindingsJSON struct {
	SchemaVersion string            `json:"schemaVersion"`
	Tool          ToolMeta          `json:"tool"`
	GeneratedAt   time.Time         `json:"generatedAt"`
	Counts        FindingsCounts    `json:"counts"`
	Findings      []*engine.Finding `json:"findings"`
}

// ToolMeta identifies the tool and version that produced the output.
// Consumers (CI/CD, dashboards) use this to scope per-tool baselines.
type ToolMeta struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// FindingsCounts is a per-severity tally plus totals.
type FindingsCounts struct {
	Total       int `json:"total"`
	UniqueRules int `json:"uniqueRules"`
	Critical    int `json:"critical"`
	High        int `json:"high"`
	Medium      int `json:"medium"`
	Low         int `json:"low"`
	Info        int `json:"info"`
	Unknown     int `json:"unknown,omitempty"`
}

// BuildOverviewJSON constructs the overview JSON document.
func BuildOverviewJSON(tool ToolMeta, summary *SummaryReport, stats *types.DatabaseStats) *OverviewJSON {
	return &OverviewJSON{
		SchemaVersion: SchemaVersion,
		Tool:          tool,
		GeneratedAt:   time.Now().UTC(),
		Stats:         stats,
		Overview:      summary,
	}
}

// BuildFindingsJSON constructs the findings JSON document with computed counts.
func BuildFindingsJSON(tool ToolMeta, findings []*engine.Finding) *FindingsJSON {
	counts := FindingsCounts{
		Total:       len(findings),
		UniqueRules: countUniqueIssues(findings),
	}
	for sev, n := range countBySeverity(findings) {
		switch sev {
		case "CRITICAL":
			counts.Critical = n
		case "HIGH":
			counts.High = n
		case "MEDIUM":
			counts.Medium = n
		case "LOW":
			counts.Low = n
		case "INFO":
			counts.Info = n
		default:
			counts.Unknown += n
		}
	}
	if findings == nil {
		findings = []*engine.Finding{}
	}
	return &FindingsJSON{
		SchemaVersion: SchemaVersion,
		Tool:          tool,
		GeneratedAt:   time.Now().UTC(),
		Counts:        counts,
		Findings:      findings,
	}
}
