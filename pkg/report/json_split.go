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
	SchemaVersion    string               `json:"schemaVersion"`
	Tool             ToolMeta             `json:"tool"`
	GeneratedAt      time.Time            `json:"generatedAt"`
	ProjectRoot      string               `json:"projectRoot,omitempty"`
	ScanTarget       string               `json:"scanTarget,omitempty"`
	AnalysisComplete bool                 `json:"analysisComplete"`
	DiagnosticCounts DiagnosticCounts     `json:"diagnosticCounts"`
	Stats            *types.DatabaseStats `json:"stats"`
	Overview         *SummaryReport       `json:"overview"`
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

// BuildOverviewJSON constructs the overview JSON document using the current
// UTC time. Use BuildOverviewJSONAt when deterministic output is required.
func BuildOverviewJSON(tool ToolMeta, summary *SummaryReport, stats *types.DatabaseStats) *OverviewJSON {
	return BuildOverviewJSONAt(time.Now().UTC(), tool, summary, stats)
}

// BuildOverviewJSONAt constructs the overview JSON document at a
// caller-supplied timestamp.
func BuildOverviewJSONAt(now time.Time, tool ToolMeta, summary *SummaryReport, stats *types.DatabaseStats) *OverviewJSON {
	now = now.UTC()
	var overview *SummaryReport
	if summary != nil {
		copySummary := *summary
		copySummary.GeneratedAt = now
		overview = &copySummary
	}
	doc := &OverviewJSON{
		SchemaVersion: SchemaVersion,
		Tool:          tool,
		GeneratedAt:   now,
		Stats:         stats,
		Overview:      overview,
	}
	if overview != nil {
		doc.ProjectRoot = overview.ProjectRoot
		doc.ScanTarget = scanTarget(overview.ProjectRoot, overview.ScanTarget)
		doc.AnalysisComplete = summaryAnalysisComplete(overview)
		doc.DiagnosticCounts = overview.DiagnosticCounts
	}
	return doc
}

func summaryAnalysisComplete(summary *SummaryReport) bool {
	if summary == nil {
		return false
	}
	// Compatibility for callers that construct SummaryReport literals without
	// the additive completeness fields: zero diagnostics means complete.
	return summary.AnalysisComplete || diagnosticCountTotal(summary.DiagnosticCounts) == 0
}

func buildFindingsCounts(findings []*engine.Finding) FindingsCounts {
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
	return counts
}

// BuildFindingsJSON constructs the findings JSON document using the current
// UTC time. Use BuildFindingsJSONAt when deterministic output is required.
func BuildFindingsJSON(tool ToolMeta, findings []*engine.Finding) *FindingsJSON {
	return BuildFindingsJSONAt(time.Now().UTC(), tool, findings)
}

// BuildFindingsJSONAt constructs the findings JSON document with computed
// counts at a caller-supplied timestamp.
func BuildFindingsJSONAt(now time.Time, tool ToolMeta, findings []*engine.Finding) *FindingsJSON {
	counts := buildFindingsCounts(findings)
	if findings == nil {
		findings = []*engine.Finding{}
	}
	return &FindingsJSON{
		SchemaVersion: SchemaVersion,
		Tool:          tool,
		GeneratedAt:   now.UTC(),
		Counts:        counts,
		Findings:      findings,
	}
}
