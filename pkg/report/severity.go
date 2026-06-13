package report

import "strings"

// SeverityOrder is the canonical highest-to-lowest severity order shared by
// every report format and the CLI's --fail-on threshold. Keeping a single
// exported source of truth avoids the four divergent copies this package
// previously carried.
var SeverityOrder = []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}

// SeverityRank returns a comparable rank for a severity label: CRITICAL=0 …
// INFO=4, with any unrecognized/empty severity ranking last. Lower rank means
// more severe, so `rank(a) <= rank(threshold)` means "at least as severe".
func SeverityRank(severity string) int {
	switch strings.ToUpper(strings.TrimSpace(severity)) {
	case "CRITICAL":
		return 0
	case "HIGH":
		return 1
	case "MEDIUM":
		return 2
	case "LOW":
		return 3
	case "INFO":
		return 4
	}
	return 5 // UNKNOWN / unrecognized — least severe
}

// SeverityAtLeast reports whether `severity` is at least as severe as
// `threshold` (used by --fail-on gating). An unrecognized threshold never
// trips, an unrecognized severity only trips a threshold that is itself
// unrecognized.
func SeverityAtLeast(severity, threshold string) bool {
	return SeverityRank(severity) <= SeverityRank(threshold)
}

// IsKnownSeverity reports whether s is one of the canonical severity labels.
func IsKnownSeverity(s string) bool {
	return SeverityRank(s) < len(SeverityOrder)
}

// renderSeverityOrder returns the severity buckets to render: the known
// severities in order, plus "UNKNOWN" appended when any group carries an
// unrecognized severity. Without the UNKNOWN bucket, a finding with a typo'd
// severity is grouped but never rendered (it silently vanishes from the
// Markdown/HTML report while still showing on the console).
func renderSeverityOrder(grouped map[string][]*GroupedFinding) []string {
	order := make([]string, len(SeverityOrder))
	copy(order, SeverityOrder)
	if len(grouped["UNKNOWN"]) > 0 {
		order = append(order, "UNKNOWN")
	}
	return order
}
