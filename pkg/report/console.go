package report

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/th13vn/w3goaudit/pkg/engine"
)

// ColorMode controls ANSI color output. The CLI sets this once at startup
// based on TTY detection and the --no-color flag, then console-rendering
// helpers consult it.
type ColorMode int

const (
	// ColorAuto enables color only when stdout is a TTY and NO_COLOR is unset.
	ColorAuto ColorMode = iota
	// ColorAlways forces color even when piped.
	ColorAlways
	// ColorNever disables color regardless of environment.
	ColorNever
)

// IsTerminal reports whether w writes to a terminal. Used by ColorAuto.
// Pure stdlib — no extra dependency for one-byte detection.
func IsTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return (info.Mode() & os.ModeCharDevice) != 0
}

// resolveColor decides whether color should be emitted for the given writer.
// NO_COLOR (any non-empty value) always wins per https://no-color.org.
func resolveColor(w io.Writer, mode ColorMode) bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	switch mode {
	case ColorNever:
		return false
	case ColorAlways:
		return true
	default:
		return IsTerminal(w)
	}
}

// ANSI palette. Kept tiny: enough for severity and structural emphasis.
const (
	ansiReset  = "\x1b[0m"
	ansiBold   = "\x1b[1m"
	ansiDim    = "\x1b[2m"
	ansiRed    = "\x1b[31m"
	ansiOrange = "\x1b[38;5;208m"
	ansiYellow = "\x1b[33m"
	ansiBlue   = "\x1b[34m"
	ansiCyan   = "\x1b[36m"
	ansiGray   = "\x1b[90m"
)

// Colorize wraps s in ANSI codes only if enabled is true. Callers compute
// `enabled` once via resolveColor and pass it in.
func Colorize(s, code string, enabled bool) string {
	if !enabled || code == "" {
		return s
	}
	return code + s + ansiReset
}

// SeverityColor returns the ANSI code for a given severity (or empty if disabled).
func SeverityColor(severity string, enabled bool) string {
	if !enabled {
		return ""
	}
	switch strings.ToUpper(severity) {
	case "CRITICAL":
		return ansiRed + ansiBold
	case "HIGH":
		return ansiOrange
	case "MEDIUM":
		return ansiYellow
	case "LOW":
		return ansiBlue
	case "INFO":
		return ansiCyan
	default:
		return ansiGray
	}
}

// PrintConsoleSummaryHeader prints a one-line "N findings: a HIGH, b MEDIUM..."
// header at the top of console output. Called before per-section rendering.
// elapsed is the scan duration (caller computes — pass "" to omit).
func PrintConsoleSummaryHeader(w io.Writer, findings []*engine.Finding, contractCount int, elapsed string, mode ColorMode) {
	enabled := resolveColor(w, mode)
	bold := func(s string) string { return Colorize(s, ansiBold, enabled) }

	if len(findings) == 0 {
		msg := bold("No findings.")
		if elapsed != "" {
			msg += Colorize(fmt.Sprintf(" · scanned %d contracts in %s", contractCount, elapsed), ansiDim, enabled)
		}
		fmt.Fprintln(w, msg)
		return
	}

	bySev := countBySeverity(findings)

	parts := []string{}
	for _, sev := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"} {
		if n := bySev[sev]; n > 0 {
			label := fmt.Sprintf("%d %s", n, sev)
			parts = append(parts, Colorize(label, SeverityColor(sev, enabled), enabled))
		}
	}

	header := fmt.Sprintf("%s findings: %s",
		bold(fmt.Sprintf("%d", len(findings))),
		strings.Join(parts, ", "),
	)
	if elapsed != "" {
		header += Colorize(fmt.Sprintf(" · scanned %d contracts in %s", contractCount, elapsed), ansiDim, enabled)
	}
	fmt.Fprintln(w, header)
}
