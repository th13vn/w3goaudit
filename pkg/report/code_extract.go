package report

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/th13vn/w3goaudit/pkg/engine"
)

// extractCodeForFinding extracts relevant code for a finding, showing function name and matches.
//
// Defensive against stale or out-of-range line numbers: returns a clear error
// comment when the file is unreadable, line is 0, or the line is past EOF.
// Previously these conditions silently produced an empty code block.
func extractCodeForFinding(finding *engine.Finding, contextLines int) string {
	if finding.Location.File == "" {
		return "// Code context not available (no source file).\n"
	}
	if finding.Location.Line == 0 {
		return "// Code context not available (line unknown).\n"
	}

	file, err := os.Open(finding.Location.File)
	if err != nil {
		return fmt.Sprintf("// Unable to read source file: %s\n", finding.Location.File)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	// Allow long source lines; default 64KB chokes on minified or generated code.
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	currentLine := 0
	allLines := make(map[int]string)

	// Read entire file
	for scanner.Scan() {
		currentLine++
		allLines[currentLine] = scanner.Text()
	}

	// Bounds check: if the finding's line is past EOF, the source has changed
	// since the scan. Be honest about it instead of returning blank lines.
	if finding.Location.Line > currentLine {
		return fmt.Sprintf("// Line %d is past end of file (%d lines). Source may have changed since scan.\n",
			finding.Location.Line, currentLine)
	}

	var lines []string

	// Find and add function signature
	funcLine := 0
	if finding.Location.Function != "" {
		for line := finding.Location.Line; line > 0 && line > finding.Location.Line-50; line-- {
			text := allLines[line]
			if strings.Contains(text, "function "+finding.Location.Function) {
				funcLine = line
				lines = append(lines, fmt.Sprintf("  %s", text))
				break
			}
		}
	}

	targetLine := finding.Location.Line

	// Show more context to capture both external call and state change
	// For reentrancy: we want to show the call line and lines after (state changes)
	expandedContext := contextLines * 2 // Show more lines to catch the pattern

	linesToShow := []int{}

	// Include lines from function signature to well after target
	startLine := targetLine - 2
	if startLine < 1 {
		startLine = 1
	}
	if funcLine > 0 && funcLine < startLine {
		startLine = funcLine + 1 // Start right after function signature
	}

	endLine := targetLine + expandedContext

	for i := startLine; i <= endLine && i <= currentLine; i++ {
		if i != funcLine { // Don't duplicate function line
			linesToShow = append(linesToShow, i)
		}
	}

	// Add lines with gap indicators
	previousLine := funcLine
	if funcLine == 0 {
		previousLine = -10
	}

	for _, lineNum := range linesToShow {
		// Add gap if there's a significant jump (more than 1 line)
		if previousLine > 0 && lineNum > previousLine+1 {
			lines = append(lines, "    .\n    .\n    .")
		}

		prefix := "  "
		if lineNum == targetLine {
			prefix = "→ "
		}

		text := allLines[lineNum]
		lines = append(lines, fmt.Sprintf("%s%4d | %s", prefix, lineNum, text))
		previousLine = lineNum
	}

	if finding.Location.Function != "" {
		// Add gap and closing brace
		if len(linesToShow) > 0 && linesToShow[len(linesToShow)-1] < currentLine-2 {
			lines = append(lines, "    .\n    .\n    .")
		}
		lines = append(lines, "}")
	}

	return strings.Join(lines, "\n") + "\n"
}

func extractFullFunctionForLocation(location engine.Location) string {
	if location.File == "" {
		return "// Code context not available (no source file).\n"
	}
	if location.Line == 0 {
		return "// Code context not available (line unknown).\n"
	}

	allLines, totalLines, err := readSourceLines(location.File)
	if err != nil {
		return fmt.Sprintf("// Unable to read source file: %s\n", location.File)
	}
	if location.Line > totalLines {
		return fmt.Sprintf("// Line %d is past end of file (%d lines). Source may have changed since scan.\n",
			location.Line, totalLines)
	}

	start := location.Line
	if location.Function != "" {
		for line := location.Line; line > 0 && line > location.Line-80; line-- {
			if declaresFunction(allLines[line], location.Function) {
				start = line
				break
			}
		}
	}

	end := findBlockEnd(allLines, totalLines, start)
	if end == 0 {
		end = location.Line + 8
		if end > totalLines {
			end = totalLines
		}
	}

	lines := make([]string, 0, end-start+1)
	for i := start; i <= end; i++ {
		prefix := "  "
		if i == location.Line {
			prefix = "→ "
		}
		lines = append(lines, fmt.Sprintf("%s%4d | %s", prefix, i, allLines[i]))
	}
	return strings.Join(lines, "\n") + "\n"
}

// declaresFunction reports whether line declares `function <name>` with a word
// boundary after the name, so a search for `withdraw` does not match a line
// declaring `withdrawAll`.
func declaresFunction(line, name string) bool {
	needle := "function " + name
	idx := strings.Index(line, needle)
	if idx < 0 {
		return false
	}
	after := idx + len(needle)
	if after >= len(line) {
		return true
	}
	c := line[after]
	isIdent := c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
	return !isIdent
}

func readSourceLines(path string) (map[int]string, int, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	currentLine := 0
	allLines := make(map[int]string)
	for scanner.Scan() {
		currentLine++
		allLines[currentLine] = scanner.Text()
	}
	if err := scanner.Err(); err != nil {
		return nil, 0, err
	}
	return allLines, currentLine, nil
}

func findBlockEnd(lines map[int]string, totalLines, start int) int {
	depth := 0
	seenOpen := false
	for i := start; i <= totalLines; i++ {
		line := stripStringContent(stripLineCommentForReport(lines[i]))
		for _, r := range line {
			switch r {
			case '{':
				depth++
				seenOpen = true
			case '}':
				if seenOpen {
					depth--
					if depth == 0 {
						return i
					}
				}
			}
		}
	}
	return 0
}

func stripLineCommentForReport(line string) string {
	if idx := strings.Index(line, "//"); idx >= 0 {
		return line[:idx]
	}
	return line
}

func stripStringContent(line string) string {
	inString := false
	escaped := false
	quote := rune(0)
	out := make([]rune, 0, len(line))
	for _, r := range line {
		if inString {
			if escaped {
				escaped = false
				continue
			}
			if r == '\\' {
				escaped = true
				continue
			}
			if r == quote {
				inString = false
				quote = 0
			}
			continue
		}
		if r == '\'' || r == '"' {
			inString = true
			quote = r
			continue
		}
		out = append(out, r)
	}
	return string(out)
}
