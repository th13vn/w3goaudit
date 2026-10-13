package builder

import (
	"regexp"
	"strings"
)

const (
	parserCode = iota
	parserQuoted
	parserLineComment
	parserBlockComment
)

// normalizeYulAssignmentsForParser works around solast-go v0.1.7 tokenizing
// Yul's := as COLON followed by ASSIGN while its assembly parser expects only
// ASSIGN. Replacing the colon with one ASCII space lets the parser produce the
// existing AssemblyAssignment/AssemblyLocalDefinition nodes without changing
// any byte offset or line/column position. The original SourceFile.Content is
// retained everywhere else.
//
// Only real inline `assembly { ... }` regions are rewritten. Quoted strings,
// comments, and ordinary Solidity code are deliberately left untouched so an
// invalid Solidity `x := 1` remains invalid and still produces parse diagnostics.
func normalizeYulAssignmentsForParser(source string) string {
	if !strings.Contains(source, ":=") || !strings.Contains(source, "assembly") {
		return source
	}

	normalizer := yulAssignmentNormalizer{source: []byte(source)}
	for normalizer.index < len(normalizer.source) {
		normalizer.advance()
	}
	return string(normalizer.source)
}

// normalizeLegacyFunctionModifiersForParser adapts Solidity 0.4.x's
// `constant` function mutability keyword to the `view` spelling accepted by
// solast-go. Only standalone tokens in function declaration headers are
// rewritten; state-variable declarations such as `string constant name` and
// function-body occurrences remain untouched. Replacing `constant` with
// `view` plus spaces preserves every byte offset reported by the parser.
func normalizeLegacyFunctionModifiersForParser(source string) string {
	if !strings.Contains(source, "constant") || !strings.Contains(source, "function") || !legacyPragmaInSource(source) {
		return source
	}
	buf := []byte(source)
	masked := maskParserProtectedText(source)
	for i := 0; i < len(masked); {
		if !isParserIdentifierStart(masked[i]) {
			i++
			continue
		}
		start := i
		for i < len(masked) && isParserIdentifierPart(masked[i]) {
			i++
		}
		if string(masked[start:i]) != "function" {
			continue
		}
		end := functionHeaderEnd(masked, i)
		if end <= i {
			continue
		}
		normalizeConstantTokens(buf, masked, i, end)
		i = end
	}
	return string(buf)
}

func maskParserProtectedText(source string) []byte {
	masked := []byte(source)
	state := parserCode
	var quote byte
	for i := 0; i < len(masked); i++ {
		switch state {
		case parserQuoted:
			if masked[i] == '\\' {
				if i+1 < len(masked) && masked[i+1] != '\n' && masked[i+1] != '\r' {
					masked[i], masked[i+1] = ' ', ' '
					i++
				}
				continue
			}
			if masked[i] == quote {
				masked[i] = ' '
				state = parserCode
			} else if masked[i] != '\n' && masked[i] != '\r' {
				masked[i] = ' '
			}
		case parserLineComment:
			if masked[i] == '\n' || masked[i] == '\r' {
				state = parserCode
			} else {
				masked[i] = ' '
			}
		case parserBlockComment:
			if masked[i] == '*' && i+1 < len(masked) && masked[i+1] == '/' {
				masked[i], masked[i+1] = ' ', ' '
				i++
				state = parserCode
			} else if masked[i] != '\n' && masked[i] != '\r' {
				masked[i] = ' '
			}
		default:
			if masked[i] == '/' && i+1 < len(masked) && masked[i+1] == '/' {
				masked[i], masked[i+1] = ' ', ' '
				i++
				state = parserLineComment
			} else if masked[i] == '/' && i+1 < len(masked) && masked[i+1] == '*' {
				masked[i], masked[i+1] = ' ', ' '
				i++
				state = parserBlockComment
			} else if masked[i] == '\'' || masked[i] == '"' {
				quote = masked[i]
				masked[i] = ' '
				state = parserQuoted
			}
		}
	}
	return masked
}

var solidityPragmaInSourcePattern = regexp.MustCompile(`(?m)\bpragma\s+solidity\s+([^;]+);`)

func legacyPragmaInSource(source string) bool {
	masked := maskParserProtectedText(source)
	matches := solidityPragmaInSourcePattern.FindAllSubmatch(masked, -1)
	if len(matches) == 0 {
		return false
	}
	for _, match := range matches {
		if len(match) != 2 || !legacyPragmaBefore05(string(match[1])) {
			return false
		}
	}
	return true
}

func functionHeaderEnd(source []byte, start int) int {
	state := parserCode
	var quote byte
	parenDepth := 0
	for i := start; i < len(source); i++ {
		switch state {
		case parserQuoted:
			if source[i] == '\\' {
				i++
				continue
			}
			if source[i] == quote {
				state = parserCode
			}
		case parserLineComment:
			if source[i] == '\n' {
				state = parserCode
			}
		case parserBlockComment:
			if source[i] == '*' && i+1 < len(source) && source[i+1] == '/' {
				i++
				state = parserCode
			}
		default:
			if source[i] == '/' && i+1 < len(source) && source[i+1] == '/' {
				i++
				state = parserLineComment
				continue
			}
			if source[i] == '/' && i+1 < len(source) && source[i+1] == '*' {
				i++
				state = parserBlockComment
				continue
			}
			if source[i] == '\'' || source[i] == '"' {
				quote = source[i]
				state = parserQuoted
				continue
			}
			switch source[i] {
			case '(':
				parenDepth++
			case ')':
				if parenDepth > 0 {
					parenDepth--
				}
			case '{', ';':
				if parenDepth == 0 {
					return i
				}
			}
		}
	}
	return len(source)
}

func normalizeConstantTokens(source, masked []byte, start, end int) {
	for i := start; i < end; {
		if !isParserIdentifierStart(masked[i]) {
			i++
			continue
		}
		wordStart := i
		for i < end && isParserIdentifierPart(masked[i]) {
			i++
		}
		if i-wordStart != len("constant") || string(masked[wordStart:i]) != "constant" {
			continue
		}
		copy(source[wordStart:wordStart+len("view")], "view")
		for j := wordStart + len("view"); j < i; j++ {
			source[j] = ' '
		}
	}
}

type yulAssignmentNormalizer struct {
	source          []byte
	index           int
	state           int
	quote           byte
	braceDepth      int
	assemblyDepths  []int
	pendingAssembly bool
}

func (n *yulAssignmentNormalizer) advance() {
	skip := 0
	switch n.state {
	case parserCode:
		skip = n.advanceCode()
	case parserQuoted:
		skip = n.advanceQuoted()
	case parserLineComment:
		n.advanceLineComment()
	case parserBlockComment:
		skip = n.advanceBlockComment()
	}
	n.index += skip + 1
}

func (n *yulAssignmentNormalizer) advanceCode() int {
	current := n.source[n.index]
	switch {
	case n.hasNext('/', '/'):
		n.state = parserLineComment
		return 1
	case n.hasNext('/', '*'):
		n.state = parserBlockComment
		return 1
	case current == '"' || current == '\'':
		n.quote = current
		n.state = parserQuoted
	case isParserIdentifierStart(current):
		return n.advanceIdentifier()
	case current == '{':
		n.openBrace()
	case current == '}':
		n.closeBrace()
	case n.hasNext(':', '=') && len(n.assemblyDepths) > 0:
		n.source[n.index] = ' '
		return 1
	case n.pendingAssembly && !isAssemblyDialectSeparator(current):
		n.pendingAssembly = false
	}
	return 0
}

func (n *yulAssignmentNormalizer) advanceIdentifier() int {
	end := n.index + 1
	for end < len(n.source) && isParserIdentifierPart(n.source[end]) {
		end++
	}
	word := string(n.source[n.index:end])
	if word == "assembly" && len(n.assemblyDepths) == 0 {
		n.pendingAssembly = true
	} else if n.pendingAssembly {
		// Only an optional quoted dialect in parentheses may appear before `{`.
		n.pendingAssembly = false
	}
	return end - n.index - 1
}

func (n *yulAssignmentNormalizer) openBrace() {
	n.braceDepth++
	if n.pendingAssembly {
		n.assemblyDepths = append(n.assemblyDepths, n.braceDepth)
		n.pendingAssembly = false
	}
}

func (n *yulAssignmentNormalizer) closeBrace() {
	last := len(n.assemblyDepths) - 1
	if last >= 0 && n.assemblyDepths[last] == n.braceDepth {
		n.assemblyDepths = n.assemblyDepths[:last]
	}
	if n.braceDepth > 0 {
		n.braceDepth--
	}
	n.pendingAssembly = false
}

func (n *yulAssignmentNormalizer) advanceQuoted() int {
	if n.source[n.index] == '\\' && n.index+1 < len(n.source) {
		return 1
	}
	if n.source[n.index] == n.quote {
		n.state = parserCode
	}
	return 0
}

func (n *yulAssignmentNormalizer) advanceLineComment() {
	if n.source[n.index] == '\n' {
		n.state = parserCode
	}
}

func (n *yulAssignmentNormalizer) advanceBlockComment() int {
	if n.hasNext('*', '/') {
		n.state = parserCode
		return 1
	}
	return 0
}

func (n *yulAssignmentNormalizer) hasNext(first, second byte) bool {
	return n.source[n.index] == first && n.index+1 < len(n.source) && n.source[n.index+1] == second
}

func isAssemblyDialectSeparator(ch byte) bool {
	return ch == '(' || ch == ')' || ch == ',' || isParserWhitespace(ch)
}

func isParserIdentifierStart(ch byte) bool {
	return ch == '_' || ch == '$' || ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z'
}

func isParserIdentifierPart(ch byte) bool {
	return isParserIdentifierStart(ch) || ch >= '0' && ch <= '9'
}

func isParserWhitespace(ch byte) bool {
	return ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n'
}
