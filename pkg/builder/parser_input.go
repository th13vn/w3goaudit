package builder

import "strings"

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
