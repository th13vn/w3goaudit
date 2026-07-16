package reader

import "strings"

type importTokenKind uint8

const (
	importTokenIdentifier importTokenKind = iota
	importTokenString
	importTokenSymbol
)

type importToken struct {
	kind    importTokenKind
	text    string
	end     int
	invalid bool
}

// extractImports returns import paths from syntactically valid Solidity import
// directives. The lightweight lexer consumes comments and string literals as
// whole tokens so import-shaped text inside either cannot create diagnostics.
func extractImports(content string) []string {
	imports := make([]string, 0)
	seen := make(map[string]struct{})

	for pos := 0; ; {
		tok, ok := nextImportToken(content, pos)
		if !ok {
			break
		}
		pos = tok.end
		if tok.kind != importTokenIdentifier || tok.text != "import" {
			continue
		}

		importPath, end, ok := parseImportDirective(content, pos)
		if !ok {
			continue
		}
		pos = end
		if _, exists := seen[importPath]; exists {
			continue
		}
		seen[importPath] = struct{}{}
		imports = append(imports, importPath)
	}

	return imports
}

func parseImportDirective(content string, start int) (string, int, bool) {
	pos := start
	first, ok := consumeImportToken(content, &pos)
	if !ok {
		return "", start, false
	}

	switch {
	case first.kind == importTokenString && !first.invalid:
		return parsePathImport(content, pos, first.text)
	case tokenIs(first, importTokenSymbol, "*"):
		return parseNamespaceImport(content, pos)
	case tokenIs(first, importTokenSymbol, "{"):
		return parseNamedImport(content, pos)
	case first.kind == importTokenIdentifier:
		return parseLegacyAliasImport(content, pos)
	default:
		return "", start, false
	}
}

func parsePathImport(content string, pos int, importPath string) (string, int, bool) {
	if importPath == "" {
		return "", pos, false
	}
	next, ok := consumeImportToken(content, &pos)
	if !ok {
		return "", pos, false
	}
	if tokenIs(next, importTokenSymbol, ";") {
		return importPath, pos, true
	}
	if !tokenIs(next, importTokenIdentifier, "as") || !consumeIdentifier(content, &pos) {
		return "", pos, false
	}
	return finishImport(content, pos, importPath)
}

func parseNamespaceImport(content string, pos int) (string, int, bool) {
	if !consumeKeyword(content, &pos, "as") || !consumeIdentifier(content, &pos) ||
		!consumeKeyword(content, &pos, "from") {
		return "", pos, false
	}
	return consumeImportPathAndSemicolon(content, pos)
}

func parseNamedImport(content string, pos int) (string, int, bool) {
	if !consumeIdentifier(content, &pos) {
		return "", pos, false
	}

	for {
		next, ok := consumeImportToken(content, &pos)
		if !ok {
			return "", pos, false
		}
		if tokenIs(next, importTokenIdentifier, "as") {
			if !consumeIdentifier(content, &pos) {
				return "", pos, false
			}
			next, ok = consumeImportToken(content, &pos)
			if !ok {
				return "", pos, false
			}
		}
		if tokenIs(next, importTokenSymbol, "}") {
			break
		}
		if !tokenIs(next, importTokenSymbol, ",") || !consumeIdentifier(content, &pos) {
			return "", pos, false
		}
	}

	if !consumeKeyword(content, &pos, "from") {
		return "", pos, false
	}
	return consumeImportPathAndSemicolon(content, pos)
}

func parseLegacyAliasImport(content string, pos int) (string, int, bool) {
	if !consumeKeyword(content, &pos, "from") {
		return "", pos, false
	}
	return consumeImportPathAndSemicolon(content, pos)
}

func consumeImportPathAndSemicolon(content string, pos int) (string, int, bool) {
	path, ok := consumeImportToken(content, &pos)
	if !ok || path.kind != importTokenString || path.invalid || path.text == "" {
		return "", pos, false
	}
	return finishImport(content, pos, path.text)
}

func finishImport(content string, pos int, importPath string) (string, int, bool) {
	semicolon, ok := consumeImportToken(content, &pos)
	if !ok || !tokenIs(semicolon, importTokenSymbol, ";") {
		return "", pos, false
	}
	return importPath, pos, true
}

func consumeKeyword(content string, pos *int, keyword string) bool {
	tok, ok := consumeImportToken(content, pos)
	return ok && tokenIs(tok, importTokenIdentifier, keyword)
}

func consumeIdentifier(content string, pos *int) bool {
	tok, ok := consumeImportToken(content, pos)
	return ok && tok.kind == importTokenIdentifier
}

func consumeImportToken(content string, pos *int) (importToken, bool) {
	tok, ok := nextImportToken(content, *pos)
	if ok {
		*pos = tok.end
	}
	return tok, ok
}

func nextImportToken(content string, start int) (importToken, bool) {
	for pos := start; pos < len(content); {
		switch {
		case isSolidityWhitespace(content[pos]):
			pos++
		case content[pos] == '/' && pos+1 < len(content) && content[pos+1] == '/':
			pos = skipLineComment(content, pos+2)
		case content[pos] == '/' && pos+1 < len(content) && content[pos+1] == '*':
			pos = skipBlockComment(content, pos+2)
		case isSolidityIdentifierStart(content[pos]):
			end := pos + 1
			for end < len(content) && isSolidityIdentifierPart(content[end]) {
				end++
			}
			return importToken{kind: importTokenIdentifier, text: content[pos:end], end: end}, true
		case content[pos] == '"' || content[pos] == '\'':
			return scanImportString(content, pos)
		default:
			return importToken{kind: importTokenSymbol, text: content[pos : pos+1], end: pos + 1}, true
		}
	}
	return importToken{}, false
}

func skipLineComment(content string, pos int) int {
	for pos < len(content) && content[pos] != '\n' {
		pos++
	}
	return pos
}

func skipBlockComment(content string, pos int) int {
	for pos+1 < len(content) {
		if content[pos] == '*' && content[pos+1] == '/' {
			return pos + 2
		}
		pos++
	}
	return len(content)
}

func scanImportString(content string, start int) (importToken, bool) {
	quote := content[start]
	for pos := start + 1; pos < len(content); pos++ {
		if content[pos] == '\\' && pos+1 < len(content) {
			pos++
			continue
		}
		if content[pos] == quote {
			decoded, valid := decodeSolidityImportString(content[start+1 : pos])
			return importToken{kind: importTokenString, text: decoded, end: pos + 1, invalid: !valid}, true
		}
	}
	return importToken{kind: importTokenString, end: len(content), invalid: true}, true
}

// decodeSolidityImportString implements the escape grammar used by Solidity's
// ordinary quoted string literals. Escaped physical line breaks are removed;
// malformed escapes and raw non-printable/non-ASCII bytes are rejected.
func decodeSolidityImportString(raw string) (string, bool) {
	var decoded strings.Builder
	decoded.Grow(len(raw))

	for pos := 0; pos < len(raw); {
		ch := raw[pos]
		if ch != '\\' {
			if ch < 0x20 || ch > 0x7e {
				return "", false
			}
			decoded.WriteByte(ch)
			pos++
			continue
		}

		pos++
		if pos >= len(raw) {
			return "", false
		}
		switch raw[pos] {
		case '\'', '"', '\\':
			decoded.WriteByte(raw[pos])
			pos++
		case 'n':
			decoded.WriteByte('\n')
			pos++
		case 'r':
			decoded.WriteByte('\r')
			pos++
		case 't':
			decoded.WriteByte('\t')
			pos++
		case '\n':
			pos++
		case '\r':
			pos++
			if pos < len(raw) && raw[pos] == '\n' {
				pos++
			}
		case 'x':
			if pos+2 >= len(raw) {
				return "", false
			}
			high, highOK := solidityHexNibble(raw[pos+1])
			low, lowOK := solidityHexNibble(raw[pos+2])
			if !highOK || !lowOK {
				return "", false
			}
			decoded.WriteByte(high<<4 | low)
			pos += 3
		case 'u':
			if pos+4 >= len(raw) {
				return "", false
			}
			var value rune
			for offset := 1; offset <= 4; offset++ {
				nibble, ok := solidityHexNibble(raw[pos+offset])
				if !ok {
					return "", false
				}
				value = value<<4 | rune(nibble)
			}
			if value >= 0xD800 && value <= 0xDFFF {
				return "", false
			}
			decoded.WriteRune(value)
			pos += 5
		default:
			return "", false
		}
	}
	return decoded.String(), true
}

func solidityHexNibble(ch byte) (byte, bool) {
	switch {
	case ch >= '0' && ch <= '9':
		return ch - '0', true
	case ch >= 'a' && ch <= 'f':
		return ch - 'a' + 10, true
	case ch >= 'A' && ch <= 'F':
		return ch - 'A' + 10, true
	default:
		return 0, false
	}
}

func tokenIs(tok importToken, kind importTokenKind, text string) bool {
	return tok.kind == kind && tok.text == text
}

func isSolidityWhitespace(ch byte) bool {
	switch ch {
	case ' ', '\t', '\n', '\r', '\f', '\v':
		return true
	default:
		return false
	}
}

func isSolidityIdentifierStart(ch byte) bool {
	return ch == '_' || ch == '$' || ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z'
}

func isSolidityIdentifierPart(ch byte) bool {
	return isSolidityIdentifierStart(ch) || ch >= '0' && ch <= '9'
}
