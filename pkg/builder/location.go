package builder

import (
	"sort"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/th13vn/solast-go/pkg/ast"
	"github.com/th13vn/w3goaudit/pkg/types"
)

// sourceSpan is the canonical source range copied onto declarations, AST
// nodes, and call sites. Lines and columns are 1-based; byte offsets are
// 0-based UTF-8 byte offsets with a half-open [start, end) range.
type sourceSpan struct {
	startLine int
	endLine   int
	startCol  int
	endCol    int
	startByte int
	endByte   int
}

type sourceRuneIndex struct {
	startByte  int
	endByte    int
	extraBytes int
}

type sourceLineIndex struct {
	startByte    int
	endByte      int
	firstInvalid int
	nonASCII     []sourceRuneIndex
}

// sourceLocator converts the parser's byte-oriented positions into the
// Unicode-code-point columns serialized by w3goaudit. Each source is indexed
// once by line and non-ASCII rune; endpoint lookup is O(log non-ASCII runes on
// the line) without an int-per-byte table. The same locator is shared by
// declaration, AST, and call-graph construction.
type sourceLocator struct {
	file    string
	lines   []sourceLineIndex
	db      *types.Database
	invalid sync.Once
}

func newSourceLocator(sf *types.SourceFile, db *types.Database) *sourceLocator {
	if sf == nil {
		return nil
	}
	return &sourceLocator{
		file:  sf.Path,
		lines: indexSourceLines(sf.Content),
		db:    db,
	}
}

func sourceLocatorFromDatabase(db *types.Database, file string) *sourceLocator {
	if db == nil || file == "" {
		return nil
	}
	return newSourceLocator(db.SourceFiles[file], db)
}

func indexSourceLines(content string) []sourceLineIndex {
	lines := make([]sourceLineIndex, 0, 64)
	for lineStart := 0; ; {
		lineEnd := len(content)
		if relativeEnd := strings.IndexByte(content[lineStart:], '\n'); relativeEnd >= 0 {
			lineEnd = lineStart + relativeEnd
		}
		lines = append(lines, indexSourceLine(content, lineStart, lineEnd))
		if lineEnd == len(content) {
			return lines
		}
		lineStart = lineEnd + 1
	}
}

func indexSourceLine(content string, startByte, endByte int) sourceLineIndex {
	line := sourceLineIndex{
		startByte:    startByte,
		endByte:      endByte,
		firstInvalid: -1,
	}
	extraBytes := 0
	for offset := startByte; offset < endByte; {
		if content[offset] < utf8.RuneSelf {
			offset++
			continue
		}
		_, size := utf8.DecodeRuneInString(content[offset:endByte])
		if size == 1 {
			if line.firstInvalid < 0 {
				line.firstInvalid = offset
			}
			offset++
			continue
		}
		extraBytes += size - 1
		line.nonASCII = append(line.nonASCII, sourceRuneIndex{
			startByte:  offset,
			endByte:    offset + size,
			extraBytes: extraBytes,
		})
		offset += size
	}
	return line
}

func (l *sourceLocator) column(line, byteOffset int) (int, bool) {
	if l == nil || line < 1 || line > len(l.lines) {
		return 0, false
	}
	indexed := &l.lines[line-1]
	if byteOffset < indexed.startByte || byteOffset > indexed.endByte {
		return 0, false
	}
	// Matching utf8.ValidString(content[lineStart:byteOffset]): an endpoint at
	// the first invalid byte is still a valid boundary, while every endpoint
	// after that byte has an invalid prefix.
	if indexed.firstInvalid >= 0 && byteOffset > indexed.firstInvalid {
		return 0, false
	}

	// Find the first multibyte rune whose end lies after the endpoint. All
	// earlier entries contribute their cumulative extra UTF-8 bytes.
	pos := sort.Search(len(indexed.nonASCII), func(i int) bool {
		return indexed.nonASCII[i].endByte > byteOffset
	})
	if pos < len(indexed.nonASCII) {
		r := indexed.nonASCII[pos]
		if byteOffset > r.startByte && byteOffset < r.endByte {
			return 0, false // endpoint splits a multibyte rune
		}
	}
	extraBytes := 0
	if pos > 0 {
		extraBytes = indexed.nonASCII[pos-1].extraBytes
	}
	return byteOffset - indexed.startByte - extraBytes + 1, true
}

// span preserves parser-provided lines and UTF-8 byte offsets, then derives
// both columns from the source. Parser columns are intentionally ignored: the
// parser counts bytes, so they are wrong after non-ASCII text.
func (l *sourceLocator) span(src ast.Node) sourceSpan {
	var span sourceSpan
	if src == nil {
		return span
	}
	if loc := src.GetLocation(); loc != nil {
		span.startLine = loc.Start.Line
		span.endLine = loc.End.Line
	}
	rng := src.GetRange()
	if rng == nil {
		return span
	}
	span.startByte, span.endByte = rng[0], rng[1]

	startCol, startOK := l.column(span.startLine, span.startByte)
	endCol, endOK := l.column(span.endLine, span.endByte)
	if !startOK || !endOK || span.endByte < span.startByte {
		l.recordInvalid()
		return span
	}
	span.startCol, span.endCol = startCol, endCol
	return span
}

// apply copies a complete source span onto an AST node. A node without a
// parser location leaves an existing destination span untouched; an invalid
// conversion still copies its valid line/byte information while omitting both
// columns so consumers never mix incompatible units.
func (l *sourceLocator) apply(dst *types.ASTNode, src ast.Node) {
	if dst == nil || src == nil {
		return
	}
	span := l.span(src)
	if span.startLine == 0 && span.endLine == 0 && src.GetRange() == nil {
		return
	}
	dst.StartLine, dst.EndLine = span.startLine, span.endLine
	dst.StartCol, dst.EndCol = span.startCol, span.endCol
	dst.StartByte, dst.EndByte = span.startByte, span.endByte
}

func (l *sourceLocator) recordInvalid() {
	if l == nil {
		return
	}
	l.invalid.Do(func() {
		if l.db == nil {
			return
		}
		l.db.AddDiagnostic(types.Diagnostic{
			Code:       types.DiagnosticInvalidLocation,
			Severity:   types.DiagnosticWarning,
			Phase:      "builder",
			Message:    "source range could not be converted to Unicode code-point columns",
			File:       l.file,
			Incomplete: true,
		})
	})
}
