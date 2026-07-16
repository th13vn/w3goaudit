package reader

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestExtractImportsIgnoresComments(t *testing.T) {
	content := `
// import "./LineComment.sol";
/* import {Block} from "./BlockComment.sol"; */
/**
 * import * as Doc from "./DocComment.sol";
 */
contract Main {}
`

	if got := extractImports(content); len(got) != 0 {
		t.Fatalf("extractImports() = %q, want no imports from comments", got)
	}
}

func TestExtractImportsIgnoresStringContents(t *testing.T) {
	content := `
contract Main {
    string constant DOUBLE_QUOTED = "import './DoubleQuoted.sol';";
    string constant SINGLE_QUOTED = 'import "./SingleQuoted.sol";';
    string constant MULTILINE_TEXT = "not an import; import {Fake} from './Fake.sol';";
    string constant ESCAPED_QUOTE = "prefix \" import './EscapedQuote.sol';";
    string constant UNICODE_TEXT = unicode"import './UnicodeString.sol';";
}
`

	if got := extractImports(content); len(got) != 0 {
		t.Fatalf("extractImports() = %q, want no imports from string contents", got)
	}
}

func TestExtractImportsSupportsSolidityFormsAndMultilineTrivia(t *testing.T) {
	content := `
import "./Plain.sol";
import "./PathAlias.sol" as PathAlias;
import LegacyAlias from "./LegacyAlias.sol";
import * as Namespace from "./Namespace.sol";
import {First, Second as Renamed} from "./Named.sol";
import
/* before symbols */ {
    MultiFirst,
    MultiSecond /* before alias */ as MultiRenamed
}
// before from
from
"./Multiline.sol"
;
import "./Plain.sol"; // duplicate paths retain first-seen order
`

	want := []string{
		"./Plain.sol",
		"./PathAlias.sol",
		"./LegacyAlias.sol",
		"./Namespace.sol",
		"./Named.sol",
		"./Multiline.sol",
	}
	if got := extractImports(content); !reflect.DeepEqual(got, want) {
		t.Fatalf("extractImports() = %q, want %q", got, want)
	}
}

func TestDecodeSolidityImportStringEscapes(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{name: "quotes and backslash", raw: `double\"single\'slash\\`, want: "double\"single'slash\\"},
		{name: "standard", raw: `line\nreturn\rtab\t`, want: "line\nreturn\rtab\t"},
		{name: "hex and unicode", raw: `.\x2fEsc\u0061ped.sol`, want: "./Escaped.sol"},
		{name: "unicode code point", raw: `Caf\u00E9.sol`, want: "Café.sol"},
		{name: "escaped line break", raw: `Line\
Continuation.sol`, want: "LineContinuation.sol"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := decodeSolidityImportString(tt.raw)
			if !ok || got != tt.want {
				t.Fatalf("decodeSolidityImportString(%q) = %q, %v; want %q, true", tt.raw, got, ok, tt.want)
			}
		})
	}
}

func TestDecodeSolidityImportStringRejectsMalformedEscapes(t *testing.T) {
	tests := []string{
		`bad\q.sol`,
		`bad\x.sol`,
		`bad\x0G.sol`,
		`bad\u123.sol`,
		`bad\u12G4.sol`,
		`bad\uD800.sol`,
		`bad\uDFFF.sol`,
		"raw\nnewline.sol",
		`raw-é.sol`,
	}
	for _, raw := range tests {
		if got, ok := decodeSolidityImportString(raw); ok {
			t.Errorf("decodeSolidityImportString(%q) = %q, true; want invalid", raw, got)
		}
	}
}

func TestExtractImportsDecodesEscapedPaths(t *testing.T) {
	content := `
import ".\x2fEsc\u0061ped.sol";
import './Single\'Quote.sol';
import "./Double\"Quote.sol";
import ".\\Backslash.sol";
import "./Line\
Continuation.sol";
import "./Escaped.sol"; // decoded duplicate
`
	want := []string{
		"./Escaped.sol",
		"./Single'Quote.sol",
		"./Double\"Quote.sol",
		`.\Backslash.sol`,
		"./LineContinuation.sol",
	}
	if got := extractImports(content); !reflect.DeepEqual(got, want) {
		t.Fatalf("extractImports() = %q, want decoded paths %q", got, want)
	}
}

func TestExtractImportsRejectsMalformedEscapedPaths(t *testing.T) {
	content := `
import ".\qWrong.sol";
import ".\x2GWrong.sol";
import ".\u12G4Wrong.sol";
import ".\uD800Wrong.sol";
import "./Good.sol";
`
	want := []string{"./Good.sol"}
	if got := extractImports(content); !reflect.DeepEqual(got, want) {
		t.Fatalf("extractImports() = %q, want only valid path %q", got, want)
	}
}

func TestResolveImportsDecodesEscapedPath(t *testing.T) {
	root := t.TempDir()
	mainPath := filepath.Join(root, "Main.sol")
	mustWrite(t, filepath.Join(root, "Escaped.sol"), "contract Escaped {}\n")
	mustWrite(t, mainPath, `import ".\x2fEsc\u0061ped.sol";`+"\n")

	r := New()
	if _, err := r.Read(mainPath); err != nil {
		t.Fatalf("Read: %v", err)
	}
	if err := r.ResolveImports(root); err != nil {
		t.Fatalf("ResolveImports: %v", err)
	}
	if diagnostics := r.Diagnostics(); len(diagnostics) != 0 {
		t.Fatalf("Diagnostics() = %#v, want no unresolved escaped import", diagnostics)
	}
	if sources := r.GetAllSources(); len(sources) != 2 {
		t.Fatalf("GetAllSources() returned %d files, want Main.sol and Escaped.sol", len(sources))
	}
}

func TestResolveImportsDoesNotLoadMalformedEscapedPath(t *testing.T) {
	root := t.TempDir()
	mainPath := filepath.Join(root, "Main.sol")
	wrongPath := filepath.Join(root, `.\qWrong.sol`)
	if err := os.WriteFile(wrongPath, []byte("contract Wrong {}\n"), 0o644); err != nil {
		t.Fatalf("write wrong-path fixture: %v", err)
	}
	mustWrite(t, mainPath, `import ".\qWrong.sol";`+"\n")

	r := New()
	if _, err := r.Read(mainPath); err != nil {
		t.Fatalf("Read: %v", err)
	}
	if err := r.ResolveImports(root); err != nil {
		t.Fatalf("ResolveImports: %v", err)
	}
	if diagnostics := r.Diagnostics(); len(diagnostics) != 0 {
		t.Fatalf("Diagnostics() = %#v, malformed Solidity import should be ignored by import resolution", diagnostics)
	}
	if sources := r.GetAllSources(); len(sources) != 1 {
		t.Fatalf("GetAllSources() returned %d files, malformed escape loaded %q", len(sources), wrongPath)
	}
}

func TestResolveImportsDoesNotReplaceSurrogateEscape(t *testing.T) {
	root := t.TempDir()
	mainPath := filepath.Join(root, "Main.sol")
	wrongPath := filepath.Join(root, "Wrong�.sol")
	mustWrite(t, wrongPath, "contract Wrong {}\n")
	mustWrite(t, mainPath, `import "./Wrong\uD800.sol";`+"\n")

	r := New()
	if _, err := r.Read(mainPath); err != nil {
		t.Fatalf("Read: %v", err)
	}
	if err := r.ResolveImports(root); err != nil {
		t.Fatalf("ResolveImports: %v", err)
	}
	if diagnostics := r.Diagnostics(); len(diagnostics) != 0 {
		t.Fatalf("Diagnostics() = %#v, surrogate import should be rejected before resolution", diagnostics)
	}
	if sources := r.GetAllSources(); len(sources) != 1 {
		t.Fatalf("GetAllSources() returned %d files, surrogate escape loaded replacement path %q", len(sources), wrongPath)
	}
}

func TestResolveImportsIgnoresCommentAndStringLookalikes(t *testing.T) {
	root := t.TempDir()
	mainPath := filepath.Join(root, "Main.sol")
	mustWrite(t, filepath.Join(root, "Present.sol"), "contract Present {}\n")
	mustWrite(t, mainPath, `
pragma solidity ^0.8.20;
// import "./MissingLineComment.sol";
/* import "./MissingBlockComment.sol"; */
contract Main {
    string constant TEXT = "import './MissingString.sol';";
}
import
    "./Present.sol"
    as PresentUnit;
`)

	r := New()
	if _, err := r.Read(mainPath); err != nil {
		t.Fatalf("Read: %v", err)
	}
	if err := r.ResolveImports(root); err != nil {
		t.Fatalf("ResolveImports: %v", err)
	}
	if diagnostics := r.Diagnostics(); len(diagnostics) != 0 {
		t.Fatalf("Diagnostics() = %#v, want no unresolved lookalike imports", diagnostics)
	}
	if sources := r.GetAllSources(); len(sources) != 2 {
		t.Fatalf("GetAllSources() returned %d files, want Main.sol and Present.sol", len(sources))
	}
}
