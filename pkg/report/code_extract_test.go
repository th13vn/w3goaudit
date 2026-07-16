package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/th13vn/w3goaudit/pkg/engine"
	"github.com/th13vn/w3goaudit/pkg/types"
)

func TestHTMLIsOfflineAndSourceExcerptUsesExactFunction(t *testing.T) {
	html := (&SummaryReport{
		ProjectRoot:   "/repo",
		GeneratedAt:   time.Unix(0, 0),
		Stats:         &types.DatabaseStats{},
		MainContracts: []*ContractSummary{},
	}).ToHTML()
	if strings.Contains(html, `<script src="http`) || !strings.Contains(html, "vis-network") {
		t.Fatal("HTML is not self-contained")
	}

	path := filepath.Join(t.TempDir(), "C.sol")
	src := "contract C {\nfunction withdrawAll() external {}\n/* { ignored } */\nfunction withdraw() external {\nuint x = 1;\n}\n}\n"
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	got := extractFullFunctionForLocation(engine.Location{File: path, Function: "withdraw", Line: 5}, nil)
	if strings.Contains(got, "withdrawAll") || !strings.Contains(got, "function withdraw()") || !strings.Contains(got, "uint x = 1") {
		t.Fatal(got)
	}
}

func TestSourceExcerptsPreferAnalyzedDatabaseSnapshot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "Snapshot.sol")
	snapshot := "contract Snapshot {\nfunction run() external {\nuint snapshotValue = 1;\nsnapshotValue++;\n}\n}\n"
	changed := "contract Snapshot {\nfunction run() external {\nuint diskValue = 99;\ndiskValue++;\n}\n}\n"
	if err := os.WriteFile(path, []byte(changed), 0o644); err != nil {
		t.Fatal(err)
	}
	db := types.NewDatabase()
	db.AddSourceFile(&types.SourceFile{Path: path, Content: snapshot})
	finding := &engine.Finding{Location: engine.Location{File: path, Function: "run", Line: 4}}

	excerpt := extractCodeForFinding(finding, 3, db)
	if !strings.Contains(excerpt, "snapshotValue") || strings.Contains(excerpt, "diskValue") {
		t.Fatalf("excerpt did not use analyzed snapshot:\n%s", excerpt)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	full := extractFullFunctionForLocation(finding.Location, db)
	if !strings.Contains(full, "snapshotValue") || strings.Contains(full, "Unable to read") {
		t.Fatalf("deleted source did not fall back to analyzed snapshot:\n%s", full)
	}
}

func TestFunctionBoundaryLexerIgnoresCommentMarkersAndBracesInsideStrings(t *testing.T) {
	path := filepath.Join(t.TempDir(), "Strings.sol")
	source := `contract Strings {
function target() external {
string memory a = "/* { }";
string memory b = "*/ // }";
string memory c = "escaped: \" /* }";
string memory d = '*/ // {';
uint kept = 1;
}
function later() external {
uint leaked = 2;
}
}
`
	if err := os.WriteFile(path, []byte(source), 0o644); err != nil {
		t.Fatal(err)
	}
	got := extractFullFunctionForLocation(engine.Location{File: path, Function: "target", Line: 7}, nil)
	if !strings.Contains(got, "uint kept = 1") || strings.Contains(got, "function later") || strings.Contains(got, "uint leaked") {
		t.Fatalf("function boundary crossed string/comment markers:\n%s", got)
	}
}
