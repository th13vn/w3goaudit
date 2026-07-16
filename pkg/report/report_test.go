package report

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/th13vn/w3goaudit/pkg/builder"
	"github.com/th13vn/w3goaudit/pkg/engine"
	"github.com/th13vn/w3goaudit/pkg/types"
)

// sampleFindings returns a small, fixed set of findings spanning multiple
// severities and metadata combinations. The project root they reference is
// "/repo" so relative-path assertions are predictable.
func sampleFindings() []*engine.Finding {
	return []*engine.Finding{
		{
			TemplateID:     "reentrancy-eth",
			Severity:       "HIGH",
			Confidence:     "high",
			Title:          "Reentrancy in withdraw",
			Message:        "External call before state update allows reentrancy.",
			Recommendation: "Apply checks-effects-interactions.",
			Location:       engine.Location{File: "/repo/src/Vault.sol", Contract: "Vault", Function: "withdraw", Line: 42},
			References:     []string{"https://swcregistry.io/docs/SWC-107"},
			Fix:            "Move balance update above the call.",
		},
		{
			TemplateID: "tx-origin-auth",
			Severity:   "MEDIUM",
			Confidence: "medium",
			Title:      "Use of tx.origin for authorization",
			Message:    "tx.origin auth is phishable.",
			Location:   engine.Location{File: "/repo/src/Auth.sol", Contract: "Auth", Function: "onlyOwner", Line: 10},
		},
		{
			TemplateID: "pragma-floating",
			Severity:   "INFO",
			Confidence: "low",
			Title:      "Floating pragma",
			Message:    "Lock the pragma to a specific compiler version.",
			Location:   engine.Location{File: "/repo/src/Vault.sol", Contract: "Vault", Line: 1},
		},
	}
}

func TestFormatFindingsAsSARIF(t *testing.T) {
	tool := ToolMeta{Name: "w3goaudit", Version: "0.1.0"}
	const projectRoot = "/repo"

	out, err := FormatFindingsAsSARIF(sampleFindings(), tool, projectRoot)
	if err != nil {
		t.Fatalf("FormatFindingsAsSARIF returned error: %v", err)
	}

	// Must be valid JSON.
	var doc map[string]interface{}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("SARIF output is not valid JSON: %v", err)
	}

	if got := doc["version"]; got != "2.1.0" {
		t.Errorf("version = %v, want 2.1.0", got)
	}
	if _, ok := doc["$schema"]; !ok {
		t.Error("missing $schema")
	}

	runs, ok := doc["runs"].([]interface{})
	if !ok || len(runs) != 1 {
		t.Fatalf("expected exactly 1 run, got %v", doc["runs"])
	}
	run := runs[0].(map[string]interface{})
	if got := run["columnKind"]; got != "unicodeCodePoints" {
		t.Errorf("columnKind = %v, want unicodeCodePoints", got)
	}

	driver := run["tool"].(map[string]interface{})["driver"].(map[string]interface{})
	if got := driver["name"]; got != "w3goaudit" {
		t.Errorf("driver.name = %v, want w3goaudit", got)
	}
	if got := driver["version"]; got != "0.1.0" {
		t.Errorf("driver.version = %v, want 0.1.0", got)
	}

	// Rules: one per unique TemplateID (3 unique here).
	rules := driver["rules"].([]interface{})
	if len(rules) != 3 {
		t.Errorf("expected 3 rules, got %d", len(rules))
	}
	ruleIDs := map[string]bool{}
	for _, r := range rules {
		ruleIDs[r.(map[string]interface{})["id"].(string)] = true
	}
	for _, want := range []string{"reentrancy-eth", "tx-origin-auth", "pragma-floating"} {
		if !ruleIDs[want] {
			t.Errorf("rule %q not registered", want)
		}
	}

	// originalUriBaseIds.srcRoot should be present when projectRoot supplied.
	if _, ok := run["originalUriBaseIds"]; !ok {
		t.Error("expected originalUriBaseIds when projectRoot is set")
	}

	// Results: one per finding.
	results := run["results"].([]interface{})
	if len(results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(results))
	}

	first := results[0].(map[string]interface{})
	if first["ruleId"] != "reentrancy-eth" {
		t.Errorf("results[0].ruleId = %v, want reentrancy-eth", first["ruleId"])
	}
	// HIGH -> error level.
	if first["level"] != "error" {
		t.Errorf("results[0].level = %v, want error (HIGH)", first["level"])
	}
	if msg := first["message"].(map[string]interface{})["text"]; msg == "" {
		t.Error("results[0].message.text is empty")
	}

	loc := first["locations"].([]interface{})[0].(map[string]interface{})
	phys := loc["physicalLocation"].(map[string]interface{})
	art := phys["artifactLocation"].(map[string]interface{})
	uri := art["uri"].(string)
	// Must be relative (under /repo), not absolute.
	if strings.HasPrefix(uri, "/") {
		t.Errorf("artifactLocation.uri = %q, want relative path", uri)
	}
	if uri != "src/Vault.sol" {
		t.Errorf("artifactLocation.uri = %q, want src/Vault.sol", uri)
	}
	if art["uriBaseId"] != "srcRoot" {
		t.Errorf("uriBaseId = %v, want srcRoot", art["uriBaseId"])
	}
	region := phys["region"].(map[string]interface{})
	if region["startLine"].(float64) != 42 {
		t.Errorf("startLine = %v, want 42", region["startLine"])
	}
}

func TestSARIFUnicodeColumnsNeverUseByteOffsetsAsCharacterOffsets(t *testing.T) {
	findings := []*engine.Finding{{
		TemplateID: "unicode-location",
		Severity:   "MEDIUM",
		Location: engine.Location{
			File:      "/repo/Unicode.sol",
			Line:      3,
			Col:       19,
			EndLine:   3,
			EndCol:    44,
			StartByte: 87,
			EndByte:   116,
		},
	}}
	out, err := FormatFindingsAsSARIF(findings, ToolMeta{Name: "w3goaudit"}, "/repo")
	if err != nil {
		t.Fatalf("FormatFindingsAsSARIF: %v", err)
	}
	var doc map[string]interface{}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("invalid SARIF: %v", err)
	}
	run := doc["runs"].([]interface{})[0].(map[string]interface{})
	if run["columnKind"] != "unicodeCodePoints" {
		t.Fatalf("columnKind = %v, want unicodeCodePoints", run["columnKind"])
	}
	result := run["results"].([]interface{})[0].(map[string]interface{})
	physical := result["locations"].([]interface{})[0].(map[string]interface{})["physicalLocation"].(map[string]interface{})
	region := physical["region"].(map[string]interface{})
	if region["startColumn"] != float64(19) || region["endColumn"] != float64(44) {
		t.Fatalf("region columns = start %v end %v", region["startColumn"], region["endColumn"])
	}
	if _, ok := region["charOffset"]; ok {
		t.Fatalf("region must not emit UTF-8 byte offset as SARIF charOffset: %#v", region)
	}
	if _, ok := region["charLength"]; ok {
		t.Fatalf("region must not emit UTF-8 byte length as SARIF charLength: %#v", region)
	}
}

func TestSARIFUsesParserBackedUnicodeColumns(t *testing.T) {
	src := `contract C {
    function run(address target, bytes memory data) external {
        string memory marker = "→😀"; target.delegatecall(data);
    }
}`
	db, err := builder.New().Build([]*types.SourceFile{{Path: "/repo/Unicode.sol", Content: src}})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	contract := db.GetContractByName("C")
	if contract == nil || len(contract.Functions) != 1 || contract.Functions[0].AST == nil {
		t.Fatalf("unexpected parsed contract: %#v", contract)
	}
	calls := contract.Functions[0].AST.CollectDescendants(func(n *types.ASTNode) bool {
		return n.Kind == types.KindCallLowlevelDelegate
	})
	if len(calls) != 1 {
		t.Fatalf("delegatecall nodes = %d, want 1", len(calls))
	}
	call := calls[0]
	callByte := strings.Index(src, "target.delegatecall")
	lineStart := strings.LastIndex(src[:callByte], "\n") + 1
	wantCol := utf8.RuneCountInString(src[lineStart:callByte]) + 1
	if call.StartCol != wantCol || call.StartByte != callByte {
		t.Fatalf("parser-backed call = col %d byte %d, want col %d byte %d", call.StartCol, call.StartByte, wantCol, callByte)
	}

	findings := []*engine.Finding{{
		TemplateID: "unicode-location",
		Severity:   "MEDIUM",
		Location: engine.Location{
			File:      "/repo/Unicode.sol",
			Line:      call.StartLine,
			Col:       call.StartCol,
			EndLine:   call.EndLine,
			EndCol:    call.EndCol,
			StartByte: call.StartByte,
			EndByte:   call.EndByte,
		},
	}}
	out, err := FormatFindingsAsSARIF(findings, ToolMeta{Name: "w3goaudit"}, "/repo")
	if err != nil {
		t.Fatalf("FormatFindingsAsSARIF: %v", err)
	}
	var doc map[string]interface{}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("invalid SARIF: %v", err)
	}
	run := doc["runs"].([]interface{})[0].(map[string]interface{})
	result := run["results"].([]interface{})[0].(map[string]interface{})
	region := result["locations"].([]interface{})[0].(map[string]interface{})["physicalLocation"].(map[string]interface{})["region"].(map[string]interface{})
	if run["columnKind"] != "unicodeCodePoints" || region["startColumn"] != float64(wantCol) {
		t.Fatalf("SARIF run/region = columnKind %v startColumn %v, want unicodeCodePoints/%d", run["columnKind"], region["startColumn"], wantCol)
	}
	if _, ok := region["charOffset"]; ok {
		t.Fatalf("parser byte offset leaked into SARIF charOffset: %#v", region)
	}
}

func TestSarifLevelMapping(t *testing.T) {
	cases := map[string]string{
		"CRITICAL": "error",
		"HIGH":     "error",
		"MEDIUM":   "warning",
		"LOW":      "note",
		"INFO":     "note",
		"bogus":    "none",
	}
	for sev, want := range cases {
		if got := sarifLevelFor(sev); got != want {
			t.Errorf("sarifLevelFor(%q) = %q, want %q", sev, got, want)
		}
	}
}

func TestSarifLineFloor(t *testing.T) {
	// A finding with Line 0 should be floored to startLine 1 (SARIF requires >=1).
	findings := []*engine.Finding{{
		TemplateID: "x",
		Severity:   "LOW",
		Location:   engine.Location{File: "/repo/a.sol", Line: 0},
	}}
	out, err := FormatFindingsAsSARIF(findings, ToolMeta{Name: "t"}, "/repo")
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	var doc map[string]interface{}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	run := doc["runs"].([]interface{})[0].(map[string]interface{})
	res := run["results"].([]interface{})[0].(map[string]interface{})
	region := res["locations"].([]interface{})[0].(map[string]interface{})["physicalLocation"].(map[string]interface{})["region"].(map[string]interface{})
	if region["startLine"].(float64) != 1 {
		t.Errorf("startLine = %v, want 1 (floored)", region["startLine"])
	}
}

func TestFormatFindingsAsMarkdown(t *testing.T) {
	// Make finding paths relative to the report root.
	SetReportProjectRoot("/repo")
	t.Cleanup(func() { SetReportProjectRoot("") })

	db := types.NewDatabase()
	md := FormatFindingsAsMarkdown(sampleFindings(), db)

	wantContains := []string{
		"# Security Findings",
		"HIGH-1 — Reentrancy in withdraw",
		"MEDIUM-2 — Use of tx.origin for authorization",
		"INFO-3 — Floating pragma",
		"### Description",
		"External call before state update allows reentrancy.",
		"### Recommendation",
		"Apply checks-effects-interactions.",
		"### Suggested Fix",
		"Move balance update above the call.",
		"### References",
		"https://swcregistry.io/docs/SWC-107",
		"src/Vault.sol :: Vault.withdraw():42", // relative path + line
	}
	for _, want := range wantContains {
		if !strings.Contains(md, want) {
			t.Errorf("markdown missing %q\n---\n%s", want, md)
		}
	}
}

func TestFormatFindingsAsMarkdownEmpty(t *testing.T) {
	db := types.NewDatabase()
	md := FormatFindingsAsMarkdown(nil, db)
	if !strings.Contains(md, "No security issues found.") {
		t.Errorf("empty findings markdown missing no-issues message:\n%s", md)
	}
}

func TestBuildFindingsJSON(t *testing.T) {
	tool := ToolMeta{Name: "w3goaudit", Version: "0.1.0"}
	doc := BuildFindingsJSON(tool, sampleFindings())

	if doc.SchemaVersion != SchemaVersion {
		t.Errorf("SchemaVersion = %q, want %q", doc.SchemaVersion, SchemaVersion)
	}
	if doc.Tool.Name != "w3goaudit" {
		t.Errorf("Tool.Name = %q", doc.Tool.Name)
	}
	if doc.Counts.Total != 3 {
		t.Errorf("Counts.Total = %d, want 3", doc.Counts.Total)
	}
	if doc.Counts.UniqueRules != 3 {
		t.Errorf("Counts.UniqueRules = %d, want 3", doc.Counts.UniqueRules)
	}
	if doc.Counts.High != 1 || doc.Counts.Medium != 1 || doc.Counts.Info != 1 {
		t.Errorf("severity counts = High:%d Medium:%d Info:%d, want 1/1/1",
			doc.Counts.High, doc.Counts.Medium, doc.Counts.Info)
	}
	if len(doc.Findings) != 3 {
		t.Fatalf("Findings len = %d, want 3", len(doc.Findings))
	}

	// Round-trip through JSON and re-parse to confirm a stable shape.
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var parsed struct {
		SchemaVersion string `json:"schemaVersion"`
		Counts        struct {
			Total int `json:"total"`
			High  int `json:"high"`
		} `json:"counts"`
		Findings []struct {
			TemplateID string `json:"template_id"`
			Severity   string `json:"severity"`
			Location   struct {
				File string `json:"file"`
				Line int    `json:"line"`
			} `json:"location"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("unmarshal round-trip: %v", err)
	}
	if parsed.SchemaVersion != SchemaVersion {
		t.Errorf("round-trip schemaVersion = %q", parsed.SchemaVersion)
	}
	if parsed.Counts.Total != 3 || parsed.Counts.High != 1 {
		t.Errorf("round-trip counts wrong: %+v", parsed.Counts)
	}
	if parsed.Findings[0].TemplateID != "reentrancy-eth" {
		t.Errorf("round-trip findings[0].template_id = %q", parsed.Findings[0].TemplateID)
	}
	if parsed.Findings[0].Location.File != "/repo/src/Vault.sol" || parsed.Findings[0].Location.Line != 42 {
		t.Errorf("round-trip findings[0].location = %+v", parsed.Findings[0].Location)
	}
}

func TestBuildFindingsJSONNilIsEmptySlice(t *testing.T) {
	doc := BuildFindingsJSON(ToolMeta{Name: "t"}, nil)
	if doc.Findings == nil {
		t.Error("Findings should be a non-nil empty slice for nil input")
	}
	raw, _ := json.Marshal(doc)
	if !strings.Contains(string(raw), `"findings":[]`) {
		t.Errorf("nil findings should marshal to empty array, got: %s", raw)
	}
}

func TestPrintConsoleSummaryHeaderNoColor(t *testing.T) {
	t.Setenv("NO_COLOR", "1")

	var buf strings.Builder
	PrintConsoleSummaryHeader(&buf, sampleFindings(), 5, "1.2s", ColorAlways)
	out := buf.String()

	if strings.Contains(out, "\x1b[") {
		t.Errorf("NO_COLOR=1 but output contains ANSI escape: %q", out)
	}
	// Content should still be present.
	for _, want := range []string{"3 findings", "1 HIGH", "1 MEDIUM", "1 INFO", "scanned 5 contracts in 1.2s"} {
		if !strings.Contains(out, want) {
			t.Errorf("header missing %q: %q", want, out)
		}
	}
}

func TestPrintConsoleSummaryHeaderColor(t *testing.T) {
	t.Setenv("NO_COLOR", "")

	var buf strings.Builder
	PrintConsoleSummaryHeader(&buf, sampleFindings(), 5, "", ColorAlways)
	out := buf.String()

	if !strings.Contains(out, "\x1b[") {
		t.Errorf("ColorAlways without NO_COLOR should emit ANSI codes: %q", out)
	}
}

func TestPrintConsoleSummaryHeaderEmpty(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	var buf strings.Builder
	PrintConsoleSummaryHeader(&buf, nil, 0, "", ColorNever)
	if !strings.Contains(buf.String(), "No findings.") {
		t.Errorf("expected 'No findings.' for empty set, got %q", buf.String())
	}
}

func TestSarifArtifactURIOutsideRoot(t *testing.T) {
	// File outside the project root should fall back to an absolute path.
	uri, baseID := sarifArtifactURI("/other/place/X.sol", "/repo")
	if baseID != "" {
		t.Errorf("uriBaseId = %q, want empty for out-of-root file", baseID)
	}
	if !filepath.IsAbs(uri) {
		t.Errorf("uri = %q, want absolute path for out-of-root file", uri)
	}
}
