package engine

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/th13vn/w3goaudit/pkg/builder"
	"github.com/th13vn/w3goaudit/pkg/reader"
)

// buildDBFromSource writes src to a temp .sol file and runs reader+builder,
// returning the database. Used by the audit-fix regression tests that need a
// small, self-contained fixture.
func buildDBFromSource(t *testing.T, src string) *builder.Builder {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "T.sol")
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	rdr := reader.New()
	sources, err := rdr.Read(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	b := builder.New()
	if _, err := b.Build(sources); err != nil {
		t.Fatalf("build: %v", err)
	}
	return b
}

// TestSortFindingsDeterministic asserts ExecuteAll produces byte-identical
// finding order across repeated runs — previously findings were collected in Go
// map-iteration order, so findings.json/results.sarif shuffled every run.
func TestSortFindingsDeterministic(t *testing.T) {
	root := repoRoot(t)
	tmpls, err := LoadTemplates(filepath.Join(root, "templates/official"))
	if err != nil {
		t.Fatalf("load templates: %v", err)
	}

	var prev []string
	for run := 0; run < 5; run++ {
		rdr := reader.New()
		sources, err := rdr.Read(filepath.Join(root, "test-data/security"))
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		db, err := builder.New().Build(sources)
		if err != nil {
			t.Fatalf("build: %v", err)
		}
		findings := New(db).ExecuteAll(tmpls)
		order := make([]string, len(findings))
		for i, f := range findings {
			order[i] = f.TemplateID + "|" + f.Location.File + "|" +
				strconv.Itoa(f.Location.Line) + "|" + strconv.Itoa(f.Location.Col) + "|" + f.Location.Function
		}
		if run > 0 && strings.Join(order, "\n") != strings.Join(prev, "\n") {
			t.Fatalf("finding order not deterministic on run %d", run)
		}
		prev = order
	}
	if len(prev) == 0 {
		t.Fatal("expected some findings from the official pack over the security fixtures")
	}
}

// TestPreciseLocationSurfacedInFinding asserts the v0.4 column/byte span is
// carried onto Finding.Location and PrimaryAST (not just the DB), so SARIF and
// findings.json can highlight the exact range.
func TestPreciseLocationSurfacedInFinding(t *testing.T) {
	src := `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract C {
    function run(address t, bytes calldata d) external {
        t.delegatecall(d);
    }
}`
	b := buildDBFromSource(t, src)
	tmpl, err := ParseTemplate(`
meta: { id: T-DC, title: dc, severity: HIGH, confidence: LOW, description: d, recommendation: r }
query:
  select: delegatecall
  from: entry_function
  where:
    - arg.0: { tainted: parameter }
`)
	if err != nil {
		t.Fatalf("parse template: %v", err)
	}
	// Default (verifier) location source — the production default; it anchors
	// Line at the matched node and so carries the node's precise span.
	findings := New(b.GetDatabase()).Execute(tmpl)
	if len(findings) == 0 {
		t.Fatal("expected a delegatecall finding")
	}
	f := findings[0]
	if f.Location.Col == 0 || f.Location.EndByte == 0 {
		t.Fatalf("Location has no precise span: %+v", f.Location)
	}
	if f.PrimaryAST == nil || f.PrimaryAST.StartCol == 0 {
		t.Fatalf("PrimaryAST has no column: %+v", f.PrimaryAST)
	}
}

// TestIfConditionSequenceNotExclusive asserts a call used as an if-condition
// followed by a state write in the body is matched by a sequence rule. The
// condition + body were previously treated as mutually-exclusive arms, dropping
// the CEI/reentrancy finding (isConditionExpr kind-prefix bug).
func TestIfConditionSequenceNotExclusive(t *testing.T) {
	src := `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract C {
    mapping(address => uint256) public bal;
    function withdraw() external {
        uint256 v = bal[msg.sender];
        if (payable(msg.sender).send(v)) {
            bal[msg.sender] = 0;
        }
    }
}`
	b := buildDBFromSource(t, src)
	tmpl, err := ParseTemplate(`
meta: { id: T-SEQ, title: seq, severity: HIGH, confidence: LOW, description: d, recommendation: r }
query:
  from: entry_function
  where:
    - sequence:
        - { block: eth_transfer }
        - { block: state_write }
`)
	if err != nil {
		t.Fatalf("parse template: %v", err)
	}
	findings := New(b.GetDatabase()).Execute(tmpl)
	if len(findings) == 0 {
		t.Fatal("expected the if-condition call + state-write sequence to match (reentrancy FN regression)")
	}
}

// TestComboSelectRejected asserts a multi-kind (list) select is rejected at
// load — it silently produced false positives before.
func TestComboSelectRejected(t *testing.T) {
	_, err := ParseTemplate(`
meta: { id: T-COMBO, title: c, severity: HIGH, confidence: LOW, description: d, recommendation: r }
query:
  select: [delegatecall, function]
  from: main_contract
  where:
    - func_name: multicall
`)
	if err == nil {
		t.Fatal("expected combo (list) select to be rejected")
	}
	if !strings.Contains(err.Error(), "select must be a scalar block kind") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestMixedLayerAnyRejected asserts an any: mixing a context-only branch with an
// AST branch is rejected — it silently failed open before.
func TestMixedLayerAnyRejected(t *testing.T) {
	_, err := ParseTemplate(`
meta: { id: T-ANY, title: a, severity: HIGH, confidence: LOW, description: d, recommendation: r }
query:
  select: delegatecall
  from: entry_function
  where:
    - any:
        - not: { preset: access_controlled }
        - arg.0: { tainted: parameter }
`)
	if err == nil {
		t.Fatal("expected a mixed-layer any: to be rejected")
	}
	if !strings.Contains(err.Error(), "any:") {
		t.Fatalf("unexpected error: %v", err)
	}
}
