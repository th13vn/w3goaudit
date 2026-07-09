package engine

import (
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/th13vn/w3goaudit/pkg/builder"
	"github.com/th13vn/w3goaudit/pkg/reader"
)

func TestInterproceduralTaintForInternalTransferFrom(t *testing.T) {
	root := repoRoot(t)
	rdr := reader.New()
	sources, err := rdr.Read(filepath.Join(root, "test-data/security/arbitrary-transferfrom.sol"))
	if err != nil {
		t.Fatalf("read sources: %v", err)
	}
	db, err := builder.New().Build(sources)
	if err != nil {
		t.Fatalf("build db: %v", err)
	}
	tmpl, err := LoadTemplate(filepath.Join(root, "templates/official/high/arbitrary-transferfrom.yaml"))
	if err != nil {
		t.Fatalf("load template: %v", err)
	}

	findings := New(db).Execute(tmpl)
	got := make([]string, 0, len(findings))
	for _, finding := range findings {
		got = append(got, finding.Location.Contract+"."+finding.Location.Function)
	}
	sort.Strings(got)

	want := []string{
		"VulnerableAliasForward.depositFrom",
		"VulnerableAliasReassignmentForward.depositFrom",
		"VulnerableArrayElementForward.deposit",
		"VulnerableBatchDeposit.batchDeposit",
		"VulnerableConditionalForward.depositFrom",
		"VulnerableDeposit.deposit",
		"VulnerableInternalForward.depositFrom",
		"VulnerableNestedForward.depositFrom",
		"VulnerableNoAuth.withdrawFrom",
		"VulnerableReturnHelperForward.depositFrom",
		"VulnerableShadowedAliasForward.deposit",
		"VulnerableStructForward.deposit",
		"VulnerableStaking.stake",
		"VulnerableStructArrayForward.depositBatch",
		"VulnerableSwap.swap",
		"VulnerableSwappedArgsForward.depositFrom",
	}
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected findings:\n got: %v\nwant: %v", got, want)
	}
}

func TestFindingLocationsUseExactFunctionIDSourceFile(t *testing.T) {
	root := repoRoot(t)
	rdr := reader.New()
	// pkg-a/ and pkg-b/ each ship a tx-origin.sol whose basename collides but
	// whose full path differs, and both define a contract literally named
	// Vulnerable_TxOrigin. Read both explicitly so the test exercises the
	// colliding-basename case.
	sources, err := rdr.ReadFiles([]string{
		filepath.Join(root, "test-data/core/engine-features/path-collision/pkg-a/tx-origin.sol"),
		filepath.Join(root, "test-data/core/engine-features/path-collision/pkg-b/tx-origin.sol"),
	})
	if err != nil {
		t.Fatalf("read sources: %v", err)
	}
	db, err := builder.New().Build(sources)
	if err != nil {
		t.Fatalf("build db: %v", err)
	}
	tmpl, err := LoadTemplate(filepath.Join(root, "templates/official/medium/tx-origin-auth.yaml"))
	if err != nil {
		t.Fatalf("load template: %v", err)
	}

	// Two findings should come back, each with a *distinct full path* so
	// downstream consumers can tell them apart even though the basenames
	// collide. Indexing the seen set by directory (pkg-a vs pkg-b) verifies
	// that both fixtures were reached AND that the Location.File carries the
	// real path, not just the basename.
	seen := make(map[string]bool)
	for _, finding := range New(db).Execute(tmpl) {
		if finding.Location.Contract != "Vulnerable_TxOrigin" {
			continue
		}
		if !strings.HasSuffix(finding.Location.File, ".sol") {
			t.Fatalf("expected Solidity source file location, got %q", finding.Location.File)
		}
		dir := filepath.Base(filepath.Dir(finding.Location.File))
		seen[dir] = true
	}

	want := map[string]bool{
		"pkg-a": true,
		"pkg-b": true,
	}
	if !reflect.DeepEqual(seen, want) {
		t.Fatalf("expected Vulnerable_TxOrigin findings from both subdirs (distinct full paths)\n got: %v\nwant: %v", seen, want)
	}
}

func TestTypeCastsDoNotCreateReentrancyFindings(t *testing.T) {
	root := repoRoot(t)
	rdr := reader.New()
	// The fixture pairs the two safe guards (address-zero and mint/burn-zero)
	// whose `require(x != address(0))` casts previously tripped a false
	// reentrancy match.
	sources, err := rdr.Read(filepath.Join(root, "test-data/core/engine-features/type-cast-guards.sol"))
	if err != nil {
		t.Fatalf("read sources: %v", err)
	}
	db, err := builder.New().Build(sources)
	if err != nil {
		t.Fatalf("build db: %v", err)
	}
	tmpl, err := LoadTemplate(filepath.Join(root, "templates/official/high/reentrancy-pattern.yaml"))
	if err != nil {
		t.Fatalf("load template: %v", err)
	}

	for _, finding := range New(db).Execute(tmpl) {
		switch finding.Location.Contract {
		case "Safe_AddressZeroCheck", "Safe_MintBurnZero":
			t.Fatalf("type casts in guards must not be treated as outgoing calls: %+v", finding.Location)
		}
	}
}

func TestInterproceduralSequenceFindsCallsInsideInternalHelpers(t *testing.T) {
	root := repoRoot(t)
	rdr := reader.New()
	sources, err := rdr.Read(filepath.Join(root, "test-data/security/reentrancy-simple.sol"))
	if err != nil {
		t.Fatalf("read sources: %v", err)
	}
	db, err := builder.New().Build(sources)
	if err != nil {
		t.Fatalf("build db: %v", err)
	}
	tmpl, err := LoadTemplate(filepath.Join(root, "templates/official/high/reentrancy-pattern.yaml"))
	if err != nil {
		t.Fatalf("load template: %v", err)
	}

	findings := New(db).Execute(tmpl)
	got := make([]string, 0, len(findings))
	for _, finding := range findings {
		got = append(got, finding.Location.Contract+"."+finding.Location.Function)
	}
	sort.Strings(got)

	want := []string{
		"DeepRecursive.withdraw",
		"DirectCall.withdraw",
		"NestedBlock.withdraw",
		"RecursiveCall.withdraw",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected reentrancy findings:\n got: %v\nwant: %v", got, want)
	}
}

func TestUncheckedArithmeticTemplateSeesUncheckedBlocks(t *testing.T) {
	root := repoRoot(t)
	rdr := reader.New()
	sources, err := rdr.Read(filepath.Join(root, "test-data/security/unchecked-arithmetic.sol"))
	if err != nil {
		t.Fatalf("read sources: %v", err)
	}
	db, err := builder.New().Build(sources)
	if err != nil {
		t.Fatalf("build db: %v", err)
	}
	tmpl, err := LoadTemplate(filepath.Join(root, "templates/official/medium/unchecked-arithmetic.yaml"))
	if err != nil {
		t.Fatalf("load template: %v", err)
	}

	findings := New(db).Execute(tmpl)
	got := make([]string, 0, len(findings))
	for _, finding := range findings {
		got = append(got, finding.Location.Contract+"."+finding.Location.Function)
	}
	sort.Strings(got)

	// Safe_GuardedUncheckedSub.withdrawAll is intentionally ABSENT: its
	// `require(bal >= amount)` is an ordering bound over both operands of
	// `bal - amount`, so the `unchecked_var:` predicate excludes it.
	// Vulnerable_NonOrderingGuard.pay IS flagged: `require(bal != amount)`
	// references both operands but is not an ordering bound. incrementSmall stays
	// flagged because its `require(amount <= 100)` bounds only one operand of
	// `balances[user] + amount`.
	want := []string{
		"Safe_BoundedUncheckedArithmetic.incrementSmall",
		"Vulnerable_NonOrderingGuard.pay",
		"Vulnerable_UncheckedArithmetic.credit",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected unchecked arithmetic findings:\n got: %v\nwant: %v", got, want)
	}
}

// TestTaintFixpointPropagatesLoopCarriedAlias proves the dataflow fixpoint.
// `a = b` is written before `b = from`, so a single forward pass leaves `a`
// untainted by the parameter. Because the assignments sit in a loop, b's
// parameter taint reaches a on the next iteration — the bounded fixpoint in
// buildFunctionTaintEnv must converge to env[a] carrying "parameter".
func TestTaintFixpointPropagatesLoopCarriedAlias(t *testing.T) {
	src := `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract LoopCarried {
    function f(address from) public pure returns (address) {
        address a;
        address b;
        for (uint256 i = 0; i < 2; i++) {
            a = b;
            b = from;
        }
        return a;
    }
}
`
	dir := t.TempDir()
	path := filepath.Join(dir, "loop_carried.sol")
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	sources, err := reader.New().Read(path)
	if err != nil {
		t.Fatalf("read sources: %v", err)
	}
	db, err := builder.New().Build(sources)
	if err != nil {
		t.Fatalf("build db: %v", err)
	}
	c := db.GetContractByName("LoopCarried")
	if c == nil {
		t.Fatal("LoopCarried not found")
	}
	var env map[string][]string
	for _, fn := range c.Functions {
		if fn.Name == "f" {
			env = New(db).buildFunctionTaintEnv(fn, nil)
		}
	}
	if env == nil {
		t.Fatal("function f not found")
	}
	found := false
	for _, s := range env["a"] {
		if s == "parameter" {
			found = true
		}
	}
	if !found {
		t.Fatalf("fixpoint should taint `a` from the parameter via the loop-carried alias; env[a] = %v", env["a"])
	}
}

// TestSequenceRespectsTryCatchArms proves the try/catch CFG-awareness upgrade.
// The body of a try and a catch clause can never both execute, so a
// `sequence: [state_write, outgoing_call]` must NOT match when the write is in
// the body and the call is in the catch (function f) — but MUST match when both
// land in the same arm (function g). The sequence starts with state_write so the
// always-executing try expression (an outgoing_call positioned before the body)
// cannot mask the arm check.
func TestSequenceRespectsTryCatchArms(t *testing.T) {
	src := `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IExt { function a() external; function b() external; }

contract TryCatchSeq {
    uint256 public state;
    IExt ext;

    // write in body, external call in catch -> mutually exclusive arms.
    function f() public {
        try ext.a() {
            state = 1;
        } catch {
            ext.b();
        }
    }

    // write then external call both in the body -> same arm.
    function g() public {
        try ext.a() {
            state = 1;
            ext.b();
        } catch {}
    }
}
`
	tmpl := `meta:
  id: TEST-TRYCATCH-SEQ
  title: try/catch sequence arm test
  severity: LOW
  confidence: LOW
query:
  scope: function
  match:
    sequence:
      - kind: state_write
      - kind: outgoing_call
`
	dir := t.TempDir()
	solPath := filepath.Join(dir, "trycatch_seq.sol")
	tmplPath := filepath.Join(dir, "seq.yaml")
	if err := os.WriteFile(solPath, []byte(src), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	if err := os.WriteFile(tmplPath, []byte(tmpl), 0o644); err != nil {
		t.Fatalf("write template: %v", err)
	}
	sources, err := reader.New().Read(solPath)
	if err != nil {
		t.Fatalf("read sources: %v", err)
	}
	db, err := builder.New().Build(sources)
	if err != nil {
		t.Fatalf("build db: %v", err)
	}
	loaded, err := LoadTemplate(tmplPath)
	if err != nil {
		t.Fatalf("load template: %v", err)
	}
	findings := New(db).Execute(loaded)
	hit := map[string]bool{}
	for _, f := range findings {
		hit[f.Location.Function] = true
	}
	if hit["f"] {
		t.Errorf("f must NOT match: state_write (body) and outgoing_call (catch) are mutually exclusive arms")
	}
	if !hit["g"] {
		t.Errorf("g must match: state_write and outgoing_call are in the same try body")
	}
}

func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "../.."))
}
