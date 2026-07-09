package engine

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/th13vn/w3goaudit/pkg/builder"
	"github.com/th13vn/w3goaudit/pkg/reader"
	"github.com/th13vn/w3goaudit/pkg/types"
)

// loadInline parses yamlSrc through the real ParseTemplate entry point (the
// same auto-detecting v1/v2 loader every template goes through), failing the
// test on any load error.
func loadInline(t *testing.T, yamlSrc string) *Template {
	t.Helper()
	tmpl, err := ParseTemplate(yamlSrc)
	if err != nil {
		t.Fatalf("ParseTemplate: %v\n---\n%s", err, yamlSrc)
	}
	return tmpl
}

// findingsFor runs tmpl against db through the same Engine construction used
// by the rest of the engine test suite (see arbitrary_send_eth_test.go).
func findingsFor(t *testing.T, tmpl *Template, db *types.Database) []*Finding {
	t.Helper()
	return New(db).Execute(tmpl)
}

// findingKey renders one finding into a comparable, order-independent key:
// TemplateID + Location (file/function/line) + sorted Related labels. Two
// findings from a v1 template and its v2 rewrite that resolve to the same key
// are considered "the same finding" for differential-testing purposes.
func findingKey(f *Finding) string {
	labels := make([]string, 0, len(f.Related))
	for _, r := range f.Related {
		labels = append(labels, r.Label)
	}
	sort.Strings(labels)
	return strings.Join([]string{
		f.TemplateID,
		f.Location.File,
		f.Location.Function,
		itoa(f.Location.Line),
		strings.Join(labels, "|"),
	}, "\x1f")
}

func itoa(n int) string {
	// Avoid importing strconv just for this; fmt.Sprintf is fine too, but
	// keep it dependency-light and obviously correct.
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// assertSameFindings loads v1YAML and v2YAML (a v1 `query:` template and its
// hand-written v2 `select/from/where` rewrite of the SAME detector), runs
// both against db, and asserts they produce identical finding sets — proving
// v2 lowering preserves v1 evaluation behavior exactly, by construction.
func assertSameFindings(t *testing.T, v1YAML, v2YAML string, db *types.Database) {
	t.Helper()

	v1Tmpl := loadInline(t, v1YAML)
	v2Tmpl := loadInline(t, v2YAML)

	v1Findings := findingsFor(t, v1Tmpl, db)
	v2Findings := findingsFor(t, v2Tmpl, db)

	if len(v1Findings) == 0 {
		t.Fatal("v1 template produced zero findings — fixture/test is not exercising the detector")
	}

	toKeySet := func(findings []*Finding) map[string]int {
		set := make(map[string]int, len(findings))
		for _, f := range findings {
			set[findingKey(f)]++
		}
		return set
	}

	v1Set := toKeySet(v1Findings)
	v2Set := toKeySet(v2Findings)

	if len(v1Set) != len(v2Set) {
		t.Fatalf("finding count mismatch: v1=%d v2=%d\nv1: %v\nv2: %v", len(v1Findings), len(v2Findings), keys(v1Set), keys(v2Set))
	}
	for k, count := range v1Set {
		if v2Set[k] != count {
			t.Fatalf("v2 findings differ from v1.\nv1 keys: %v\nv2 keys: %v", keys(v1Set), keys(v2Set))
		}
	}
}

func keys(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// delegatecallUserInputV1 is the real templates/official/critical/delegatecall-user-input.yaml
// detector (CRITICAL-DELEGATECALL-USER-INPUT), reproduced inline: an
// entrypoint-scoped delegatecall to a parameter-tainted address, gated by the
// unAuthenticated preset (no access control).
const delegatecallUserInputV1 = `
meta:
  id: CRITICAL-DELEGATECALL-USER-INPUT
  title: Delegatecall to User-Controlled Address
  severity: CRITICAL
  confidence: HIGH
  description: >
    A delegatecall is executed with a target address that comes from a function
    parameter (user-controlled).
  recommendation: >
    Never delegatecall to user-supplied addresses.

query:
  scope: entrypoint

  filter:
    preset: unAuthenticated

  match:
    contains:
      kind: delegatecall
      contains:
        kind: expr.identifier
        attr:
          call_receiver: true
        tainted_from: parameter
`

// delegatecallUserInputV2 is the WQL v2 select/from/where rewrite of the same
// detector. `not: {preset: access_controlled}` is the v2 spelling of v1's
// `filter: {preset: unAuthenticated}` (v2 presets name the safety PROPERTY, so
// asserting the property is ABSENT via `not:` is the vulnerable condition —
// see presetToV1's doc comment in pkg/engine/wql_v2_catalog.go). The `has:`
// matcher lowers to the same nested Match.Contains.Contains shape the v1
// template authors directly.
const delegatecallUserInputV2 = `
meta:
  id: CRITICAL-DELEGATECALL-USER-INPUT
  title: Delegatecall to User-Controlled Address
  severity: CRITICAL
  confidence: HIGH
  description: >
    A delegatecall is executed with a target address that comes from a function
    parameter (user-controlled).
  recommendation: >
    Never delegatecall to user-supplied addresses.

from: entry_function
select: delegatecall
where:
  - not: { preset: access_controlled }
  - has:
      block: identifier
      receiver: true
      tainted: parameter
`

// delegatecallFixtureSol is a minimal fixture with a genuinely vulnerable
// entrypoint (delegatecall to a caller-supplied address, no access control)
// and a safe sibling gated by `onlyOwner` (require(msg.sender == owner)),
// which IsAccessControlled recognizes as privileged access control.
const delegatecallFixtureSol = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Vulnerable_DelegatecallUserInput {
    // SHOULD FLAG: delegatecall target is a caller-supplied parameter, no
    // access control on the entry point.
    function execute(address target, bytes calldata data) external {
        (bool ok, ) = target.delegatecall(data);
        require(ok, "delegatecall failed");
    }
}

contract Safe_OwnerGatedDelegatecall {
    address public owner;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    // SHOULD NOT FLAG: same shape as the vulnerable case, but gated by
    // onlyOwner — IsAccessControlled recognizes the owner-gate modifier.
    function execute(address target, bytes calldata data) external onlyOwner {
        (bool ok, ) = target.delegatecall(data);
        require(ok, "delegatecall failed");
    }
}
`

// buildDelegatecallFixtureDB builds the *types.Database for
// delegatecallFixtureSol via the real reader -> builder pipeline, the same
// pattern every other pkg/engine differential/pipeline test uses (see
// arbitrary_send_eth_test.go).
func buildDelegatecallFixtureDB(t *testing.T) *types.Database {
	t.Helper()

	dir := t.TempDir()
	solPath := filepath.Join(dir, "delegatecall_fixture.sol")
	if err := os.WriteFile(solPath, []byte(delegatecallFixtureSol), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	sources, err := reader.New().Read(solPath)
	if err != nil {
		t.Fatalf("read sources: %v", err)
	}
	db, err := builder.New().Build(sources)
	if err != nil {
		t.Fatalf("build db: %v", err)
	}
	return db
}

// TestDifferential_DelegatecallUserInput is the Task A4 differential test:
// the v2 select/from/where rewrite of CRITICAL-DELEGATECALL-USER-INPUT must
// produce EXACTLY the same findings as the hand-written v1 query/filter/match
// template, on the same fixture (one vulnerable entrypoint, one onlyOwner-
// gated safe sibling). This is RED until the v2 loader is wired into
// ParseTemplate (pkg/engine/template.go) — v2 YAML fails to load beforehand.
func TestDifferential_DelegatecallUserInput(t *testing.T) {
	db := buildDelegatecallFixtureDB(t)
	assertSameFindings(t, delegatecallUserInputV1, delegatecallUserInputV2, db)
}
