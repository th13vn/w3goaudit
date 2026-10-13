package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/th13vn/w3goaudit/pkg/builder"
	"github.com/th13vn/w3goaudit/pkg/types"
)

func buildHunterDatabase(t *testing.T, path, source string) *types.Database {
	t.Helper()
	db, err := builder.New().Build([]*types.SourceFile{{Path: path, Content: source}})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	return db
}

func hunterEntryByID(t *testing.T, doc *HunterJSON, entryID, contractID string) *HunterEntry {
	t.Helper()
	for _, entry := range doc.Entries {
		if entry.EntryID == entryID && entry.ContractID == contractID {
			return entry
		}
	}
	t.Fatalf("entry %q in %q not found; have %+v", entryID, contractID, doc.Entries)
	return nil
}

func TestBuildHunterJSONRanksOpenValueSurfaceFirst(t *testing.T) {
	db := buildHunterDatabase(t, "/tmp/HunterRank.sol", `
pragma solidity ^0.8.20;
contract HunterRank {
    address public owner;
    mapping(address => uint256) public balance;
    function drain(address payable to, uint256 amount) external {
        (bool ok, ) = to.call{value: amount}("");
        require(ok);
        balance[msg.sender] = 0;
    }
    function setOwner(address next) external {
        require(msg.sender == owner);
        owner = next;
    }
}`)

	doc := BuildHunterJSON(db)
	if doc.SchemaVersion != SchemaVersion || doc.ModelVersion != HunterModelVersion {
		t.Fatalf("versions = schema %q model %q", doc.SchemaVersion, doc.ModelVersion)
	}
	if !doc.Available || doc.FactsVersions.ExternalBoundary != types.ExternalBoundaryFactsVersion ||
		doc.FactsVersions.Authorization != types.AuthorizationFactsVersion {
		t.Fatalf("availability = %+v", doc)
	}
	if doc.Count != len(doc.Entries) || doc.Count != 2 {
		t.Fatalf("count = %d, entries = %d", doc.Count, len(doc.Entries))
	}
	if doc.Entries[0].Rank != 1 || doc.Entries[1].Rank != 2 {
		t.Fatalf("ranks = %d, %d", doc.Entries[0].Rank, doc.Entries[1].Rank)
	}

	drain := doc.Entries[0]
	if !strings.HasPrefix(drain.FunctionSelector, "drain(") {
		t.Fatalf("first entry = %q, want drain to outrank the guarded setter", drain.FunctionSelector)
	}
	if drain.Tier != HunterTierOpenValue || drain.TierName != "open-value-surface" {
		t.Fatalf("drain tier = %d %q", drain.Tier, drain.TierName)
	}
	if drain.Signals.Authorization.Value != string(types.AuthorizationUnprotected) {
		t.Fatalf("drain authorization = %+v", drain.Signals.Authorization)
	}
	if len(drain.BoundaryIDs) == 0 || len(drain.Signals.ValueReach.FactIDs) == 0 {
		t.Fatalf("drain evidence = boundaries %v value %+v", drain.BoundaryIDs, drain.Signals.ValueReach)
	}
	if drain.ContractID != drain.DeclaredContractID {
		t.Fatalf("declared contract = %q, want %q", drain.DeclaredContractID, drain.ContractID)
	}
	if drain.Range.File != "/tmp/HunterRank.sol" || drain.Range.StartLine == 0 {
		t.Fatalf("drain range = %+v", drain.Range)
	}

	setter := doc.Entries[1]
	if setter.Signals.Authorization.Value != string(types.AuthorizationProtected) {
		t.Fatalf("setter authorization = %+v", setter.Signals.Authorization)
	}
	if setter.Tier != HunterTierNoBoundary {
		t.Fatalf("setter tier = %d, want no-boundary", setter.Tier)
	}
}

func TestBuildHunterJSONIsDeterministicAndTimestampFree(t *testing.T) {
	db := buildHunterDatabase(t, "/tmp/HunterStable.sol", `
pragma solidity ^0.8.20;
contract HunterStable {
    function a(address to) external { to.call(""); }
    function b(address to) external { to.call(""); }
    function c() external payable {}
}`)

	first, err := json.Marshal(BuildHunterJSON(db))
	if err != nil {
		t.Fatalf("marshal first: %v", err)
	}
	second, err := json.Marshal(BuildHunterJSON(db))
	if err != nil {
		t.Fatalf("marshal second: %v", err)
	}
	if string(first) != string(second) {
		t.Fatalf("hunter artifact is not byte-stable")
	}
	for _, banned := range []string{"generatedAt", "timestamp", "\"time\""} {
		if strings.Contains(string(first), banned) {
			t.Fatalf("artifact contains a timestamp field %q", banned)
		}
	}
}

func TestBuildHunterJSONOrdersTiesByEntryID(t *testing.T) {
	db := buildHunterDatabase(t, "/tmp/HunterTies.sol", `
pragma solidity ^0.8.20;
contract HunterTies {
    function zeta(address to) external { to.call(""); }
    function alpha(address to) external { to.call(""); }
}`)

	doc := BuildHunterJSON(db)
	if len(doc.Entries) != 2 {
		t.Fatalf("entries = %d", len(doc.Entries))
	}
	if doc.Entries[0].EntryID >= doc.Entries[1].EntryID {
		t.Fatalf("tie order = %q then %q, want ascending entry ID", doc.Entries[0].EntryID, doc.Entries[1].EntryID)
	}
}

func TestBuildHunterJSONEmitsOneRowPerDeployedContract(t *testing.T) {
	db := buildHunterDatabase(t, "/tmp/HunterMRO.sol", `
pragma solidity ^0.8.20;
abstract contract BaseVault {
    function pull(address to) external { to.call(""); }
}
contract VaultOne is BaseVault {}
contract VaultTwo is BaseVault {}`)

	doc := BuildHunterJSON(db)
	entryID := types.MakeFunctionID("/tmp/HunterMRO.sol", "BaseVault", "pull(address)")
	one := hunterEntryByID(t, doc, entryID, types.MakeContractID("/tmp/HunterMRO.sol", "VaultOne"))
	two := hunterEntryByID(t, doc, entryID, types.MakeContractID("/tmp/HunterMRO.sol", "VaultTwo"))

	declared := types.MakeContractID("/tmp/HunterMRO.sol", "BaseVault")
	if one.DeclaredContractID != declared || two.DeclaredContractID != declared {
		t.Fatalf("declared contract = %q and %q, want %q", one.DeclaredContractID, two.DeclaredContractID, declared)
	}
	if one.ContractName != "VaultOne" || two.ContractName != "VaultTwo" {
		t.Fatalf("contract names = %q and %q", one.ContractName, two.ContractName)
	}
}

func TestBuildHunterJSONFailsClosedWithoutFacts(t *testing.T) {
	cases := map[string]*types.Database{
		"nil database":    nil,
		"legacy database": types.NewDatabase(),
	}
	for name, db := range cases {
		t.Run(name, func(t *testing.T) {
			doc := BuildHunterJSON(db)
			if doc.Available {
				t.Fatalf("%s reported available", name)
			}
			if doc.Count != 0 || len(doc.Entries) != 0 || doc.Entries == nil {
				t.Fatalf("%s entries = %+v, want an empty non-nil slice", name, doc.Entries)
			}
			if len(doc.Limitations) == 0 {
				t.Fatalf("%s produced no limitation", name)
			}
			if doc.SchemaVersion != SchemaVersion || doc.ModelVersion != HunterModelVersion {
				t.Fatalf("%s versions = %+v", name, doc)
			}
		})
	}
}

func TestBuildHunterJSONPropagatesAnalysisLoss(t *testing.T) {
	db := buildHunterDatabase(t, "/tmp/HunterLoss.sol", `
pragma solidity ^0.8.20;
contract HunterLoss {
    function go(address to) external { to.call(""); }
}`)
	db.AddDiagnostic(types.Diagnostic{
		Code:       types.DiagnosticParseRecovered,
		Severity:   types.DiagnosticWarning,
		File:       "/tmp/HunterLoss.sol",
		Incomplete: true,
	})

	doc := BuildHunterJSON(db)
	if doc.AnalysisComplete {
		t.Fatalf("analysisComplete must be false when a diagnostic is incomplete")
	}
	if doc.DiagnosticCounts.Warning != 1 {
		t.Fatalf("diagnostic counts = %+v", doc.DiagnosticCounts)
	}
	if len(doc.Entries) != 1 {
		t.Fatalf("entries = %d", len(doc.Entries))
	}
	entry := doc.Entries[0]
	if entry.EvidenceComplete {
		t.Fatalf("entry in a parse-recovered file must not claim complete evidence")
	}
	if len(entry.Limitations) == 0 {
		t.Fatalf("entry limitations = %v, want the parse diagnostic recorded", entry.Limitations)
	}
}

func TestWriteBundleEmitsHunterArtifact(t *testing.T) {
	db := buildHunterDatabase(t, "/tmp/HunterBundle.sol", `
pragma solidity ^0.8.20;
contract HunterBundle {
    function go(address to) external payable { to.call{value: msg.value}(""); }
}`)
	dir := t.TempDir()
	summary := NewGenerator(db).GenerateSummary()
	opts := BundleOptions{Now: func() time.Time { return time.Unix(0, 0) }}
	if err := WriteBundle(dir, db, summary, nil, ToolMeta{Name: "w3goaudit", Version: "test"}, opts); err != nil {
		t.Fatalf("write bundle: %v", err)
	}

	raw, err := os.ReadFile(filepath.Join(dir, "data", "hunter.json"))
	if err != nil {
		t.Fatalf("read hunter artifact: %v", err)
	}
	var doc HunterJSON
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("decode hunter artifact: %v", err)
	}
	if !doc.Available || doc.Count != 1 || doc.Entries[0].Rank != 1 {
		t.Fatalf("bundled hunter artifact = %+v", doc)
	}
	if doc.Entries[0].Tier != HunterTierOpenValue {
		t.Fatalf("payable value-forwarding entry tier = %d", doc.Entries[0].Tier)
	}

	manifestRaw, err := os.ReadFile(filepath.Join(dir, "data", "manifest.json"))
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	var manifest ManifestJSON
	if err := json.Unmarshal(manifestRaw, &manifest); err != nil {
		t.Fatalf("decode manifest: %v", err)
	}
	if manifest.Files.Data.Hunter != "data/hunter.json" {
		t.Fatalf("manifest hunter path = %q", manifest.Files.Data.Hunter)
	}
}

// A function inherited by several deployed contracts has no single runtime.
// When the authorization facts record that every runtime agrees
// (`runtime.alternatives.agree`, empty RuntimeContractID), the verdict holds
// for each deployed contract's row instead of reading as missing.
func TestBuildHunterJSONUsesAgreedRuntimeAuthorization(t *testing.T) {
	db := buildHunterDatabase(t, "/tmp/HunterAgree.sol", `
pragma solidity ^0.8.20;
abstract contract BaseVault {
    address authority;
    modifier gate() { require(msg.sender == authority); _; }
    function pull(address to) external gate { to.call(""); }
}
contract VaultOne is BaseVault {}
contract VaultTwo is BaseVault {}`)

	doc := BuildHunterJSON(db)
	entryID := types.MakeFunctionID("/tmp/HunterAgree.sol", "BaseVault", "pull(address)")
	for _, name := range []string{"VaultOne", "VaultTwo"} {
		row := hunterEntryByID(t, doc, entryID, types.MakeContractID("/tmp/HunterAgree.sol", name))
		if row.Signals.Authorization.Value != string(types.AuthorizationProtected) {
			t.Errorf("%s authorization = %+v, want protected from the agreed fact", name, row.Signals.Authorization)
		}
	}
}
