package engine

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/th13vn/w3goaudit/pkg/builder"
	"github.com/th13vn/w3goaudit/pkg/reader"
)

// accessMappingContract renders a contract whose only guard is a
// mapping-membership check on the caller: `require(<name>[msg.sender])`. It is the
// most common access-control idiom in DeFi after a plain owner comparison.
func accessMappingContract(mappingName string) string {
	return `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Sweeper {
    mapping(address => bool) public ` + mappingName + `;

    modifier gated() {
        require(` + mappingName + `[msg.sender], "not permitted");
        _;
    }

    // Guarded by a caller-membership check: must NOT be reported.
    function guarded(address payable to, uint256 amount) external gated {
        to.transfer(amount);
    }
}
`
}

// findAccessMappingFindings scans one generated source with the shipped
// arbitrary-send-eth detector and returns the flagged function names.
func findAccessMappingFindings(t *testing.T, source string) []string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "Sweeper.sol")
	if err := os.WriteFile(path, []byte(source), 0o644); err != nil {
		t.Fatal(err)
	}
	sources, err := reader.New().Read(path)
	if err != nil {
		t.Fatalf("read sources: %v", err)
	}
	db, err := builder.New().Build(sources)
	if err != nil {
		t.Fatalf("build db: %v", err)
	}
	tmpl, err := LoadTemplate(filepath.Join(repoRoot(t), "templates/official/high/arbitrary-send-eth.yaml"))
	if err != nil {
		t.Fatalf("load template: %v", err)
	}
	var got []string
	for _, finding := range New(db).Execute(tmpl) {
		got = append(got, finding.Location.Function)
	}
	return got
}

// TestAccessMappingVocabularyCoversPrivilegedRoleNames pins that a caller
// membership check is recognized as access control for every conventional
// privileged-role mapping name, not just the handful originally listed.
//
// The mapping-membership path is gated on a name allowlist, so precision used to
// depend on what the author happened to call the mapping: `operators` and
// `whitelist` were recognized while `keepers`, `managers`, `controllers`,
// `governors`, and `trustedCallers` produced false positives on identical code.
func TestAccessMappingVocabularyCoversPrivilegedRoleNames(t *testing.T) {
	// Every one of these is a conventional name for a privileged principal.
	names := []string{
		"owners", "admins", "operators", "whitelist", "allowlist",
		"authorized", "roles", "permissions", "guardians", "minters", "pausers",
		// Previously missing — the F-4 regression set.
		"keepers", "managers", "controllers", "governors", "governance",
		"gov", "trustedCallers", "isTrusted", "signers", "validators",
		"executors", "relayers", "strategists", "moderators", "maintainers",
	}
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			got := findAccessMappingFindings(t, accessMappingContract(name))
			if len(got) != 0 {
				t.Errorf("mapping %q: require(%s[msg.sender]) is access control, but %v was flagged",
					name, name, got)
			}
		})
	}
}

// TestAccessMappingVocabularyRejectsNonAuthorityNames is the other half of the
// contract: widening the vocabulary must not turn every mapping read into proof
// of authorization. A balance, deposit, or stake lookup on the caller says
// nothing about WHO may call — anyone can acquire a nonzero balance — so those
// must still be reported.
func TestAccessMappingVocabularyRejectsNonAuthorityNames(t *testing.T) {
	names := []string{"balances", "deposits", "stakes", "shares", "rewards", "nonces", "blacklist"}
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			got := findAccessMappingFindings(t, accessMappingContract(name))
			if len(got) != 1 || got[0] != "guarded" {
				t.Errorf("mapping %q is not an authority check; want [guarded] flagged, got %v", name, got)
			}
		})
	}
}

// TestAccessMappingUnguardedIsStillFlagged is the baseline control: with no guard
// at all the detector must fire, proving the tests above measure the guard and
// not some unrelated suppression.
func TestAccessMappingUnguardedIsStillFlagged(t *testing.T) {
	source := `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Sweeper {
    function guarded(address payable to, uint256 amount) external {
        to.transfer(amount);
    }
}
`
	got := findAccessMappingFindings(t, source)
	if len(got) != 1 || got[0] != "guarded" {
		t.Fatalf("unguarded withdrawal must be flagged; got %v", got)
	}
}
