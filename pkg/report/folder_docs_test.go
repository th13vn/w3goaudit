package report

import "testing"

// TestContractFolderRel verifies the per-contract folder path mirrors the source
// layout (relative, extension stripped, sanitized contract name) and that the
// root-prefix walks back up exactly that many levels.
func TestContractFolderRel(t *testing.T) {
	SetReportProjectRoot("/project")
	t.Cleanup(func() { SetReportProjectRoot("") })

	cases := []struct {
		source     string
		name       string
		wantDir    string
		wantPrefix string
	}{
		{"/project/src/vault/Vault.sol", "VulnerableVault",
			"contracts/src/vault/Vault/VulnerableVault", "../../../../../"},
		{"/project/Token.sol", "Token",
			"contracts/Token/Token", "../../../"},
		{"/outside/Weird.sol", "Weird", // outside root -> basename fallback
			"contracts/Weird/Weird", "../../../"},
	}
	for _, c := range cases {
		mc := &ContractSummary{Name: c.name, SourceFile: c.source}
		if got := contractFolderRel(mc); got != c.wantDir {
			t.Errorf("contractFolderRel(%s, %s) = %q, want %q", c.source, c.name, got, c.wantDir)
		}
		if got := rootPrefixFor(c.wantDir); got != c.wantPrefix {
			t.Errorf("rootPrefixFor(%s) = %q, want %q", c.wantDir, got, c.wantPrefix)
		}
	}
}
