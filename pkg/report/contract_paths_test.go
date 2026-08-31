package report

import (
	"strings"
	"testing"
	"time"
)

func TestContractReportPathSanitizesAndPreservesSource(t *testing.T) {
	got := contractReportPath("/repo", &ContractSummary{
		Name:       "Vault<>Admin",
		SourceFile: "/repo/src/vault/Vault.sol",
	})
	want := "contracts/src/vault/Vault__Vault_Admin.md"
	if got != want {
		t.Fatalf("contractReportPath = %q, want %q", got, want)
	}
}

func TestContractReportPathUsesBasenameOutsideRoot(t *testing.T) {
	got := contractReportPath("/repo", &ContractSummary{Name: "Weird", SourceFile: "/other/Weird.sol"})
	if got != "contracts/Weird__Weird.md" {
		t.Fatalf("outside-root report path = %q", got)
	}
}

func TestContractReportPathProtectsReservedAndLongComponents(t *testing.T) {
	name := strings.Repeat("x", 120)
	got := contractReportPath("/repo", &ContractSummary{Name: "CON", SourceFile: "/repo/" + name + ".sol"})
	if strings.Contains(got, "CON.md") || !strings.HasPrefix(got, "contracts/") || !strings.HasSuffix(got, "__CON_.md") {
		t.Fatalf("reserved/long report path = %q", got)
	}
	if len(strings.TrimSuffix(got, ".md")) > 160 {
		t.Fatalf("long report path was not bounded: len=%d path=%q", len(got), got)
	}
}

func TestContractReportIndexDisambiguatesSameNamesAndSorts(t *testing.T) {
	summary := &SummaryReport{
		ProjectRoot: "/repo",
		MainContracts: []*ContractSummary{
			{Name: "Vault", SourceFile: "/repo/z/Z.sol"},
			{Name: "Vault", SourceFile: "/repo/a/A.sol"},
			{Name: "A", SourceFile: "/repo/a/A.sol"},
		},
	}
	idx, err := buildContractReportIndex(summary, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(idx.refs) != 3 {
		t.Fatalf("refs = %d, want 3", len(idx.refs))
	}
	if idx.refs[0].Report != "contracts/a/A__A.md" || idx.refs[1].Report != "contracts/a/A__Vault.md" || idx.refs[2].Report != "contracts/z/Z__Vault.md" {
		t.Fatalf("refs not sorted/path-planned: %#v", idx.refs)
	}
	for _, ref := range idx.refs {
		if ref.Report == "" || ref.Dir == "" {
			t.Fatalf("incomplete ref: %#v", ref)
		}
	}
}

func TestContractReportIndexAddsIdentityDigestForSanitizedCollision(t *testing.T) {
	summary := &SummaryReport{
		ProjectRoot: "/repo",
		MainContracts: []*ContractSummary{
			{Name: "A/B", SourceFile: "/repo/src/A.sol"},
			{Name: "A\\B", SourceFile: "/repo/src/A.sol"},
		},
	}
	idx, err := buildContractReportIndex(summary, nil)
	if err != nil {
		t.Fatal(err)
	}
	if idx.refs[0].Report == idx.refs[1].Report || !strings.Contains(idx.refs[0].Report, "__") || !strings.Contains(idx.refs[1].Report, "__") {
		t.Fatalf("collision reports not disambiguated: %#v", idx.refs)
	}
}

func TestManifestCanonicalPaths(t *testing.T) {
	summary := &SummaryReport{ProjectRoot: "/repo", MainContracts: []*ContractSummary{{Name: "C", SourceFile: "/repo/C.sol"}}}
	idx, err := buildContractReportIndex(summary, nil)
	if err != nil {
		t.Fatal(err)
	}
	m := BuildManifestAt(time.Unix(0, 0), ToolMeta{Name: "w3goaudit"}, summary, nil, idx.refs, nil, true)
	if m.Files.Audit != "audit.md" || m.Files.AuditHTML != "audit.html" {
		t.Fatalf("canonical files = %#v", m.Files)
	}
	if m.Files.Summary != "audit.md" || m.Files.Overview != "audit.md" || m.Files.Findings != "audit.md" {
		t.Fatalf("Markdown compatibility aliases = %#v", m.Files)
	}
	if m.Files.OverviewHTML != "audit.html" || m.Files.FindingsHTML != "audit.html" {
		t.Fatalf("HTML compatibility aliases = %#v", m.Files)
	}
	if len(m.Contracts) != 1 || m.Contracts[0].Report != idx.refs[0].Report {
		t.Fatalf("canonical contract report = %#v", m.Contracts)
	}
	withoutHTML := BuildManifestAt(time.Unix(0, 0), ToolMeta{Name: "w3goaudit"}, summary, nil, idx.refs, nil, false)
	if withoutHTML.Files.AuditHTML != "" || withoutHTML.Files.OverviewHTML != "" || withoutHTML.Files.FindingsHTML != "" {
		t.Fatalf("HTML indexed when disabled = %#v", withoutHTML.Files)
	}
}
