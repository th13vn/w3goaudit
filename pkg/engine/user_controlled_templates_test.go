package engine

import (
	"path/filepath"
	"testing"

	"github.com/th13vn/w3goaudit/pkg/builder"
	"github.com/th13vn/w3goaudit/pkg/reader"
	"github.com/th13vn/w3goaudit/pkg/types"
)

func TestRepositoryUserControlledTemplatesMatchCallerIdentity(t *testing.T) {
	root := repoRoot(t)
	skipWithoutBenchmarkHarness(t, root)
	db := buildRepositoryFixtureDatabase(t, root, "test-data/security/user-controlled-caller-identity.sol")

	groups := []struct {
		name      string
		templates []string
		want      []string
		reject    []string
	}{
		{
			name: "delegatecall",
			templates: []string{
				"templates/official/critical/delegatecall-user-input.yaml",
				"scripts/benchmark/templates/slither-inspired/controlled-delegatecall.yaml",
				"scripts/benchmark/templates/decurity-semgrep-inspired/delegatecall-to-arbitrary-address.yaml",
			},
			want: []string{
				"CallerIdentityDelegatecall.execute",
				"InternalHelperDelegatecall.execute",
				"ParameterDelegatecall.execute",
				"ParameterNamedMsgSenderDelegatecall.execute",
			},
			reject: []string{
				"FixedTargetDelegatecall.execute",
				"AccessControlledDelegatecall.execute",
				"ExternalMsgSenderDelegatecall.execute",
				"StateNamedMsgSenderDelegatecall.execute",
				"LocalNamedMsgSenderDelegatecall.execute",
				"NonzeroMsgSenderDelegatecall.execute",
			},
		},
		{
			name: "arbitrary low-level call",
			templates: []string{
				"templates/official/high/arbitrary-low-level-call.yaml",
				"scripts/benchmark/templates/decurity-semgrep-inspired/arbitrary-low-level-call.yaml",
			},
			want: []string{
				"CallerIdentityLowLevelCall.execute",
				"ParameterLowLevelCall.execute",
			},
			reject: []string{
				"FixedTargetLowLevelCall.execute",
				"AccessControlledLowLevelCall.execute",
			},
		},
		{
			name: "unrestricted transferOwnership",
			templates: []string{
				"templates/official/high/unrestricted-transferownership.yaml",
				"scripts/benchmark/templates/decurity-semgrep-inspired/unrestricted-transferownership.yaml",
			},
			want: []string{
				"CallerIdentityTransferOwnership.transferOwnership",
				"ParameterTransferOwnership.transferOwnership",
			},
			reject: []string{
				"FixedTargetTransferOwnership.transferOwnership",
				"AccessControlledTransferOwnership.transferOwnership",
			},
		},
		{
			name: "accessible selfdestruct",
			templates: []string{
				"scripts/benchmark/templates/decurity-semgrep-inspired/accessible-selfdestruct.yaml",
			},
			want: []string{
				"CallerIdentitySelfdestruct.destroy",
				"ParameterSelfdestruct.destroy",
				"FixedTargetSelfdestruct.destroy",
			},
			reject: []string{
				"AccessControlledSelfdestruct.destroy",
			},
		},
	}

	for _, group := range groups {
		group := group
		t.Run(group.name, func(t *testing.T) {
			for _, templatePath := range group.templates {
				templatePath := templatePath
				t.Run(filepath.Base(templatePath), func(t *testing.T) {
					got := executeRepositoryTemplate(t, root, db, templatePath)
					assertFindingSetContains(t, got, group.want)
					assertFindingSetExcludes(t, got, group.reject)
				})
			}
		})
	}
}

func TestRetainedParameterTemplatesRejectCallerIdentity(t *testing.T) {
	root := repoRoot(t)
	db := buildRepositoryFixtureDatabase(t, root, "test-data/security/user-controlled-caller-identity.sol")

	cases := []struct {
		name                 string
		templatePath         string
		parameter            string
		additionalParameters []string
		caller               string
	}{
		{
			name:         "transferFrom from account",
			templatePath: "templates/official/high/arbitrary-transferfrom.yaml",
			parameter:    "RetainedParameterTransferFrom.pullParameter",
			additionalParameters: []string{
				"RetainedParameterTransferFrom.pullParameterNamedMsgSender",
			},
			caller: "RetainedParameterTransferFrom.pullCallerIdentity",
		},
		{
			name:         "ETH recipient",
			templatePath: "templates/official/high/arbitrary-send-eth.yaml",
			parameter:    "RetainedParameterSendETH.sendParameter",
			caller:       "RetainedParameterSendETH.sendCallerIdentity",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := executeRepositoryTemplate(t, root, db, tc.templatePath)
			assertFindingSetContains(t, got, append([]string{tc.parameter}, tc.additionalParameters...))
			assertFindingSetExcludes(t, got, []string{tc.caller})
		})
	}
}

func TestRepositoryCallerIdentityAccessControlUsesExactMsgSenderHelper(t *testing.T) {
	root := repoRoot(t)
	db := buildRepositoryFixtureDatabase(t, root, "test-data/security/user-controlled-caller-identity.sol")

	cases := []struct {
		contract string
		want     bool
	}{
		{contract: "ExactInternalMsgSenderGuard", want: true},
		{contract: "ExternalMsgSenderGuard", want: false},
		{contract: "StateNamedMsgSenderGuard", want: false},
		{contract: "LocalNamedMsgSenderGuard", want: false},
		{contract: "ParameterNamedMsgSenderGuard", want: false},
		{contract: "NonzeroMsgSenderGuard", want: false},
	}

	for _, tc := range cases {
		t.Run(tc.contract, func(t *testing.T) {
			contract := mustContractByName(t, db, tc.contract)
			fn := mustFunctionByName(t, contract, "guard")
			if got := fn.IsAccessControlled(db); got != tc.want {
				t.Errorf("IsAccessControlled = %v, want %v", got, tc.want)
			}
			if got := fn.ComparesCallerIdentity(db); got != tc.want {
				t.Errorf("ComparesCallerIdentity = %v, want %v", got, tc.want)
			}
		})
	}
}

func buildRepositoryFixtureDatabase(t *testing.T, root, rel string) *types.Database {
	t.Helper()
	sources, err := reader.New().Read(filepath.Join(root, filepath.FromSlash(rel)))
	if err != nil {
		t.Fatalf("read fixture %s: %v", rel, err)
	}
	db, err := builder.New().Build(sources)
	if err != nil {
		t.Fatalf("build fixture %s: %v", rel, err)
	}
	return db
}

func executeRepositoryTemplate(t *testing.T, root string, db *types.Database, rel string) map[string]bool {
	t.Helper()
	tmpl, err := LoadTemplate(filepath.Join(root, filepath.FromSlash(rel)))
	if err != nil {
		t.Fatalf("load template %s: %v", rel, err)
	}
	got := make(map[string]bool)
	for _, finding := range New(db).Execute(tmpl) {
		got[finding.Location.Contract+"."+finding.Location.Function] = true
	}
	return got
}

func assertFindingSetContains(t *testing.T, got map[string]bool, want []string) {
	t.Helper()
	for _, finding := range want {
		if !got[finding] {
			t.Errorf("missing finding %s; got=%v", finding, got)
		}
	}
}

func assertFindingSetExcludes(t *testing.T, got map[string]bool, reject []string) {
	t.Helper()
	for _, finding := range reject {
		if got[finding] {
			t.Errorf("unexpected safe finding %s; got=%v", finding, got)
		}
	}
}
