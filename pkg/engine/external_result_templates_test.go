package engine

import (
	"encoding/json"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/th13vn/w3goaudit/pkg/builder"
	"github.com/th13vn/w3goaudit/pkg/reader"
	"github.com/th13vn/w3goaudit/pkg/types"
)

func TestUncheckedResultDetectorsUseSemanticResultFacts(t *testing.T) {
	root := repoRoot(t)
	sources, err := reader.New().Read(filepath.Join(root, "test-data/core/semantic-hardening/external-boundaries.sol"))
	if err != nil {
		t.Fatal(err)
	}
	db, err := builder.New().Build(sources)
	if err != nil {
		t.Fatal(err)
	}

	factCases := []struct {
		contract    string
		function    string
		disposition string
		checked     string
	}{
		{"ExternalBoundaryMatrix", "capturedChecked(address,bytes)", types.BoundaryResultCaptured, types.BoundaryResultYes},
		{"ExternalBoundaryMatrix", "capturedUnchecked(address,bytes)", types.BoundaryResultCaptured, types.BoundaryResultNo},
		{"ExternalBoundaryMatrix", "discarded(address,bytes)", types.BoundaryResultDiscarded, types.BoundaryResultNo},
		{"ExternalBoundaryMatrix", "returned(address,bytes)", types.BoundaryResultReturned, types.BoundaryResultNo},
		{"ExternalBoundaryMatrix", "directCondition(address,uint256)", types.BoundaryResultCondition, types.BoundaryResultYes},
		{"ExternalBoundaryMatrix", "consumed(address,uint256)", types.BoundaryResultConsumed, types.BoundaryResultNo},
		{"ERC20ResultMatrix", "transferDiscarded(address,uint256)", types.BoundaryResultDiscarded, types.BoundaryResultNo},
		{"ERC20ResultMatrix", "transferCapturedUnchecked(address,uint256)", types.BoundaryResultCaptured, types.BoundaryResultNo},
		{"ERC20ResultMatrix", "transferChecked(address,uint256)", types.BoundaryResultCondition, types.BoundaryResultYes},
	}
	for _, tc := range factCases {
		t.Run(tc.contract+"/"+tc.function, func(t *testing.T) {
			contract := findContractByName(t, db, tc.contract)
			selector := tc.function
			functionID := types.MakeFunctionID(contract.SourceFile, contract.Name, selector)
			var matches []*types.ExternalBoundaryFact
			for _, fact := range db.Semantics.ExternalBoundaries {
				if fact.ScopeID == functionID && fact.Result.Disposition == tc.disposition {
					matches = append(matches, fact)
				}
			}
			if len(matches) != 1 || matches[0].Result.DirectCheck != tc.checked {
				t.Fatalf("result facts = %+v, want one disposition=%q checked=%q", matches, tc.disposition, tc.checked)
			}
		})
	}

	cases := []struct {
		template string
		want     []string
		exclude  []string
	}{
		{
			template: "templates/official/medium/unchecked-lowlevel-call.yaml",
			want: []string{
				"ExternalBoundaryMatrix._orphan",
				"ExternalBoundaryMatrix.capturedUnchecked",
				"ExternalBoundaryMatrix.discarded",
				"ExternalBoundaryMatrix.constructor",
				"ExternalBoundaryMatrix.stateBefore",
				"ExternalBoundaryMatrix.stateAfter",
			},
			exclude: []string{"ExternalBoundaryMatrix.capturedChecked", "ExternalBoundaryMatrix.returned"},
		},
		{
			template: "templates/official/medium/unchecked-send.yaml",
			want:     []string{"ExternalBoundaryMatrix.loopUnknown"},
			exclude:  []string{"ExternalBoundaryMatrix.consumed", "ExternalBoundaryMatrix.directCondition", "ExternalBoundaryMatrix.unordered"},
		},
		{
			template: "templates/official/high/unchecked-erc20-transfer.yaml",
			want:     []string{"ERC20ResultMatrix.transferCapturedUnchecked", "ERC20ResultMatrix.transferDiscarded"},
			exclude:  []string{"ERC20ResultMatrix.transferChecked"},
		},
	}
	for _, tc := range cases {
		t.Run(filepath.Base(tc.template), func(t *testing.T) {
			tmpl, err := LoadTemplate(filepath.Join(root, tc.template))
			if err != nil {
				t.Fatal(err)
			}
			got := findingSites(New(db).Execute(tmpl))
			if !reflect.DeepEqual(got, sortedStrings(tc.want)) {
				t.Fatalf("findings = %v, want %v", got, sortedStrings(tc.want))
			}
			for _, site := range tc.exclude {
				if containsString(got, site) {
					t.Errorf("unsafe-result detector reported suppressed site %s", site)
				}
			}
		})
	}
}

func TestUncheckedResultTemplatesSourceCacheParity(t *testing.T) {
	root := repoRoot(t)
	sources, err := reader.New().Read(filepath.Join(root, "test-data/core/semantic-hardening/external-boundaries.sol"))
	if err != nil {
		t.Fatal(err)
	}
	db, err := builder.New().Build(sources)
	if err != nil {
		t.Fatal(err)
	}
	templates := make([]*Template, 0, 3)
	for _, path := range []string{
		"templates/official/medium/unchecked-lowlevel-call.yaml",
		"templates/official/medium/unchecked-send.yaml",
		"templates/official/high/unchecked-erc20-transfer.yaml",
	} {
		tmpl, err := LoadTemplate(filepath.Join(root, path))
		if err != nil {
			t.Fatal(err)
		}
		templates = append(templates, tmpl)
	}
	encode := func(database *types.Database) []byte {
		t.Helper()
		all := make([]*Finding, 0)
		for _, tmpl := range templates {
			all = append(all, New(database).Execute(tmpl)...)
		}
		raw, err := json.Marshal(all)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	want := encode(db)
	for run := 0; run < 3; run++ {
		if got := encode(db); !reflect.DeepEqual(got, want) {
			t.Fatalf("source execution changed on repeat %d", run+1)
		}
	}
	rawDB, err := json.Marshal(db)
	if err != nil {
		t.Fatal(err)
	}
	var cached types.Database
	if err := json.Unmarshal(rawDB, &cached); err != nil {
		t.Fatal(err)
	}
	cached.RestoreASTParents()
	if got := encode(&cached); !reflect.DeepEqual(got, want) {
		t.Fatal("source/cache result findings differ")
	}
}

func findContractByName(t *testing.T, db *types.Database, name string) *types.Contract {
	t.Helper()
	for _, contract := range db.Contracts {
		if contract.Name == name {
			return contract
		}
	}
	t.Fatalf("contract %q not found", name)
	return nil
}

func findingSites(findings []*Finding) []string {
	sites := make([]string, 0, len(findings))
	for _, finding := range findings {
		sites = append(sites, finding.Location.Contract+"."+finding.Location.Function)
	}
	return sortedStrings(sites)
}

func sortedStrings(values []string) []string {
	out := append([]string(nil), values...)
	sort.Strings(out)
	return out
}

func containsString(values []string, want string) bool {
	return strings.Contains("|"+strings.Join(values, "|")+"|", "|"+want+"|")
}
