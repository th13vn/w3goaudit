package engine

import (
	"encoding/json"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/th13vn/w3goaudit/pkg/types"
)

func TestMsgValueInLoopUsesProvenTransactionContextEffects(t *testing.T) {
	db := buildSemanticFixture(t, "transaction-context.sol")
	tmpl, err := LoadTemplate(filepath.Join(repoRoot(t), "templates/official/high/msg-value-in-loop.yaml"))
	if err != nil {
		t.Fatal(err)
	}

	want := sortedStrings([]string{
		"TransactionContextMatrix.arithmetic",
		"TransactionContextMatrix.assemblyCallValue",
		"TransactionContextMatrix.assemblyCreate2Value",
		"TransactionContextMatrix.assemblyCreateValue",
		"TransactionContextMatrix.assemblyStateWrite",
		"TransactionContextMatrix.callValue",
		"TransactionContextMatrix.directState",
		"TransactionContextMatrix.inheritedHelper",
		"TransactionContextMatrix.localAlias",
		"TransactionContextMatrix.nested",
		"TransactionContextMatrix.pushValue",
		"TransactionContextMatrix.selfHelper",
		"TransactionContextMatrix.sendValue",
		"TransactionContextMatrix.statefulHelper",
		"TransactionContextMatrix.superHelper",
		"TransactionContextMatrix.transferValue",
		"TransactionContextMatrix.transitiveHelper",
		"TransactionContextMatrix.twoAliasEffects",
	})
	if got := findingSites(New(db).Execute(tmpl)); !reflect.DeepEqual(got, want) {
		t.Fatalf("msg-value-loop findings = %v, want %v", got, want)
	}
}

func TestTransactionContextAttributesAreCanonicalWQL(t *testing.T) {
	for _, name := range []string{
		"transaction_context_source",
		"transaction_context_use",
		"transaction_context_repeatability",
	} {
		if got, ok := attrNameToIR(name); !ok || got != name {
			t.Fatalf("attrNameToIR(%q) = %q, %v, want identity mapping", name, got, ok)
		}
	}
}

func TestMsgValueInLoopFactsAndFindingsAreStableAcrossSourceAndCache(t *testing.T) {
	db := buildSemanticFixture(t, "transaction-context.sol")
	tmpl, err := LoadTemplate(filepath.Join(repoRoot(t), "templates/official/high/msg-value-in-loop.yaml"))
	if err != nil {
		t.Fatal(err)
	}

	encodeFindings := func(database *types.Database) []byte {
		t.Helper()
		findings := New(database).Execute(tmpl)
		raw, err := json.Marshal(findings)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}

	wantFindings := encodeFindings(db)
	for run := 0; run < 3; run++ {
		if got := encodeFindings(db); !reflect.DeepEqual(got, wantFindings) {
			t.Fatalf("source findings changed on repeat %d", run+1)
		}
	}
	wantFacts, err := db.TransactionContextFactsSnapshot()
	if err != nil {
		t.Fatal(err)
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
	gotFacts, err := cached.TransactionContextFactsSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(gotFacts, wantFacts) {
		t.Fatalf("source/cache transaction-context facts differ\n got: %#v\nwant: %#v", gotFacts, wantFacts)
	}
	if got := encodeFindings(&cached); !reflect.DeepEqual(got, wantFindings) {
		t.Fatalf("source/cache findings differ\n got: %s\nwant: %s", got, wantFindings)
	}
}
