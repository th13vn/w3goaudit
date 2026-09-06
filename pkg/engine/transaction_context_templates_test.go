package engine

import (
	"path/filepath"
	"reflect"
	"testing"
)

func TestMsgValueInLoopUsesProvenTransactionContextEffects(t *testing.T) {
	db := buildSemanticFixture(t, "transaction-context.sol")
	tmpl, err := LoadTemplate(filepath.Join(repoRoot(t), "templates/official/high/msg-value-in-loop.yaml"))
	if err != nil {
		t.Fatal(err)
	}

	want := sortedStrings([]string{
		"TransactionContextMatrix.arithmetic",
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
