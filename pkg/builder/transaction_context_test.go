package builder

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/th13vn/w3goaudit/pkg/types"
)

const transactionContextFixture = "../../test-data/core/semantic-hardening/transaction-context.sol"

func TestBuildTransactionContextFactsClassifiesEffectMatrix(t *testing.T) {
	db := buildFixture(t, transactionContextFixture)
	if db.Semantics == nil || db.Semantics.TransactionContextVersion != types.TransactionContextFactsVersion {
		t.Fatalf("transaction context capability = %+v", db.Semantics)
	}

	assertTransactionFact(t, db, "directState(address[])", types.TransactionContextUseStateWrite, types.TransactionContextRepeatabilityPossible)
	assertTransactionFact(t, db, "callValue(address[])", types.TransactionContextUseCallValue, types.TransactionContextRepeatabilityPossible)
	helper := assertTransactionFact(t, db, "statefulHelper(address[])", types.TransactionContextUseStatefulInternalCall, types.TransactionContextRepeatabilityPossible)
	if helper.ResolvedCalleeID == "" {
		t.Fatalf("stateful helper fact has no exact callee: %+v", helper)
	}
	assertTransactionFact(t, db, "transitiveHelper(address[])", types.TransactionContextUseStatefulInternalCall, types.TransactionContextRepeatabilityPossible)
	assertTransactionFact(t, db, "localAlias(address[])", types.TransactionContextUseStateWrite, types.TransactionContextRepeatabilityPossible)
	assertTransactionFact(t, db, "arithmetic(address[])", types.TransactionContextUseStateWrite, types.TransactionContextRepeatabilityPossible)
	assertTransactionFact(t, db, "pushValue(address[])", types.TransactionContextUseStateWrite, types.TransactionContextRepeatabilityPossible)
	assertTransactionFact(t, db, "transferValue(address[])", types.TransactionContextUseCallValue, types.TransactionContextRepeatabilityPossible)
	assertTransactionFact(t, db, "sendValue(address[])", types.TransactionContextUseCallValue, types.TransactionContextRepeatabilityPossible)
	for _, selector := range []string{
		"inheritedHelper(address[])",
		"superHelper(address[])",
		"selfHelper(address[])",
	} {
		fact := assertTransactionFact(t, db, selector, types.TransactionContextUseStatefulInternalCall, types.TransactionContextRepeatabilityPossible)
		if fact.ResolvedCalleeID == "" {
			t.Fatalf("%s has no exact dispatched callee: %+v", selector, fact)
		}
	}
}

func TestBuildTransactionContextFactsSuppressesObservationalAndUnresolvedUses(t *testing.T) {
	db := buildFixture(t, transactionContextFixture)
	for _, selector := range []string{
		"emitOnly(address[])",
		"conditionOnly(address[])",
		"localOnly(address[])",
		"returnOnly(address[])",
		"pureHelper(address[])",
		"unresolvedHelper(address[])",
		"mappingKeyOnly(address[])",
		"externalCalldata(address[],IContextSink)",
		"reassignedAlias(address[])",
		"branchAlias(address[],bool)",
		"unresolvedReturnAlias(address[])",
		"whileFalse(address)",
		"falseFor(address)",
		"missingIncrement(address)",
	} {
		if facts := transactionFactsForSelector(t, db, selector); len(facts) != 0 {
			t.Errorf("%s facts = %+v, want none", selector, facts)
		}
	}
}

func TestBuildTransactionContextFactsKeepDistinctEffectsFromOneAlias(t *testing.T) {
	db := buildFixture(t, transactionContextFixture)
	facts := transactionFactsForSelector(t, db, "twoAliasEffects(address[])")
	if len(facts) != 2 {
		t.Fatalf("twoAliasEffects facts = %+v, want two exact effects", facts)
	}
	if facts[0].ID == facts[1].ID || facts[0].EffectRange.StartByte == facts[1].EffectRange.StartByte {
		t.Fatalf("twoAliasEffects facts are not distinct = %+v", facts)
	}
}

func TestBuildTransactionContextFactsClassifiesLoopRepeatability(t *testing.T) {
	db := buildFixture(t, transactionContextFixture)
	assertTransactionFact(t, db, "oneIteration(address)", types.TransactionContextUseStateWrite, types.TransactionContextRepeatabilitySingleIteration)
	assertTransactionFact(t, db, "doOnce(address)", types.TransactionContextUseStateWrite, types.TransactionContextRepeatabilitySingleIteration)
	assertTransactionFact(t, db, "nested(address[])", types.TransactionContextUseStateWrite, types.TransactionContextRepeatabilityPossible)
	if facts := transactionFactsForSelector(t, db, "missingIncrement(address)"); len(facts) != 0 {
		t.Fatalf("missingIncrement facts = %+v, want no fact for unsupported loop shape", facts)
	}
}

func TestBuildTransactionContextFactsCarryExactRangesAndEffectAttributes(t *testing.T) {
	db := buildFixture(t, transactionContextFixture)
	fact := assertTransactionFact(t, db, "directState(address[])", types.TransactionContextUseStateWrite, types.TransactionContextRepeatabilityPossible)
	if fact.SourceRange.StartLine == 0 || fact.SourceRange.StartByte == 0 || fact.EffectRange.StartLine == 0 || fact.EffectRange.StartByte == 0 || fact.LoopPath == "" {
		t.Fatalf("transaction context ranges/path incomplete = %+v", fact)
	}
	fn, ok := db.GetFunctionByID(fact.FunctionID)
	if !ok {
		t.Fatalf("function %s not found", fact.FunctionID)
	}
	loop := findASTNodeByPath(fn.AST, fact.LoopPath)
	if loop == nil || loop.Kind != types.KindStmtLoop {
		t.Fatalf("loop path %s resolved to %+v", fact.LoopPath, loop)
	}
	if loop.GetAttributeString("transaction_context_source") != "" {
		t.Fatalf("loop should remain an ordinary structural anchor, attributes = %+v", loop.Attributes)
	}
	source := findASTNodeByRange(fn.AST, fact.SourceRange.StartByte, fact.SourceRange.EndByte)
	effect := findASTNodeByRange(fn.AST, fact.EffectRange.StartByte, fact.EffectRange.EndByte)
	for label, node := range map[string]*types.ASTNode{"source": source, "effect": effect} {
		if node == nil || node.GetAttributeString("transaction_context_source") != types.TransactionContextSourceMsgValue ||
			node.GetAttributeString("transaction_context_use") != types.TransactionContextUseStateWrite ||
			node.GetAttributeString("transaction_context_repeatability") != types.TransactionContextRepeatabilityPossible {
			t.Fatalf("%s semantic attributes = %+v", label, node)
		}
	}
}

func TestBuildTransactionContextFactsSurviveDatabaseCache(t *testing.T) {
	db := buildFixture(t, transactionContextFixture)
	raw, err := json.Marshal(db)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	cache := filepath.Join(t.TempDir(), "database.json")
	if err := os.WriteFile(cache, raw, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	loaded, err := types.LoadFromJSON(cache)
	if err != nil {
		t.Fatalf("LoadFromJSON: %v", err)
	}
	if loaded.Semantics.TransactionContextVersion != types.TransactionContextFactsVersion ||
		!reflect.DeepEqual(loaded.Semantics.TransactionContextFacts, db.Semantics.TransactionContextFacts) {
		t.Fatalf("transaction-context facts changed across cache round-trip\n got: %#v\nwant: %#v", loaded.Semantics.TransactionContextFacts, db.Semantics.TransactionContextFacts)
	}
	for _, fact := range loaded.Semantics.TransactionContextFacts {
		fn, ok := loaded.GetFunctionByID(fact.FunctionID)
		if !ok {
			t.Fatalf("cached function %s not found", fact.FunctionID)
		}
		source := findASTNodeByRange(fn.AST, fact.SourceRange.StartByte, fact.SourceRange.EndByte)
		effect := findASTNodeByRange(fn.AST, fact.EffectRange.StartByte, fact.EffectRange.EndByte)
		if source == nil || effect == nil || source.GetAttributeString("transaction_context_source") != fact.Source || effect.GetAttributeString("transaction_context_use") != fact.Use {
			t.Fatalf("cached AST lost fact projection: fact=%+v source=%+v effect=%+v", fact, source, effect)
		}
	}
}

func findASTNodeByRange(root *types.ASTNode, startByte, endByte int) *types.ASTNode {
	if root == nil {
		return nil
	}
	if root.StartByte == startByte && root.EndByte == endByte {
		return root
	}
	for _, child := range root.Children {
		if found := findASTNodeByRange(child, startByte, endByte); found != nil {
			return found
		}
	}
	return nil
}

func assertTransactionFact(t *testing.T, db *types.Database, selector, use, repeatability string) *types.TransactionContextFact {
	t.Helper()
	facts := transactionFactsForSelector(t, db, selector)
	if len(facts) != 1 {
		t.Fatalf("%s facts = %+v, want one", selector, facts)
	}
	fact := facts[0]
	if fact.Source != types.TransactionContextSourceMsgValue || fact.Use != use || fact.Repeatability != repeatability {
		t.Fatalf("%s fact = %+v, want use=%s repeatability=%s", selector, fact, use, repeatability)
	}
	return fact
}

func transactionFactsForSelector(t *testing.T, db *types.Database, selector string) []*types.TransactionContextFact {
	t.Helper()
	abs := fixtureAbs(t, transactionContextFixture)
	functionID := types.MakeFunctionID(abs, "TransactionContextMatrix", selector)
	var facts []*types.TransactionContextFact
	for _, fact := range db.Semantics.TransactionContextFacts {
		if fact != nil && fact.FunctionID == functionID {
			facts = append(facts, fact)
		}
	}
	return facts
}
