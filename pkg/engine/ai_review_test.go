package engine

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/th13vn/w3goaudit/pkg/types"
)

func TestParseTemplateAcceptsAIReviewContract(t *testing.T) {
	tmpl, err := ParseTemplate(`
meta: {id: AI-GENERAL, severity: HIGH, confidence: MEDIUM}
ai:
  enabled: true
  min_confidence: 0.9
  invariant: Assets must not leave protocol custody without caller authorization.
  trigger_conditions:
    - The caller can reach the value-transfer path.
    - No authorization proof constrains the caller.
  reject_if:
    - The destination and amount are fully protocol controlled.
query:
  select: eth_transfer
  from: entry_function
`)
	if err != nil {
		t.Fatalf("ParseTemplate: %v", err)
	}
	if tmpl.AI == nil {
		t.Fatal("Template.AI = nil")
	}
	if tmpl.AI.MinConfidence != 0.9 || len(tmpl.AI.TriggerConditions) != 2 {
		t.Fatalf("Template.AI = %#v", tmpl.AI)
	}
}

func TestParseTemplateRejectsInvalidAIReviewContracts(t *testing.T) {
	tests := map[string]string{
		"unknown key": `ai:
  enabled: true
  invariant: x
  trigger_conditions: [y]
  provider: codex`,
		"disabled": `ai:
  enabled: false
  invariant: x
  trigger_conditions: [y]`,
		"empty invariant": `ai:
  enabled: true
  invariant: ""
  trigger_conditions: [y]`,
		"no conditions": `ai:
  enabled: true
  invariant: x
  trigger_conditions: []`,
		"low confidence": `ai:
  enabled: true
  min_confidence: 0.49
  invariant: x
  trigger_conditions: [y]`,
	}
	for name, block := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := ParseTemplate("meta: {id: AI, severity: HIGH}\n" + block + "\nquery:\n  select: eth_transfer\n  from: entry_function\n")
			if err == nil {
				t.Fatal("ParseTemplate accepted invalid ai contract")
			}
		})
	}
}

type stubAIReviewer struct {
	verdict AIReviewVerdict
	err     error
	calls   []AIReviewRequest
}

func (s *stubAIReviewer) Review(_ context.Context, request AIReviewRequest) (AIReviewVerdict, error) {
	s.calls = append(s.calls, request)
	return s.verdict, s.err
}

func TestAIReviewFiltersCandidatesFailClosed(t *testing.T) {
	db := aiReviewTestDatabase()
	tmpl := &Template{
		Meta: TemplateMeta{ID: "AI-TRANSFER", Severity: "HIGH", Confidence: "MEDIUM"},
		AI: &AITemplatePolicy{
			Enabled: true, MinConfidence: 0.85, Invariant: "Unauthorized value must not leave custody",
			TriggerConditions: []string{"caller reaches transfer", "authorization is absent"},
		},
		Query: QueryBlock{Scope: ScopeEntrypoint, Match: Rule{Contains: &Rule{Kind: "eth_transfer"}}},
	}

	tests := []struct {
		name       string
		verdict    AIReviewVerdict
		err        error
		wantCount  int
		wantStatus AIReviewStatus
	}{
		{name: "accepted", verdict: AIReviewVerdict{ValidBug: true, TriggerConditionsMet: true, Confidence: 0.91, Reasoning: "caller can drain", Evidence: []string{"sendValue at line 4"}}, wantCount: 1, wantStatus: AIReviewAccepted},
		{name: "negative verdict", verdict: AIReviewVerdict{ValidBug: false, TriggerConditionsMet: false, Confidence: 0.96, Reasoning: "owner gate exists", MissingConditions: []string{"authorization is absent"}}, wantStatus: AIReviewRejected},
		{name: "low confidence", verdict: AIReviewVerdict{ValidBug: true, TriggerConditionsMet: true, Confidence: 0.7, Reasoning: "uncertain"}, wantStatus: AIReviewRejected},
		{name: "review error", err: errors.New("provider timeout"), wantStatus: AIReviewError},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			reviewer := &stubAIReviewer{verdict: tc.verdict, err: tc.err}
			eng := NewWithOptions(db, Options{AIReviewer: reviewer})
			findings := eng.Execute(tmpl)
			if len(findings) != tc.wantCount {
				t.Fatalf("findings = %d, want %d", len(findings), tc.wantCount)
			}
			records := eng.AIReviewRecords()
			if len(records) != 1 || records[0].Status != tc.wantStatus {
				t.Fatalf("records = %#v, want status %q", records, tc.wantStatus)
			}
			if len(reviewer.calls) != 1 || !strings.Contains(reviewer.calls[0].MatchedSource, "sendValue") {
				t.Fatalf("review requests = %#v", reviewer.calls)
			}
			if !strings.Contains(reviewer.calls[0].FunctionSource, "function withdraw") ||
				!strings.Contains(reviewer.calls[0].ContractSource, "contract Vault") {
				t.Fatalf("review request lacks enclosing source context: %#v", reviewer.calls[0])
			}
			if tc.wantCount == 1 && findings[0].AITriage == nil {
				t.Fatal("accepted finding has no aiTriage verdict")
			}
		})
	}
}

func aiReviewTestDatabase() *types.Database {
	path := "/tmp/AIReview.sol"
	content := "contract Vault {\n    function withdraw(address payable to) external {\n        to.sendValue(1);\n    }\n}\n"
	node := &types.ASTNode{
		Kind: types.KindCallBuiltinTransfer, Name: "sendValue", StartLine: 3, EndLine: 3,
		StartCol: 9, EndCol: 25, StartByte: 79, EndByte: 95,
		Attributes: map[string]interface{}{"source_file": path},
	}
	fn := &types.Function{
		Name: "withdraw", ContractName: "Vault", SourceFile: path,
		Visibility: types.VisibilityExternal, StateMutability: types.StateMutabilityNonPayable, Selector: "withdraw(address)",
		StartLine: 2, EndLine: 4, AST: &types.ASTNode{Kind: types.KindStmtBlock, Children: []*types.ASTNode{node}},
	}
	contract := &types.Contract{ID: path + "#Vault", Name: "Vault", Kind: types.ContractKindContract, SourceFile: path, Functions: []*types.Function{fn}}
	db := &types.Database{
		SourceFiles: map[string]*types.SourceFile{path: {Path: path, Content: content}},
		Contracts:   map[string]*types.Contract{contract.ID: contract},
	}
	db.CalculateMainContracts()
	db.RestoreASTParents()
	return db
}
