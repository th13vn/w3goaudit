package engine

import (
	"testing"
)

// TestLegacyReentrancyTemplateMatchesImplicitPublicFunction locks the
// end-to-end paper-corpus regression: a Solidity 0.4.x function with omitted
// visibility uses the language's implicit-public default and must be scanned
// as an entry function.
func TestLegacyReentrancyTemplateMatchesImplicitPublicFunction(t *testing.T) {
	db := buildDBFromSource(t, `pragma solidity ^0.4.19;
contract LegacyBank {
    mapping(address => uint256) balances;
    function withdraw(uint256 amount) {
        if (msg.sender.call.value(amount)()) {
            balances[msg.sender] -= amount;
        }
    }
}`)
	tmpl, err := LoadTemplate(repoRoot(t) + "/templates/official/high/reentrancy-pattern.yaml")
	if err != nil {
		t.Fatalf("load reentrancy template: %v", err)
	}
	findings := New(db.GetDatabase()).Execute(tmpl)
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1; got %+v", len(findings), findings)
	}
	if got := findings[0].Location.Function; got != "withdraw" {
		t.Fatalf("finding function = %q, want withdraw", got)
	}
}

func TestReentrancySequenceIncludesAppliedModifierExecution(t *testing.T) {
	db := buildDBFromSource(t, "pragma solidity ^0.4.24;\ncontract ModifierEntrancy {\n    mapping (address => uint) public tokenBalance;\n    function airDrop() hasNoBalance supportsToken public {\n        tokenBalance[msg.sender] += 20;\n    }\n    modifier supportsToken() {\n        require(msg.sender.call.value(1)());\n        _;\n    }\n    modifier hasNoBalance() {\n        require(tokenBalance[msg.sender] == 0);\n        _;\n    }\n}")
	tmpl := &Template{
		Meta: TemplateMeta{ID: "MODIFIER-SEQUENCE", Severity: "HIGH", Confidence: "HIGH"},
		Query: QueryBlock{
			Scope:  ScopeEntrypoint,
			Filter: &Rule{Not: &Rule{Preset: "reentrancy_guarded"}},
			Match:  Rule{Sequence: []Rule{{Kind: "eth_transfer"}, {Kind: "state_write"}}},
		},
	}
	findings := New(db.GetDatabase()).Execute(tmpl)
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1 from external call in applied modifier; got %+v", len(findings), findings)
	}
	if got := findings[0].Location.Function; got != "airDrop" {
		t.Fatalf("finding function = %q, want airDrop", got)
	}
}

func TestSequenceIncludesTypedExternalCallInAppliedModifier(t *testing.T) {
	db := buildDBFromSource(t, "pragma solidity ^0.4.24;\ncontract ModifierEntrancy {\n    uint256 value;\n    function run() supportsToken public { value = 1; }\n    modifier supportsToken() { require(Bank(msg.sender).supportsToken()); _; }\n}\ncontract Bank { function supportsToken() external returns(bool) { return true; } }")
	tmpl := &Template{
		Meta: TemplateMeta{ID: "MODIFIER-OUTGOING", Severity: "HIGH"},
		Query: QueryBlock{
			Scope: ScopeEntrypoint,
			Match: Rule{Sequence: []Rule{{Kind: "outgoing_call"}, {Kind: "state_write"}}},
		},
	}
	if findings := New(db.GetDatabase()).Execute(tmpl); len(findings) != 1 {
		t.Fatalf("typed modifier sequence findings = %d, want 1; got %+v", len(findings), findings)
	}
}

func TestSequenceModifierWithoutPlaceholderSkipsWrappedBody(t *testing.T) {
	db := buildDBFromSource(t, "pragma solidity ^0.4.24;\ncontract ModifierStopsExecution {\n    uint256 value;\n    function run() stop public { value = 1; }\n    modifier stop() { require(msg.sender.call.value(1)()); }\n}")
	tmpl := &Template{
		Meta: TemplateMeta{ID: "MODIFIER-STOPS", Severity: "HIGH"},
		Query: QueryBlock{
			Scope: ScopeEntrypoint,
			Match: Rule{Sequence: []Rule{{Kind: "eth_transfer"}, {Kind: "state_write"}}},
		},
	}
	if findings := New(db.GetDatabase()).Execute(tmpl); len(findings) != 0 {
		t.Fatalf("modifier without placeholder executed wrapped body: %+v", findings)
	}
}

func TestSequenceModifierWithTwoPlaceholdersExecutesWrappedBodyTwice(t *testing.T) {
	db := buildDBFromSource(t, "pragma solidity ^0.4.24;\ncontract ModifierRepeatsExecution {\n    uint256 value;\n    function run() twice public { value = 1; }\n    modifier twice() { _; require(msg.sender.call.value(1)()); _; }\n}")
	tmpl := &Template{
		Meta: TemplateMeta{ID: "MODIFIER-REPEATS", Severity: "HIGH"},
		Query: QueryBlock{
			Scope: ScopeEntrypoint,
			Match: Rule{Sequence: []Rule{{Kind: "state_write"}, {Kind: "eth_transfer"}, {Kind: "state_write"}}},
		},
	}
	if findings := New(db.GetDatabase()).Execute(tmpl); len(findings) != 1 {
		t.Fatalf("two-placeholder modifier findings = %d, want 1; got %+v", len(findings), findings)
	}
}

func TestSequenceModifierPlaceholderInsideConditionalExecutesWrappedBodyOnArm(t *testing.T) {
	db := buildDBFromSource(t, "pragma solidity ^0.4.24;\ncontract ConditionalModifierExecution {\n    uint256 value;\n    function run(bool enabled) maybe(enabled) public { value = 1; }\n    modifier maybe(bool enabled) { if (enabled) { require(msg.sender.call.value(1)()); _; } }\n}")
	tmpl := &Template{
		Meta: TemplateMeta{ID: "MODIFIER-CONDITIONAL", Severity: "HIGH"},
		Query: QueryBlock{
			Scope: ScopeEntrypoint,
			Match: Rule{Sequence: []Rule{{Kind: "eth_transfer"}, {Kind: "state_write"}}},
		},
	}
	if findings := New(db.GetDatabase()).Execute(tmpl); len(findings) != 1 {
		t.Fatalf("conditional-placeholder findings = %d, want 1; got %+v", len(findings), findings)
	}
}

func TestSequenceDoesNotTreatWrappedFunctionUnderscoreLocalAsPlaceholder(t *testing.T) {
	db := buildDBFromSource(t, "pragma solidity ^0.4.24;\ncontract UnderscoreLocal {\n    uint256 value;\n    function run() gate public { uint256 _ = 1; value = _; }\n    modifier gate() { require(msg.sender.call.value(1)()); _; }\n}")
	tmpl := &Template{
		Meta: TemplateMeta{ID: "UNDERSCORE-LOCAL", Severity: "HIGH"},
		Query: QueryBlock{
			Scope: ScopeEntrypoint,
			Match: Rule{Sequence: []Rule{{Kind: "eth_transfer"}, {Kind: "state_write"}}},
		},
	}
	if findings := New(db.GetDatabase()).Execute(tmpl); len(findings) != 1 {
		t.Fatalf("underscore-local findings = %d, want 1; got %+v", len(findings), findings)
	}
}

func TestSequenceRepeatedSameModifierRestoresOuterPlaceholder(t *testing.T) {
	db := buildDBFromSource(t, "pragma solidity ^0.4.24;\ncontract RepeatedModifier {\n    uint256 value;\n    function run() twice twice public { value = 1; }\n    modifier twice() { _; require(msg.sender.call.value(1)()); _; }\n}")
	tmpl := &Template{
		Meta: TemplateMeta{ID: "REPEATED-MODIFIER", Severity: "HIGH"},
		Query: QueryBlock{
			Scope: ScopeEntrypoint,
			Match: Rule{Sequence: []Rule{
				{Kind: "state_write"},
				{Kind: "eth_transfer"},
				{Kind: "state_write"},
				{Kind: "eth_transfer"},
				{Kind: "state_write"},
			}},
		},
	}
	if findings := New(db.GetDatabase()).Execute(tmpl); len(findings) != 1 {
		t.Fatalf("repeated-same-modifier findings = %d, want 1; got %+v", len(findings), findings)
	}
}

func TestReentrancySequenceContinuesAfterInternalHelper(t *testing.T) {
	db := buildDBFromSource(t, "pragma solidity ^0.4.24;\ncontract ReentrancyBonus {\n    mapping(address => uint) rewardsForA;\n    mapping(address => bool) claimedBonus;\n    function withdrawReward(address recipient) public {\n        uint amountToWithdraw = rewardsForA[recipient];\n        rewardsForA[recipient] = 0;\n        bool success = recipient.call.value(amountToWithdraw)(\"\");\n        require(success);\n    }\n    function getFirstWithdrawalBonus(address recipient) public {\n        require(!claimedBonus[recipient]);\n        rewardsForA[recipient] += 100;\n        withdrawReward(recipient);\n        claimedBonus[recipient] = true;\n    }\n}")
	tmpl, err := LoadTemplate(repoRoot(t) + "/templates/official/high/reentrancy-pattern.yaml")
	if err != nil {
		t.Fatalf("load reentrancy template: %v", err)
	}
	findings := New(db.GetDatabase()).Execute(tmpl)
	for _, finding := range findings {
		if finding.EntryPoint != nil && finding.EntryPoint.Function == "getFirstWithdrawalBonus" {
			return
		}
	}
	t.Fatalf("no caller finding for helper-hosted reentrancy: %+v", findings)
}
