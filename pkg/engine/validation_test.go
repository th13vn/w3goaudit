package engine

import (
	"encoding/json"
	"os"
	"os/exec"
	"runtime/debug"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/th13vn/w3goaudit/pkg/types"
	"gopkg.in/yaml.v3"
)

// validMeta is a minimal valid meta block for assembling test templates.
const validMeta = "meta:\n  id: T\n  severity: HIGH\n  confidence: HIGH\n"

func TestParseTemplateAcceptsWQL(t *testing.T) {
	tmpl, err := ParseTemplate(`
meta: {id: canonical-valid, severity: HIGH}
query:
  select: external_call
  from: entry_function
  where: [{name: transfer}]
`)
	if err != nil {
		t.Fatalf("ParseTemplate returned error: %v", err)
	}
	if tmpl.Meta.ID != "canonical-valid" || tmpl.Query.Scope != ScopeEntrypoint {
		t.Fatalf("template = %#v, want valid canonical entrypoint template", tmpl)
	}
}

func TestLegacyRuleJSONAliasesNormalizeWithoutEnteringWQL(t *testing.T) {
	legacy := Rule{
		SourceRegex:      `delegatecall\(`,
		VisibilityFilter: "public,external",
		MutabilityFilter: "payable",
	}

	raw, err := json.Marshal(legacy)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	for _, key := range []string{`"source_regex"`, `"visibility_filter"`, `"mutability_filter"`} {
		if !strings.Contains(string(raw), key) {
			t.Fatalf("legacy Rule JSON = %s, want key %s", raw, key)
		}
	}

	var decoded Rule
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	tmpl := &Template{
		Meta: TemplateMeta{ID: "legacy-json", Severity: "HIGH"},
		Query: QueryBlock{
			Scope:  ScopeFunction,
			Filter: &decoded,
			Match:  Rule{Kind: types.KindCallExternal},
		},
	}
	if err := finalizeTemplate(tmpl, "legacy JSON IR"); err != nil {
		t.Fatalf("finalizeTemplate: %v", err)
	}
	if got := tmpl.Query.Filter.Regex; got != legacy.SourceRegex {
		t.Errorf("Regex = %q, want legacy SourceRegex %q", got, legacy.SourceRegex)
	}
	if got := tmpl.Query.Filter.Visibility; got != legacy.VisibilityFilter {
		t.Errorf("Visibility = %q, want legacy VisibilityFilter %q", got, legacy.VisibilityFilter)
	}
	if got := tmpl.Query.Filter.Mutability; got != legacy.MutabilityFilter {
		t.Errorf("Mutability = %q, want legacy MutabilityFilter %q", got, legacy.MutabilityFilter)
	}
}

func TestLegacyRuleJSONAliasesRejectConflictingCanonicalValues(t *testing.T) {
	tmpl := &Template{
		Meta: TemplateMeta{ID: "legacy-conflict", Severity: "HIGH"},
		Query: QueryBlock{
			Scope: ScopeFunction,
			Filter: &Rule{
				Visibility:       "public",
				VisibilityFilter: "external",
			},
			Match: Rule{Kind: types.KindCallExternal},
		},
	}
	err := finalizeTemplate(tmpl, "conflicting JSON IR")
	if err == nil || !strings.Contains(err.Error(), "conflicting") {
		t.Fatalf("error = %v, want conflicting compatibility-field error", err)
	}
}

func TestExecuteNormalizesLegacyProgrammaticRuleAliases(t *testing.T) {
	db := buildDBFromSource(t, `
contract C {
    function run(address target) external payable { target.call(""); }
}
`).GetDatabase()
	baseline := &Template{
		Meta:  TemplateMeta{ID: "legacy-execute-baseline", Severity: "HIGH"},
		Query: QueryBlock{Scope: ScopeFunction, Match: Rule{Contains: &Rule{Kind: types.KindCallLowlevelCall}}},
	}
	if findings := New(db).Execute(baseline); len(findings) != 1 {
		t.Fatalf("baseline low-level call findings = %d, want 1", len(findings))
	}
	tmpl := &Template{
		Meta: TemplateMeta{ID: "legacy-execute", Severity: "HIGH"},
		Query: QueryBlock{
			Scope: ScopeFunction,
			Filter: &Rule{
				VisibilityFilter: "internal",
				MutabilityFilter: "view",
			},
			Match: Rule{Contains: &Rule{
				Kind:        types.KindCallLowlevelCall,
				SourceRegex: "DOES_NOT_EXIST",
			}},
		},
	}
	if findings := New(db).Execute(tmpl); len(findings) != 0 {
		t.Fatalf("legacy programmatic constraints were ignored: findings = %+v", findings)
	}
}

func TestDirectEvaluatorEntryPointsNormalizeLegacyAliasesWithoutMutation(t *testing.T) {
	const file = "/virtual/DirectAliases.sol"
	db := types.NewDatabase()
	db.AddSourceFile(&types.SourceFile{Path: file, Content: "contract DirectAliases {}\n"})
	contract := &types.Contract{
		Name:              "DirectAliases",
		SourceFile:        file,
		Kind:              types.ContractKindContract,
		LinearizedBases:   []string{"DirectAliases"},
		LinearizedBaseIDs: []string{types.MakeContractID(file, "DirectAliases")},
	}
	root := types.NewASTNode(types.KindDeclFunction)
	root.Name = "run"
	root.SetAttribute("visibility", "external")
	root.SetAttribute("mutability", "payable")
	child := types.NewASTNode(types.KindCallExternal)
	child.Name = "ping"
	child.SetAttribute("visibility", "external")
	child.SetAttribute("mutability", "payable")
	root.AddChild(child)
	fn := &types.Function{
		Name:            "run",
		ContractName:    contract.Name,
		SourceFile:      file,
		Visibility:      types.VisibilityExternal,
		StateMutability: types.StateMutabilityPayable,
		AST:             root,
	}
	contract.Functions = []*types.Function{fn}
	db.AddContract(contract)
	e := New(db)

	t.Run("Verify alias-only mismatch", func(t *testing.T) {
		rule := Rule{VisibilityFilter: "internal"}
		if e.Verify(child, rule) {
			t.Fatal("Verify ignored legacy visibility mismatch")
		}
		if rule.Visibility != "" {
			t.Fatalf("Verify mutated caller rule: Visibility = %q", rule.Visibility)
		}
	})

	t.Run("Verify nested alias and conflict", func(t *testing.T) {
		aliasChild := &Rule{MutabilityFilter: "view"}
		if e.Verify(root, Rule{Contains: aliasChild}) {
			t.Fatal("Verify ignored nested legacy mutability mismatch")
		}
		if aliasChild.Mutability != "" {
			t.Fatalf("Verify mutated nested caller rule: Mutability = %q", aliasChild.Mutability)
		}

		conflictChild := &Rule{Visibility: "external", VisibilityFilter: "internal"}
		if e.Verify(root, Rule{Contains: conflictChild}) {
			t.Fatal("Verify accepted nested canonical/legacy conflict")
		}
		if conflictChild.Visibility != "external" || conflictChild.VisibilityFilter != "internal" {
			t.Fatalf("Verify mutated nested conflict rule: %#v", conflictChild)
		}
	})

	functionCases := []struct {
		name string
		call func(Rule) bool
	}{
		{name: "VerifyAtFunction", call: func(rule Rule) bool { return e.VerifyAtFunction(fn, rule, contract) }},
		{name: "VerifyAtFunctionWithCallees", call: func(rule Rule) bool { return e.VerifyAtFunctionWithCallees(fn, rule, contract) }},
	}
	for _, tc := range functionCases {
		t.Run(tc.name+" alias-only mismatch", func(t *testing.T) {
			rule := Rule{VisibilityFilter: "internal"}
			if tc.call(rule) {
				t.Fatalf("%s ignored legacy visibility mismatch", tc.name)
			}
			if rule.Visibility != "" {
				t.Fatalf("%s mutated caller rule: Visibility = %q", tc.name, rule.Visibility)
			}
		})
		t.Run(tc.name+" conflict", func(t *testing.T) {
			rule := Rule{Visibility: "external", VisibilityFilter: "internal"}
			if tc.call(rule) {
				t.Fatalf("%s accepted canonical/legacy conflict", tc.name)
			}
		})
	}

	t.Run("VerifyAtContract alias-only mismatch", func(t *testing.T) {
		rule := Rule{SourceRegex: "DOES_NOT_EXIST"}
		if e.VerifyAtContract(contract, rule) {
			t.Fatal("VerifyAtContract ignored legacy source regex mismatch")
		}
		if rule.Regex != "" {
			t.Fatalf("VerifyAtContract mutated caller rule: Regex = %q", rule.Regex)
		}
	})

	t.Run("VerifyAtContract conflict", func(t *testing.T) {
		rule := Rule{Regex: "contract DirectAliases", SourceRegex: "DOES_NOT_EXIST"}
		if e.VerifyAtContract(contract, rule) {
			t.Fatal("VerifyAtContract accepted canonical/legacy conflict")
		}
	})
}

func TestCommaOnlyCSVValuesAreRejected(t *testing.T) {
	for _, matcher := range []string{
		"visibility: ', , '",
		"mutability: ',,'",
	} {
		_, err := ParseTemplate("meta: {id: CSV, severity: LOW}\nquery:\n" +
			"  select: external_call\n  where:\n    - " + matcher + "\n")
		if err == nil {
			t.Fatalf("%s loaded", matcher)
		}
	}
}

func TestDirectEvaluatorRejectsInvalidRuleValues(t *testing.T) {
	node := types.NewASTNode(types.KindCallExternal)
	e := New(types.NewDatabase())
	tests := []Rule{
		{Kind: "not.a.real.kind"},
		{Preset: "not_a_preset"},
		{Regex: "("},
		{TaintedFrom: "attacker_magic"},
		{Visibility: ", ,"},
		{Mutability: "payble"},
		{Version: "banana"},
	}
	for _, rule := range tests {
		if e.Verify(node, rule) {
			t.Errorf("Verify accepted %#v", rule)
		}
	}
}

func TestPrepareRuleForEvaluationReportsEveryInvalidValueClass(t *testing.T) {
	tests := []struct {
		name    string
		rule    Rule
		wantErr string
	}{
		{name: "regex", rule: Rule{Name: "("}, wantErr: `invalid regex in "name": (`},
		{name: "kind", rule: Rule{Kind: "not.a.real.kind"}, wantErr: `unknown kind "not.a.real.kind"`},
		{name: "preset", rule: Rule{Preset: "not_a_preset"}, wantErr: `unknown preset "not_a_preset"`},
		{name: "taint source", rule: Rule{TaintedFrom: "attacker_magic"}, wantErr: `unknown tainted_from "attacker_magic"`},
		{name: "visibility", rule: Rule{Visibility: ", ,"}, wantErr: "visibility must contain at least one value"},
		{name: "mutability", rule: Rule{Mutability: "payble"}, wantErr: `unknown mutability value "payble"`},
		{name: "version", rule: Rule{Version: "banana"}, wantErr: `invalid version constraint "banana"`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := prepareRuleForEvaluation(tc.rule, "rule")
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %v, want diagnostic containing %q", err, tc.wantErr)
			}
		})
	}
}

func TestAllDirectEvaluatorEntryPointsRejectOtherwiseMatchableInvalidRule(t *testing.T) {
	const file = "/virtual/InvalidDirectRule.sol"
	db := types.NewDatabase()
	db.AddSourceFile(&types.SourceFile{Path: file, Content: "contract InvalidDirectRule {}\n"})
	contract := &types.Contract{
		Name:              "InvalidDirectRule",
		SourceFile:        file,
		Kind:              types.ContractKindContract,
		LinearizedBases:   []string{"InvalidDirectRule"},
		LinearizedBaseIDs: []string{types.MakeContractID(file, "InvalidDirectRule")},
	}
	node := types.NewASTNode(types.KindDeclFunction)
	node.Name = "run"
	fn := &types.Function{
		Name:         "run",
		ContractName: contract.Name,
		SourceFile:   file,
		AST:          node,
	}
	contract.Functions = []*types.Function{fn}
	db.AddContract(contract)
	e := New(db)
	invalid := Rule{Version: "banana"}

	tests := []struct {
		name string
		call func() bool
	}{
		{name: "Verify", call: func() bool { return e.Verify(node, invalid) }},
		{name: "VerifyAtFunction", call: func() bool { return e.VerifyAtFunction(fn, invalid, contract) }},
		{name: "VerifyAtFunctionWithCallees", call: func() bool { return e.VerifyAtFunctionWithCallees(fn, invalid, contract) }},
		{name: "VerifyAtContract", call: func() bool { return e.VerifyAtContract(contract, invalid) }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.call() {
				t.Fatalf("%s accepted otherwise-matchable invalid rule %#v", tc.name, invalid)
			}
		})
	}
}

func TestCyclicProgrammaticRulesFailClosedWithoutMutation(t *testing.T) {
	if cycleCase := os.Getenv("W3GOAUDIT_RULE_CYCLE_CASE"); cycleCase != "" {
		debug.SetMaxStack(1 << 20)
		node := types.NewASTNode(types.KindCallExternal)
		node.SetAttribute("visibility", "external")
		e := New(types.NewDatabase())

		switch cycleCase {
		case "self":
			rule := Rule{VisibilityFilter: "external"}
			rule.Not = &rule
			if e.Verify(node, rule) {
				t.Fatal("Verify accepted a self-referential Rule")
			}
			if rule.Not != &rule || rule.Visibility != "" || rule.VisibilityFilter != "external" {
				t.Fatalf("Verify mutated self-referential caller Rule: %#v", rule)
			}
		case "two-node":
			a := Rule{VisibilityFilter: "external"}
			b := Rule{MutabilityFilter: "view"}
			a.Not = &b
			b.Not = &a
			if e.Verify(node, a) {
				t.Fatal("Verify accepted a two-node Rule cycle")
			}
			if a.Not != &b || b.Not != &a || a.Visibility != "" || b.Mutability != "" {
				t.Fatalf("Verify mutated two-node caller cycle: a=%#v b=%#v", a, b)
			}
		case "slice-backedge":
			rule := Rule{VisibilityFilter: "external"}
			rule.All = []Rule{{Not: &rule}}
			if e.Verify(node, rule) {
				t.Fatal("Verify accepted a Rule cycle through an All slice")
			}
			if rule.All[0].Not != &rule || rule.Visibility != "" {
				t.Fatalf("Verify mutated slice-cycle caller Rule: %#v", rule)
			}
		case "args-backedge":
			rule := Rule{VisibilityFilter: "external"}
			rule.Args = map[int]Rule{0: {Not: &rule}}
			if e.Verify(node, rule) {
				t.Fatal("Verify accepted a Rule cycle through Args")
			}
			if rule.Args[0].Not != &rule || rule.Visibility != "" {
				t.Fatalf("Verify mutated Args-cycle caller Rule: %#v", rule)
			}
		default:
			t.Fatalf("unknown child cycle case %q", cycleCase)
		}
		return
	}

	for _, cycleCase := range []string{"self", "two-node", "slice-backedge", "args-backedge"} {
		t.Run(cycleCase, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=^TestCyclicProgrammaticRulesFailClosedWithoutMutation$")
			cmd.Env = append(os.Environ(), "W3GOAUDIT_RULE_CYCLE_CASE="+cycleCase)
			output, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("cyclic Rule child failed instead of returning false: %v\n%s", err, output)
			}
		})
	}
}

func TestCyclicProgrammaticAttributeContainersFailClosedWithoutMutation(t *testing.T) {
	if cycleCase := os.Getenv("W3GOAUDIT_ATTR_GRAPH_CASE"); cycleCase != "" {
		debug.SetMaxStack(1 << 20)
		rule := Rule{VisibilityFilter: "external"}
		switch cycleCase {
		case "self-map":
			attributes := map[string]interface{}{}
			attributes["self"] = attributes
			rule.Attr = attributes
		case "self-slice":
			values := make([]interface{}, 1)
			values[0] = values
			rule.Attr = map[string]interface{}{"values": values}
		case "mixed-backedge":
			attributes := map[string]interface{}{}
			values := make([]interface{}, 1)
			attributes["values"] = values
			values[0] = attributes
			rule.Attr = attributes
		default:
			t.Fatalf("unknown attribute cycle case %q", cycleCase)
		}

		switch operation := os.Getenv("W3GOAUDIT_ATTR_GRAPH_OPERATION"); operation {
		case "verify":
			node := types.NewASTNode(types.KindCallExternal)
			node.SetAttribute("visibility", "external")
			if New(types.NewDatabase()).Verify(node, rule) {
				t.Fatal("Verify accepted a cyclic attribute container")
			}
		case "execute":
			tmpl := &Template{
				Meta:  TemplateMeta{ID: "cyclic-attr-execute", Severity: "HIGH"},
				Query: QueryBlock{Scope: ScopeFunction, Match: rule},
			}
			if findings := New(types.NewDatabase()).Execute(tmpl); len(findings) != 0 {
				t.Fatalf("Execute returned findings for cyclic attributes: %+v", findings)
			}
		case "finalize":
			tmpl := &Template{
				Meta:  TemplateMeta{ID: "cyclic-attr-finalize", Severity: "HIGH"},
				Query: QueryBlock{Scope: ScopeFunction, Match: rule},
			}
			if err := finalizeTemplate(tmpl, "cyclic attribute IR"); err == nil {
				t.Fatal("finalizeTemplate accepted cyclic attributes")
			}
		default:
			t.Fatalf("unknown attribute cycle operation %q", operation)
		}

		if rule.Visibility != "" || rule.VisibilityFilter != "external" {
			t.Fatalf("attribute graph path mutated caller rule: %#v", rule)
		}
		return
	}

	for _, cycleCase := range []string{"self-map", "self-slice", "mixed-backedge"} {
		for _, operation := range []string{"verify", "execute", "finalize"} {
			t.Run(cycleCase+"/"+operation, func(t *testing.T) {
				cmd := exec.Command(os.Args[0], "-test.run=^TestCyclicProgrammaticAttributeContainersFailClosedWithoutMutation$")
				cmd.Env = append(os.Environ(),
					"W3GOAUDIT_ATTR_GRAPH_CASE="+cycleCase,
					"W3GOAUDIT_ATTR_GRAPH_OPERATION="+operation,
				)
				output, err := cmd.CombinedOutput()
				if err != nil {
					t.Fatalf("cyclic attribute child failed instead of failing closed: %v\n%s", err, output)
				}
			})
		}
	}
}

func TestRuleCompatibilityCopyBoundsNestedAttributeContainers(t *testing.T) {
	makeNestedAttributes := func(depth int) map[string]interface{} {
		root := map[string]interface{}{}
		current := root
		for level := 1; level < depth; level++ {
			next := map[string]interface{}{}
			current["next"] = next
			current = next
		}
		current["leaf"] = "ok"
		return root
	}

	atLimit := Rule{Attr: makeNestedAttributes(MaxRuleRecursionDepth)}
	if _, err := normalizedRuleCompatibilityCopy(atLimit, "rule"); err != nil {
		t.Fatalf("maximum supported attribute depth rejected: %v", err)
	}
	if err := finalizeTemplate(&Template{
		Meta:  TemplateMeta{ID: "attr-depth-limit", Severity: "HIGH"},
		Query: QueryBlock{Scope: ScopeFunction, Match: atLimit},
	}, "attribute depth limit"); err != nil {
		t.Fatalf("finalizeTemplate rejected maximum attribute depth: %v", err)
	}

	overLimit := Rule{Attr: makeNestedAttributes(MaxRuleRecursionDepth + 1)}
	if _, err := normalizedRuleCompatibilityCopy(overLimit, "rule"); err == nil {
		t.Fatal("compatibility copy accepted attributes deeper than MaxRuleRecursionDepth")
	}
	if err := finalizeTemplate(&Template{
		Meta:  TemplateMeta{ID: "attr-depth-over-limit", Severity: "HIGH"},
		Query: QueryBlock{Scope: ScopeFunction, Match: overLimit},
	}, "attribute depth over limit"); err == nil {
		t.Fatal("finalizeTemplate accepted attributes deeper than MaxRuleRecursionDepth")
	}
}

func TestRuleCompatibilityCopyAllowsSharedAttributeDAGWithoutMutation(t *testing.T) {
	shared := map[string]interface{}{"leaf": "original"}
	rule := Rule{Attr: map[string]interface{}{"left": shared, "right": shared}}

	cloned, err := normalizedRuleCompatibilityCopy(rule, "rule")
	if err != nil {
		t.Fatalf("shared attribute DAG rejected: %v", err)
	}
	left, ok := cloned.Attr["left"].(map[string]interface{})
	if !ok {
		t.Fatalf("cloned left attribute = %#v, want map", cloned.Attr["left"])
	}
	left["leaf"] = "changed"
	if got := shared["leaf"]; got != "original" {
		t.Fatalf("compatibility copy mutated caller-owned shared map: %v", got)
	}
}

func TestCyclicProgrammaticIsStateVarContainersFailClosedWithoutMutation(t *testing.T) {
	if graphCase := os.Getenv("W3GOAUDIT_IS_STATE_VAR_GRAPH_CASE"); graphCase != "" {
		debug.SetMaxStack(1 << 20)
		rule := Rule{VisibilityFilter: "external"}
		switch graphCase {
		case "self-map":
			value := map[string]interface{}{}
			value["self"] = value
			rule.IsStateVar = value
		case "self-slice":
			value := make([]interface{}, 1)
			value[0] = value
			rule.IsStateVar = value
		case "mixed-backedge":
			value := map[string]interface{}{}
			slice := make([]interface{}, 1)
			value["slice"] = slice
			slice[0] = value
			rule.IsStateVar = value
		case "depth-65":
			rule.IsStateVar = nestedInterfaceMap(MaxRuleRecursionDepth + 1)
		default:
			t.Fatalf("unknown IsStateVar graph case %q", graphCase)
		}

		node := types.NewASTNode(types.KindStmtAssign)
		node.SetAttribute("is_state_var", true)
		db := databaseWithSingleASTNode(node)
		switch operation := os.Getenv("W3GOAUDIT_IS_STATE_VAR_GRAPH_OPERATION"); operation {
		case "verify":
			if New(db).Verify(node, rule) {
				t.Fatal("Verify accepted malformed IsStateVar graph")
			}
		case "execute":
			tmpl := &Template{Meta: TemplateMeta{ID: "is-state-var-graph", Severity: "HIGH"}, Query: QueryBlock{Scope: ScopeFunction, Match: rule}}
			if findings := New(db).Execute(tmpl); len(findings) != 0 {
				t.Fatalf("Execute returned findings for malformed IsStateVar graph: %+v", findings)
			}
		case "finalize":
			tmpl := &Template{Meta: TemplateMeta{ID: "is-state-var-graph", Severity: "HIGH"}, Query: QueryBlock{Scope: ScopeFunction, Match: rule}}
			if err := finalizeTemplate(tmpl, "malformed IsStateVar graph"); err == nil {
				t.Fatal("finalizeTemplate accepted malformed IsStateVar graph")
			}
		default:
			t.Fatalf("unknown IsStateVar graph operation %q", operation)
		}
		if rule.IsStateVar == nil || rule.Visibility != "" || rule.VisibilityFilter != "external" {
			t.Fatalf("IsStateVar graph path mutated caller rule: %#v", rule)
		}
		return
	}

	for _, graphCase := range []string{"self-map", "self-slice", "mixed-backedge", "depth-65"} {
		for _, operation := range []string{"verify", "execute", "finalize"} {
			t.Run(graphCase+"/"+operation, func(t *testing.T) {
				cmd := exec.Command(os.Args[0], "-test.run=^TestCyclicProgrammaticIsStateVarContainersFailClosedWithoutMutation$")
				cmd.Env = append(os.Environ(),
					"W3GOAUDIT_IS_STATE_VAR_GRAPH_CASE="+graphCase,
					"W3GOAUDIT_IS_STATE_VAR_GRAPH_OPERATION="+operation,
				)
				if output, err := cmd.CombinedOutput(); err != nil {
					t.Fatalf("IsStateVar graph child failed instead of failing closed: %v\n%s", err, output)
				}
			})
		}
	}
}

func TestIsStateVarCompatibilityCopyAllowsDepthLimitAndSharedDAGWithoutMutation(t *testing.T) {
	original := nestedInterfaceMap(MaxRuleRecursionDepth)
	rule := Rule{IsStateVar: original}
	cloned, err := normalizedRuleCompatibilityCopy(rule, "rule")
	if err != nil {
		t.Fatalf("maximum supported IsStateVar depth rejected: %v", err)
	}
	clonedMap, ok := cloned.IsStateVar.(map[string]interface{})
	if !ok {
		t.Fatalf("cloned IsStateVar = %#v, want map", cloned.IsStateVar)
	}
	clonedMap["new"] = "changed"
	if _, exists := original["new"]; exists {
		t.Fatal("compatibility copy mutated caller-owned IsStateVar map")
	}
	if rule.IsStateVar == nil {
		t.Fatal("compatibility copy cleared caller-owned IsStateVar field")
	}
	if err := finalizeTemplate(&Template{
		Meta:  TemplateMeta{ID: "is-state-var-depth-limit", Severity: "HIGH"},
		Query: QueryBlock{Scope: ScopeFunction, Match: rule},
	}, "IsStateVar depth limit"); err != nil {
		t.Fatalf("finalizeTemplate rejected maximum IsStateVar depth: %v", err)
	}

	shared := map[string]interface{}{"leaf": "original"}
	sharedRule := Rule{IsStateVar: map[string]interface{}{"left": shared, "right": shared}}
	sharedClone, err := normalizedRuleCompatibilityCopy(sharedRule, "rule")
	if err != nil {
		t.Fatalf("shared IsStateVar DAG rejected: %v", err)
	}
	root := sharedClone.IsStateVar.(map[string]interface{})
	root["left"].(map[string]interface{})["leaf"] = "changed"
	if got := shared["leaf"]; got != "original" {
		t.Fatalf("shared IsStateVar DAG clone mutated caller value: %v", got)
	}

	node := types.NewASTNode(types.KindStmtAssign)
	_ = New(databaseWithSingleASTNode(node)).Verify(node, sharedRule)
	if sharedRule.IsStateVar == nil {
		t.Fatal("Verify mutated caller-owned shared IsStateVar DAG")
	}
	tmpl := &Template{Meta: TemplateMeta{ID: "is-state-var-shared", Severity: "HIGH"}, Query: QueryBlock{Scope: ScopeFunction, Match: sharedRule}}
	_ = New(databaseWithSingleASTNode(node)).Execute(tmpl)
	if sharedRule.IsStateVar == nil {
		t.Fatal("Execute mutated caller-owned shared IsStateVar DAG")
	}
	if err := finalizeTemplate(tmpl, "shared IsStateVar DAG"); err != nil {
		t.Fatalf("finalizeTemplate rejected shared IsStateVar DAG: %v", err)
	}
}

func nestedInterfaceMap(depth int) map[string]interface{} {
	root := map[string]interface{}{}
	current := root
	for level := 1; level < depth; level++ {
		next := map[string]interface{}{}
		current["next"] = next
		current = next
	}
	current["leaf"] = "ok"
	return root
}

func databaseWithSingleASTNode(node *types.ASTNode) *types.Database {
	db := types.NewDatabase()
	file := "/tmp/is-state-var.sol"
	fn := &types.Function{Name: "run", Selector: "run()", SourceFile: file, AST: node}
	contract := &types.Contract{Name: "IsStateVarGraph", SourceFile: file, Functions: []*types.Function{fn}}
	db.AddSourceFile(&types.SourceFile{Path: file})
	db.AddContract(contract)
	return db
}

func TestRuleCompatibilityCopyEnforcesMaximumDepth(t *testing.T) {
	makeNestedAll := func(depth int) Rule {
		rule := Rule{
			Kind:             types.KindCallExternal,
			VisibilityFilter: "external",
		}
		for level := 1; level < depth; level++ {
			rule = Rule{All: []Rule{rule}}
		}
		return rule
	}
	deepest := func(rule *Rule) *Rule {
		for len(rule.All) == 1 {
			rule = &rule.All[0]
		}
		return rule
	}

	node := types.NewASTNode(types.KindCallExternal)
	node.SetAttribute("visibility", "external")

	atLimit := makeNestedAll(MaxRuleRecursionDepth)
	if _, err := normalizedRuleCompatibilityCopy(atLimit, "rule"); err != nil {
		t.Fatalf("maximum supported depth rejected: %v", err)
	}
	if !New(types.NewDatabase()).Verify(node, atLimit) {
		t.Fatal("Verify rejected a matching Rule at MaxRuleRecursionDepth")
	}
	if leaf := deepest(&atLimit); leaf.Visibility != "" || leaf.VisibilityFilter != "external" {
		t.Fatalf("Verify mutated the maximum-depth caller Rule leaf: %#v", leaf)
	}

	overLimit := makeNestedAll(MaxRuleRecursionDepth + 1)
	if _, err := normalizedRuleCompatibilityCopy(overLimit, "rule"); err == nil {
		t.Fatal("compatibility copy accepted a Rule deeper than MaxRuleRecursionDepth")
	}
	if New(types.NewDatabase()).Verify(node, overLimit) {
		t.Fatal("Verify accepted a Rule deeper than MaxRuleRecursionDepth")
	}
	if leaf := deepest(&overLimit); leaf.Visibility != "" || leaf.VisibilityFilter != "external" {
		t.Fatalf("Verify mutated the over-depth caller Rule leaf: %#v", leaf)
	}
}

func TestTemplatePathsRejectOverDepthRulesWithoutMutation(t *testing.T) {
	makeOverDepthRule := func() Rule {
		rule := Rule{Kind: types.KindCallExternal, SourceRegex: "ping"}
		for level := 1; level <= MaxRuleRecursionDepth; level++ {
			rule = Rule{All: []Rule{rule}}
		}
		return rule
	}
	deepest := func(rule *Rule) *Rule {
		for len(rule.All) == 1 {
			rule = &rule.All[0]
		}
		return rule
	}

	finalized := &Template{
		Meta:  TemplateMeta{ID: "over-depth-finalize", Severity: "HIGH"},
		Query: QueryBlock{Scope: ScopeFunction, Match: makeOverDepthRule()},
	}
	if err := finalizeTemplate(finalized, "over-depth programmatic IR"); err == nil {
		t.Fatal("finalizeTemplate accepted a Rule deeper than MaxRuleRecursionDepth")
	}
	if leaf := deepest(&finalized.Query.Match); leaf.Regex != "" || leaf.SourceRegex != "ping" {
		t.Fatalf("failed finalization mutated caller template leaf: %#v", leaf)
	}

	executed := &Template{
		Meta:  TemplateMeta{ID: "over-depth-execute", Severity: "HIGH"},
		Query: QueryBlock{Scope: ScopeFunction, Match: makeOverDepthRule()},
	}
	if findings := New(types.NewDatabase()).Execute(executed); len(findings) != 0 {
		t.Fatalf("Execute returned findings for over-depth Rule: %+v", findings)
	}
	if leaf := deepest(&executed.Query.Match); leaf.Regex != "" || leaf.SourceRegex != "ping" {
		t.Fatalf("failed Execute mutated caller template leaf: %#v", leaf)
	}
}

func TestSDKDocumentsReachabilityAndPrimaryNodePreciseFields(t *testing.T) {
	data, err := os.ReadFile("../../docs/sdk.md")
	if err != nil {
		t.Fatalf("read docs/sdk.md: %v", err)
	}
	doc := string(data)
	reachStart := strings.Index(doc, "type ReachStep struct {")
	nodeStart := strings.Index(doc, "type NodeRef struct {")
	entryStart := strings.Index(doc, "type EntryRef struct {")
	if reachStart < 0 || nodeStart <= reachStart || entryStart <= nodeStart {
		t.Fatalf("docs/sdk.md finding type snippets are missing or out of order")
	}
	reachSection := doc[reachStart:nodeStart]
	nodeSection := doc[nodeStart:entryStart]
	if !strings.Contains(reachSection, "File       string") {
		t.Errorf("ReachStep snippet omits File")
	}
	for _, required := range []string{"StartCol  int", "EndCol    int", "StartByte int", "EndByte   int"} {
		if !strings.Contains(nodeSection, required) {
			t.Errorf("NodeRef snippet missing %q", required)
		}
	}
	for _, required := range []string{
		"NodeRef columns are one-based Unicode-code-point columns",
		"NodeRef byte offsets are zero-based, half-open UTF-8 byte offsets",
	} {
		if !strings.Contains(doc, required) {
			t.Errorf("docs/sdk.md missing exact unit statement %q", required)
		}
	}
}

func TestParseTemplateRejectsIRShapedQuery(t *testing.T) {
	// The evaluator IR shape (scope/filter/match) is not the authoring
	// surface: a query: written that way must fail strict decoding.
	_, err := ParseTemplate(`
meta: {id: bad-shape, severity: HIGH}
query: {scope: entrypoint, match: {kind: call.external}}
`)
	if err == nil || !strings.Contains(err.Error(), "field scope not found") {
		t.Fatalf("error = %v, want strict unknown-field error for query.scope", err)
	}
}

func TestTemplateRejectsDirectYAMLUnmarshal(t *testing.T) {
	var tmpl Template
	err := yaml.Unmarshal([]byte(`
meta: {id: direct, severity: HIGH}
query: {scope: entrypoint, match: {kind: call.external}}
`), &tmpl)
	if err == nil || !strings.Contains(err.Error(), "use ParseTemplate or LoadTemplate") {
		t.Fatalf("error = %v, want loader-redirect guidance", err)
	}
}

func TestParseTemplateRejectsUnknownTopLevelKey(t *testing.T) {
	_, err := ParseTemplate(`
meta: {id: bad-key, severity: HIGH}
query:
  select: external_call
  from: entry_function
  where: [{name: transfer}]
bogus: true
`)
	if err == nil || !strings.Contains(err.Error(), "field bogus not found") {
		t.Fatalf("error = %v, want strict unknown-field error", err)
	}
}

func TestParseTemplateRejectsMultipleYAMLDocuments(t *testing.T) {
	_, err := ParseTemplate(`
meta: {id: first, severity: HIGH}
query:
  select: external_call
  from: entry_function
---
meta: {id: second, severity: LOW}
query:
  select: state_write
  from: function
`)
	if err == nil || !strings.Contains(err.Error(), "multiple YAML documents are unsupported") {
		t.Fatalf("error = %v, want multiple-document error", err)
	}
}

func TestParseTemplateRejectsInvalidDocuments(t *testing.T) {
	cases := []struct {
		name string
		yaml string
		want string
	}{
		{
			name: "removed matcher name",
			yaml: `
meta: {id: removed-matcher, severity: HIGH}
query:
  select: external_call
  from: entry_function
  where: [{contains: {block: identifier}}]
`,
			want: `unknown matcher key "contains"`,
		},
		{
			name: "no actionable AST or source matcher",
			yaml: `
meta: {id: context-only, severity: HIGH}
query:
  from: entry_function
  where: [{modifier: onlyOwner}]
`,
			want: "select: required",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseTemplate(tc.yaml)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want substring %q", err, tc.want)
			}
		})
	}
}

// TestLoadRejectsBadValues verifies the closed-set/load-time validations: each
// of these used to load cleanly and then silently misbehave at scan time.
func TestLoadRejectsBadValues(t *testing.T) {
	cases := []struct {
		name string
		yaml string
		want string // substring expected in the error
	}{
		{
			name: "unknown scope",
			yaml: validMeta + "query:\n  select: external_call\n  from: functions\n",
			want: "unknown scope",
		},
		{
			name: "bad tainted_from",
			yaml: validMeta + "query:\n  select: external_call\n  from: entry_function\n  where: [{tainted: parameters}]\n",
			want: "unknown tainted_from",
		},
		{
			name: "bad visibility",
			yaml: validMeta + "query:\n  select: external_call\n  from: entry_function\n  where: [{visibility: exernal}]\n",
			want: "unknown visibility",
		},
		{
			name: "bad version constraint",
			yaml: validMeta + "query:\n  select: external_call\n  from: entry_function\n  where: [{version: not-a-version}]\n",
			want: "invalid version constraint",
		},
		{
			name: "bad severity",
			yaml: "meta:\n  id: T\n  severity: hgih\n  confidence: HIGH\nquery:\n  select: external_call\n  from: entry_function\n",
			want: "invalid severity",
		},
		{
			name: "source scope without regex",
			yaml: validMeta + "query:\n  select: external_call\n  from: source\n",
			want: "source scope",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseTemplate(tc.yaml)
			if err == nil {
				t.Fatalf("expected load error containing %q, got nil", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %q, want substring %q", err.Error(), tc.want)
			}
		})
	}
}

// TestLoadAcceptsValidForms verifies representative WQL forms that must not
// error.
func TestLoadAcceptsValidForms(t *testing.T) {
	cases := map[string]string{
		"lowlevel call":        validMeta + "query:\n  select: lowlevel_call\n  from: entry_function\n",
		"builtin call":         validMeta + "query:\n  select: builtin_transfer\n  from: entry_function\n",
		"tainted sender":       validMeta + "query:\n  select: external_call\n  from: entry_function\n  where: [{tainted: sender}]\n",
		"caret version":        validMeta + "query:\n  select: external_call\n  from: entry_function\n  where: [{version: ^0.8.0}]\n",
		"empty scope defaults": "meta:\n  id: T\n  severity: LOW\n  confidence: LOW\nquery:\n  select: external_call\n",
		"contract scope name":  validMeta + "query:\n  from: contract\n  where: [{name: Vault}]\n",
		"contract scope AST":   validMeta + "query:\n  from: contract\n  where: [{has: {block: external_call}}]\n",
	}
	for name, y := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseTemplate(y); err != nil {
				t.Fatalf("expected valid template, got error: %v", err)
			}
		})
	}
}

func TestValidationRejectsNonCanonicalPresetNames(t *testing.T) {
	for _, preset := range []string{
		"unAuthenticated",
		"unCheckedSender",
		"unLocked",
		"user_controlled",
	} {
		t.Run(preset, func(t *testing.T) {
			yaml := validMeta + "query:\n  select: external_call\n  where: [{preset: " + preset + "}]\n"
			if _, err := ParseTemplate(yaml); err == nil {
				t.Fatalf("ParseTemplate accepted non-canonical preset %q", preset)
			}
		})
	}
}

func TestUserControlledTaintValidation(t *testing.T) {
	yaml := validMeta + "query:\n  select: external_call\n  where: [{tainted: user_controlled}]\n"
	if _, err := ParseTemplate(yaml); err != nil {
		t.Fatalf("ParseTemplate rejected tainted: user_controlled: %v", err)
	}
}

func TestStatementHasRejectsContextMatcher(t *testing.T) {
	_, err := ParseTemplate(`
meta: {id: statement-context, severity: HIGH}
query:
  select: binary
  from: entry_function
  where:
    - statement_has: {preset: access_controlled}
`)
	if err == nil || !strings.Contains(err.Error(), "context-level field") {
		t.Fatalf("error = %v, want statement_has context-placement rejection", err)
	}

	if _, err := ParseTemplate(`
meta: {id: statement-ast, severity: HIGH}
query:
  select: binary
  from: entry_function
  where:
    - statement_has: {block: identifier}
`); err != nil {
		t.Fatalf("AST-only statement_has control was rejected: %v", err)
	}
}

// TestAnchoredOperatorMatching verifies attribute matching is anchored:
// operator: "=" must match exactly "=", not "==".
func TestAnchoredOperatorMatching(t *testing.T) {
	e := &Engine{}
	eq := types.NewASTNode("expr.binary_op")
	eq.SetAttribute("operator", "=")
	eqeq := types.NewASTNode("expr.binary_op")
	eqeq.SetAttribute("operator", "==")

	if !e.matchAttributeValue(eq, "operator", "=") {
		t.Error(`"=" attribute should match pattern "="`)
	}
	if e.matchAttributeValue(eqeq, "operator", "=") {
		t.Error(`"==" attribute should NOT match anchored pattern "=" (regression: unanchored regex)`)
	}
}

// TestBoolAttrTolerance verifies a YAML bool template value matches a
// string-stored "true"/"false" attribute (and vice versa).
func TestBoolAttrTolerance(t *testing.T) {
	e := &Engine{}
	n := types.NewASTNode("expr.conditional")
	n.SetAttribute("conditional_part", "true") // stored as string by the builder

	if !e.matchAttributeValue(n, "conditional_part", true) {
		t.Error("YAML bool `true` should match string attribute \"true\"")
	}
	if e.matchAttributeValue(n, "conditional_part", false) {
		t.Error("YAML bool `false` should not match string attribute \"true\"")
	}
}

// TestVersionChecking exercises the version comparator (previously untested).
func TestVersionChecking(t *testing.T) {
	cmpCases := []struct {
		a, b string
		want int
	}{
		{"0.8.0", "0.8.0", 0},
		{"0.7.6", "0.8.0", -1},
		{"0.8.1", "0.8.0", 1},
		{"0.8.0", "0.8", 0}, // missing patch treated as 0
	}
	for _, c := range cmpCases {
		if got := compareVersions(c.a, c.b); got != c.want {
			t.Errorf("compareVersions(%q,%q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}

	// parseVersionConstraint splits operator from version.
	if op, v := parseVersionConstraint(">=0.8.0"); op != ">=" || v != "0.8.0" {
		t.Errorf("parseVersionConstraint(>=0.8.0) = (%q,%q), want (>=,0.8.0)", op, v)
	}

	// checkVersion against a pragma.
	e := &Engine{}
	e.currentSourceFile = &types.SourceFile{PragmaVersion: "^0.8.13"}
	if !e.checkVersion(">=0.8.0") {
		t.Error("checkVersion(>=0.8.0) against ^0.8.13 should be true")
	}
	if e.checkVersion("<0.8.0") {
		t.Error("checkVersion(<0.8.0) against ^0.8.13 should be false")
	}

	// Missing pragma → skip (vacuously true).
	e.currentSourceFile = &types.SourceFile{}
	if !e.checkVersion(">=0.8.0") {
		t.Error("checkVersion with no pragma should skip (return true)")
	}
}

// TestLoadTemplatesFromFS verifies templates load from an fs.FS with the same
// validation (one good, one bad → fail-closed error).
func TestLoadTemplatesFromFS(t *testing.T) {
	good := validMeta + "query:\n  select: external_call\n  from: entry_function\n"
	fsys := fstest.MapFS{
		"pack/a.yaml": &fstest.MapFile{Data: []byte(good)},
	}
	tmpls, err := LoadTemplatesFromFS(fsys, "pack", TemplateLoadOptions{})
	if err != nil {
		t.Fatalf("LoadTemplatesFromFS: %v", err)
	}
	if len(tmpls) != 1 {
		t.Fatalf("want 1 template, got %d", len(tmpls))
	}

	bad := validMeta + "query:\n  select: external_call\n  from: bogus\n"
	fsysBad := fstest.MapFS{
		"pack/a.yaml": &fstest.MapFile{Data: []byte(good)},
		"pack/b.yaml": &fstest.MapFile{Data: []byte(bad)},
	}
	if _, err := LoadTemplatesFromFS(fsysBad, "pack", TemplateLoadOptions{}); err == nil {
		t.Fatal("expected fail-closed error for an invalid template in the FS")
	}
}
