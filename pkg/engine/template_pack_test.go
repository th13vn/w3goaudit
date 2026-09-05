package engine

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestOfficialPackUsesCanonicalVocabulary(t *testing.T) {
	root := repoRoot(t)
	forEachOfficialTemplate(t, filepath.Join(root, "templates", "official"), func(path string) {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		var doc yaml.Node
		if err := yaml.Unmarshal(raw, &doc); err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		rootNode := documentMapping(doc.Content)
		if rootNode == nil {
			t.Fatalf("%s has no top-level mapping", path)
		}
		id := nestedScalar(rootNode, "meta", "id")
		if retiredOfficialIDs[id] {
			t.Errorf("%s uses retired official ID %q", path, id)
		}
		query := mappingValueNode(rootNode, "query")
		if query == nil {
			t.Fatalf("%s has no query", path)
		}
		for _, violation := range officialQueryVocabularyViolations(query) {
			t.Errorf("%s: %s", path, violation)
		}
	})
}

func TestOfficialPackHasUniqueIDsAndStrictLoads(t *testing.T) {
	root := repoRoot(t)
	seen := map[string]string{}
	count := 0
	forEachOfficialTemplate(t, filepath.Join(root, "templates", "official"), func(path string) {
		count++
		tmpl, err := LoadTemplate(path)
		if err != nil {
			t.Fatalf("LoadTemplate(%s): %v", path, err)
		}
		if previous, ok := seen[tmpl.Meta.ID]; ok {
			t.Errorf("duplicate official template ID %q in %s and %s", tmpl.Meta.ID, previous, path)
		}
		seen[tmpl.Meta.ID] = path
	})
	if count == 0 {
		t.Fatal("official template directory contains no YAML files")
	}
	if count != len(seen) {
		t.Fatalf("official template files = %d, unique IDs = %d", count, len(seen))
	}
}

func TestOfficialPackInventoryIsMigrationSized(t *testing.T) {
	root := repoRoot(t)
	want := []string{
		"CRITICAL-DELEGATECALL-USER-INPUT",
		"CRITICAL-SELFDESTRUCT-UNPROTECTED",
		"HIGH-ARBITRARY-LOW-LEVEL-CALL",
		"HIGH-ENCODE-PACKED-COLLISION",
		"HIGH-INCORRECT-EXP",
		"HIGH-MSG-VALUE-IN-LOOP",
		"HIGH-NO-SLIPPAGE-CHECK",
		"HIGH-REENTRANCY-PATTERN",
		"HIGH-UNCHECKED-ERC20-TRANSFER",
		"HIGH-UNPROTECTED-INITIALIZER",
		"HIGH-UNRESTRICTED-TRANSFEROWNERSHIP",
		"HIGH-WEAK-PRNG",
		"MEDIUM-BIDI-CHARACTERS",
		"MEDIUM-DANGEROUS-STRICT-EQUALITY",
		"MEDIUM-DIVIDE-BEFORE-MULTIPLY",
		"MEDIUM-TX-ORIGIN-AUTH",
		"MEDIUM-UNCHECKED-ARITHMETIC",
		"MEDIUM-UNCHECKED-LOWLEVEL-CALL",
		"MEDIUM-UNCHECKED-SEND",
		"MEDIUM-VIEW-PURE-MODIFIES-STATE",
	}
	got := make(map[string]struct{}, len(want))
	forEachOfficialTemplate(t, filepath.Join(root, "templates", "official"), func(path string) {
		tmpl, err := LoadTemplate(path)
		if err != nil {
			t.Fatalf("LoadTemplate(%s): %v", path, err)
		}
		got[tmpl.Meta.ID] = struct{}{}
	})
	if len(got) != len(want) {
		t.Fatalf("official template count = %d, want %d", len(got), len(want))
	}
	for _, id := range want {
		if _, ok := got[id]; !ok {
			t.Errorf("official pack missing canonical ID %q", id)
		}
	}
}

var retiredOfficialIDs = map[string]bool{
	// Unsupported rework and merged-family IDs leave the trusted pack until
	// generic semantic evidence is available. The migration deliberately
	// prefers a smaller truthful pack over protocol-name or source-regex claims.
	"HIGH-ARBITRARY-SEND-ETH":                  true,
	"HIGH-ARBITRARY-TRANSFERFROM":              true,
	"HIGH-DELEGATECALL-IN-LOOP":                true,
	"HIGH-ECDSA-RECOVER-MALLEABLE":             true,
	"HIGH-ERC20-PUBLIC-BURN":                   true,
	"HIGH-ORACLE-PRICE-UPDATE-UNRESTRICTED":    true,
	"HIGH-PROXY-STORAGE-COLLISION":             true,
	"HIGH-REENTRANCY-BALANCE":                  true,
	"HIGH-UNISWAP-CALLBACK-UNPROTECTED":        true,
	"HIGH-UNISWAP-V4-HOOK-UNPROTECTED":         true,
	"MEDIUM-ORACLE-CURVE-SPOT-PRICE":           true,
	"MEDIUM-ORACLE-LP-SPOT-PRICE":              true,
	"HIGH-CALLBACK-REENTRANCY":                 true,
	"HIGH-READONLY-REENTRANCY":                 true,
	"MEDIUM-ORACLE-ROUND-VALIDATION":           true,
	"HIGH-ERC721-CALLBACK-REENTRANCY":          true,
	"HIGH-ERC777-CALLBACK-REENTRANCY":          true,
	"HIGH-READONLY-REENTRANCY-BALANCER":        true,
	"HIGH-READONLY-REENTRANCY-CURVE":           true,
	"MEDIUM-STALE-ORACLE-DATA":                 true,
	"MEDIUM-DEPRECATED-CHAINLINK-LATESTANSWER": true,
	"MEDIUM-BOOLEAN-CST":                       true,
}

var forbiddenOfficialQueryKeys = map[string]bool{
	"runtime": true, "runtime_contract": true,
	"access_controlled": true, "caller_checked": true,
	"initializer_guarded": true, "auth_verdict": true,
	"auth_principal": true, "auth_dominates": true,
	"first_call_takeover": true, "constructor_disable": true,
	"proxy_linkage": true,
}

var forbiddenOfficialQueryValues = map[string]bool{
	"unknown": true, "runtime": true, "runtime_contract": true,
	"access_controlled": true, "caller_checked": true,
	"initializer_guarded": true, "first_call_takeover": true,
	"constructor_disable": true, "proxy_linkage": true,
}

func forEachOfficialTemplate(t *testing.T, root string, fn func(string)) {
	t.Helper()
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || filepath.Ext(path) != ".yaml" {
			return nil
		}
		fn(path)
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
}

func documentMapping(content []*yaml.Node) *yaml.Node {
	if len(content) == 0 || content[0] == nil || content[0].Kind != yaml.MappingNode {
		return nil
	}
	return content[0]
}

func mappingValueNode(mapping *yaml.Node, key string) *yaml.Node {
	if mapping == nil || mapping.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(mapping.Content); i += 2 {
		if mapping.Content[i].Value == key {
			return mapping.Content[i+1]
		}
	}
	return nil
}

func nestedScalar(mapping *yaml.Node, parent, key string) string {
	nested := mappingValueNode(mapping, parent)
	value := mappingValueNode(nested, key)
	if value == nil || value.Kind != yaml.ScalarNode {
		return ""
	}
	return strings.TrimSpace(value.Value)
}

func officialQueryVocabularyViolations(node *yaml.Node) []string {
	var violations []string
	var walk func(*yaml.Node)
	walk = func(current *yaml.Node) {
		if current == nil {
			return
		}
		if current.Kind == yaml.MappingNode {
			for i := 0; i+1 < len(current.Content); i += 2 {
				keyNode, valueNode := current.Content[i], current.Content[i+1]
				key := strings.TrimSpace(keyNode.Value)
				if forbiddenOfficialQueryKeys[key] {
					violations = append(violations, "forbidden query key "+key)
				}
				if valueNode.Kind == yaml.ScalarNode && forbiddenOfficialQueryValues[strings.TrimSpace(valueNode.Value)] {
					violations = append(violations, "forbidden query value "+strings.TrimSpace(valueNode.Value))
				}
				if key == "receiver" && valueNode.Kind == yaml.ScalarNode && strings.EqualFold(strings.TrimSpace(valueNode.Value), "true") {
					violations = append(violations, "receiver must use a nested matcher")
				}
				if key == "unchecked_var" && valueNode.Kind == yaml.ScalarNode {
					value := strings.TrimSpace(valueNode.Value)
					if strings.EqualFold(value, "true") || strings.EqualFold(value, "false") {
						violations = append(violations, "unchecked_var must be presence-only")
					}
				}
				walk(valueNode)
			}
			return
		}
		for _, child := range current.Content {
			walk(child)
		}
	}
	walk(node)
	return violations
}

func TestRepositoryTemplatePackIsValidWQL(t *testing.T) {
	root := repoRoot(t)
	templateRoots := []struct {
		path  string
		want  int
		fixed bool
	}{
		// The trusted official pack is intentionally migration-sized. Its
		// inventory is derived from the filesystem so removing an unproven
		// detector cannot leave a stale count assertion behind.
		{path: "templates/official"},
		{path: "templates/test", want: 5, fixed: true},
	}
	// The benchmark template lane lives under the dev-only, git-ignored
	// scripts/benchmark/ harness; only assert it when the harness is present.
	if benchmarkHarnessAvailable(root) {
		templateRoots = append(templateRoots, struct {
			path  string
			want  int
			fixed bool
		}{path: "scripts/benchmark/templates", want: 76, fixed: true})
	}

	total := 0
	for _, templateRoot := range templateRoots {
		count := validateRepositoryTemplateLane(t, root, templateRoot.path)
		if templateRoot.fixed && count != templateRoot.want {
			t.Errorf("repository template lane %s = %d, want %d", templateRoot.path, count, templateRoot.want)
		}
		total += count
	}
	if total == 0 {
		t.Fatal("repository template inventory is empty")
	}
}

func validateRepositoryTemplateLane(t *testing.T, root, templateRoot string) int {
	t.Helper()

	laneRoot := filepath.Join(root, filepath.FromSlash(templateRoot))
	count := 0
	err := filepath.WalkDir(laneRoot, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || filepath.Ext(path) != ".yaml" {
			return nil
		}

		count++
		rel, err := filepath.Rel(root, path)
		if err != nil {
			rel = path
		}
		if _, err := LoadTemplate(path); err != nil {
			t.Errorf("LoadTemplate(%s): %v", rel, err)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk required template lane %s: %v", templateRoot, err)
	}

	if count == 0 {
		t.Fatalf("required template lane %s contains no .yaml templates", templateRoot)
	}
	return count
}

func TestAuthoritativeWQLDocsUseCanonicalVocabulary(t *testing.T) {
	root := repoRoot(t)
	required := map[string][]string{
		"docs/wql-syntax.md": {
			"where-only", "entry_function", "state_write",
			"push", "pop", "delete", "guarded_by", "modifier",
		},
		"docs/internals.md": {
			"initialization", "condition", "body", "post",
			"stmt.state_mutation",
		},
		"docs/sdk.md": {
			"ResolvedImports", "SourceFiles", "Content",
		},
	}
	for rel, phrases := range required {
		text := readRepositoryText(t, root, rel)
		for _, phrase := range phrases {
			if !strings.Contains(text, phrase) {
				t.Errorf("%s missing %q", rel, phrase)
			}
		}
	}

	falseStatements := map[string][]string{
		"docs/extension-output.md": {
			`"signature": "transfer(address,uint256)"`,
		},
		"docs/workflows.md": {
			"Generate function signatures (e.g., `transfer(address,uint256)`)",
			"overview.md contains the full report",
		},
		"docs/usage.md": {
			"`--fail-on`, `--location-source`, and `--log`",
			"All main contracts with their pragma version, stats, Mermaid call graphs, inheritance, entry-point tables",
			"overview.md contains the full report",
		},
		"docs/sdk.md": {
			"source files must remain on disk",
		},
	}
	for rel, phrases := range falseStatements {
		text := readRepositoryText(t, root, rel)
		for _, phrase := range phrases {
			if strings.Contains(text, phrase) {
				t.Errorf("%s still contains false statement %q", rel, phrase)
			}
		}
	}

	forbidden := []string{
		strings.Join([]string{"WQL", "v1"}, " "),
		strings.Join([]string{"WQL", "v2"}, " "),
		"Template" + "V2",
		"Matcher" + "V2",
		"parse" + "V2",
		strings.Join([]string{"wql", "v2"}, "_"),
		strings.Join([]string{"wql", "v2"}, "-"),
		"valid" + "-v2",
		"unAuthenticated",
		"unCheckedSender",
		"unLocked",
		"presetToIR",
		"meta`/`select`/`from`/`where",
		"meta/select/from/where",
		"`all:`",
	}

	for _, rel := range []string{"README.md", "CONTRIBUTING.md", "docs/wql-syntax.md"} {
		text := readRepositoryText(t, root, rel)
		if !strings.Contains(text, "A WQL document is meta plus one query: block.") {
			t.Errorf("%s does not state the canonical document shape", rel)
		}
		for _, obsolete := range forbidden {
			if strings.Contains(text, obsolete) {
				t.Errorf("%s contains obsolete public WQL vocabulary %q", rel, obsolete)
			}
		}
	}

	staleText := map[string][]string{
		"scripts/benchmark/fixtures/decurity-semgrep-inspired/unrestricted-transfer-ownership-fake-modifier.sol": {
			"unAuthenticated",
		},
		"templates/AI.md": {
			"written in WQL**",
			"FOURNALY3ER_LOCK_SHA256",
			"reviewed hash is still an external blocker",
		},
	}
	for rel, obsoleteTerms := range staleText {
		if strings.HasPrefix(rel, "scripts/benchmark/") && !benchmarkHarnessAvailable(root) {
			continue // dev-only harness not checked out
		}
		text := readRepositoryText(t, root, rel)
		for _, obsolete := range obsoleteTerms {
			if strings.Contains(text, obsolete) {
				t.Errorf("%s contains stale repository text %q", rel, obsolete)
			}
		}
	}

	engineRoot := filepath.Join(root, "pkg", "engine")
	if err := filepath.WalkDir(engineRoot, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || filepath.Ext(path) != ".go" {
			return nil
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			rel = path
		}
		for _, obsolete := range forbidden[:8] {
			if strings.Contains(string(content), obsolete) {
				t.Errorf("%s contains obsolete active-language vocabulary %q", rel, obsolete)
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("scan active Go sources: %v", err)
	}

	activeVocabulary := map[string][]string{
		"docs/wql-syntax.md": {
			"until the corpus migration in Task 5",
			"block: identifier\n        receiver: true\n        tainted: user_controlled",
		},
		"docs/project-overview.md": {
			"token_call",
		},
		"scripts/benchmark/templates/4naly3er-inspired/M-erc721-safe-transfer-from.yaml": {
			"token_call",
		},
		"templates/test/feature-inside.yaml": {
			"contains + inside",
			"`inside` ancestor-traversal operator",
		},
		"test-data/core/engine-features/README.md": {
			"match.sequence",
			"`contains` + `inside`",
			"`kind: eth_transfer`",
		},
		"test-data/core/engine-features/01-sequence.sol": {
			"match.sequence",
		},
		"test-data/core/engine-features/02-inside.sol": {
			"contains + inside",
		},
		"AI.md": {
			"`match.all`",
		},
		"pkg/types/AI.md": {
			"`token_call`",
			"`kind: guard`",
			"`kind: selfdestruct`",
		},
		"pkg/types/ast.go": {
			"Used with kind: token_call in WQL templates.",
			"allowing `kind: guard` in WQL templates.",
		},
	}
	for rel, obsoleteTerms := range activeVocabulary {
		if strings.HasPrefix(rel, "scripts/benchmark/") && !benchmarkHarnessAvailable(root) {
			continue // dev-only harness not checked out
		}
		text := readRepositoryText(t, root, rel)
		for _, obsolete := range obsoleteTerms {
			if strings.Contains(text, obsolete) {
				t.Errorf("%s contains evaluator vocabulary presented as public WQL %q", rel, obsolete)
			}
		}
	}

	templateIndex := readRepositoryText(t, root, "templates/AI.md")
	if !strings.Contains(templateIndex, "delegatecall` whose target flows from a parameter or caller identity") {
		t.Errorf("templates/AI.md does not describe the widened delegatecall taint source")
	}
}

func TestAuthoritativeCorrectnessDocsDescribeRelationships(t *testing.T) {
	root := repoRoot(t)
	required := map[string][]string{
		"README.md": {
			`(?is)Function\.Selector\W+stores\s+canonical\s+text.{0,160}Function\.Signature\W+stores\s+its\s+four-byte\s+Keccak\s+value`,
			`(?is)one-based.{0,60}Unicode-code-point\s+columns.{0,100}zero-based.{0,60}UTF-8\s+byte\s+offsets.{0,180}not\s+LSP\s+positions`,
			`(?is)README\.md.{0,80}bounded\s+landing\s+page.{0,220}audit\.md.{0,120}consolidated\s+project\s+audit`,
			`(?s)inputPath\s*:=\s*"\./contracts/".{0,160}projectRoot,\s*err\s*:=\s*reader\.DetectProjectRoot\(inputPath\).{0,180}if\s+err\s*!=\s*nil.{0,260}if\s+err\s*:=\s*r\.ResolveImports\(projectRoot\);\s*err\s*!=\s*nil.{0,180}sources\s*=\s*r\.GetAllSources\(\)`,
		},
		"docs/sdk.md": {
			`(?s)####\s+1\.\s+Empty\s+Source\s+Files.{0,500}\*\*Correct\s+Handling:\*\*.{0,200}inputPath\s*:=\s*path.{0,160}projectRoot,\s*err\s*:=\s*reader\.DetectProjectRoot\(inputPath\).{0,180}if\s+err\s*!=\s*nil.{0,260}if\s+err\s*:=\s*r\.ResolveImports\(projectRoot\);\s*err\s*!=\s*nil`,
			`(?is)SourceFile\.Content.{0,120}current\s+cached\s+excerpts.{0,80}workflows.{0,160}disk\s+is\s+only\s+a\s+legacy\s+fallback`,
			`(?is)serialized\s+AST.{0,180}Database\.RestoreASTParents.{0,100}parent\s+links`,
		},
		"docs/internals.md": {
			`(?s)Function\.Selector.*?canonical.*?text.*?Function\.Signature.*?4-byte.*?hash`,
			`(?s)StartCol.*?one-based.*?Unicode.*?StartByte.*?zero-based.*?half-open.*?UTF-8.*?LSP\s+positions.*?zero-based`,
			`(?is)Solidity.{0,20}for.{0,20}runtime\s+order.{0,100}initialization.{0,40}condition.{0,40}body.{0,40}post`,
			`(?s)state_write.*?stmt\.assign.*?push.*?pop.*?delete.*?\+\+.*?--.*?asm\.sstore`,
			`(?is)stmt\.state_mutation.{0,120}not.{0,40}call\.\*\W+node`,
		},
		"docs/wql-syntax.md": {
			`(?s)exact\s+source\s+spans.*?Active\s+inherited\s+functions.*?deduplicated\s+by\s+canonical\s+selector`,
			`(?s)guarded_by.*?inline\s+guard.*?exact\s+applied\s+modifier.*?modifier\s+name.*?does\s+not.*?access\s+control`,
			`(?is)where-only\s+query.{0,180}default.{0,30}entry_function.{0,220}context-only\W+where.{0,100}rejected`,
		},
	}
	for rel, patterns := range required {
		text := readRepositoryText(t, root, rel)
		for _, pattern := range patterns {
			if !regexp.MustCompile(pattern).MatchString(text) {
				t.Errorf("%s missing relationship /%s/", rel, pattern)
			}
		}
	}
	for rel, want := range map[string]int{"README.md": 1, "docs/sdk.md": 9} {
		text := readRepositoryText(t, root, rel)
		if got := strings.Count(text, "reader.DetectProjectRoot(inputPath)"); got != want {
			t.Errorf("%s checked project-root flows = %d, want %d", rel, got, want)
		}
		if got := strings.Count(text, "r.ResolveImports(projectRoot)"); got != want {
			t.Errorf("%s resolved project-root flows = %d, want %d", rel, got, want)
		}
		if strings.Contains(text, "ResolveImports(r.ProjectRoot)") {
			t.Errorf("%s still resolves imports through unset Reader.ProjectRoot", rel)
		}
	}

	forbidden := map[string][]string{
		"README.md": {
			`(?is)Function\.Selector\s+(?:is|stores|holds)\s+(?:the\s+)?(?:four-byte|4-byte|hash)`,
			`(?is)(?:four-byte|4-byte|Keccak\s+value|hash).{0,80}(?:stored|held|represented)\s+(?:in|by)\s+Function\.Selector`,
			`(?is)Function\.Signature\s+(?:is|stores|holds)\s+(?:canonical|textual|selector\s+text)`,
			`(?is)(?:canonical|textual|selector\s+text).{0,80}(?:stored|held|represented)\s+(?:in|by)\s+Function\.Signature`,
			`(?is)overview\.md.{0,80}(?:contains|is).{0,30}(?:the\s+)?(?:full|complete)\s+report`,
			`(?is)(?:full|complete)\s+report.{0,80}(?:is|appears|lives).{0,30}overview\.md`,
		},
		"docs/sdk.md": {
			`(?is)SourceFile\.Content.{0,180}AST\s+reconstruction`,
			`(?is)AST\s+reconstruction.{0,180}(?:depends|relies).{0,40}SourceFile\.Content`,
			`(?is)(?:current|modern).{0,30}cache.{0,100}(?:requires?|must).{0,40}(?:source|disk)`,
			`(?is)source\s+files\s+must\s+remain\s+on\s+disk`,
		},
		"docs/usage.md": {
			`(?is)overview\.md.{0,120}all\s+main\s+contracts.{0,120}call\s+graphs`,
			`(?is)location-source.{0,50}(?:removed|no\s+longer\s+available)`,
		},
		"docs/extension-output.md": {
			`(?s)"signature"\s*:\s*"transfer\(address,uint256\)"`,
		},
	}
	for rel, patterns := range forbidden {
		text := readRepositoryText(t, root, rel)
		for _, pattern := range patterns {
			if regexp.MustCompile(pattern).MatchString(text) {
				t.Errorf("%s contains forbidden relationship /%s/", rel, pattern)
			}
		}
	}
}

func readRepositoryText(t *testing.T, root, rel string) string {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return string(content)
}
