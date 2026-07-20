package engine

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/th13vn/w3goaudit/pkg/builder"
	"github.com/th13vn/w3goaudit/pkg/reader"
	"github.com/th13vn/w3goaudit/pkg/types"
)

func buildSemanticFixture(t *testing.T, name string) *types.Database {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("resolve repository root: %v", err)
	}
	path := filepath.Join(root, "test-data", "core", "semantic-hardening", name)
	sources, err := reader.New().Read(path)
	if err != nil {
		t.Fatalf("read semantic fixture %q: %v", name, err)
	}
	db, err := builder.New().Build(sources)
	if err != nil {
		t.Fatalf("build semantic fixture %q: %v", name, err)
	}
	return db
}

func buildSemanticFixturePath(t *testing.T, rel string) *types.Database {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("resolve repository root: %v", err)
	}
	sources, err := reader.New().Read(filepath.Join(root, filepath.FromSlash(rel)))
	if err != nil {
		t.Fatalf("read semantic fixture %q: %v", rel, err)
	}
	db, err := builder.New().Build(sources)
	if err != nil {
		t.Fatalf("build semantic fixture %q: %v", rel, err)
	}
	return db
}

func semanticFixtureFunction(t *testing.T, db *types.Database, contractName, functionName string) (*types.Function, *types.Contract) {
	t.Helper()
	contracts := db.FindContractsByName(contractName)
	if len(contracts) != 1 {
		ids := make([]string, 0, len(contracts))
		for _, contract := range contracts {
			if contract != nil {
				ids = append(ids, contract.ID)
			}
		}
		t.Fatalf("contract %q resolved to %d exact objects: %v", contractName, len(contracts), ids)
	}
	contract := contracts[0]
	var matches []*types.Function
	for _, fn := range contract.Functions {
		if fn != nil && (fn.Name == functionName || fn.Selector == functionName) {
			matches = append(matches, fn)
		}
	}
	if len(matches) != 1 {
		selectors := make([]string, 0, len(matches))
		for _, fn := range matches {
			selectors = append(selectors, fn.Selector)
		}
		t.Fatalf("function %s.%s resolved to %d exact objects: %v", contractName, functionName, len(matches), selectors)
	}
	return matches[0], contract
}

func pathRootName(path accessPath) string {
	refID := path.Root.RefID
	if strings.Contains(refID, ":local:") {
		if marker := strings.LastIndexByte(refID, ':'); marker >= 0 {
			return refID[marker+1:]
		}
	}
	if strings.Contains(refID, ":yul:") {
		if marker := strings.LastIndexByte(refID, ':'); marker >= 0 {
			return refID[marker+1:]
		}
	}
	if marker := strings.LastIndex(refID, ".-"); marker >= 0 {
		return refID[marker+2:]
	}
	if marker := strings.LastIndex(refID, ":root:"); marker >= 0 {
		return refID[marker+6:]
	}
	if marker := strings.LastIndexByte(refID, '.'); marker >= 0 {
		return refID[marker+1:]
	}
	return refID
}

func allSemanticPaths(operations []*semanticOp) []accessPath {
	paths := allOperationPaths(operations)
	for _, operation := range operations {
		if operation == nil {
			continue
		}
		for _, input := range operation.Inputs {
			if input.Path != nil {
				paths = append(paths, *input.Path)
			}
			paths = append(paths, input.Sources...)
		}
	}
	return paths
}

func pathHasField(path accessPath, fields ...string) bool {
	if len(path.Segments) < len(fields) {
		return false
	}
	for i, field := range fields {
		segment := path.Segments[i]
		if segment.Kind != segmentField || segment.Name != field {
			return false
		}
	}
	return true
}

func allOperationPaths(operations []*semanticOp) []accessPath {
	var paths []accessPath
	for _, operation := range operations {
		if operation == nil {
			continue
		}
		paths = append(paths, operation.Reads...)
		paths = append(paths, operation.Writes...)
	}
	return paths
}

func findPaths(operations []*semanticOp, root string, fields ...string) []accessPath {
	var matches []accessPath
	for _, path := range allOperationPaths(operations) {
		if pathRootName(path) == root && pathHasField(path, fields...) {
			matches = append(matches, path)
		}
	}
	return matches
}

func operationForNode(t *testing.T, lowered *semanticFunction, node *types.ASTNode) []*semanticOp {
	t.Helper()
	indexes := lowered.ByNode[node]
	if len(indexes) == 0 {
		t.Fatalf("node %p (%s) has no operation indexes", node, node.Kind)
	}
	operations := make([]*semanticOp, 0, len(indexes))
	for _, index := range indexes {
		if index < 0 || index >= len(lowered.Operations) {
			t.Fatalf("node %p has invalid operation index %d", node, index)
		}
		operations = append(operations, lowered.Operations[index])
	}
	return operations
}

func collectNodes(root *types.ASTNode, predicate func(*types.ASTNode) bool) []*types.ASTNode {
	if root == nil {
		return nil
	}
	var nodes []*types.ASTNode
	if predicate(root) {
		nodes = append(nodes, root)
	}
	root.WalkDescendants(func(node *types.ASTNode) bool {
		if predicate(node) {
			nodes = append(nodes, node)
		}
		return true
	})
	return nodes
}
