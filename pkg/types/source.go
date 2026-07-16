package types

import (
	"os"
	"strings"
)

// GetFunctionSource returns the raw Solidity source lines for a function.
// Uses StartLine/EndLine (1-based) and reads directly from the source file.
// Falls back to the in-memory Content field if available; reads from disk otherwise.
// Returns empty string if source is not available.
func (db *Database) GetFunctionSource(fn *Function) string {
	if fn == nil {
		return ""
	}
	// Prefer the file recorded on the function itself. Resolving the owning
	// contract by name is ambiguous under collisions (e.g. a mock `Token` and a
	// real `Token`) and can slice a different file's source. Fall back to
	// name resolution only for databases built before SourceFile was recorded.
	sourceFile := fn.SourceFile
	if sourceFile == "" {
		if contract := db.GetContractByName(fn.ContractName); contract != nil {
			sourceFile = contract.SourceFile
		}
	}
	if sourceFile == "" {
		return ""
	}
	return db.GetSourceLines(sourceFile, fn.StartLine, fn.EndLine)
}

// GetModifierSource returns the raw Solidity source for a modifier defined in
// the given contract. Mirrors GetFunctionSource.
func (db *Database) GetModifierSource(contract *Contract, mod *Modifier) string {
	if contract == nil || mod == nil {
		return ""
	}
	return db.GetSourceLines(contract.SourceFile, mod.StartLine, mod.EndLine)
}

// GetSourceLines returns lines [startLine, endLine] (1-based, inclusive) of the
// given source file. Prefers the in-memory Content (serialized in the cached
// database) and falls back to reading from disk. Returns "" when unavailable.
func (db *Database) GetSourceLines(sourceFilePath string, startLine, endLine int) string {
	if sourceFilePath == "" || startLine <= 0 || endLine <= 0 {
		return ""
	}

	var content string
	if sf, ok := db.SourceFiles[sourceFilePath]; ok && sf != nil && sf.Content != "" {
		content = sf.Content
	} else {
		data, err := os.ReadFile(sourceFilePath)
		if err != nil {
			return ""
		}
		content = string(data)
	}

	lines := strings.Split(content, "\n")
	start := startLine - 1 // convert to 0-based
	end := endLine         // EndLine is an inclusive line number → exclusive slice bound

	if start < 0 {
		start = 0
	}
	if end > len(lines) {
		end = len(lines)
	}
	if start >= end {
		return ""
	}
	return strings.Join(lines[start:end], "\n")
}

// GetFunctionSourceByName finds a function by name within a named contract
// and returns its raw Solidity source. Returns ("", nil) if not found.
func (db *Database) GetFunctionSourceByName(contractName, funcName string) (string, *Function) {
	contract := db.GetContractByName(contractName)
	if contract == nil {
		return "", nil
	}
	for _, fn := range contract.Functions {
		if fn.Name == funcName {
			return db.GetFunctionSource(fn), fn
		}
	}
	return "", nil
}
