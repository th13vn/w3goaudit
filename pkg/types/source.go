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
	if fn == nil || fn.StartLine <= 0 || fn.EndLine <= 0 {
		return ""
	}

	// Resolve the contract to find the source file path
	var content string

	contract := db.GetContractByName(fn.ContractName)
	if contract == nil {
		return ""
	}
	sourceFilePath := contract.SourceFile

	// Try in-memory content first (set during build, tagged json:"-" so not in JSON DB)
	if sf, ok := db.SourceFiles[sourceFilePath]; ok && sf != nil && sf.Content != "" {
		content = sf.Content
	} else {
		// Fall back to reading from disk (e.g. after loading from cached JSON DB)
		data, err := os.ReadFile(sourceFilePath)
		if err != nil {
			return ""
		}
		content = string(data)
	}

	lines := strings.Split(content, "\n")
	start := fn.StartLine - 1 // convert to 0-based
	end := fn.EndLine          // exclusive upper bound (EndLine is inclusive line number)

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
