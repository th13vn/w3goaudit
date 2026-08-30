package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func validateOutputBoundary(inputPath, dbPath, outputPath string) error {
	if strings.TrimSpace(outputPath) == "" {
		return nil
	}
	source, err := selectedScanBoundary(inputPath, dbPath)
	if err != nil {
		return fmt.Errorf("resolving scan boundary: %w", err)
	}
	if source == "" {
		return nil
	}
	output, err := canonicalBoundaryPath(outputPath)
	if err != nil {
		return fmt.Errorf("resolving output boundary: %w", err)
	}
	if pathContains(source, output) || pathContains(output, source) {
		return fmt.Errorf("refusing report output %q: output and scan source %q overlap", outputPath, source)
	}
	return nil
}

func selectedScanBoundary(inputPath, dbPath string) (string, error) {
	if strings.TrimSpace(dbPath) != "" {
		return databaseScanBoundary(dbPath)
	}
	if strings.TrimSpace(inputPath) == "" {
		return "", nil
	}
	return canonicalBoundaryPath(inputPath)
}

func databaseScanBoundary(dbPath string) (string, error) {
	f, err := os.Open(dbPath)
	if err != nil {
		return "", err
	}
	defer f.Close()
	var header struct {
		ProjectRoot string `json:"projectRoot"`
		ScanTarget  string `json:"scanTarget"`
	}
	if err := json.NewDecoder(f).Decode(&header); err != nil {
		return "", err
	}
	target := header.ScanTarget
	if target == "" {
		target = header.ProjectRoot
	}
	if target == "" {
		return "", nil
	}
	return canonicalBoundaryPath(target)
}

func canonicalBoundaryPath(path string) (string, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	current := filepath.Clean(absPath)
	var suffix []string
	for {
		resolved, resolveErr := filepath.EvalSymlinks(current)
		if resolveErr == nil {
			for i := len(suffix) - 1; i >= 0; i-- {
				resolved = filepath.Join(resolved, suffix[i])
			}
			return filepath.Clean(resolved), nil
		}
		if !os.IsNotExist(resolveErr) {
			return "", resolveErr
		}
		parent := filepath.Dir(current)
		if parent == current {
			return filepath.Clean(absPath), nil
		}
		suffix = append(suffix, filepath.Base(current))
		current = parent
	}
}

func pathContains(root, candidate string) bool {
	rel, err := filepath.Rel(root, candidate)
	if err != nil || filepath.IsAbs(rel) {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)))
}
