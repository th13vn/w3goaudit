package reader

import (
	"os"
	"path/filepath"
)

// ProjectMarkers are files/directories that indicate a project root
var ProjectMarkers = []string{
	".git",
	"foundry.toml",
	"hardhat.config.js",
	"hardhat.config.ts",
	"truffle-config.js",
	"package.json",
	"yarn.lock",
	"pnpm-lock.yaml",
	"remappings.txt",
}

// DetectProjectRoot finds the project root by looking for marker files
func DetectProjectRoot(startPath string) (string, error) {
	absPath, err := filepath.Abs(startPath)
	if err != nil {
		return "", err
	}

	// If startPath is a file, start from its directory
	info, err := os.Stat(absPath)
	if err != nil {
		return "", err
	}

	if !info.IsDir() {
		absPath = filepath.Dir(absPath)
	}

	// Walk up the directory tree looking for markers
	current := absPath
	for {
		for _, marker := range ProjectMarkers {
			markerPath := filepath.Join(current, marker)
			if _, err := os.Stat(markerPath); err == nil {
				return current, nil
			}
		}

		// Move to parent directory
		parent := filepath.Dir(current)
		if parent == current {
			// Reached filesystem root, return original path
			return absPath, nil
		}
		current = parent
	}
}

// DetectFramework detects the Solidity development framework
type Framework string

const (
	FrameworkUnknown  Framework = "unknown"
	FrameworkFoundry  Framework = "foundry"
	FrameworkHardhat  Framework = "hardhat"
	FrameworkTruffle  Framework = "truffle"
	FrameworkBrownie  Framework = "brownie"
)

// DetectFramework identifies the development framework used
func DetectFramework(projectRoot string) Framework {
	// Check for Foundry
	if _, err := os.Stat(filepath.Join(projectRoot, "foundry.toml")); err == nil {
		return FrameworkFoundry
	}

	// Check for Hardhat
	if _, err := os.Stat(filepath.Join(projectRoot, "hardhat.config.js")); err == nil {
		return FrameworkHardhat
	}
	if _, err := os.Stat(filepath.Join(projectRoot, "hardhat.config.ts")); err == nil {
		return FrameworkHardhat
	}

	// Check for Truffle
	if _, err := os.Stat(filepath.Join(projectRoot, "truffle-config.js")); err == nil {
		return FrameworkTruffle
	}

	// Check for Brownie
	if _, err := os.Stat(filepath.Join(projectRoot, "brownie-config.yaml")); err == nil {
		return FrameworkBrownie
	}

	return FrameworkUnknown
}

// GetSourceDirectories returns typical source directories for the framework
func GetSourceDirectories(projectRoot string, framework Framework) []string {
	switch framework {
	case FrameworkFoundry:
		return []string{
			filepath.Join(projectRoot, "src"),
			filepath.Join(projectRoot, "contracts"),
		}
	case FrameworkHardhat:
		return []string{
			filepath.Join(projectRoot, "contracts"),
		}
	case FrameworkTruffle:
		return []string{
			filepath.Join(projectRoot, "contracts"),
		}
	case FrameworkBrownie:
		return []string{
			filepath.Join(projectRoot, "contracts"),
		}
	default:
		// Check common directories
		dirs := []string{}
		candidates := []string{"src", "contracts", "lib"}
		for _, c := range candidates {
			path := filepath.Join(projectRoot, c)
			if info, err := os.Stat(path); err == nil && info.IsDir() {
				dirs = append(dirs, path)
			}
		}
		if len(dirs) == 0 {
			return []string{projectRoot}
		}
		return dirs
	}
}
