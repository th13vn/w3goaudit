package reader

import (
	"bufio"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/pelletier/go-toml/v2"
)

type foundryTomlConfig struct {
	Remappings *[]string                     `toml:"remappings"`
	Profile    map[string]foundryTomlProfile `toml:"profile"`
}

type foundryTomlProfile struct {
	Remappings *[]string `toml:"remappings"`
}

type remappingCandidate struct {
	remapping          Remapping
	contextSpecificity int
}

// parseRemappingsFile parses context:prefix=target and prefix=target entries
// from a Foundry remappings.txt file, retaining declaration order.
func parseRemappingsFile(path string) ([]Remapping, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var remappings []Remapping
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if remapping, ok := parseRemapping(line); ok {
			remappings = append(remappings, remapping)
		}
	}
	return remappings, scanner.Err()
}

// parseFoundryTomlRemappings parses real TOML so comments and inactive
// profiles cannot leak remappings into the selected Foundry configuration.
func parseFoundryTomlRemappings(path string) ([]Remapping, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var config foundryTomlConfig
	if err := toml.Unmarshal(content, &config); err != nil {
		return nil, err
	}

	specs := activeFoundryRemappingSpecs(config)
	remappings := make([]Remapping, 0, len(specs))
	for _, spec := range specs {
		if remapping, ok := parseRemapping(spec); ok {
			remappings = append(remappings, remapping)
		}
	}
	return remappings, nil
}

func activeFoundryRemappingSpecs(config foundryTomlConfig) []string {
	profileName := strings.TrimSpace(os.Getenv("FOUNDRY_PROFILE"))
	if profileName == "" {
		profileName = "default"
	}

	if profile, ok := config.Profile[profileName]; ok && profile.Remappings != nil {
		return *profile.Remappings
	}
	if profileName != "default" {
		if profile, ok := config.Profile["default"]; ok && profile.Remappings != nil {
			return *profile.Remappings
		}
	}
	if config.Remappings != nil {
		return *config.Remappings
	}
	return nil
}

func parseRemapping(spec string) (Remapping, bool) {
	left, target, ok := strings.Cut(strings.TrimSpace(spec), "=")
	if !ok {
		return Remapping{}, false
	}
	left = strings.TrimSpace(left)
	target = strings.TrimSpace(target)
	if left == "" || target == "" {
		return Remapping{}, false
	}

	context, prefix, scoped := strings.Cut(left, ":")
	if !scoped {
		prefix = left
		context = ""
	}
	context = strings.TrimSpace(context)
	prefix = strings.TrimSpace(prefix)
	if prefix == "" {
		return Remapping{}, false
	}
	return Remapping{Context: context, From: prefix, To: target}, true
}

// applicableRemappings filters context-scoped entries against the importing
// source unit and orders them by context specificity, then import-prefix
// specificity. Stable sorting preserves declaration order for exact ties.
func applicableRemappings(remappings []Remapping, root, fromFile, importPath string) []Remapping {
	sourceUnit, sourceUnitOK := relativeSourceUnit(root, fromFile)
	candidates := make([]remappingCandidate, 0, len(remappings))
	for _, remapping := range remappings {
		if !strings.HasPrefix(importPath, remapping.From) {
			continue
		}
		context := normalizeRemappingContext(remapping.Context)
		if context != "" && (!sourceUnitOK || !strings.HasPrefix(sourceUnit, context)) {
			continue
		}
		candidates = append(candidates, remappingCandidate{
			remapping:          remapping,
			contextSpecificity: len(context),
		})
	}

	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].contextSpecificity != candidates[j].contextSpecificity {
			return candidates[i].contextSpecificity > candidates[j].contextSpecificity
		}
		return len(candidates[i].remapping.From) > len(candidates[j].remapping.From)
	})

	ordered := make([]Remapping, len(candidates))
	for i, candidate := range candidates {
		ordered[i] = candidate.remapping
	}
	return ordered
}

func relativeSourceUnit(root, fromFile string) (string, bool) {
	relative, err := filepath.Rel(root, fromFile)
	if err != nil {
		return "", false
	}
	return strings.TrimPrefix(filepath.ToSlash(relative), "./"), true
}

func normalizeRemappingContext(context string) string {
	context = strings.ReplaceAll(strings.TrimSpace(context), "\\", "/")
	for strings.HasPrefix(context, "./") {
		context = strings.TrimPrefix(context, "./")
	}
	return context
}
