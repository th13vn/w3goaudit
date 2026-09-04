package engine

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// AuthorizationPreset is the public, parameterized authorization predicate.
// It is intentionally a first-class evaluator value rather than a collection
// of auth_* attributes.
type AuthorizationPreset struct {
	Type           string   `json:"type"`
	Principals     []string `json:"principals,omitempty"`
	PrincipalRegex string   `json:"principalRegex,omitempty"`
}

// InitializerPreset is the narrow lifecycle predicate exposed to templates.
// The function name remains an ordinary func_name matcher; this preset only
// answers whether first-call takeover is statically possible.
type InitializerPreset struct {
	Takeover string `json:"takeover"`
}

func lowerParameterizedPreset(val yaml.Node) (*Rule, error) {
	if val.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("where.preset: expected a scalar preset name or a mapping with authorization/initializer")
	}
	if len(val.Content) == 0 {
		return nil, fmt.Errorf("where.preset: mapping must not be empty")
	}
	var result Rule
	seen := map[string]bool{}
	for i := 0; i+1 < len(val.Content); i += 2 {
		key, child := val.Content[i].Value, *val.Content[i+1]
		if seen[key] {
			return nil, fmt.Errorf("where.preset.%s: duplicate preset family", key)
		}
		seen[key] = true
		switch key {
		case "authorization":
			preset, err := parseAuthorizationPreset(child)
			if err != nil {
				return nil, err
			}
			result.Authorization = preset
		case "initializer":
			preset, err := parseInitializerPreset(child)
			if err != nil {
				return nil, err
			}
			result.Initializer = preset
		default:
			return nil, fmt.Errorf("where.preset: unknown parameterized preset %q; use authorization or initializer", key)
		}
	}
	if result.Authorization == nil && result.Initializer == nil {
		return nil, fmt.Errorf("where.preset: mapping must contain authorization or initializer")
	}
	if result.Authorization != nil && result.Initializer != nil {
		return nil, fmt.Errorf("where.preset: choose one parameterized preset family")
	}
	return &result, nil
}

func parseAuthorizationPreset(node yaml.Node) (*AuthorizationPreset, error) {
	if node.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("where.preset.authorization: expected a mapping")
	}
	preset := &AuthorizationPreset{}
	seen := map[string]bool{}
	for i := 0; i+1 < len(node.Content); i += 2 {
		key, value := node.Content[i].Value, *node.Content[i+1]
		if seen[key] {
			return nil, fmt.Errorf("where.preset.authorization.%s: duplicate field", key)
		}
		seen[key] = true
		switch key {
		case "type":
			if value.Kind != yaml.ScalarNode || value.Tag != "!!str" {
				return nil, fmt.Errorf("where.preset.authorization.type: expected protected or self_sender")
			}
			preset.Type = strings.TrimSpace(value.Value)
		case "principal":
			if value.Kind == yaml.MappingNode {
				regex, err := parsePrincipalRegex(value)
				if err != nil {
					return nil, err
				}
				preset.PrincipalRegex = regex
				continue
			}
			principals, err := parsePrincipalLiterals(value)
			if err != nil {
				return nil, err
			}
			preset.Principals = principals
		default:
			return nil, fmt.Errorf("where.preset.authorization: unknown field %q; use type and optional principal", key)
		}
	}
	if preset.Type != "protected" && preset.Type != "self_sender" {
		return nil, fmt.Errorf("where.preset.authorization.type: must be protected or self_sender")
	}
	if preset.Type == "self_sender" && (len(preset.Principals) > 0 || preset.PrincipalRegex != "") {
		return nil, fmt.Errorf("where.preset.authorization.principal: self_sender does not accept a principal")
	}
	if preset.Type == "protected" && len(preset.Principals) == 0 && preset.PrincipalRegex == "" {
		return preset, nil
	}
	return preset, nil
}

func parsePrincipalLiterals(node yaml.Node) ([]string, error) {
	values := []string{}
	if node.Kind == yaml.ScalarNode && node.Tag == "!!str" {
		values = append(values, node.Value)
	} else if node.Kind == yaml.SequenceNode {
		for _, child := range node.Content {
			if child.Kind != yaml.ScalarNode || child.Tag != "!!str" {
				return nil, fmt.Errorf("where.preset.authorization.principal: expected a string or non-empty list of strings")
			}
			values = append(values, child.Value)
		}
	} else {
		return nil, fmt.Errorf("where.preset.authorization.principal: expected a string or non-empty list of strings")
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			return nil, fmt.Errorf("where.preset.authorization.principal: values must not be empty")
		}
		if !seen[value] {
			seen[value] = true
			out = append(out, value)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("where.preset.authorization.principal: values must not be empty")
	}
	sort.Strings(out)
	return out, nil
}

func parsePrincipalRegex(node yaml.Node) (string, error) {
	if len(node.Content) != 2 || node.Content[0].Value != "regex" {
		return "", fmt.Errorf("where.preset.authorization.principal: regex option must contain only regex")
	}
	value := *node.Content[1]
	if value.Kind != yaml.ScalarNode || value.Tag != "!!str" || strings.TrimSpace(value.Value) == "" {
		return "", fmt.Errorf("where.preset.authorization.principal.regex: expected a non-empty string")
	}
	pattern := strings.TrimSpace(value.Value)
	if _, err := regexp.Compile(pattern); err != nil {
		return "", fmt.Errorf("where.preset.authorization.principal.regex: invalid regex: %w", err)
	}
	return pattern, nil
}

func parseInitializerPreset(node yaml.Node) (*InitializerPreset, error) {
	if node.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("where.preset.initializer: expected a mapping")
	}
	preset := &InitializerPreset{}
	seen := map[string]bool{}
	for i := 0; i+1 < len(node.Content); i += 2 {
		key, value := node.Content[i].Value, *node.Content[i+1]
		if seen[key] {
			return nil, fmt.Errorf("where.preset.initializer.%s: duplicate field", key)
		}
		seen[key] = true
		if key != "takeover" {
			return nil, fmt.Errorf("where.preset.initializer: unknown field %q; use takeover", key)
		}
		if value.Kind != yaml.ScalarNode || value.Tag != "!!str" || strings.TrimSpace(value.Value) != "possible" {
			return nil, fmt.Errorf("where.preset.initializer.takeover: must be possible")
		}
		preset.Takeover = "possible"
	}
	if preset.Takeover == "" {
		return nil, fmt.Errorf("where.preset.initializer: takeover is required")
	}
	return preset, nil
}
