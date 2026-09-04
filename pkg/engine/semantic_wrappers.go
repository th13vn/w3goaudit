package engine

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

func lowerAuthorizationWrapper(val yaml.Node) (*Rule, error) {
	fields, err := wrapperFields(val, "authorization")
	if err != nil {
		return nil, err
	}
	proofKinds := 0
	for _, key := range []string{"protected", "self_scoped", "role", "expected_principal"} {
		if _, ok := fields[key]; ok {
			proofKinds++
		}
	}
	if proofKinds > 1 {
		return nil, fmt.Errorf("where.authorization: choose exactly one of protected, self_scoped, role, or expected_principal")
	}
	rule := &Rule{Attr: make(map[string]interface{})}
	for key, node := range fields {
		switch key {
		case "protected":
			if err := requireWrapperTrue(node, "authorization.protected"); err != nil {
				return nil, err
			}
			rule.Attr["auth_verdict"] = "protected"
			rule.Attr["auth_dominates"] = "dominates"
		case "self_scoped":
			if err := requireWrapperTrue(node, "authorization.self_scoped"); err != nil {
				return nil, err
			}
			rule.Attr["auth_verdict"] = "self_scoped"
			rule.Attr["auth_principal"] = "caller_self_scope"
			rule.Attr["auth_dominates"] = "dominates"
		case "role":
			if err := requireWrapperTrue(node, "authorization.role"); err != nil {
				return nil, err
			}
			rule.Attr["auth_verdict"] = "protected"
			rule.Attr["auth_principal"] = "role"
			rule.Attr["auth_dominates"] = "dominates"
		case "expected_principal":
			names, err := wrapperStringList(node, "authorization.expected_principal")
			if err != nil {
				return nil, err
			}
			parts := make([]string, len(names))
			for i, name := range names {
				parts[i] = regexp.QuoteMeta(name)
			}
			rule.Attr["auth_verdict"] = "protected"
			rule.Attr["auth_principal"] = "expected_external"
			rule.Attr["auth_expected_principal"] = "(?i)^(?:" + strings.Join(parts, "|") + ")$"
			rule.Attr["auth_dominates"] = "dominates"
		case "dominates":
			return nil, fmt.Errorf("where.authorization.dominates is not accepted: all-path coverage is implicit; remove this field")
		default:
			return nil, fmt.Errorf("where.authorization: unknown field %q; use protected, self_scoped, role, or expected_principal", key)
		}
	}
	return rule, nil
}

func lowerInitializerWrapper(val yaml.Node) (*Rule, error) {
	fields, err := wrapperFields(val, "initializer")
	if err != nil {
		return nil, err
	}
	rule := &Rule{Attr: make(map[string]interface{})}
	for key, node := range fields {
		switch key {
		case "entry":
			if err := requireWrapperTrue(node, "initializer.entry"); err != nil {
				return nil, err
			}
			rule.Attr["initializer_entry"] = true
		case "mutex":
			if err := requireWrapperTrue(node, "initializer.mutex"); err != nil {
				return nil, err
			}
			rule.Attr["one_time_mutex"] = true
		case "takeover":
			values, err := wrapperEnumList(node, "initializer.takeover", map[string]bool{"possible": true, "unknown": true})
			if err != nil {
				return nil, err
			}
			rule.Attr["first_call_takeover"] = enumRegex(values)
		case "atomic":
			values, err := wrapperEnumList(node, "initializer.atomic", map[string]bool{"before_guard": true, "after_guard": true, "unknown": true})
			if err != nil {
				return nil, err
			}
			rule.Attr["atomic_initialization"] = enumRegex(values)
		case "constructor_disabled":
			if err := requireWrapperTrue(node, "initializer.constructor_disabled"); err != nil {
				return nil, err
			}
			rule.Attr["constructor_disable"] = true
		case "proxy":
			values, err := wrapperEnumList(node, "initializer.proxy", map[string]bool{"unknown": true})
			if err != nil {
				return nil, err
			}
			rule.Attr["proxy_linkage"] = enumRegex(values)
		default:
			return nil, fmt.Errorf("where.initializer: unknown field %q; use entry, mutex, takeover, atomic, constructor_disabled, or proxy", key)
		}
	}
	return rule, nil
}

func lowerRuntimeWrapper(val yaml.Node) (*Rule, error) {
	fields, err := wrapperFields(val, "runtime")
	if err != nil {
		return nil, err
	}
	rule := &Rule{Attr: make(map[string]interface{})}
	for key, node := range fields {
		switch key {
		case "authorization":
			values, err := wrapperEnumList(node, "runtime.authorization", map[string]bool{"protected": true, "self_scoped": true, "unknown": true})
			if err != nil {
				return nil, err
			}
			rule.Attr["auth_verdict"] = enumRegex(values)
		case "dispatch":
			values, err := wrapperEnumList(node, "runtime.dispatch", map[string]bool{"virtual": true, "super": true})
			if err != nil {
				return nil, err
			}
			mapped := make([]string, len(values))
			for i, v := range values {
				if v == "virtual" {
					mapped[i] = "virtual_override\\.guard\\.proven"
				} else {
					mapped[i] = "super\\.guard\\.proven"
				}
			}
			rule.Attr["auth_reason"] = "^(?:" + strings.Join(mapped, "|") + ")$"
		default:
			return nil, fmt.Errorf("where.runtime: unknown field %q; use authorization or dispatch", key)
		}
	}
	return rule, nil
}

func wrapperFields(val yaml.Node, name string) (map[string]yaml.Node, error) {
	if val.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("where.%s: expected a mapping", name)
	}
	fields := make(map[string]yaml.Node, len(val.Content)/2)
	for i := 0; i+1 < len(val.Content); i += 2 {
		key := val.Content[i].Value
		if _, ok := fields[key]; ok {
			return nil, fmt.Errorf("where.%s.%s: duplicate field", name, key)
		}
		fields[key] = *val.Content[i+1]
	}
	if len(fields) == 0 {
		return nil, fmt.Errorf("where.%s: wrapper must contain at least one field", name)
	}
	return fields, nil
}

func requireWrapperTrue(node yaml.Node, path string) error {
	var value bool
	if err := node.Decode(&value); err != nil {
		return fmt.Errorf("where.%s: expected boolean true", path)
	}
	if !value {
		return fmt.Errorf("where.%s: only true is meaningful; use not: for a negative condition", path)
	}
	return nil
}

func wrapperStringList(node yaml.Node, path string) ([]string, error) {
	if node.Kind == yaml.ScalarNode {
		if node.Tag != "!!str" {
			return nil, fmt.Errorf("where.%s must be a string or a non-empty list of strings", path)
		}
		var v string
		if err := node.Decode(&v); err != nil || strings.TrimSpace(v) == "" {
			return nil, fmt.Errorf("where.%s must be a string or a non-empty list of strings", path)
		}
		return []string{v}, nil
	}
	if node.Kind != yaml.SequenceNode || len(node.Content) == 0 {
		return nil, fmt.Errorf("where.%s must be a string or a non-empty list of strings", path)
	}
	out := make([]string, len(node.Content))
	for i, item := range node.Content {
		if item.Kind != yaml.ScalarNode || item.Tag != "!!str" || strings.TrimSpace(item.Value) == "" {
			return nil, fmt.Errorf("where.%s must be a string or a non-empty list of strings", path)
		}
		out[i] = item.Value
	}
	return out, nil
}

func wrapperEnumList(node yaml.Node, path string, allowed map[string]bool) ([]string, error) {
	values, err := wrapperStringList(node, path)
	if err != nil {
		return nil, err
	}
	keys := make([]string, 0, len(allowed))
	for k := range allowed {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, v := range values {
		if !allowed[v] {
			return nil, fmt.Errorf("where.%s must be one of %s", path, strings.Join(keys, ", "))
		}
	}
	return values, nil
}
func enumRegex(values []string) string {
	parts := make([]string, len(values))
	for i, v := range values {
		parts[i] = regexp.QuoteMeta(v)
	}
	return "^(?:" + strings.Join(parts, "|") + ")$"
}
