package engine

import (
	"sort"

	"github.com/th13vn/w3goaudit/pkg/types"
)

// PresetFunc is a function type for preset checks
type PresetFunc func(fn *types.Function, contract *types.Contract, e *Engine) bool

// BuiltinPresets contains all built-in preset checks
var BuiltinPresets = map[string]PresetFunc{
	"access_controlled":  checkAccessControlled,
	"caller_checked":     checkCallerChecked,
	"reentrancy_guarded": checkReentrancyGuarded,
}

// checkBuiltinPreset checks if a built-in preset condition is satisfied.
//
// If the preset name is unknown, returns false (fail safe). Previously this
// returned true, which silently made a typo like `preset: unAuthenticatd`
// match every function — a giant noise generator. Template load now rejects
// unknown presets via IsKnownPreset, so this fallback should never fire in
// practice.
func checkBuiltinPreset(fn *types.Function, contract *types.Contract, e *Engine, preset string) bool {
	if checkFn, exists := BuiltinPresets[preset]; exists {
		return checkFn(fn, contract, e)
	}
	e.logf("checkBuiltinPreset: unknown preset %q — returning false (template should have been rejected at load)", preset)
	return false
}

// IsKnownPreset reports whether name refers to a registered built-in preset.
// Used by template load to reject typos at author time.
func IsKnownPreset(name string) bool {
	_, ok := BuiltinPresets[name]
	return ok
}

// KnownPresetNames returns the registered evaluator preset names, sorted,
// for use in error messages so the list never drifts from BuiltinPresets.
func KnownPresetNames() []string {
	names := make([]string, 0, len(BuiltinPresets))
	for name := range BuiltinPresets {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// checkAccessControlled reports whether privileged access control is present.
func checkAccessControlled(fn *types.Function, _ *types.Contract, e *Engine) bool {
	return fn.IsAccessControlled(e.db)
}

// checkCallerChecked reports whether the caller is privileged or constrained
// to act on its own behalf.
func checkCallerChecked(fn *types.Function, _ *types.Contract, e *Engine) bool {
	return fn.IsAccessControlled(e.db) || fn.ComparesCallerIdentity(e.db)
}

// checkReentrancyGuarded reports whether a reentrancy-guard modifier is present.
func checkReentrancyGuarded(fn *types.Function, _ *types.Contract, _ *Engine) bool {
	const pattern = `(?i)(nonReentrant|noReentrancy|lock|locked|guard|mutex|reentrancyGuard)`
	for _, mod := range fn.Modifiers {
		if MatchesRegex(pattern, mod) {
			return true
		}
	}
	return false
}
