package engine

import (
	"github.com/th13vn/w3goaudit-engine/pkg/types"
)

// PresetFunc is a function type for preset checks
type PresetFunc func(fn *types.Function, contract *types.Contract, e *Engine) bool

// BuiltinPresets contains all built-in preset checks
var BuiltinPresets = map[string]PresetFunc{
	"unAuthenticated": checkUnAuthenticated,
	"unLocked":        checkUnLocked,
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
	VerboseLog("checkBuiltinPreset: unknown preset %q — returning false (template should have been rejected at load)", preset)
	return false
}

// IsKnownPreset reports whether name refers to a registered built-in preset.
// Used by template load to reject typos at author time.
func IsKnownPreset(name string) bool {
	_, ok := BuiltinPresets[name]
	return ok
}

// checkUnAuthenticated checks if a function does NOT have authentication
// Returns true if the function is NOT authenticated (vulnerable)
// Logic delegated to types.Function.IsAccessControlled()
func checkUnAuthenticated(fn *types.Function, contract *types.Contract, e *Engine) bool {
	return !fn.IsAccessControlled(e.db)
}

// checkUnLocked checks if a function does NOT have reentrancy protection
// Returns true if the function is NOT protected (vulnerable)
// Protection is defined as having a reentrancy guard modifier
func checkUnLocked(fn *types.Function, contract *types.Contract, e *Engine) bool {
	// Check for reentrancy guard modifiers
	lockModifierPattern := `(?i)(nonReentrant|noReentrancy|lock|locked|guard|mutex|reentrancyGuard)`
	for _, mod := range fn.Modifiers {
		if MatchesRegex(lockModifierPattern, mod) {
			return false // Has reentrancy protection, NOT vulnerable
		}
	}

	return true // No reentrancy protection found, IS vulnerable
}
