package engine

import (
	"github.com/th13vn/w3goaudit/pkg/types"
)

// PresetFunc is a function type for preset checks
type PresetFunc func(fn *types.Function, contract *types.Contract, e *Engine) bool

// BuiltinPresets contains all built-in preset checks
var BuiltinPresets = map[string]PresetFunc{
	"unAuthenticated": checkUnAuthenticated,
	"unCheckedSender": checkUnCheckedSender,
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
// Logic delegated to types.Function.IsAccessControlled() — privileged access
// control only (owner/admin/role modifiers, auth helpers, and caller-vs-storage
// or caller-vs-hardcoded-address guards). A caller self-scoping check such as
// require(from == msg.sender) is NOT privileged access control and does NOT
// satisfy this preset — use `unCheckedSender` where self-scoping is a valid
// mitigation (e.g. arbitrary transferFrom).
func checkUnAuthenticated(fn *types.Function, contract *types.Contract, e *Engine) bool {
	return !fn.IsAccessControlled(e.db)
}

// checkUnCheckedSender is the safety predicate for arbitrary-transferFrom-style
// detectors, where binding a sensitive argument to the caller is itself a valid
// mitigation ("you can only act on your own behalf"). A function is vulnerable
// only when it has NEITHER privileged access control NOR a caller self-scoping
// equality check (e.g. require(from == msg.sender) / if (from != msg.sender)
// revert). This is broader than `unAuthenticated`: it also clears functions that
// scope the caller without gating to a privileged role.
func checkUnCheckedSender(fn *types.Function, contract *types.Contract, e *Engine) bool {
	return !fn.IsAccessControlled(e.db) && !fn.ComparesCallerIdentity()
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
