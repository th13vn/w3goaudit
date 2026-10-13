package report

import (
	"sort"

	"github.com/th13vn/w3goaudit/pkg/types"
)

// HunterModelVersion versions the entry-point ranking model independently of
// the result-folder SchemaVersion. Later semantic-fact tranches change how
// entries are ranked without moving the schema that every consumer pins.
const HunterModelVersion = "1.0.0"

// hunterSignalNone is the value of a dimension no observation ever raised. It
// is deliberately not a claim: "none" means nothing fired, not "this is safe".
const hunterSignalNone = "none"

// Hunter tier bands. A lower tier is read first. Bands come from hunterTier's
// decision table, never from a score threshold.
const (
	HunterTierOpenValue    = 0
	HunterTierOpenReentry  = 1
	HunterTierOpenExternal = 2
	HunterTierGuarded      = 3
	HunterTierNoBoundary   = 4
)

var hunterTierNames = map[int]string{
	HunterTierOpenValue:    "open-value-surface",
	HunterTierOpenReentry:  "open-reentry-or-arbitrary",
	HunterTierOpenExternal: "open-external-surface",
	HunterTierGuarded:      "guarded-external-surface",
	HunterTierNoBoundary:   "no-boundary-surface",
}

// HunterSignal is one ranked dimension of an entry point. Value carries the
// underlying evidence enum verbatim; Ordinal exists only to order rows and is
// never summed, weighted, or averaged. FactIDs cite the facts that prove it.
type HunterSignal struct {
	Value   string   `json:"value"`
	Ordinal int      `json:"ordinal"`
	FactIDs []string `json:"factIds"`
}

// HunterAuthorizationSignal adds the guard shape to the shared signal fields,
// so a reader can tell an owner guard from a role guard or a self scope.
type HunterAuthorizationSignal struct {
	HunterSignal
	Dominance     string `json:"dominance,omitempty"`
	PrincipalKind string `json:"principalKind,omitempty"`
}

// HunterSignals is the full evidence vector for one entry point.
type HunterSignals struct {
	Authorization    HunterAuthorizationSignal `json:"authorization"`
	ValueReach       HunterSignal              `json:"valueReach"`
	Reentry          HunterSignal              `json:"reentry"`
	StateAfterCall   HunterSignal              `json:"stateAfterCall"`
	TargetResolution HunterSignal              `json:"targetResolution"`
	ResultHandling   HunterSignal              `json:"resultHandling"`
}

// hunterAuthorizationOrdinal ranks an authorization verdict. An unproven
// verdict outranks a proven guard: this repository treats an unknown state as
// unproven rather than safe, and an unexamined entry point is exactly what a
// hunter should read first. Any unrecognized verdict falls back to the unknown
// ordinal for the same reason.
func hunterAuthorizationOrdinal(verdict types.AuthorizationVerdict) int {
	switch verdict {
	case types.AuthorizationUnprotected:
		return 3
	case types.AuthorizationSelfScoped:
		return 1
	case types.AuthorizationProtected:
		return 0
	default:
		return 2
	}
}

// hunterValueOrdinal ranks how much of a boundary's value operand the caller
// controls.
func hunterValueOrdinal(control types.BoundaryValueControl) int {
	switch control {
	case types.BoundaryValueCallerControlled:
		return 4
	case types.BoundaryValueStateDerived:
		return 3
	case types.BoundaryValueFixed:
		return 1
	case "":
		return 0
	default:
		return 2
	}
}

// hunterReentryOrdinal ranks a boundary's reentry class. Classes that prove a
// bounded reentry (stipend, same contract, constructor) rank at zero; an
// unknown class does not, because nothing was proven about it.
func hunterReentryOrdinal(class string) int {
	switch class {
	case types.BoundaryReentryDelegateContext:
		return 4
	case types.BoundaryReentryPossible:
		return 3
	case types.BoundaryReentryReadOnlyPossible:
		return 2
	case types.BoundaryReentryUnknown:
		return 1
	default:
		return 0
	}
}

// hunterStateOrdinal ranks a state write's order relative to its boundary. A
// write after an external call is the checks-effects-interactions shape.
func hunterStateOrdinal(relation string) int {
	switch relation {
	case types.BoundaryStateAfter:
		return 2
	case types.BoundaryStateUnordered, types.BoundaryStateUnknown, types.BoundaryStateIncompatible:
		return 1
	default:
		return 0
	}
}

// hunterTier applies the band decision table top to bottom, first match wins.
func hunterTier(signals HunterSignals, payable, hasBoundary bool) (int, string) {
	open := signals.Authorization.Ordinal >= 2
	switch {
	case open && (signals.ValueReach.Ordinal >= 2 || payable):
		return HunterTierOpenValue, hunterTierNames[HunterTierOpenValue]
	case open && (signals.Reentry.Ordinal >= 2 || signals.TargetResolution.Ordinal == 1):
		return HunterTierOpenReentry, hunterTierNames[HunterTierOpenReentry]
	case open && hasBoundary:
		return HunterTierOpenExternal, hunterTierNames[HunterTierOpenExternal]
	case hasBoundary:
		return HunterTierGuarded, hunterTierNames[HunterTierGuarded]
	default:
		return HunterTierNoBoundary, hunterTierNames[HunterTierNoBoundary]
	}
}

// hunterSignalTuple is the fixed dimension order used for within-tier ordering.
// Rows compare this tuple lexicographically, descending.
func hunterSignalTuple(signals HunterSignals) [6]int {
	return [6]int{
		signals.Authorization.Ordinal,
		signals.ValueReach.Ordinal,
		signals.Reentry.Ordinal,
		signals.StateAfterCall.Ordinal,
		signals.TargetResolution.Ordinal,
		signals.ResultHandling.Ordinal,
	}
}

// newHunterSignal is the unraised state of one dimension.
func newHunterSignal() HunterSignal {
	return HunterSignal{Value: hunterSignalNone, FactIDs: []string{}}
}

// raiseHunterSignal keeps the strongest observation and accumulates every fact
// that ties with it, so a rank is always traceable to all the evidence behind
// it. At an equal ordinal the first distinct value wins, which is deterministic
// because boundary facts arrive in normalized order.
func raiseHunterSignal(signal *HunterSignal, value string, ordinal int, factID string) {
	switch {
	case ordinal < signal.Ordinal:
		return
	case ordinal > signal.Ordinal:
		signal.Value = value
		signal.Ordinal = ordinal
		signal.FactIDs = []string{}
	case signal.Value != value:
		if signal.Value != hunterSignalNone {
			return
		}
		signal.Value = value
	}
	signal.FactIDs = appendHunterFactID(signal.FactIDs, factID)
}

// appendHunterFactID inserts into a sorted, deduplicated slice so evidence
// order never depends on traversal order.
func appendHunterFactID(ids []string, factID string) []string {
	if factID == "" {
		return ids
	}
	position := sort.SearchStrings(ids, factID)
	if position < len(ids) && ids[position] == factID {
		return ids
	}
	ids = append(ids, "")
	copy(ids[position+1:], ids[position:])
	ids[position] = factID
	return ids
}
