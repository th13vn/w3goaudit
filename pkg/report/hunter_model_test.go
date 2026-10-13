package report

import (
	"testing"

	"github.com/th13vn/w3goaudit/pkg/types"
)

func TestHunterOrdinalsRankUnprovenStatesHigh(t *testing.T) {
	if hunterAuthorizationOrdinal(types.AuthorizationUnknown) <= hunterAuthorizationOrdinal(types.AuthorizationProtected) {
		t.Fatalf("unknown authorization must outrank protected")
	}
	if hunterAuthorizationOrdinal(types.AuthorizationUnknown) <= hunterAuthorizationOrdinal(types.AuthorizationSelfScoped) {
		t.Fatalf("unknown authorization must outrank self_scoped")
	}
	if hunterAuthorizationOrdinal(types.AuthorizationUnprotected) <= hunterAuthorizationOrdinal(types.AuthorizationUnknown) {
		t.Fatalf("unprotected must outrank unknown")
	}
	if hunterReentryOrdinal(types.BoundaryReentryUnknown) <= hunterReentryOrdinal(types.BoundaryReentryStipendLimited) {
		t.Fatalf("unknown reentry must outrank stipend_limited")
	}
	if hunterReentryOrdinal(types.BoundaryReentryDelegateContext) <= hunterReentryOrdinal(types.BoundaryReentryPossible) {
		t.Fatalf("delegate_context must outrank possible")
	}
	if hunterValueOrdinal(types.BoundaryValueUnknown) <= hunterValueOrdinal(types.BoundaryValueFixed) {
		t.Fatalf("unknown value control must outrank fixed")
	}
	if hunterValueOrdinal(types.BoundaryValueCallerControlled) <= hunterValueOrdinal(types.BoundaryValueStateDerived) {
		t.Fatalf("caller_controlled must outrank state_derived")
	}
	if hunterStateOrdinal(types.BoundaryStateAfter) <= hunterStateOrdinal(types.BoundaryStateBefore) {
		t.Fatalf("state write after a call must outrank one before it")
	}
	if got := hunterAuthorizationOrdinal("not-a-verdict"); got != hunterAuthorizationOrdinal(types.AuthorizationUnknown) {
		t.Fatalf("unrecognized verdict = %d, want the unknown ordinal", got)
	}
}

func TestHunterTierDecisionTable(t *testing.T) {
	unprotected := HunterSignals{Authorization: HunterAuthorizationSignal{
		HunterSignal: HunterSignal{Value: string(types.AuthorizationUnprotected), Ordinal: 3},
	}}
	protected := HunterSignals{Authorization: HunterAuthorizationSignal{
		HunterSignal: HunterSignal{Value: string(types.AuthorizationProtected), Ordinal: 0},
	}}

	withValue := unprotected
	withValue.ValueReach = HunterSignal{Value: string(types.BoundaryValueCallerControlled), Ordinal: 4}
	withReentry := unprotected
	withReentry.Reentry = HunterSignal{Value: types.BoundaryReentryPossible, Ordinal: 3}
	withUnresolved := unprotected
	withUnresolved.TargetResolution = HunterSignal{Value: types.BoundaryTargetUnresolved, Ordinal: 1}

	cases := []struct {
		name        string
		signals     HunterSignals
		payable     bool
		hasBoundary bool
		wantTier    int
		wantName    string
	}{
		{"value reach", withValue, false, true, HunterTierOpenValue, "open-value-surface"},
		{"payable with no boundary", unprotected, true, false, HunterTierOpenValue, "open-value-surface"},
		{"reentry", withReentry, false, true, HunterTierOpenReentry, "open-reentry-or-arbitrary"},
		{"unresolved target", withUnresolved, false, true, HunterTierOpenReentry, "open-reentry-or-arbitrary"},
		{"open external", unprotected, false, true, HunterTierOpenExternal, "open-external-surface"},
		{"guarded external", protected, false, true, HunterTierGuarded, "guarded-external-surface"},
		{"no boundary", protected, false, false, HunterTierNoBoundary, "no-boundary-surface"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tier, name := hunterTier(tc.signals, tc.payable, tc.hasBoundary)
			if tier != tc.wantTier || name != tc.wantName {
				t.Fatalf("hunterTier = (%d, %q), want (%d, %q)", tier, name, tc.wantTier, tc.wantName)
			}
		})
	}
}

func TestHunterSignalTupleOrdersDimensionsAsSpecified(t *testing.T) {
	signals := HunterSignals{
		Authorization:    HunterAuthorizationSignal{HunterSignal: HunterSignal{Ordinal: 3}},
		ValueReach:       HunterSignal{Ordinal: 4},
		Reentry:          HunterSignal{Ordinal: 2},
		StateAfterCall:   HunterSignal{Ordinal: 1},
		TargetResolution: HunterSignal{Ordinal: 1},
		ResultHandling:   HunterSignal{Ordinal: 0},
	}
	if got, want := hunterSignalTuple(signals), [6]int{3, 4, 2, 1, 1, 0}; got != want {
		t.Fatalf("hunterSignalTuple = %v, want %v", got, want)
	}
}

func TestRaiseHunterSignalKeepsStrongestAndAccumulatesTies(t *testing.T) {
	signal := HunterSignal{Value: hunterSignalNone, FactIDs: []string{}}

	raiseHunterSignal(&signal, types.BoundaryReentrySameContract, 0, "eb:c")
	if signal.Value != types.BoundaryReentrySameContract || signal.Ordinal != 0 {
		t.Fatalf("first observation = %+v", signal)
	}

	raiseHunterSignal(&signal, types.BoundaryReentryStipendLimited, 0, "eb:d")
	if signal.Value != types.BoundaryReentrySameContract || len(signal.FactIDs) != 1 {
		t.Fatalf("a different value at the same ordinal must not overwrite: %+v", signal)
	}

	raiseHunterSignal(&signal, types.BoundaryReentryPossible, 3, "eb:b")
	if signal.Value != types.BoundaryReentryPossible || signal.Ordinal != 3 || len(signal.FactIDs) != 1 {
		t.Fatalf("a stronger observation must replace the evidence: %+v", signal)
	}

	raiseHunterSignal(&signal, types.BoundaryReentryPossible, 3, "eb:a")
	raiseHunterSignal(&signal, types.BoundaryReentryPossible, 3, "eb:a")
	if got, want := signal.FactIDs, []string{"eb:a", "eb:b"}; len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("tied evidence = %v, want sorted and deduplicated %v", got, want)
	}

	raiseHunterSignal(&signal, types.BoundaryReentryUnknown, 1, "eb:z")
	if signal.Value != types.BoundaryReentryPossible || len(signal.FactIDs) != 2 {
		t.Fatalf("a weaker observation must be ignored: %+v", signal)
	}
}
