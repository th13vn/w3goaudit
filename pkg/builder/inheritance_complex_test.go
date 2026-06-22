package builder

import (
	"strings"
	"testing"

	"github.com/th13vn/w3goaudit/pkg/types"
)

const (
	classicKZFixture   = "../../test-data/core/build-database/11-c3-classic-kz.sol"
	superChainFixture  = "../../test-data/core/build-database/12-super-chain.sol"
	codingStyleFixture = "../../test-data/core/build-database/13-coding-styles.sol"
	superMultiLeafFixt = "../../test-data/core/build-database/14-super-multi-leaf.sol"
)

// TestC3ClassicKZEndToEnd runs the canonical Dylan/CPython C3 example through the
// FULL c3Linearize pipeline from real Solidity source (base-list reversal +
// canonical merge), not just the c3Merge primitive. The Python result
//
//	L[Z] = [Z, K1, K2, K3, D, A, B, C, E, O]
//
// must be reproduced exactly after w3goaudit reverses each contract's written
// base list (Solidity treats the last-listed base as most derived).
func TestC3ClassicKZEndToEnd(t *testing.T) {
	db := buildFixture(t, classicKZFixture)

	cases := map[string][]string{
		"K1": {"K1", "A", "B", "C", "O"},
		"K2": {"K2", "D", "B", "E", "O"},
		"K3": {"K3", "D", "A", "O"},
		"Z":  {"Z", "K1", "K2", "K3", "D", "A", "B", "C", "E", "O"},
	}
	for name, want := range cases {
		c := db.GetContractByName(name)
		if c == nil {
			t.Fatalf("contract %s not found", name)
		}
		if !equalStrings(c.LinearizedBases, want) {
			t.Errorf("%s MRO = %v, want %v (canonical C3)", name, c.LinearizedBases, want)
		}
	}
}

// TestCodingStylesParsing verifies the builder survives mixed real-world coding
// styles without losing base lists, override targets, or state-variable order.
func TestCodingStylesParsing(t *testing.T) {
	db := buildFixture(t, codingStyleFixture)

	// 1. Constructor-argument base: `is Priced(100)` — base NAME must be "Priced",
	//    not "Priced(100)" or "100".
	vault := db.GetContractByName("Vault")
	if vault == nil {
		t.Fatal("Vault not found")
	}
	wantBases := []string{"Priced", "Middle"}
	if !equalStrings(vault.BaseContracts, wantBases) {
		t.Errorf("Vault.BaseContracts = %v, want %v (constructor args must be stripped)", vault.BaseContracts, wantBases)
	}

	// 2. Interface inheriting multiple interfaces.
	combined := db.GetContractByName("ICombined")
	if combined == nil {
		t.Fatal("ICombined not found")
	}
	if combined.Kind != types.ContractKindInterface {
		t.Errorf("ICombined.Kind = %q, want interface", combined.Kind)
	}
	if !equalStrings(combined.BaseContracts, []string{"IRoot", "IExtra"}) {
		t.Errorf("ICombined.BaseContracts = %v, want [IRoot IExtra]", combined.BaseContracts)
	}
	wantCombinedMRO := []string{"ICombined", "IExtra", "IRoot"}
	if !equalStrings(combined.LinearizedBases, wantCombinedMRO) {
		t.Errorf("ICombined MRO = %v, want %v", combined.LinearizedBases, wantCombinedMRO)
	}

	// 3. Abstract contract participates in the chain.
	pricing := db.GetContractByName("Pricing")
	if pricing == nil {
		t.Fatal("Pricing not found")
	}
	if !pricing.IsAbstract {
		t.Errorf("Pricing should be abstract")
	}

	// 4. Vault MRO (derived-first), solc 0.8.20.
	wantVaultMRO := []string{"Vault", "Middle", "Priced", "Pricing", "Storage", "Base"}
	if !equalStrings(vault.LinearizedBases, wantVaultMRO) {
		t.Errorf("Vault MRO = %v, want %v", vault.LinearizedBases, wantVaultMRO)
	}

	// 5. State-variable storage order (most-base first = reverse MRO, declaration
	//    order within each contract).
	var layout []string
	for i := len(vault.LinearizedBases) - 1; i >= 0; i-- {
		base := db.GetContractByName(vault.LinearizedBases[i])
		if base == nil {
			continue
		}
		for _, sv := range base.StateVariables {
			layout = append(layout, base.Name+"."+sv.Name)
		}
	}
	wantLayout := []string{
		"Base.baseSlot",
		"Storage.storageSlot", "Storage.balances",
		"Pricing.priceSlot",
		"Priced.fixedPrice",
		"Middle.middleSlot",
		"Vault.vaultSlot",
	}
	if !equalStrings(layout, wantLayout) {
		t.Errorf("Vault storage layout = %v, want %v", layout, wantLayout)
	}
}

// TestSuperChainContextSensitivity pins the cooperative-multiple-inheritance
// super chain after leaf-context super resolution (ResolveSuperAcrossLeaves).
//
// Full's MRO is [Full, StepB, StepA, Root]. The solc-correct runtime super chain
// for Full().step() is:
//
//	Full.step  -> StepB.step
//	StepB.step -> StepA.step   (ONLY in Full's context — not StepB's own MRO)
//	StepA.step -> Root.step
//
// StepB.step's super target is context-dependent: standalone (StepB's own MRO
// [StepB, Root]) it is Root.step, but inside Full it is StepA.step. The call
// graph now records the SOUND UNION of both, so StepA.step is reachable from
// Full's entry via the super chain.
func TestSuperChainContextSensitivity(t *testing.T) {
	db := buildFixture(t, superChainFixture)
	db.CallGraph.EnsureIndex()

	full := db.GetContractByName("Full")
	if full == nil {
		t.Fatal("Full not found")
	}
	wantMRO := []string{"Full", "StepB", "StepA", "Root"}
	if !equalStrings(full.LinearizedBases, wantMRO) {
		t.Errorf("Full MRO = %v, want %v", full.LinearizedBases, wantMRO)
	}

	superTargets := func(fromSuffix string) []string {
		var out []string
		for _, e := range db.CallGraph.Edges {
			if strings.HasSuffix(e.From, fromSuffix) && e.Type == types.CallTypeSuper {
				out = append(out, e.To)
			}
		}
		return out
	}
	hasTarget := func(targets []string, want string) bool {
		for _, tgt := range targets {
			if strings.Contains(tgt, want) {
				return true
			}
		}
		return false
	}

	if got := superTargets("#Full.step()"); !hasTarget(got, "#StepB.step") {
		t.Errorf("Full.step super targets = %v, want one to StepB.step", got)
	}
	if got := superTargets("#StepA.step()"); !hasTarget(got, "#Root.step") {
		t.Errorf("StepA.step super targets = %v, want one to Root.step", got)
	}

	// The union: StepB.step now binds to BOTH StepA.step (Full context, the
	// previously-missing edge) and Root.step (StepB standalone context).
	stepB := superTargets("#StepB.step()")
	if !hasTarget(stepB, "#StepA.step") {
		t.Errorf("StepB.step super targets = %v, want one to StepA.step (Full's MRO context)", stepB)
	}
	if !hasTarget(stepB, "#Root.step") {
		t.Errorf("StepB.step super targets = %v, want one to Root.step (StepB standalone)", stepB)
	}
}

// TestSuperSharedMixinMultipleLeaves is the definitive "super across multiple
// classes" check: a single shared mixin M is pulled into two distinct concrete
// leaves (LeafX is A,M and LeafY is B,M), and M.f()'s super target differs per
// leaf. A context-free per-function call graph cannot encode that with one edge,
// so the sound UNION must hold every per-leaf target — exactly, with no spurious
// extras.
//
//	LeafX MRO = [LeafX, M, A, Root]  => M.f super -> A.f
//	LeafY MRO = [LeafY, M, B, Root]  => M.f super -> B.f
//	M standalone MRO = [M, Root]     => M.f super -> Root.f
func TestSuperSharedMixinMultipleLeaves(t *testing.T) {
	db := buildFixture(t, superMultiLeafFixt)
	db.CallGraph.EnsureIndex()

	// MROs.
	wantMRO := map[string][]string{
		"LeafX": {"LeafX", "M", "A", "Root"},
		"LeafY": {"LeafY", "M", "B", "Root"},
		"M":     {"M", "Root"},
		"A":     {"A", "Root"},
		"B":     {"B", "Root"},
	}
	for name, want := range wantMRO {
		c := db.GetContractByName(name)
		if c == nil {
			t.Fatalf("contract %s not found", name)
		}
		if !equalStrings(c.LinearizedBases, want) {
			t.Errorf("%s MRO = %v, want %v", name, c.LinearizedBases, want)
		}
	}

	// Collect the exact set of super edges (contract.selector -> contract.selector).
	type pair struct{ from, to string }
	got := map[pair]bool{}
	for _, e := range db.CallGraph.Edges {
		if e.Type != types.CallTypeSuper {
			continue
		}
		fp := e.From[strings.Index(e.From, "#")+1:]
		tp := e.To[strings.Index(e.To, "#")+1:]
		got[pair{fp, tp}] = true
	}

	want := []pair{
		{"LeafX.f()", "M.f()"},
		{"LeafY.f()", "M.f()"},
		{"M.f()", "A.f()"},    // LeafX context
		{"M.f()", "B.f()"},    // LeafY context
		{"M.f()", "Root.f()"}, // M standalone context
		{"A.f()", "Root.f()"},
		{"B.f()", "Root.f()"},
	}
	for _, w := range want {
		if !got[w] {
			t.Errorf("missing super edge %s -> %s", w.from, w.to)
		}
	}
	// Exact union: no spurious extras (e.g. M.f -> Root.f is fine, but M.f must
	// NOT bind to, say, LeafX.f or skip A in LeafX's context).
	if len(got) != len(want) {
		var all []string
		for p := range got {
			all = append(all, p.from+" -> "+p.to)
		}
		t.Errorf("super edge count = %d, want %d; got %v", len(got), len(want), all)
	}
}
