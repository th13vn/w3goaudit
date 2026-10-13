package builder

import "testing"

// Solidity 0.4.x treated a function without an explicit visibility modifier
// as public. The paper corpus contains this legacy form in reentrancy cases,
// so the builder must expose it as an entry point rather than silently
// excluding the function from entry_function scans.
func TestLegacySolidityDefaultsMissingFunctionVisibilityToPublic(t *testing.T) {
	db := buildFromSource(t, `pragma solidity ^0.4.19;
contract LegacyBank {
    uint256 public balance;
    function withdraw() {
        balance = 0;
    }
}`)
	c := db.GetContractByName("LegacyBank")
	if c == nil {
		t.Fatal("LegacyBank contract missing")
	}
	var fnName string
	for _, fn := range c.Functions {
		if fn.Name == "withdraw" {
			fnName = fn.Name
			if string(fn.Visibility) != "public" {
				t.Fatalf("legacy function visibility = %q, want public", fn.Visibility)
			}
			if !fn.IsEntrypoint() {
				t.Fatal("legacy function without visibility must be an entry point")
			}
		}
	}
	if fnName == "" {
		t.Fatal("withdraw function missing")
	}
}

func TestModernSolidityMissingFunctionVisibilityIsNotGuessed(t *testing.T) {
	db := buildFromSource(t, `pragma solidity ^0.8.20;
contract Modern {
    uint256 public balance;
    function withdraw() {
        balance = 0;
    }
}`)
	c := db.GetContractByName("Modern")
	if c == nil {
		t.Fatal("Modern contract missing")
	}
	for _, fn := range c.Functions {
		if fn.Name != "withdraw" {
			continue
		}
		if fn.Visibility != "" {
			t.Fatalf("modern function visibility = %q, want empty for malformed omitted modifier", fn.Visibility)
		}
		if fn.IsEntrypoint() {
			t.Fatal("modern function with omitted visibility must not be guessed as an entry point")
		}
		return
	}
	t.Fatal("withdraw function missing")
}

func TestLegacyVisibilityDoesNotDependOnPragmaOrder(t *testing.T) {
	db := buildFromSource(t, `contract LegacyOrder {
    function withdraw() {}
}
pragma solidity ^0.4.24;`)
	c := db.GetContractByName("LegacyOrder")
	if c == nil || len(c.Functions) != 1 {
		t.Fatalf("LegacyOrder function missing: %+v", c)
	}
	if c.Functions[0].Visibility != "public" {
		t.Fatalf("legacy visibility with trailing pragma = %q, want public", c.Functions[0].Visibility)
	}
}

func TestLegacyPragmaDetectionRequiresPre05OnlyConstraint(t *testing.T) {
	cases := map[string]bool{
		"^0.4.24":          true,
		"^0.4":             true,
		"0.4.19":           true,
		">=0.4.0 <0.5.0":   true,
		">= 0.4.0 < 0.5.0": true,
		"<=0.4.26":         true,
		">=0.4.0":          false,
		"^0.4.0 || ^0.5.0": false,
		"^0.8.20":          false,
		"^0":               false,
		"~0":               false,
		"0":                false,
		"<0.5.1":           false,
		"":                 false,
	}
	for pragma, want := range cases {
		t.Run(pragma, func(t *testing.T) {
			if got := legacyPragmaBefore05(pragma); got != want {
				t.Fatalf("legacyPragmaBefore05(%q) = %v, want %v", pragma, got, want)
			}
		})
	}
}
