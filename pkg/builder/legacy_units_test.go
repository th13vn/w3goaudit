package builder

import (
	"testing"

	"github.com/th13vn/w3goaudit/pkg/types"
)

// A contract compiled before Solidity 0.7 can use the `finney` and `szabo`
// ether units. Before solast-go v0.1.14 one `1 finney` (MUSystem, pragma
// =0.6.4) produced 195 parse.recovered diagnostics and erased every function
// after it, so the MUSystem incident rule could not match the verified source.
func TestLegacyEtherUnitsParseWithoutRecovery(t *testing.T) {
	db, file := buildSourceText(t, `pragma solidity =0.6.4;
contract Legacy {
    uint256 public total;
    function deposit() public payable {
        if (msg.value >= 100 * 1 finney) { total += msg.value; }
        if (msg.value < 1 szabo) { revert("dust"); }
    }
    function afterDeposit() public view returns (uint256) { return total; }
}`)
	for _, diagnostic := range db.Diagnostics {
		if diagnostic.Code == types.DiagnosticParseRecovered || diagnostic.Code == types.DiagnosticParseSkipped {
			t.Fatalf("unexpected parse diagnostic: %+v", diagnostic)
		}
	}
	contract := db.Contracts[types.MakeContractID(file, "Legacy")]
	if contract == nil {
		t.Fatal("Legacy contract missing")
	}
	found := false
	for _, fn := range contract.Functions {
		if fn != nil && fn.Name == "afterDeposit" {
			found = true
		}
	}
	if !found {
		t.Fatal("the function after the ether units was dropped")
	}
}
