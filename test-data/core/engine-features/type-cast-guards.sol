// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Regression fixture for TestTypeCastsDoNotCreateReentrancyFindings.
//
// A `require(x != address(0), ...)` guard contains the elementary type
// conversion `address(0)`. A naive matcher can mistake that conversion for an
// outgoing call and then match the reentrancy `sequence: [state_write,
// outgoing_call]` against an entirely safe function. Neither contract below
// performs any external/low-level call, so neither must yield a reentrancy
// finding. The state writes follow the guard, exercising the exact ordering a
// false positive would trip on.

// SHOULD NOT TRIGGER reentrancy: address(0) in the guard is a type cast.
contract Safe_AddressZeroCheck {
    address public treasury;

    function setTreasury(address _treasury) external {
        require(_treasury != address(0), "Zero address");
        treasury = _treasury;
    }
}

// SHOULD NOT TRIGGER reentrancy: mint/burn guard casts to address(0) then
// writes state, with no outgoing call anywhere.
contract Safe_MintBurnZero {
    mapping(address => uint256) public balances;
    uint256 public totalSupply;

    function mint(address to, uint256 amount) external {
        require(to != address(0), "Mint to zero");
        balances[to] += amount;
        totalSupply += amount;
    }

    function burn(address from, uint256 amount) external {
        require(from != address(0), "Burn from zero");
        balances[from] -= amount;
        totalSupply -= amount;
    }
}
