// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Fixture for `extract involve` and `extract inheritance` testing.
//
// VaultV1 is a main contract with two entry points that BOTH reach the
// internal helper `_settle()`. `_settle()` in turn calls `_clamp()`.
// `extract involve _settle` should return TWO workflows (deposit, withdraw).
// `extract involve _clamp` should also return both workflows (transitively).
// `extract inheritance VaultV1` should succeed (main contract).
// `extract inheritance Math` should fail (library, not deployable).

library Math {
    function clamp(uint256 v, uint256 max) internal pure returns (uint256) {
        return v > max ? max : v;
    }
}

abstract contract VaultBase {
    uint256 internal _cap;
    event Settled(address indexed user, uint256 amount);

    function _clamp(uint256 v) internal view returns (uint256) {
        return Math.clamp(v, _cap);
    }
}

contract VaultV1 is VaultBase {
    mapping(address => uint256) public balances;

    constructor(uint256 cap) {
        _cap = cap;
    }

    function deposit(uint256 amount) external payable {
        _settle(msg.sender, amount);
    }

    function withdraw(uint256 amount) external {
        _settle(msg.sender, amount);
    }

    // Only-internal helper — `involve _settle` should surface deposit + withdraw.
    function _settle(address user, uint256 amount) internal {
        uint256 capped = _clamp(amount);
        balances[user] += capped;
        emit Settled(user, capped);
    }
}
