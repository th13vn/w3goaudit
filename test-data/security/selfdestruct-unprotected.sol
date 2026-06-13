// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Fixtures for SEC-DEST-001 (unprotected selfdestruct). The detector uses the
// unAuthenticated preset, so it must flag the truly-unprotected case and NOT
// flag functions guarded by a modifier OR an inline msg.sender check.

contract VulnerableSelfdestruct {
    // VULNERABLE: anyone can destroy the contract.
    function kill() external {
        selfdestruct(payable(msg.sender));
    }
}

contract SafeSelfdestructModifier {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    // SAFE: guarded by an auth-named modifier.
    function kill() external onlyOwner {
        selfdestruct(payable(owner));
    }
}

contract SafeSelfdestructInlineGuard {
    address public owner = msg.sender;

    // SAFE: inline msg.sender guard (the old modifier-name regex missed this,
    // producing a false positive).
    function kill() external {
        require(msg.sender == owner, "not owner");
        selfdestruct(payable(owner));
    }
}
