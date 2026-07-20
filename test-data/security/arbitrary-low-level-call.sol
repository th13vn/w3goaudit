// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// SEC-CALL-001 — Arbitrary low-level call (user-controlled target + calldata)
// Vulnerable_* SHOULD fire; Safe_* SHOULD NOT.

contract Vulnerable_ArbitraryLowLevelCall {
    // BAD: caller chooses both target and calldata, no auth
    function execute(address target, bytes calldata data) external {
        (bool ok, ) = target.call(data);
        require(ok, "call failed");
    }
}

contract Safe_ArbitraryLowLevelCall {
    address public owner;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    // GOOD: same shape, but access-controlled (not: access_controlled excludes it)
    function execute(address target, bytes calldata data) external onlyOwner {
        (bool ok, ) = target.call(data);
        require(ok, "call failed");
    }
}
