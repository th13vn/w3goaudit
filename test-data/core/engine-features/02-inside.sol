// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Exercises WQL feature: has: + in: (ancestor traversal).
// Pattern: a `tx.origin` member access nested inside a require/if guard.

// VULNERABLE: tx.origin used inside a require() guard for authentication.
// Should be matched by feature-inside.yaml.
contract VulnerableInside {
    address owner;

    function adminAction() external view {
        require(tx.origin == owner, "not owner"); // tx.origin inside check.require
    }
}

// SAFE: uses msg.sender instead of tx.origin.
// Should NOT be matched (no tx.origin node).
contract SafeInside {
    address owner;

    function adminAction() external view {
        require(msg.sender == owner, "not owner");
    }
}
