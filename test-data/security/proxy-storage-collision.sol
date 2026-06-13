// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// SEC-PROXY-001 — Proxy storage layout collision
// Vulnerable_* SHOULD fire; Safe_* SHOULD NOT.

contract UpgradeabilityProxy {}

// BAD: mutable storage declared on a proxy with a constructor
contract Vulnerable_ProxyStorageCollision is UpgradeabilityProxy {
    address public owner;

    constructor(address initialOwner) {
        owner = initialOwner;
    }
}

// GOOD: only immutable storage (fixed at construction, no slot collision)
contract Safe_ProxyStorageImmutable is UpgradeabilityProxy {
    address public immutable owner;

    constructor(address initialOwner) {
        owner = initialOwner;
    }
}

// GOOD: not a proxy at all
contract Safe_PlainContract {
    address public owner;

    constructor(address initialOwner) {
        owner = initialOwner;
    }
}
