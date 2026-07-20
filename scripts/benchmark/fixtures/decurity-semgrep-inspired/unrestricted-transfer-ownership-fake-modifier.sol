// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// ─── Adversarial bypass: empty `auth`-NAMED modifier ──────────────────────
// This one is aimed squarely at heuristic detectors. The modifier is NAMED
// `auth` (a token w3goaudit's IsAccessControlled regex treats as a positive
// signal for the `access_controlled` preset) — but its body is a no-op. So a
// rule that gates on "function lacks an `onlyOwner`/`auth`/… modifier" will
// see one and skip the function, even though it provides no protection.
//
// Expected behavior: a careful detector should fire. This is the canonical
// failure mode of name-based heuristics; documenting it explicitly here lets
// us measure both tools' susceptibility.

contract VulnerableUnrestrictedTransferOwnershipFakeModifier {
    address public owner;

    // BAD: looks like access control but does nothing.
    modifier auth() {
        _;
    }

    // Auditor's eye: owner can be set by anyone. Auth modifier is a decoy.
    function transferOwnership(address newOwner) external auth {
        owner = newOwner;
    }
}

// Safe: same shape, but the modifier actually checks. Must NOT fire.
contract SafeUnrestrictedTransferOwnershipRealAuth {
    address public owner;

    constructor() { owner = msg.sender; }

    modifier auth() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function transferOwnership(address newOwner) external auth {
        owner = newOwner;
    }
}
