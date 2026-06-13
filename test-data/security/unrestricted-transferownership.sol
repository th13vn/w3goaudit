// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// SEC-OWNER-001 — Unrestricted transferOwnership
// Vulnerable_* SHOULD fire; Safe_* SHOULD NOT.

contract Vulnerable_UnrestrictedTransferOwnership {
    address public owner;

    // BAD: anyone can take ownership
    function transferOwnership(address newOwner) public {
        owner = newOwner;
    }
}

contract Safe_UnrestrictedTransferOwnership {
    address public owner;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    // GOOD: guarded by onlyOwner
    function transferOwnership(address newOwner) public onlyOwner {
        owner = newOwner;
    }
}
