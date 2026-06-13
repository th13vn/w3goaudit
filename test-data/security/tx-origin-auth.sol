// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Fixtures for SEC-TXORIGIN-001 (tx.origin authentication). The detector must
// flag tx.origin used for auth, but NOT the legitimate anti-contract idiom
// `require(msg.sender == tx.origin)` which only asserts the caller is an EOA.

contract VulnerableTxOrigin {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    // VULNERABLE: tx.origin used for authentication (phishing vector).
    function withdraw(address to) external {
        require(tx.origin == owner, "not owner");
        payable(to).transfer(address(this).balance);
    }
}

contract SafeEOACheck {
    // SAFE: tx.origin used only to assert the caller is an externally-owned
    // account (msg.sender == tx.origin), not for authentication.
    function action() external view returns (bool) {
        require(msg.sender == tx.origin, "no contracts");
        return true;
    }
}

contract SafeMsgSenderAuth {
    address public owner = msg.sender;

    // SAFE: uses msg.sender for authentication, not tx.origin.
    function adminOnly() external view returns (bool) {
        require(msg.sender == owner, "not owner");
        return true;
    }
}
