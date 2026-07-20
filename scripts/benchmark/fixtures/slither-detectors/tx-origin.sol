// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// =============================================================================
// Test Contracts for Slither→WQL Template Verification
// Each Vulnerable_* contract SHOULD trigger its corresponding detector.
// Each Safe_* contract SHOULD NOT trigger the detector.
// =============================================================================

// --- Interfaces used across tests ---
interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function approve(address spender, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

// =============================================================================
// 16. TX-ORIGIN — tx.origin used for authorization
// =============================================================================

// SHOULD TRIGGER: tx-origin
contract Vulnerable_TxOrigin {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    // BAD: tx.origin used for auth check
    function withdraw() external {
        require(tx.origin == owner, "Not owner");
        payable(msg.sender).transfer(address(this).balance);
    }
}

// SHOULD NOT TRIGGER: tx-origin
contract Safe_TxOrigin {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    // SAFE: msg.sender used for auth
    function withdraw() external {
        require(msg.sender == owner, "Not owner");
        payable(msg.sender).transfer(address(this).balance);
    }
}
