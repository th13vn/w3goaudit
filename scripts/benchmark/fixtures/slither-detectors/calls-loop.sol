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
// 22. CALLS-LOOP — External calls inside loop (DoS risk)
// =============================================================================

// SHOULD TRIGGER: calls-loop
contract Vulnerable_CallsLoop {
    address[] public recipients;

    // BAD: external call in loop — single failure blocks all
    function distributeEther() external payable {
        uint256 share = msg.value / recipients.length;
        for (uint256 i = 0; i < recipients.length; i++) {
            payable(recipients[i]).transfer(share); // if one reverts, all fail
        }
    }
}

// SHOULD NOT TRIGGER: calls-loop
contract Safe_CallsLoop {
    mapping(address => uint256) public pendingWithdrawals;

    // SAFE: pull pattern — no external calls in loop
    function recordDistribution(address[] calldata addrs, uint256 amount) external {
        for (uint256 i = 0; i < addrs.length; i++) {
            pendingWithdrawals[addrs[i]] += amount;
        }
    }

    function withdraw() external {
        uint256 amount = pendingWithdrawals[msg.sender];
        pendingWithdrawals[msg.sender] = 0;
        payable(msg.sender).transfer(amount);
    }
}
