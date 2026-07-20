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
// 17. INCORRECT-EQUALITY — Strict equality on balance
// =============================================================================

// SHOULD TRIGGER: incorrect-equality
contract Vulnerable_IncorrectEquality {
    // BAD: strict equality on balance — can be broken by forced ETH send
    function goalReached() external view returns (bool) {
        return address(this).balance == 100 ether;
    }
}

// SHOULD NOT TRIGGER: incorrect-equality
contract Safe_IncorrectEquality {
    // SAFE: uses >= instead of ==
    function goalReached() external view returns (bool) {
        return address(this).balance >= 100 ether;
    }
}
