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
// 18. DIVIDE-BEFORE-MULTIPLY — Precision loss
// =============================================================================

// SHOULD TRIGGER: divide-before-multiply
contract Vulnerable_DivideBeforeMultiply {
    // BAD: division before multiplication causes truncation
    function calculate(uint256 supply, uint256 n, uint256 interest) external pure returns (uint256) {
        return (supply / n) * interest;
    }
}

// SHOULD NOT TRIGGER: divide-before-multiply
contract Safe_DivideBeforeMultiply {
    // SAFE: multiplication before division
    function calculate(uint256 supply, uint256 n, uint256 interest) external pure returns (uint256) {
        return (supply * interest) / n;
    }
}
