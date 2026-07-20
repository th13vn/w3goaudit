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
// 11. INCORRECT-EXP — ^ (XOR) instead of ** (exponentiation)
// =============================================================================

// SHOULD TRIGGER: incorrect-exp
contract Vulnerable_IncorrectExp {
    // BAD: ^ is XOR, not exponentiation; 2^8 = 10, not 256
    function power(uint256 base, uint256 exp) external pure returns (uint256) {
        return base ^ exp;
    }
}

// SHOULD NOT TRIGGER: incorrect-exp
contract Safe_IncorrectExp {
    // SAFE: using ** for exponentiation
    function power(uint256 base, uint256 exp) external pure returns (uint256) {
        return base ** exp;
    }
}
