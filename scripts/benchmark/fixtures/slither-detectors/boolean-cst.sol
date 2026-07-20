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
// 19. BOOLEAN-CST — Boolean constant misuse
// =============================================================================

// SHOULD TRIGGER: boolean-cst
contract Vulnerable_BooleanCst {
    uint256 public x;

    // BAD: boolean constant in condition — dead code
    function badFunc(uint256 val) external {
        if (false) {
            x = val; // dead code
        }
    }

    // BAD: boolean constant makes expression always true
    function alwaysTrue(bool b) external pure returns (bool) {
        if (true) {
            return b;
        }
        return false;
    }
}

// SHOULD NOT TRIGGER: boolean-cst
contract Safe_BooleanCst {
    uint256 public x;

    // SAFE: real condition
    function goodFunc(uint256 val) external {
        if (val > 0) {
            x = val;
        }
    }
}
