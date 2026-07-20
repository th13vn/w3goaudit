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
// 26. ASSEMBLY — Inline assembly usage
// =============================================================================

// SHOULD TRIGGER: assembly
contract Vulnerable_Assembly {
    // Has inline assembly
    function getBalance(address addr) external view returns (uint256 bal) {
        assembly {
            bal := balance(addr)
        }
    }
}

// SHOULD NOT TRIGGER: assembly
contract Safe_Assembly {
    // SAFE: no assembly
    function getBalance(address addr) external view returns (uint256) {
        return addr.balance;
    }
}
