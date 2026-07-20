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
// 9. WEAK-PRNG — Block variables used for randomness
// =============================================================================

// SHOULD TRIGGER: weak-prng
contract Vulnerable_WeakPRNG {
    // BAD: block.timestamp used with modulo for randomness
    function random() external view returns (uint256) {
        return uint256(keccak256(abi.encodePacked(block.timestamp))) % 100;
    }

    // BAD: block.number used for randomness
    function random2() external view returns (uint256) {
        return block.number % 10;
    }
}

// SHOULD NOT TRIGGER: weak-prng
contract Safe_WeakPRNG {
    uint256 private seed;

    // SAFE: no modulo on block variables
    function getTimestamp() external view returns (uint256) {
        return block.timestamp; // just reading, not using for randomness
    }
}
