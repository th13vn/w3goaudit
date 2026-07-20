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
// 20. CONSTANT-FUNCTION-STATE — view/pure function modifies state
// =============================================================================

// SHOULD TRIGGER: constant-function-state
contract Vulnerable_ConstantFunctionState {
    uint256 public counter;

    // BAD: declared view but modifies state (won't compile in >= 0.5 but
    // illustrates the pattern for pre-0.5 contracts)
    // Note: This won't actually compile in ^0.8.0 due to compiler enforcement.
    // For testing purposes, we use a workaround with assembly.
    function get() public view returns (uint256) {
        // Workaround: assembly bypasses view restriction
        assembly {
            sstore(0, add(sload(0), 1))
        }
        return counter;
    }
}

// SHOULD NOT TRIGGER: constant-function-state
contract Safe_ConstantFunctionState {
    uint256 public counter;

    // SAFE: view function only reads state
    function get() public view returns (uint256) {
        return counter;
    }

    // SAFE: non-view function modifies state
    function increment() public {
        counter += 1;
    }
}
