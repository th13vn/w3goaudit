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
// 25. ASSERT-STATE-CHANGE — State change inside assert()
// =============================================================================

// SHOULD TRIGGER: assert-state-change
contract Vulnerable_AssertStateChange {
    uint256 public counter;
    mapping(address => uint256) public nonces;

    // BAD: state change inside assert — optimizer may remove it
    function processWithAssert(address user) external {
        assert(incrementNonce(user));
    }

    function incrementNonce(address user) internal returns (bool) {
        nonces[user] += 1;
        return true;
    }
}

// SHOULD NOT TRIGGER: assert-state-change
contract Safe_AssertStateChange {
    uint256 public counter;

    // SAFE: assert only checks invariant, no state change
    function process(uint256 x) external {
        counter += x;
        assert(counter >= x); // pure invariant check
    }
}
