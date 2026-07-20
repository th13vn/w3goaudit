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
// 15. UNCHECKED-SEND — send() return not checked
// =============================================================================

// SHOULD TRIGGER: unchecked-send
contract Vulnerable_UncheckedSend {
    // BAD: send return value ignored
    function pay(address payable to, uint256 amount) external {
        to.send(amount); // return value not checked!
    }
}

// SHOULD NOT TRIGGER: unchecked-send
contract Safe_UncheckedSend {
    // SAFE: return value checked
    function pay(address payable to, uint256 amount) external {
        require(to.send(amount), "Send failed");
    }
}
