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
// 14. UNCHECKED-LOWLEVEL — Low-level call return not checked
// =============================================================================

// SHOULD TRIGGER: unchecked-lowlevel
contract Vulnerable_UncheckedLowLevel {
    // BAD: low-level call return value ignored
    function sendEther(address payable to) external payable {
        to.call{value: msg.value}(""); // return value not checked!
    }
}

// SHOULD NOT TRIGGER: unchecked-lowlevel
contract Safe_UncheckedLowLevel {
    // SAFE: return value checked
    function sendEther(address payable to) external payable {
        (bool success, ) = to.call{value: msg.value}("");
        require(success, "Call failed");
    }
}
