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
// 7. DELEGATECALL-LOOP — delegatecall inside a loop
// =============================================================================

// SHOULD TRIGGER: delegatecall-loop
contract Vulnerable_DelegatecallLoop {
    // BAD: delegatecall in loop
    function multicall(address target, bytes[] calldata data) external {
        for (uint256 i = 0; i < data.length; i++) {
            (bool success, ) = target.delegatecall(data[i]);
            require(success, "Failed");
        }
    }
}

// SHOULD NOT TRIGGER: delegatecall-loop
contract Safe_DelegatecallLoop {
    // SAFE: regular call in loop instead of delegatecall
    function multicall(address target, bytes[] calldata data) external {
        for (uint256 i = 0; i < data.length; i++) {
            (bool success, ) = target.call(data[i]);
            require(success, "Failed");
        }
    }
}
