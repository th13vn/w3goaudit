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
// 3. CONTROLLED-DELEGATECALL — delegatecall with user-controlled target
// =============================================================================

// SHOULD TRIGGER: controlled-delegatecall
contract Vulnerable_ControlledDelegatecall {
    // BAD: delegatecall target from parameter
    function execute(address target, bytes calldata data) external {
        (bool success, ) = target.delegatecall(data);
        require(success, "Delegatecall failed");
    }
}

// SHOULD NOT TRIGGER: controlled-delegatecall
contract Safe_ControlledDelegatecall {
    address public immutable implementation;

    constructor(address _impl) {
        implementation = _impl;
    }

    // SAFE: delegatecall to fixed implementation, not parameter
    function execute(bytes calldata data) external {
        (bool success, ) = implementation.delegatecall(data);
        require(success, "Delegatecall failed");
    }
}
