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
// 4. SUICIDAL — Unprotected selfdestruct
// =============================================================================

// SHOULD TRIGGER: suicidal
contract Vulnerable_Suicidal {
    // BAD: anyone can destroy this contract
    function destroy() external {
        selfdestruct(payable(msg.sender));
    }
}

// SHOULD NOT TRIGGER: suicidal
contract Safe_Suicidal {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    // SAFE: only owner can destroy
    function destroy() external onlyOwner {
        selfdestruct(payable(owner));
    }
}
