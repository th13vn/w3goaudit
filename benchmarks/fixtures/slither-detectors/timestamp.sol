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
// 24. TIMESTAMP — block.timestamp used in comparison
// =============================================================================

// SHOULD TRIGGER: timestamp
contract Vulnerable_Timestamp {
    uint256 public unlockTime;

    constructor(uint256 _unlockTime) {
        unlockTime = _unlockTime;
    }

    // Detectable: block.timestamp in require condition
    function withdraw() external {
        require(block.timestamp >= unlockTime, "Too early");
        payable(msg.sender).transfer(address(this).balance);
    }
}

// SHOULD NOT TRIGGER: timestamp
contract Safe_Timestamp {
    // SAFE: block.timestamp not used in comparison
    function getTime() external view returns (uint256) {
        return block.number;
    }
}
