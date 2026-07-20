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
// 6. MSG-VALUE-LOOP — msg.value used inside a loop
// =============================================================================

// SHOULD TRIGGER: msg-value-loop
contract Vulnerable_MsgValueLoop {
    mapping(address => uint256) public balances;

    // BAD: msg.value reused in each iteration
    function batchDeposit(address[] calldata receivers) external payable {
        for (uint256 i = 0; i < receivers.length; i++) {
            balances[receivers[i]] += msg.value; // Same msg.value each iter!
        }
    }
}

// SHOULD NOT TRIGGER: msg-value-loop
contract Safe_MsgValueLoop {
    mapping(address => uint256) public balances;

    // SAFE: explicit amounts array, sum validated
    function batchDeposit(address[] calldata receivers, uint256[] calldata amounts) external payable {
        uint256 total = 0;
        for (uint256 i = 0; i < receivers.length; i++) {
            balances[receivers[i]] += amounts[i];
            total += amounts[i];
        }
        require(total == msg.value, "Amount mismatch");
    }
}
