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
// 23. COSTLY-LOOP — State variable update inside loop
// =============================================================================

// SHOULD TRIGGER: costly-loop
contract Vulnerable_CostlyLoop {
    uint256 public totalBalance;
    mapping(address => uint256) public balances;

    // BAD: state variable updated in every loop iteration (expensive SSTORE)
    function updateBalances(address[] calldata users, uint256[] calldata amounts) external {
        for (uint256 i = 0; i < users.length; i++) {
            balances[users[i]] = amounts[i];
            totalBalance += amounts[i]; // SSTORE in each iteration!
        }
    }
}

// SHOULD NOT TRIGGER: costly-loop
contract Safe_CostlyLoop {
    uint256 public totalBalance;
    mapping(address => uint256) public balances;

    // SAFE: accumulate in memory, single state write after loop
    function updateBalances(address[] calldata users, uint256[] calldata amounts) external {
        uint256 tempTotal = 0;
        for (uint256 i = 0; i < users.length; i++) {
            balances[users[i]] = amounts[i];
            tempTotal += amounts[i]; // memory variable
        }
        totalBalance += tempTotal; // single SSTORE
    }
}
