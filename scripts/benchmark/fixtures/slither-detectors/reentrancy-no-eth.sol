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
// 13. REENTRANCY-NO-ETH — External call before state write (no ETH)
// =============================================================================

// SHOULD TRIGGER: reentrancy-no-eth
contract Vulnerable_ReentrancyNoEth {
    IERC20 public token;
    mapping(address => bool) public claimed;

    constructor(IERC20 _token) {
        token = _token;
    }

    // BAD: external call before state update, no guard
    function claim() external {
        require(!claimed[msg.sender], "Already claimed");
        token.transfer(msg.sender, 100e18); // external call
        claimed[msg.sender] = true; // state write after call
    }
}

// SHOULD NOT TRIGGER: reentrancy-no-eth
contract Safe_ReentrancyNoEth {
    IERC20 public token;
    mapping(address => bool) public claimed;

    constructor(IERC20 _token) {
        token = _token;
    }

    // SAFE: state written before external call (CEI)
    function claim() external {
        require(!claimed[msg.sender], "Already claimed");
        claimed[msg.sender] = true; // state write BEFORE call
        token.transfer(msg.sender, 100e18);
    }
}
