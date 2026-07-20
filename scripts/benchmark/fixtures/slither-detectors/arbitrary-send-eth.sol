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
// 5. ARBITRARY-SEND-ETH — ETH transfer without auth
// =============================================================================

// SHOULD TRIGGER: arbitrary-send-eth
contract Vulnerable_ArbitrarySendEth {
    // BAD: anyone can drain ETH
    function drain(address payable to) external {
        to.transfer(address(this).balance);
    }

    receive() external payable {}
}

// SHOULD NOT TRIGGER: arbitrary-send-eth
contract Safe_ArbitrarySendEth {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    // SAFE: restricted to owner
    function withdraw(address payable to) external onlyOwner {
        to.transfer(address(this).balance);
    }

    receive() external payable {}
}
