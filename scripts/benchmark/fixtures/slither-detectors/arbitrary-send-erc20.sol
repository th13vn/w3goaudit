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
// 2. ARBITRARY-SEND-ERC20 — transferFrom with user-controlled 'from'
// =============================================================================

// SHOULD TRIGGER: arbitrary-send-erc20
contract Vulnerable_ArbitrarySendERC20 {
    IERC20 public token;

    constructor(IERC20 _token) {
        token = _token;
    }

    // BAD: 'from' is user-controlled parameter, no auth
    function steal(address from, address to, uint256 amount) external {
        token.transferFrom(from, to, amount);
    }
}

// SHOULD NOT TRIGGER: arbitrary-send-erc20
contract Safe_ArbitrarySendERC20 {
    IERC20 public token;
    address public owner;

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    constructor(IERC20 _token) {
        token = _token;
        owner = msg.sender;
    }

    // SAFE: has onlyOwner modifier
    function adminTransfer(address from, address to, uint256 amount) external onlyOwner {
        token.transferFrom(from, to, amount);
    }

    // SAFE: uses msg.sender as from
    function deposit(uint256 amount) external {
        token.transferFrom(msg.sender, address(this), amount);
    }
}
