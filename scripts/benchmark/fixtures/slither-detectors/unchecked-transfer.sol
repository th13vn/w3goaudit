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
// 8. UNCHECKED-TRANSFER — ERC20 transfer return value not checked
// =============================================================================

// SHOULD TRIGGER: unchecked-transfer
contract Vulnerable_UncheckedTransfer {
    IERC20 public token;

    constructor(IERC20 _token) {
        token = _token;
    }

    // BAD: return value of transfer not checked
    function pay(address to, uint256 amount) external {
        token.transfer(to, amount); // return value ignored!
    }

    // BAD: return value of transferFrom not checked
    function collect(address from, uint256 amount) external {
        token.transferFrom(from, address(this), amount); // return value ignored!
    }
}

// SHOULD NOT TRIGGER: unchecked-transfer
contract Safe_UncheckedTransfer {
    IERC20 public token;

    constructor(IERC20 _token) {
        token = _token;
    }

    // SAFE: return value checked with require
    function pay(address to, uint256 amount) external {
        require(token.transfer(to, amount), "Transfer failed");
    }

    // SAFE: return value checked in if
    function collect(address from, uint256 amount) external {
        if (!token.transferFrom(from, address(this), amount)) {
            revert("TransferFrom failed");
        }
    }
}
