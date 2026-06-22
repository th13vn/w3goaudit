// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// =============================================================================
// Test Contracts for Slither→WQL Template Verification
// Each Vulnerable_* contract SHOULD trigger its corresponding detector.
// Each Safe_* contract SHOULD NOT trigger the detector.
// =============================================================================

// Callback the Vulnerable_ReentrancyBalance contract invokes on msg.sender —
// the reentrancy primitive the detector is meant to flag. Declared here so
// the fragment is self-compilable (the original monolithic fixture had this
// interface co-located between the contract pairs; the splitter dropped it).
interface ICallback {
    function pay(uint256 amount) external;
}

// --- Interfaces used across tests ---
interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function approve(address spender, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

// =============================================================================
// 12. REENTRANCY-BALANCE — balanceOf before external call
// =============================================================================

// SHOULD TRIGGER: reentrancy-balance
contract Vulnerable_ReentrancyBalance {
    IERC20 public token;

    constructor(IERC20 _token) {
        token = _token;
    }

    // BAD: balance read before external call, no guard
    function mint(uint256 amountToPay) external {
        uint256 balanceBefore = token.balanceOf(address(this));
        // Attacker can reenter via this callback
        ICallback(msg.sender).pay(amountToPay);
        require(token.balanceOf(address(this)) - balanceBefore >= amountToPay, "Underpaid");
    }
}

// SHOULD NOT TRIGGER: reentrancy-balance
contract Safe_ReentrancyBalance {
    IERC20 public token;
    bool private locked;

    modifier nonReentrant() {
        require(!locked, "Locked");
        locked = true;
        _;
        locked = false;
    }

    constructor(IERC20 _token) {
        token = _token;
    }

    // SAFE: nonReentrant guard
    function mint(uint256 amountToPay) external nonReentrant {
        uint256 balanceBefore = token.balanceOf(address(this));
        ICallback(msg.sender).pay(amountToPay);
        require(token.balanceOf(address(this)) - balanceBefore >= amountToPay, "Underpaid");
    }
}
