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
// 21. REENTRANCY-EVENTS — External call before event emission
// =============================================================================

// SHOULD TRIGGER: reentrancy-events
contract Vulnerable_ReentrancyEvents {
    event Withdrawal(address indexed user, uint256 amount);
    mapping(address => uint256) public balances;

    // BAD: event emitted AFTER external call — can be reordered via reentrancy
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient");
        balances[msg.sender] -= amount;
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Failed");
        emit Withdrawal(msg.sender, amount); // event AFTER call
    }
}

// SHOULD NOT TRIGGER: reentrancy-events
contract Safe_ReentrancyEvents {
    event Withdrawal(address indexed user, uint256 amount);
    mapping(address => uint256) public balances;
    bool private locked;

    modifier nonReentrant() {
        require(!locked, "Locked");
        locked = true;
        _;
        locked = false;
    }

    // SAFE: has nonReentrant guard
    function withdraw(uint256 amount) external nonReentrant {
        require(balances[msg.sender] >= amount, "Insufficient");
        balances[msg.sender] -= amount;
        emit Withdrawal(msg.sender, amount);
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Failed");
    }
}
