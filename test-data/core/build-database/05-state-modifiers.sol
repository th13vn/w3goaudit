// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title Test 05: State and Modifiers
 * @notice Tests state mutability and function modifiers
 */

contract StateAndModifiers {
    uint256 public counter;
    address public owner;
    bool public locked;

    constructor() {
        owner = msg.sender;
    }

    // Modifiers
    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    modifier nonReentrant() {
        require(!locked, "Reentrancy");
        locked = true;
        _;
        locked = false;
    }

    modifier validAmount(uint256 amount) {
        require(amount > 0, "Invalid amount");
        _;
    }

    // State mutability: default (can modify state)
    function increment() external {
        counter++;
    }

    // State mutability: view (read-only)
    function getCounter() external view returns (uint256) {
        return counter;
    }

    // State mutability: pure (no state access)
    function calculate(uint256 a, uint256 b) external pure returns (uint256) {
        return a + b;
    }

    // State mutability: payable (can receive ETH)
    function deposit() external payable {
        counter += msg.value;
    }

    // Multiple modifiers
    function protectedIncrement(
        uint256 amount
    ) external onlyOwner nonReentrant validAmount(amount) {
        counter += amount;
    }

    // Override and virtual
    function hook() public virtual {
        // Can be overridden
    }
}

// Inheritance with override
contract ExtendedState is StateAndModifiers {
    // Override virtual function
    function hook() public override {
        counter += 10;
    }
}
