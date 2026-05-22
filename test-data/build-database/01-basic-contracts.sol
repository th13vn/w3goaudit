// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title Test 01: Basic Contracts
 * @notice Tests basic contract types and function visibility
 */

// Interface - should be identified as interface
interface IToken {
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

// Library - should be identified as library
library MathLib {
    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        return a + b;
    }

    function mul(uint256 a, uint256 b) internal pure returns (uint256) {
        return a * b;
    }
}

// Abstract Contract - should NOT be main contract
abstract contract Ownable {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    function transferOwnership(address newOwner) public virtual onlyOwner {
        owner = newOwner;
    }
}

// Concrete Contract - should be MAIN contract
contract BasicToken is Ownable {
    mapping(address => uint256) public balances;
    uint256 public totalSupply;

    // External entry point (public/external)
    function mint(address to, uint256 amount) external onlyOwner {
        balances[to] += amount;
        totalSupply += amount;
    }

    // External entry point
    function transfer(address to, uint256 amount) external returns (bool) {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        balances[msg.sender] -= amount;
        balances[to] += amount;
        return true;
    }

    // View function (read-only)
    function balanceOf(address account) external view returns (uint256) {
        return balances[account];
    }

    // Pure function (no state access)
    function calculate(uint256 a, uint256 b) external pure returns (uint256) {
        return MathLib.add(a, b);
    }

    // Internal function (not entry point)
    function _beforeTransfer(address from, address to) internal virtual {
        // Hook
    }

    // Private function (not entry point)
    function _validate(uint256 amount) private pure returns (bool) {
        return amount > 0;
    }
}
