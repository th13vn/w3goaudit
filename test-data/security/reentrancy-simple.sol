// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title Simplified Reentrancy Test Cases
 * @notice Minimal test cases to verify reentrancy detection engine enhancements
 */

// ============================================================================
// CASE 1: Direct External Call (VULNERABLE)
// ============================================================================
contract DirectCall {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    // VULNERABLE: External call BEFORE state update
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");

        // External call FIRST
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        // State change AFTER (VULNERABLE!)
        balances[msg.sender] -= amount;
    }
}

// ============================================================================
// CASE 2: Recursive - External Call in Internal Function (VULNERABLE)
// ============================================================================
contract RecursiveCall {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    // VULNERABLE: Calls internal function that makes external call
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");

        // Internal call that contains external call
        _sendETH(msg.sender, amount);

        // State change AFTER (VULNERABLE via call graph!)
        balances[msg.sender] -= amount;
    }

    // Internal function with external call
    function _sendETH(address to, uint256 amount) internal {
        (bool success, ) = payable(to).call{value: amount}("");
        require(success, "Transfer failed");
    }
}

// ============================================================================
// CASE 3: Nested in Block (VULNERABLE)
// ============================================================================
contract NestedBlock {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    // VULNERABLE: External call nested in if-block
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");

        // External call in nested block
        if (amount > 0) {
            (bool success, ) = msg.sender.call{value: amount}("");
            require(success, "Transfer failed");
        }

        // State change AFTER the block (VULNERABLE!)
        balances[msg.sender] -= amount;
    }
}

// ============================================================================
// CASE 4: Safe - Check-Effects-Interactions Pattern (SAFE)
// ============================================================================
contract SafeCEI {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    // SAFE: State updated BEFORE external call
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");

        // State change FIRST (Effects)
        balances[msg.sender] -= amount;

        // External call AFTER (Interactions)
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
    }
}

// ============================================================================
// CASE 5: Safe - ReentrancyGuard Protected (SAFE)
// ============================================================================
contract SafeGuarded {
    mapping(address => uint256) public balances;
    bool private locked;

    modifier nonReentrant() {
        require(!locked, "ReentrancyGuard: reentrant call");
        locked = true;
        _;
        locked = false;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    // SAFE: Protected by nonReentrant modifier
    function withdraw(uint256 amount) external nonReentrant {
        require(balances[msg.sender] >= amount, "Insufficient balance");

        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        balances[msg.sender] -= amount;
    }
}

// ============================================================================
// CASE 6: Deep Recursive - Multiple Levels (VULNERABLE)
// ============================================================================
contract DeepRecursive {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    // VULNERABLE: External call 3 levels deep
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");

        // Level 1: Call internal
        _processWithdrawal(msg.sender, amount);

        // State change AFTER (VULNERABLE via deep call chain!)
        balances[msg.sender] -= amount;
    }

    function _processWithdrawal(address to, uint256 amount) internal {
        // Level 2: Call another internal
        _executeTransfer(to, amount);
    }

    function _executeTransfer(address to, uint256 amount) internal {
        // Level 3: Finally make external call
        (bool success, ) = payable(to).call{value: amount}("");
        require(success, "Transfer failed");
    }
}
