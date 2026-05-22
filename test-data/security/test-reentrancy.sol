// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title ReentrancyTests
 * @notice Test contracts for SEC-GEN-REENTRANCY: Reentrancy via CEI violation
 * @dev This file contains both VULNERABLE and SAFE patterns
 */

// ============================================================================
// VULNERABLE PATTERNS (Should be detected by w3goaudit)
// ============================================================================

/**
 * @notice VULNERABLE: State change AFTER external call
 * @dev Classic reentrancy vulnerability
 */
contract VulnerableBank1 {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    // VULNERABLE: State updated AFTER external call
    // Pattern: external_call -> assignment(state_var)
    // Should be detected by w3goaudit
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");

        // External call FIRST
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        // State change AFTER (VULNERABLE!)
        balances[msg.sender] -= amount;
    }
}

/**
 * @notice VULNERABLE: Multiple state changes after external call
 */
contract VulnerableBank2 {
    mapping(address => uint256) public balances;
    uint256 public totalWithdrawn;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    // VULNERABLE: Multiple state updates after call
    function withdrawAll() external {
        uint256 balance = balances[msg.sender];
        require(balance > 0, "No balance");

        // External call
        payable(msg.sender).transfer(balance);

        // State changes AFTER (VULNERABLE!)
        balances[msg.sender] = 0;
        totalWithdrawn += balance;
    }
}

/**
 * @notice VULNERABLE: Using send() with state change after
 */
contract VulnerableBank3 {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    // VULNERABLE: send() followed by state change
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");

        // External call using send
        bool success = payable(msg.sender).send(amount);
        require(success, "Send failed");

        // State change AFTER
        balances[msg.sender] -= amount;
    }
}

/**
 * @notice VULNERABLE: External contract call with state change after
 */
contract VulnerableVault {
    mapping(address => uint256) public shares;
    address public token;

    // VULNERABLE: External call to token contract, then state update
    function withdraw(uint256 amount) external {
        require(shares[msg.sender] >= amount, "Insufficient shares");

        // External call to transfer tokens
        (bool success, ) = token.call(
            abi.encodeWithSignature(
                "transfer(address,uint256)",
                msg.sender,
                amount
            )
        );
        require(success, "Transfer failed");

        // State change AFTER external call
        shares[msg.sender] -= amount;
    }
}

/**
 * @notice VULNERABLE: Callback pattern with state change after
 */
contract VulnerableAuction {
    mapping(address => uint256) public bids;
    address public highestBidder;
    uint256 public highestBid;

    // VULNERABLE: Callback with state update after
    function refund() external {
        uint256 refundAmount = bids[msg.sender];
        require(refundAmount > 0, "No refund available");

        // External call
        (bool success, ) = msg.sender.call{value: refundAmount}("");
        require(success, "Refund failed");

        // State change AFTER
        bids[msg.sender] = 0;
    }
}

// ============================================================================
// SAFE PATTERNS (Should NOT be detected by w3goaudit)
// ============================================================================

/**
 * @notice SAFE: Check-Effects-Interactions pattern (CEI)
 * @dev State updated BEFORE external call
 */
contract SafeBank1 {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    // SAFE: State updated BEFORE external call (CEI pattern)
    // Should NOT be detected
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");

        // State change FIRST
        balances[msg.sender] -= amount;

        // External call AFTER
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
    }
}

/**
 * @notice SAFE: Using ReentrancyGuard modifier
 */
contract SafeBank2 {
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
    // Should NOT be detected (has guard modifier)
    function withdraw(uint256 amount) external nonReentrant {
        require(balances[msg.sender] >= amount, "Insufficient balance");

        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        balances[msg.sender] -= amount;
    }
}

/**
 * @notice SAFE: Using OpenZeppelin's ReentrancyGuard
 */
contract SafeBank3 {
    mapping(address => uint256) public balances;
    uint256 private _status;

    // Simulating OpenZeppelin's nonReentrant
    modifier nonReentrant() {
        require(_status != 2, "ReentrancyGuard: reentrant call");
        _status = 2;
        _;
        _status = 1;
    }

    // SAFE: Has nonReentrant modifier
    function withdrawWithGuard(uint256 amount) external nonReentrant {
        require(balances[msg.sender] >= amount, "Insufficient balance");

        payable(msg.sender).transfer(amount);
        balances[msg.sender] -= amount;
    }
}

/**
 * @notice SAFE: View function (no state changes)
 */
contract SafeBank4 {
    mapping(address => uint256) public balances;

    // SAFE: View function, no state changes
    // Should NOT be detected
    function checkBalance(address account) external view returns (uint256) {
        return balances[account];
    }

    // SAFE: Pure function
    function calculateFee(uint256 amount) external pure returns (uint256) {
        return amount / 100;
    }
}

/**
 * @notice SAFE: Only reads state after external call
 */
contract SafeBank5 {
    mapping(address => uint256) public balances;

    // SAFE: No state WRITES after external call (only reads)
    function withdrawAndCheck(uint256 amount) external returns (uint256) {
        require(balances[msg.sender] >= amount, "Insufficient balance");

        // State write BEFORE
        balances[msg.sender] -= amount;

        // External call
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        // Only reading state AFTER (SAFE)
        return balances[msg.sender];
    }
}

/**
 * @notice SAFE: Pull payment pattern
 */
contract SafeBank6 {
    mapping(address => uint256) public pendingWithdrawals;

    // SAFE: Two-step process, user controls when to withdraw
    function initiateWithdrawal(uint256 amount) external {
        // State updated in separate function
        pendingWithdrawals[msg.sender] += amount;
    }

    function withdraw() external {
        uint256 amount = pendingWithdrawals[msg.sender];
        require(amount > 0, "No pending withdrawal");

        // State updated BEFORE external call
        pendingWithdrawals[msg.sender] = 0;

        payable(msg.sender).transfer(amount);
    }
}

// ============================================================================
// EDGE CASES
// ============================================================================

/**
 * @notice EDGE CASE: No external calls at all
 */
contract EdgeCaseBank1 {
    mapping(address => uint256) public balances;

    // Should NOT be detected (no external calls)
    function updateBalance(uint256 amount) external {
        balances[msg.sender] = amount;
    }
}

/**
 * @notice EDGE CASE: Internal transfers only
 */
contract EdgeCaseBank2 {
    mapping(address => uint256) public balances;

    // Should NOT be detected (internal transfer between state vars)
    function internalTransfer(address to, uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        balances[msg.sender] -= amount;
        balances[to] += amount;
    }
}

/**
 * @notice EDGE CASE: External call but no state changes
 */
contract EdgeCaseBank3 {
    // Should NOT be detected (external call but no state writes)
    function triggerCallback(address target) external {
        (bool success, ) = target.call("");
        require(success, "Callback failed");
    }
}
