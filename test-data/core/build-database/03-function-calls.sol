// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title Test 03: Function Calls
 * @notice Tests different types of function calls and call graph building
 */

library MathLib {
    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        return a + b;
    }
}

interface IVault {
    function deposit(uint256 amount) external;
    function withdraw(uint256 amount) external;
}

contract CallTest {
    IVault public vault;
    address public owner;

    constructor(address _vault) {
        vault = IVault(_vault);
        owner = msg.sender;
    }

    // Entry point -> calls internal functions
    function processDeposit(uint256 amount) external {
        _validateAmount(amount);
        _transferToVault(amount);
        _updateState(amount);
    }

    // Internal call chain
    function _validateAmount(uint256 amount) internal pure {
        require(amount > 0, "Invalid amount");
    }

    // External call via interface
    function _transferToVault(uint256 amount) internal {
        vault.deposit(amount); // External call
    }

    // Library call
    function _updateState(uint256 amount) internal {
        uint256 newBalance = MathLib.add(amount, 100); // Library call
        // Update state
    }

    // Low-level call
    function callContract(
        address target,
        bytes memory data
    ) external returns (bool) {
        (bool success, ) = target.call(data); // Low-level call
        return success;
    }

    // Delegate call
    function delegateToLogic(
        address logic,
        bytes memory data
    ) external returns (bool) {
        (bool success, ) = logic.delegatecall(data); // Delegatecall
        return success;
    }

    // Static call
    function readContract(
        address target,
        bytes memory data
    ) external view returns (bytes memory) {
        (bool success, bytes memory result) = target.staticcall(data); // Staticcall
        require(success, "Static call failed");
        return result;
    }

    // Self-call (external)
    function selfCall(uint256 amount) external {
        this.processDeposit(amount); // External call to self
    }

    // Payable function
    function receiveEther() external payable {
        // Can receive ETH
    }
}
