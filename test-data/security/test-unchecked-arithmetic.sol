// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Tests SEC-MATH-001: arithmetic inside unchecked blocks.

contract Vulnerable_UncheckedArithmetic {
    mapping(address => uint256) public balances;

    function credit(address user, uint256 amount) external {
        unchecked {
            balances[user] = balances[user] + amount;
        }
    }
}

contract Safe_CheckedArithmetic {
    mapping(address => uint256) public balances;

    function credit(address user, uint256 amount) external {
        balances[user] = balances[user] + amount;
    }
}

contract Safe_BoundedUncheckedArithmetic {
    mapping(address => uint256) public balances;

    function incrementSmall(address user, uint256 amount) external {
        require(amount <= 100, "amount too large");
        unchecked {
            // Intentional gas optimization after a tight explicit bound.
            balances[user] = balances[user] + amount;
        }
    }
}
