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

// Full guard: a require that references BOTH operands of the subtraction
// (`bal >= amount`) makes the unchecked op deliberately range-checked — the
// OpenZeppelin SafeERC20.safeDecreaseAllowance / SafeMath.sub pattern. The
// `unguarded:` predicate must exclude it. SHOULD NOT FLAG.
contract Safe_GuardedUncheckedSub {
    mapping(address => uint256) public balances;

    function withdrawAll(address user, uint256 amount) external {
        unchecked {
            uint256 bal = balances[user];
            require(bal >= amount, "insufficient");
            balances[user] = bal - amount;
        }
    }
}

// Non-ordering guard: `require(bal != amount)` references both operands but does
// NOT bound the subtraction (bal can still be < amount → underflow). The
// `unchecked_var:` predicate requires an ordering comparison (<,<=,>,>=), so
// this is correctly STILL FLAGGED.
contract Vulnerable_NonOrderingGuard {
    mapping(address => uint256) public balances;

    function pay(address user, uint256 amount) external {
        uint256 bal = balances[user];
        require(bal != amount, "equal");
        unchecked {
            balances[user] = bal - amount;
        }
    }
}

// Pure library math (mirrors OpenZeppelin SafeMath/Math). Overflow here cannot
// corrupt persistent state, so the detector excludes pure/view functions.
// SHOULD NOT FLAG any function in this contract.
library Safe_PureMathLibrary {
    function tryAdd(uint256 a, uint256 b) internal pure returns (bool, uint256) {
        unchecked {
            uint256 c = a + b;
            if (c < a) return (false, 0);
            return (true, c);
        }
    }

    function average(uint256 a, uint256 b) internal pure returns (uint256) {
        unchecked {
            return (a / 2) + (b / 2);
        }
    }

    function stringLen(uint256 value) internal pure returns (uint256 length) {
        unchecked {
            length = value + 1;
        }
    }
}
