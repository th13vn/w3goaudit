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
// `unchecked_var:` predicate must exclude it. SHOULD NOT FLAG.
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

// Guard-direction and enforcement matrix for semantic subtraction bounds.
// Only a fact that proves `balance >= amount` and remains valid on an
// effect-free path to the operation may clear the unchecked subtraction.
contract UncheckedSubtractionGuardMatrix {
    uint256 public balance = 100;

    event Seen();

    function mutateBalance() internal {
        balance = 0;
    }

    function mutateBalanceExternally() external {
        balance = 0;
    }

    function sink(uint256, uint256) internal pure {}

    function sinkExternally(uint256, uint256) external pure {}

    function mutateBalanceTrue() internal returns (bool) {
        balance = 0;
        return true;
    }

    function mutateBalanceFalse() internal returns (bool) {
        balance = 0;
        return false;
    }

    function effectfulMessage() internal returns (string memory) {
        balance = 0;
        return "bounded";
    }

    // VULNERABLE: the comparison proves the opposite of the required bound.
    function reversedRequire(uint256 amount) external returns (uint256) {
        require(balance <= amount, "reversed");
        unchecked {
            return balance - amount;
        }
    }

    // VULNERABLE: both names occur in ordering expressions, but no expression
    // relates the minuend to the subtrahend.
    function unrelatedOrdering(uint256 amount) external returns (uint256) {
        require(balance >= 1 && amount >= 1, "nonzero");
        unchecked {
            return balance - amount;
        }
    }

    // VULNERABLE: observing a safe condition in a non-terminating branch does
    // not constrain the later fallthrough subtraction.
    function nonTerminatingIf(uint256 amount) external {
        if (balance >= amount) {
            emit Seen();
        }
        unchecked {
            balance -= amount;
        }
    }

    // VULNERABLE: this exits on the safe condition, so fallthrough proves the
    // subtraction is unsafe rather than safe.
    function wrongFallthroughPolarity(uint256 amount) external {
        if (balance >= amount) revert();
        unchecked {
            balance -= amount;
        }
    }

    // VULNERABLE: a later write invalidates the earlier relation.
    function interveningWrite(uint256 amount) external {
        require(balance >= amount, "temporarily bounded");
        balance = 0;
        unchecked {
            balance -= amount;
        }
    }

    // VULNERABLE: the safe arm mutates the state-backed operand before the
    // subtraction, so the dominating condition no longer proves the bound.
    function dominatedArmInterveningWrite(uint256 amount) external {
        if (balance >= amount) {
            balance = 0;
            unchecked {
                balance -= amount;
            }
        }
    }

    // VULNERABLE: the else arm exits, but the surviving then arm invalidates
    // the condition before control falls through to the subtraction.
    function exitingElseSurvivingWrite(uint256 amount) external {
        if (balance >= amount) {
            balance = 0;
        } else {
            revert();
        }
        unchecked {
            balance -= amount;
        }
    }

    // VULNERABLE: an internal call may mutate the state-backed operand after
    // the condition was evaluated.
    function dominatedArmInternalCall(uint256 amount) external {
        if (balance >= amount) {
            mutateBalance();
            unchecked {
                balance -= amount;
            }
        }
    }

    // VULNERABLE: an external call may reenter or otherwise mutate the
    // state-backed operand after the condition was evaluated.
    function dominatedArmExternalCall(uint256 amount) external {
        if (balance >= amount) {
            this.mutateBalanceExternally();
            unchecked {
                balance -= amount;
            }
        }
    }

    // VULNERABLE: Solidity does not specify sibling argument evaluation order.
    // The assignment may invalidate the state-backed operand before subtraction.
    function dominatedArmEffectfulSibling(uint256 amount) external {
        if (balance >= amount) {
            unchecked {
                sink((balance = 0), balance - amount);
            }
        }
    }

    // VULNERABLE: the same effectful sibling invalidates an immediately
    // preceding require proof inside the subtraction's own statement.
    function requireEffectfulSibling(uint256 amount) external {
        require(balance >= amount, "temporarily bounded");
        unchecked {
            sink((balance = 0), balance - amount);
        }
    }

    // VULNERABLE: an external call ancestor with an effectful sibling also
    // fails closed because sibling evaluation order is unspecified.
    function dominatedArmExternalEffectfulSibling(uint256 amount) external {
        if (balance >= amount) {
            unchecked {
                this.sinkExternally((balance = 0), balance - amount);
            }
        }
    }

    // VULNERABLE: the bound appears in a true conjunction, but evaluating the
    // other conjunct mutates the state-backed operand before the subtraction.
    function requireEffectfulConjunctAfterBound(uint256 amount) external {
        require(balance >= amount && mutateBalanceTrue(), "bounded");
        unchecked {
            balance -= amount;
        }
    }

    // VULNERABLE: an effectful sibling makes the complete guard expression an
    // unsound source of a persistent bound, regardless of operand order.
    function requireEffectfulConjunctBeforeBound(uint256 amount) external {
        require(mutateBalanceTrue() && balance >= amount, "bounded");
        unchecked {
            balance -= amount;
        }
    }

    // VULNERABLE: evaluating an additional require argument may invalidate the
    // state-backed operand after the condition was computed.
    function requireEffectfulMessage(uint256 amount) external {
        require(balance >= amount, effectfulMessage());
        unchecked {
            balance -= amount;
        }
    }

    // VULNERABLE: the safe comparison does not dominate the subtraction once
    // another condition operand mutates balance on the same path.
    function dominatedArmEffectfulCondition(uint256 amount) external {
        if (balance >= amount && mutateBalanceTrue()) {
            unchecked {
                balance -= amount;
            }
        }
    }

    // VULNERABLE: false fallthrough from the disjunction evaluates an
    // effectful operand after the comparison that otherwise implied the bound.
    function exitingDisjunctionEffectfulCondition(uint256 amount) external {
        if (balance < amount || mutateBalanceFalse()) revert();
        unchecked {
            balance -= amount;
        }
    }

    function safeRequire(uint256 amount) external {
        require(balance >= amount, "bounded");
        unchecked {
            balance -= amount;
        }
    }

    function safeSwappedRequire(uint256 amount) external {
        require(amount <= balance, "bounded");
        unchecked {
            balance -= amount;
        }
    }

    function safeAssert(uint256 amount) external {
        assert(balance >= amount);
        unchecked {
            balance -= amount;
        }
    }

    // SAFE: every conjunct is structurally pure, so the exact bound remains a
    // valid fact after require succeeds.
    function safeRequirePureConjunct(uint256 amount) external {
        require(balance >= amount && amount > 0, "bounded");
        unchecked {
            balance -= amount;
        }
    }

    function safeExitingUnsafeArm(uint256 amount) external {
        if (amount > balance) revert();
        unchecked {
            balance -= amount;
        }
    }

    // SAFE: the subtraction is the first executable operation in the safe arm,
    // reached only through transparent block and unchecked wrappers.
    function safeDominatedArm(uint256 amount) external {
        if (balance >= amount) {
            unchecked {
                balance -= amount;
            }
        }
    }

    // SAFE: the binary subtraction is the only expression evaluated by the
    // return statement after the dominating bound.
    function safeDominatedBinaryReturn(uint256 amount) external returns (uint256) {
        if (balance >= amount) {
            unchecked {
                return balance - amount;
            }
        }
        return balance;
    }

    // SAFE: the binary subtraction is the only expression evaluated by the
    // return statement after the immediately preceding bound.
    function safeRequireBinaryReturn(uint256 amount) external returns (uint256) {
        require(balance >= amount, "bounded");
        unchecked {
            return balance - amount;
        }
    }
}

contract SignedSubtractionGuardMatrix {
    int256 public balance;

    // VULNERABLE: `balance >= amount` prevents an unsigned-style underflow but
    // does not prove signed subtraction cannot overflow its upper bound.
    function signedRangeOnly(int256 amount) external {
        require(balance >= amount, "one-sided");
        unchecked {
            balance -= amount;
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
