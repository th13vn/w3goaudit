// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Canonical fixture for MEDIUM-BOOLEAN-CST (Boolean Constant Misuse).
//
// Functions in VulnerableBooleanCst SHOULD be flagged (genuine misuse).
// Functions in SafeBooleanUsage SHOULD NOT be flagged — they cover the exact
// false-positive shapes that the old recursive `if contains literal` rule hit
// in OpenZeppelin / real audit code (return values, assignment RHS, call args,
// while(true) loops).

contract VulnerableBooleanCst {
    bool flag;

    // 1. comparison `== true`  -> FLAG
    function cmpEqTrue(bool x) external pure returns (uint) {
        if (x == true) {
            return 1;
        }
        return 0;
    }

    // 2. comparison `!= false` -> FLAG
    function cmpNeqFalse(bool x) external pure returns (uint) {
        if (x != false) {
            return 1;
        }
        return 0;
    }

    // 3. logical `&& true`     -> FLAG
    function andTrue(bool a) external pure returns (uint) {
        if (a && true) {
            return 1;
        }
        return 0;
    }

    // 4. logical `|| false`    -> FLAG
    function orFalse(bool b) external pure returns (uint) {
        if (b || false) {
            return 1;
        }
        return 0;
    }

    // 5. constant if condition -> FLAG
    function constIfTrue() external pure returns (uint) {
        if (true) {
            return 1;
        }
        return 0;
    }

    // 6. constant if condition -> FLAG
    function constIfFalse() external pure returns (uint) {
        if (false) {
            return 1;
        }
        return 0;
    }

    // 7. constant ternary condition -> FLAG
    function ternaryConstCond() external pure returns (uint) {
        uint z = true ? 1 : 2;
        return z;
    }

    // 8. comparison in a return -> FLAG (misuse anywhere, like Slither)
    function cmpInReturn(bool s) external pure returns (bool) {
        return s == true;
    }

    // 9. comparison in an assignment -> FLAG
    function cmpInAssign(bool s) external pure returns (bool) {
        bool r = s == false;
        return r;
    }
}

contract SafeBooleanUsage {
    bool flag;
    bool known;
    mapping(uint => bool) known2;

    function sink(bool v) internal pure returns (bool) {
        return v;
    }

    // MonetrixVault.canKeeperBridge shape: `false` is a return value, not a
    // condition. NO FLAG.
    function returnFalseInBranch(address a) external pure returns (bool) {
        if (a == address(0)) return false;
        return true;
    }

    // MonetrixAccountant.notifyVaultSupply shape: `true` is an assignment RHS
    // inside the then-branch. NO FLAG.
    function assignInBranch() external {
        if (!known) {
            known = true;
        }
    }

    // _grantRole shape: plain returns in both arms. NO FLAG.
    function plainReturns(bool v) external pure returns (bool) {
        if (v) {
            return true;
        } else {
            return false;
        }
    }

    // boolean literals as plain assignments. NO FLAG.
    function assignBool() external {
        flag = true;
        flag = false;
    }

    // boolean literals as call arguments. NO FLAG.
    function callArg() external pure returns (bool) {
        return sink(true) && sink(false);
    }

    // legitimate infinite loop with break. NO FLAG (while(true) is idiomatic).
    function whileTrueLoop() external pure returns (uint) {
        uint i = 0;
        while (true) {
            i++;
            if (i > 3) break;
        }
        return i;
    }

    // real condition, no boolean constant. NO FLAG.
    function realCondition(bool a, bool b) external pure returns (uint) {
        if (a && b) {
            return 1;
        }
        return 0;
    }

    // mapping assignment. NO FLAG.
    function mappingAssign(uint k) external {
        known2[k] = true;
    }
}
