// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// SEC-BOOL-001 — Boolean Constant Misuse
// Vulnerable_* SHOULD fire; Safe_* SHOULD NOT.

contract Vulnerable_BooleanConstant {
    uint256 public x;

    // BAD: dead branch guarded by a boolean constant
    function deadBranch(uint256 val) external {
        if (false) {
            x = val;
        }
    }

    // BAD: branch is always taken
    function alwaysTaken(bool b) external pure returns (bool) {
        if (true) {
            return b;
        }
        return false;
    }
}

contract Safe_BooleanConstant {
    uint256 public x;

    // GOOD: a real, data-dependent condition
    function realCondition(uint256 val) external {
        if (val > 0) {
            x = val;
        }
    }
}
