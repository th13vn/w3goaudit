// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Token {
    uint256 public safeCount;

    function helper() internal {
        safeCount++;
    }

    modifier gate() {
        helper();
        _;
    }

    function run() external gate {
        helper();
    }
}
