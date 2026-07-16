// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Token {
    bool public destroyed;

    function danger() internal {
        destroyed = true;
        selfdestruct(payable(msg.sender));
    }

    modifier gate() {
        danger();
        _;
    }

    function run() external gate {
        danger();
    }
}
