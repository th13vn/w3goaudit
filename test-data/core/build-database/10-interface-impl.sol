// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IToken {
    function transfer(address to, uint256 amount) external returns (bool);
}

contract Token is IToken {
    mapping(address => uint256) balances;
    function transfer(address to, uint256 amount) external returns (bool) {
        balances[to] += amount;
        return true;
    }
}
