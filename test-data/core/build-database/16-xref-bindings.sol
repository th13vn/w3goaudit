// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Fixture for xref reference binding + identifier position backfill.
contract XrefBindings {
    error Unauthorized(address who);
    event Moved(address indexed to, uint256 amount);

    address public owner;
    mapping(address => uint256) public balances;

    function move(address to, uint256 amount) external {
        if (msg.sender != owner) revert Unauthorized(msg.sender);
        balances[to] = amount;
        owner.call("");
        emit Moved(to, amount);
    }
}
