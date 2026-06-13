// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Exercises WQL feature: match.sequence (ordered descendants).
// Pattern: outgoing_call followed by state_write in the same function body.

// VULNERABLE: external call happens BEFORE the state update (reentrancy-shaped).
// Should be matched by feature-sequence.yaml.
contract VulnerableSequence {
    mapping(address => uint256) public balances;

    function withdraw(uint256 amount) external {
        (bool ok, ) = msg.sender.call{value: amount}(""); // outgoing_call
        require(ok, "transfer failed");
        balances[msg.sender] -= amount; // state_write AFTER the call
    }
}

// SAFE: state update happens BEFORE the external call (check-effects-interactions).
// Should NOT be matched (no outgoing_call -> state_write ordering).
contract SafeSequence {
    mapping(address => uint256) public balances;

    function withdraw(uint256 amount) external {
        balances[msg.sender] -= amount; // state_write BEFORE the call
        (bool ok, ) = msg.sender.call{value: amount}(""); // outgoing_call
        require(ok, "transfer failed");
    }
}
