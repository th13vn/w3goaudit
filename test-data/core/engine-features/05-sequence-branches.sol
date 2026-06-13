// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Exercises WQL feature: sequence operator control-flow awareness.
// `sequence: [outgoing_call, state_write]` must only match when the two
// operations can co-execute on a single path.

// MATCH: straight-line external call followed by a state write (real CEI
// violation). Should be matched by feature-sequence.yaml.
contract LinearSequence {
    mapping(address => uint256) public balances;

    function withdraw(uint256 amount) external {
        (bool ok, ) = msg.sender.call{value: amount}(""); // outgoing_call
        require(ok, "fail");
        balances[msg.sender] -= amount; // state_write — same path, after the call
    }
}

// NO MATCH: the external call and the state write live in mutually-exclusive
// arms of the same if/else, so they can never both execute. Before the
// execution-path fix this was a FALSE POSITIVE. Should NOT be matched.
contract BranchedExclusive {
    mapping(address => uint256) public balances;

    function withdraw(uint256 amount) external {
        if (amount > 0) {
            (bool ok, ) = msg.sender.call{value: amount}(""); // outgoing_call (THEN arm)
            require(ok, "fail");
        } else {
            balances[msg.sender] = amount; // state_write (ELSE arm) — never co-executes
        }
    }
}
