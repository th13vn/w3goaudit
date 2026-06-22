// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Access-control detection fixtures.
//
// A caller-identity comparison (msg.sender / tx.origin / _msgSender) is access
// control ONLY when the other side is a value the caller cannot control:
// a state variable, a state-reading getter, a state mapping, an immutable, a
// constant, or a hardcoded literal address. Comparing against a function
// argument (or a value derived solely from arguments) is self-authorization,
// NOT a privileged access gate.
contract AccessControlChecks {
    address public owner;
    address public pendingOwner;
    address public immutable ADMIN;
    address internal constant TREASURY = 0x1234567890123456789012345678901234567890;
    mapping(address => bool) public isOperator;

    constructor(address admin) {
        owner = msg.sender;
        ADMIN = admin;
    }

    // ─── Access controlled: storage-anchored authority ───────────────────────

    // compare to a state variable
    function setOwnerState(address n) external {
        require(msg.sender == owner);
        owner = n;
    }

    // compare to a state variable (acceptOwnership / pendingOwner pattern)
    function acceptOwnership() external {
        require(msg.sender == pendingOwner);
        owner = pendingOwner;
    }

    // compare to an immutable
    function adminOnly() external {
        require(msg.sender == ADMIN);
    }

    // compare to a constant
    function treasuryOnly() external {
        require(msg.sender == TREASURY);
    }

    // hardcoded literal address baked into bytecode
    function hardcodedGate() external {
        require(msg.sender == 0xAbcdEF0123456789012345678901234567890123);
    }

    // state mapping lookup
    function operatorOnly() external {
        require(isOperator[msg.sender]);
    }

    // local aliased from state
    function localFromState() external {
        address o = owner;
        require(msg.sender == o);
    }

    // ─── NOT access controlled: caller-controlled comparison ──────────────────

    // compare to a function parameter (self-auth) — the false positive being fixed
    function selfAuthParam(address from, uint256 amt) external {
        require(from == msg.sender);
        owner = address(uint160(amt));
    }

    // parameter on the right-hand side
    function selfAuthParam2(address to) external {
        require(msg.sender == to);
    }

    // local aliased from a parameter
    function localFromParam(address who) external {
        address w = who;
        require(msg.sender == w);
    }

    // no caller check at all — permissionless
    function permissionless(uint256 x) external {
        owner = address(uint160(x));
    }
}
