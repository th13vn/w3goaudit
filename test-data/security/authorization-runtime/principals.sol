// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract PrincipalMatrix {
    address owner;
    address counterparty;
    address immutable immutablePeer;
    bytes32 constant EXECUTOR_ROLE = keccak256("EXECUTOR_ROLE");
    mapping(bytes32 => mapping(address => bool)) members;
    uint256 value;

    constructor(address peer) { immutablePeer = peer; }

    modifier exactModifier() { require(msg.sender == owner); _; }
    modifier lateModifier() { _; require(msg.sender == owner); }
    modifier expectedPrincipal(address expected) { require(msg.sender == expected); _; }
    modifier fixedRole(bytes32 role) { require(members[role][msg.sender]); _; }

    function directOwner() external { require(msg.sender == owner); value = 1; }
    function exactRole() external { require(members[EXECUTOR_ROLE][msg.sender]); value = 2; }
    function fixedStatePrincipal() external { require(msg.sender == counterparty); value = 3; }
    function immutablePrincipal() external { require(msg.sender == immutablePeer); value = 4; }
    function literalPrincipal() external { require(msg.sender == address(0x1234)); value = 5; }
    function callerSelfScope(address selected) external { require(msg.sender == selected); value = 6; }
    function internalHelper() external { _checkOwner(); value = 7; }
    function _checkOwner() internal { require(msg.sender == owner); }
    function appliedModifier() external exactModifier { value = 8; }
    function wrongBranch(bool enabled) external { if (enabled) { require(msg.sender == owner); } value = 9; }
    function guardAfterOperation() external { value = 10; require(msg.sender == owner); }
    function modifierAfterOperation() external lateModifier { value = 11; }
    function modifierFixedPrincipal() external expectedPrincipal(counterparty) { value = 12; }
    function modifierSelectedPrincipal(address selected) external expectedPrincipal(selected) { value = 13; }
    function modifierFixedRole() external fixedRole(EXECUTOR_ROLE) { value = 14; }
    function modifierSelectedRole(bytes32 selectedRole) external fixedRole(selectedRole) { value = 15; }
    function helperForwardedCaller() external { _checkPrincipal(msg.sender, counterparty); value = 16; }
    function helperFixedPrincipal() external { _checkSender(counterparty); value = 17; }
    function helperSelectedPrincipal(address selected) external { _checkPrincipal(msg.sender, selected); value = 18; }
    function helperFixedRole() external { _checkRole(EXECUTOR_ROLE, msg.sender); value = 19; }
    function helperSelectedRole(bytes32 selectedRole) external { _checkRole(selectedRole, msg.sender); value = 20; }
    function helperOverloadAmbiguous(uint256 selected) external { _ambiguous(selected); value = 21; }
    function helperTrulyAmbiguous() external { _ambiguousPrincipal(1); value = 22; }

    function _checkPrincipal(address caller, address expected) internal { require(caller == expected); }
    function _checkSender(address expected) internal { require(msg.sender == expected); }
    function _checkRole(bytes32 role, address caller) internal { require(members[role][caller]); }
    function _ambiguous(address expected) internal { require(msg.sender == expected); }
    function _ambiguous(uint256 amount) internal pure { require(amount > 0); }
    function _ambiguousPrincipal(address expected) internal { require(msg.sender == expected); }
    function _ambiguousPrincipal(uint256 amount) internal pure { require(amount > 0); }
}
