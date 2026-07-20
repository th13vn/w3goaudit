// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Focused end-to-end fixtures for canonical tainted: user_controlled detector
// templates. CallerIdentity* cases require the sender branch; Parameter* cases
// prove the original parameter branch remains live. Same-named state/local/
// external/nonzero-call shapes must retain ordinary provenance. Fixed targets
// stay safe for taint-dependent sinks, while any unauthenticated selfdestruct
// remains vulnerable regardless of beneficiary provenance.

contract CallerIdentityDelegatecall {
    function execute() external {
        bytes memory payload = abi.encode(msg.sender);
        (bool ok, ) = msg.sender.delegatecall(payload);
        require(ok, "delegatecall failed");
    }
}

contract ParameterDelegatecall {
    function execute(address target, bytes calldata payload) external {
        (bool ok, ) = target.delegatecall(payload);
        require(ok, "delegatecall failed");
    }
}

abstract contract CallerIdentityContext {
    function _msgSender() internal view returns (address) {
        return msg.sender;
    }
}

contract InternalHelperDelegatecall is CallerIdentityContext {
    function execute(bytes calldata payload) external {
        (bool ok, ) = _msgSender().delegatecall(payload);
        require(ok, "delegatecall failed");
    }
}

interface ICallerIdentityOracle {
    function _msgSender() external returns (address);
}

contract ExternalMsgSenderDelegatecall {
    ICallerIdentityOracle public oracle;

    constructor(ICallerIdentityOracle oracle_) {
        oracle = oracle_;
    }

    function execute(bytes calldata payload) external {
        (bool ok, ) = oracle._msgSender().delegatecall(payload);
        require(ok, "delegatecall failed");
    }
}

contract StateNamedMsgSenderDelegatecall {
    address public _msgSender;

    constructor(address target) {
        _msgSender = target;
    }

    function execute(bytes calldata payload) external {
        (bool ok, ) = _msgSender.delegatecall(payload);
        require(ok, "delegatecall failed");
    }
}

contract LocalNamedMsgSenderDelegatecall {
    address public implementation;

    constructor(address target) {
        implementation = target;
    }

    function execute(bytes calldata payload) external {
        address _msgSender = implementation;
        (bool ok, ) = _msgSender.delegatecall(payload);
        require(ok, "delegatecall failed");
    }
}

contract NonzeroMsgSenderDelegatecall {
    address public implementation;

    constructor(address target) {
        implementation = target;
    }

    function _msgSender(address candidate) internal pure returns (address) {
        return candidate;
    }

    function execute(bytes calldata payload) external {
        (bool ok, ) = _msgSender(implementation).delegatecall(payload);
        require(ok, "delegatecall failed");
    }
}

contract ParameterNamedMsgSenderDelegatecall {
    function execute(address _msgSender, bytes calldata payload) external {
        (bool ok, ) = _msgSender.delegatecall(payload);
        require(ok, "delegatecall failed");
    }
}

contract FixedTargetDelegatecall {
    address public implementation;

    constructor(address target) {
        implementation = target;
    }

    function execute(bytes calldata payload) external {
        (bool ok, ) = implementation.delegatecall(payload);
        require(ok, "delegatecall failed");
    }
}

contract AccessControlledDelegatecall {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function execute() external onlyOwner {
        bytes memory payload = abi.encode(msg.sender);
        (bool ok, ) = msg.sender.delegatecall(payload);
        require(ok, "delegatecall failed");
    }
}

contract CallerIdentityLowLevelCall {
    function execute() external {
        bytes memory payload = abi.encode(msg.sender);
        (bool ok, ) = msg.sender.call(payload);
        require(ok, "call failed");
    }
}

contract ParameterLowLevelCall {
    function execute(address target, bytes calldata payload) external {
        (bool ok, ) = target.call(payload);
        require(ok, "call failed");
    }
}

contract FixedTargetLowLevelCall {
    address public target;

    constructor(address fixedTarget) {
        target = fixedTarget;
    }

    function execute(bytes calldata payload) external {
        (bool ok, ) = target.call(payload);
        require(ok, "call failed");
    }
}

contract AccessControlledLowLevelCall {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function execute() external onlyOwner {
        bytes memory payload = abi.encode(msg.sender);
        (bool ok, ) = msg.sender.call(payload);
        require(ok, "call failed");
    }
}

contract CallerIdentityTransferOwnership {
    address public owner;

    function transferOwnership() external {
        owner = msg.sender;
    }
}

contract ParameterTransferOwnership {
    address public owner;

    function transferOwnership(address newOwner) external {
        owner = newOwner;
    }
}

contract FixedTargetTransferOwnership {
    address public owner;
    address public pendingOwner;

    function transferOwnership() external {
        owner = pendingOwner;
    }
}

contract AccessControlledTransferOwnership {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function transferOwnership() external onlyOwner {
        owner = msg.sender;
    }
}

contract CallerIdentitySelfdestruct {
    function destroy() external {
        selfdestruct(payable(msg.sender));
    }
}

contract ParameterSelfdestruct {
    function destroy(address payable beneficiary) external {
        selfdestruct(beneficiary);
    }
}

contract FixedTargetSelfdestruct {
    address payable public beneficiary;

    constructor(address payable fixedBeneficiary) {
        beneficiary = fixedBeneficiary;
    }

    function destroy() external {
        selfdestruct(beneficiary);
    }
}

contract AccessControlledSelfdestruct {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function destroy() external onlyOwner {
        selfdestruct(payable(msg.sender));
    }
}

contract ExactInternalMsgSenderGuard is CallerIdentityContext {
    address public owner;

    function guard() external {
        require(owner == _msgSender(), "not owner");
    }
}

contract ExternalMsgSenderGuard {
    address public owner;
    ICallerIdentityOracle public oracle;

    constructor(ICallerIdentityOracle oracle_) {
        oracle = oracle_;
    }

    function guard() external {
        require(owner == oracle._msgSender(), "not owner");
    }
}

contract StateNamedMsgSenderGuard {
    address public owner;
    address public _msgSender;

    function guard() external view {
        require(owner == _msgSender, "not owner");
    }
}

contract LocalNamedMsgSenderGuard {
    address public owner;

    function guard() external view {
        address _msgSender = address(0xBEEF);
        require(owner == _msgSender, "not owner");
    }
}

contract ParameterNamedMsgSenderGuard {
    address public owner;

    function guard(address _msgSender) external view {
        require(owner == _msgSender, "not owner");
    }
}

contract NonzeroMsgSenderGuard {
    address public owner;

    function _msgSender(address candidate) internal pure returns (address) {
        return candidate;
    }

    function guard(address candidate) external view {
        require(owner == _msgSender(candidate), "not owner");
    }
}

interface ICallerIdentityToken {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

contract RetainedParameterTransferFrom {
    ICallerIdentityToken public token;

    constructor(ICallerIdentityToken token_) {
        token = token_;
    }

    function pullParameter(address from, address to, uint256 amount) external {
        token.transferFrom(from, to, amount);
    }

    function pullCallerIdentity(address to, uint256 amount) external {
        token.transferFrom(msg.sender, to, amount);
    }

    function pullParameterNamedMsgSender(address _msgSender, address to, uint256 amount) external {
        token.transferFrom(_msgSender, to, amount);
    }
}

contract RetainedParameterSendETH {
    function sendParameter(address payable recipient) external {
        recipient.transfer(1 wei);
    }

    function sendCallerIdentity() external {
        payable(msg.sender).transfer(1 wei);
    }
}
