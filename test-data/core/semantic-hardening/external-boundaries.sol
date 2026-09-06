// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IBoundaryTarget {
    function ping(bytes calldata data) external returns (bool);
}

library BoundaryLibrary {
    function forward(address target, bytes memory data) internal {
        (bool ok, ) = target.call(data);
        require(ok, "library failed");
    }
}

contract BoundaryChild {
    constructor(uint256 value) payable {
        value;
    }
}

contract ExternalBoundaryMatrix {
    mapping(uint256 => address payable) public savedTargets;
    uint256 public total;
    event Result(bool value);

    constructor(address target, bytes memory data) {
        target.call(data);
    }

    modifier boundaryCall(address target, bytes memory data) {
        (bool ok, ) = target.call(data);
        require(ok, "modifier call failed");
        _;
    }

    function callerControlled(
        address payable[] calldata targets,
        uint256 index,
        uint256 amount,
        bytes calldata data
    ) external {
        (bool ok, ) = targets[index].call{value: amount, gas: 100000}(data);
        require(ok, "call failed");
    }

    function stateDerived(uint256 index, bytes calldata data) external {
        (bool ok, ) = savedTargets[index].call(data);
        require(ok, "call failed");
    }

    function exactTarget(IBoundaryTarget target, bytes calldata data) external returns (bool) {
        return target.ping(data);
    }

    function lowLevelKinds(address target, bytes calldata data) external {
        (bool delegated, ) = target.delegatecall(data);
        (bool readOnly, ) = target.staticcall(data);
        require(delegated || readOnly, "both failed");
    }

    function etherKinds(address payable target, uint256 amount) external {
        target.transfer(amount);
        bool sent = target.send(amount);
        require(sent, "send failed");
    }

    function createKinds(uint256 value) external {
        new BoundaryChild{value: value}(value);
        new BoundaryChild(value);
    }

    function selfTarget(bytes calldata data) external returns (bool) {
        return this.exactTarget(IBoundaryTarget(address(this)), data);
    }

    function helperEntry(address payable target, bytes calldata data) external {
        _helper(target, data);
    }

    function modifierEntry(address target, bytes calldata data) external boundaryCall(target, data) {}

    function libraryEntry(address target, bytes calldata data) external {
        BoundaryLibrary.forward(target, data);
    }

    function _helper(address payable target, bytes calldata data) internal {
        (bool ok, ) = target.call(data);
        require(ok, "helper failed");
    }

    function _orphan(address target, bytes calldata data) internal {
        target.call(data);
    }

    function yulKinds(address target, uint256 amount) external {
        assembly {
            pop(call(gas(), target, amount, 0, 0, 0, 0))
            pop(delegatecall(gas(), target, 0, 0, 0, 0))
            pop(staticcall(gas(), target, 0, 0, 0, 0))
            pop(create(amount, 0, 0))
            pop(create2(amount, 0, 0, 0))
        }
    }

    function capturedChecked(address target, bytes calldata data) external {
        (bool ok, ) = target.call(data);
        require(ok, "checked");
    }

    function capturedUnchecked(address target, bytes calldata data) external {
        (bool looksChecked, ) = target.call(data);
        total = looksChecked ? 1 : 0;
    }

    function discarded(address target, bytes calldata data) external {
        target.call(data);
    }

    function returned(address target, bytes calldata data) external returns (bool, bytes memory) {
        return target.call(data);
    }

    function directCondition(address payable target, uint256 amount) external {
        require(target.send(amount), "direct");
    }

    function consumed(address payable target, uint256 amount) external {
        emit Result(target.send(amount));
    }

    function stateBefore(address target, bytes calldata data) external {
        total = 1;
        target.call(data);
    }

    function stateAfter(address target, bytes calldata data) external {
        target.call(data);
        total = 1;
    }

    function incompatible(address target, bytes calldata data, bool branch) external {
        if (branch) {
            target.call(data);
        } else {
            total = 1;
        }
    }

    function unordered(address payable target, uint256 amount) external {
        _consumePair(target.send(amount), total = 1);
    }

    function loopUnknown(address payable target, uint256 amount) external {
        for (uint256 i = 0; i < 1; i++) {
            target.send(amount);
            total = i;
        }
    }

    function _consumePair(bool sent, uint256 value) internal pure {
        sent;
        value;
    }
}

interface IERC20ResultMatrix {
    function transfer(address to, uint256 amount) external returns (bool);
}

contract ERC20ResultMatrix {
    IERC20ResultMatrix token;
    uint256 public total;

    function transferDiscarded(address to, uint256 amount) external {
        token.transfer(to, amount);
    }

    function transferCapturedUnchecked(address to, uint256 amount) external {
        bool ok = token.transfer(to, amount);
        total = ok ? 1 : 0;
    }

    function transferChecked(address to, uint256 amount) external {
        require(token.transfer(to, amount), "transfer failed");
    }
}
