// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IBoundaryTarget {
    function ping(bytes calldata data) external returns (bool);
}

contract BoundaryChild {
    constructor(uint256 value) payable {
        value;
    }
}

contract ExternalBoundaryMatrix {
    mapping(uint256 => address payable) public savedTargets;

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

    function _helper(address payable target, bytes calldata data) internal {
        (bool ok, ) = target.call(data);
        require(ok, "helper failed");
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
}
