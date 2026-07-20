// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract AccessPaths {
    struct Inner {
        uint256 amount;
    }

    struct Request {
        address target;
        bytes payload;
        Inner inner;
    }

    Request private stored;
    uint256[] private values;
    mapping(address => uint256) private balances;

    function pair() internal pure returns (uint256, uint256) {
        return (1, 2);
    }

    function triple() internal pure returns (uint256, uint256, uint256) {
        return (1, 2, 3);
    }

    function sink(address, bytes memory) internal pure {}

    function localShadow(
        uint256[] memory data,
        uint256 outerIndex,
        uint256 innerIndex
    ) external pure returns (uint256 total) {
        uint256 x = outerIndex;
        total = data[x];
        {
            uint256 x = innerIndex;
            total += data[x];
        }
        total += data[x];
    }

    function singleLaneHoles() external pure returns (uint256 a, uint256 b, uint256 c) {
        (a, , ) = triple();
        (, b, ) = triple();
        (, , c) = triple();
        (, b) = (a, c);
    }

    function run(
        Request calldata request,
        uint256 i,
        uint256 j,
        address who
    ) external {
        stored.target = request.target;
        stored.payload = request.payload;
        stored.inner.amount = request.inner.amount;

        (uint256 first, uint256 second) = pair();
        (second, first) = pair();
        (first, second) = (second, first);
        (first, , second) = (second, 0, first);

        values[3] = first;
        values[i] = second;
        values[i] = first;
        values[j] = first;
        balances[who] = values[i];

        sink(address(request.target), bytes(request.payload));
        delete balances[who];
        values[i]++;
        --values[j];

        assembly {
            let shadow := i
            {
                let shadow := j
                sstore(shadow, 1)
            }
            sstore(shadow, 2)
            sstore(5, i)
            let loaded := sload(5)
            let other := sload(6)
            mstore(0x40, loaded)
            mstore8(0x60, 1)
            let memoryValue := mload(0x40)
            calldatacopy(0x80, 0, 32)
            pop(add(memoryValue, other))
        }
    }
}
