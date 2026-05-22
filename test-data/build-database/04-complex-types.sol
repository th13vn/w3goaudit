// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title Test 04: Complex Types
 * @notice Tests function signatures with complex parameter types
 */

contract ComplexTypes {
    // Simple struct
    struct User {
        address addr;
        uint256 balance;
    }

    // Nested struct
    struct Transaction {
        User from;
        User to;
        uint256 amount;
        uint256 timestamp;
    }

    // Struct with arrays
    struct Batch {
        address[] recipients;
        uint256[] amounts;
        bytes32 merkleRoot;
    }

    // Simple types
    function simpleParams(
        address addr,
        uint256 amount,
        bool flag
    ) external pure returns (bool) {
        return flag;
    }

    // Arrays
    function arrayParams(
        address[] memory addresses,
        uint256[] calldata amounts
    ) external pure returns (uint256) {
        return addresses.length + amounts.length;
    }

    // Fixed-size arrays
    function fixedArrays(
        uint256[5] memory numbers,
        bytes32[2] calldata hashes
    ) external pure returns (uint256) {
        return numbers[0];
    }

    // Struct params
    function structParam(User memory user) external pure returns (address) {
        return user.addr;
    }

    // Nested struct
    function nestedStruct(
        Transaction memory tx
    ) external pure returns (uint256) {
        return tx.amount;
    }

    // Struct with arrays
    function batchTransfer(Batch memory batch) external pure returns (uint256) {
        return batch.recipients.length;
    }

    // Mapping (storage only)
    mapping(address => User) public users;
    mapping(bytes32 => Transaction) public transactions;

    // Tuple returns
    function multiReturn() external pure returns (address, uint256, bool) {
        return (address(0), 0, false);
    }

    // Named returns
    function namedReturns()
        external
        pure
        returns (address user, uint256 balance, bool active)
    {
        user = address(0);
        balance = 0;
        active = false;
    }

    // Bytes types
    function bytesTypes(
        bytes memory data,
        bytes32 hash,
        string memory text
    ) external pure returns (uint256) {
        return data.length;
    }
}
