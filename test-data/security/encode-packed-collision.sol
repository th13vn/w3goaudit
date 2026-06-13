// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// SEC-HASH-001 — abi.encodePacked collision with multiple dynamic arguments
// Vulnerable_* SHOULD fire; Safe_* SHOULD NOT.

contract Vulnerable_EncodePackedCollision {
    // BAD: two dynamic args packed without delimiters -> colliding digests
    function digest(string memory a, string memory b) external pure returns (bytes32) {
        return keccak256(abi.encodePacked(a, b));
    }
}

contract Safe_EncodePackedCollision {
    // GOOD: abi.encode is length-prefixed, no collision
    function digest(string memory a, string memory b) external pure returns (bytes32) {
        return keccak256(abi.encode(a, b));
    }

    // GOOD: a single dynamic argument cannot collide
    function digestOne(bytes memory a) external pure returns (bytes32) {
        return keccak256(abi.encodePacked(a));
    }
}
