// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Sibling of pkg-a/tx-origin.sol: same basename, same contract name, different
// directory. Used to verify the engine keeps the full path on each finding so
// the basename collision does not merge the two. See
// TestFindingLocationsUseExactFunctionIDSourceFile.
contract Vulnerable_TxOrigin {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    // BAD: tx.origin used for authorization.
    function withdraw() external {
        require(tx.origin == owner, "Not owner");
        payable(msg.sender).transfer(address(this).balance);
    }
}
