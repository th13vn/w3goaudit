// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Vulnerable_TxOrigin is defined in TWO files that share the basename
// `tx-origin.sol` but live in different directories (pkg-a/ and pkg-b/).
// The engine must record each finding's full source path — not just the
// basename — so downstream consumers can tell the two apart. See
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
