// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Fixture for MEDIUM-BIDI-CHARACTERS (Trojan Source).
//
// WARNING TO READERS: the Vulnerable_ contract below contains REAL Unicode
// bidirectional control characters (U+202E RLO and U+202C PDF). They are
// invisible in most editors and deliberately make the rendered text disagree
// with what the compiler sees - that is exactly the property under test. Do
// not "clean up" this file; MEDIUM-BIDI-CHARACTERS asserts on their presence.

contract Vulnerable_BidiCharacters {
    address public owner;
    uint256 public balance;

    // The comment below carries an RLO/PDF pair, so the rendered text can
    // disagree with what the compiler actually sees.
    function withdraw(uint256 amount) external {
        // safe: only owner ‮ reviewed ‬
        balance -= amount;
    }
}

contract Safe_BidiCharacters {
    address public owner;
    uint256 public balance;

    // Plain ASCII only: what is rendered is what is compiled.
    function withdraw(uint256 amount) external {
        require(msg.sender == owner, "not owner");
        balance -= amount;
    }
}
