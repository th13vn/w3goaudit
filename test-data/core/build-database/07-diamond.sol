// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Classic C3 diamond. D inherits B and C, both of which inherit A.
// In Solidity the last-listed base is most-derived, so the C3 linearization
// (derived-first), verified against solc 0.8.20, is:
//   D -> C -> B -> A
contract A {
    function a() public pure {}
}

contract B is A {
    function b() public pure {}
}

contract C is A {
    function c() public pure {}
}

contract D is B, C {
    function d() public pure {}
}
