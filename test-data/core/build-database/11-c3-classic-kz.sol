// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// The canonical C3 linearization example from the original Dylan / CPython
// papers, encoded as real Solidity source. This exercises the FULL c3Linearize
// pipeline (base-list reversal + canonical forward-order merge), not just the
// c3Merge primitive that TestC3MergeCanonicalClassicExample pins in isolation.
//
// Python notation (first-listed base = highest priority / most derived):
//   class O
//   class A(O); class B(O); class C(O); class D(O); class E(O)
//   class K1(A, B, C)
//   class K2(D, B, E)
//   class K3(D, A)
//   class Z(K1, K2, K3)
//
// Canonical C3 result:
//   L[Z] = [Z, K1, K2, K3, D, A, B, C, E, O]
//
// Solidity lists bases "most-base-first" (the LAST-listed base is most derived),
// i.e. the reverse of Python's argument order. So Python `class Z(K1, K2, K3)`
// becomes Solidity `contract Z is K3, K2, K1`. After w3goaudit reverses the
// written base list internally, the MRO must match the Python result exactly.

contract O {
    function root() public pure virtual returns (uint256) {
        return 0;
    }
}

contract A is O {}
contract B is O {}
contract C is O {}
contract D is O {}
contract E is O {}

// Python class K1(A, B, C)  ->  Solidity reverse order: C, B, A
contract K1 is C, B, A {}

// Python class K2(D, B, E)  ->  Solidity reverse order: E, B, D
contract K2 is E, B, D {}

// Python class K3(D, A)     ->  Solidity reverse order: A, D
contract K3 is A, D {}

// Python class Z(K1, K2, K3) -> Solidity reverse order: K3, K2, K1
contract Z is K3, K2, K1 {
    function root() public pure override returns (uint256) {
        return 42;
    }
}
