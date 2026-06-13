// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Stress fixture for three inheritance properties, all pinned to solc 0.8.20:
//
//   1. Complex (asymmetric) diamond C3 linearization.
//   2. State-variable storage order (most-base contract first, then declaration
//      order within each contract).
//   3. Function-override resolution along the MRO (most-derived wins; an
//      override only on one branch still resolves to that branch).
//
// Hierarchy (most-derived base written last, per Solidity):
//
//        Base
//       /    \
//     Left   Right
//       \    /
//      Middle            (Middle is Left, Right)
//        |
//      Derived           (Derived is Middle)
//
// solc 0.8.20 C3 linearization, derived-first:
//   Derived -> Middle -> Right -> Left -> Base
// Storage layout order (reverse of that, most-base first):
//   Base.baseVar, Base.baseFlag, Left.leftVar, Right.rightVar,
//   Middle.middleVar, Derived.derivedVar

contract Base {
    uint256 public baseVar;
    bool public baseFlag;

    function foo() public virtual returns (string memory) {
        return "Base.foo";
    }

    function bar() public virtual returns (uint256) {
        return 1;
    }

    function baz() public virtual returns (uint256) {
        return 100;
    }
}

contract Left is Base {
    uint256 public leftVar;

    function foo() public virtual override returns (string memory) {
        return "Left.foo";
    }
}

contract Right is Base {
    uint256 public rightVar;

    function foo() public virtual override returns (string memory) {
        return "Right.foo";
    }

    // bar() is overridden ONLY on the Right branch.
    function bar() public virtual override returns (uint256) {
        return 2;
    }
}

contract Middle is Left, Right {
    uint256 public middleVar;

    // Resolves both Left and Right definitions of foo().
    function foo() public virtual override(Left, Right) returns (string memory) {
        return "Middle.foo";
    }
}

contract Derived is Middle {
    uint256 public derivedVar;

    // Derived overrides foo() and calls super.foo() (must bind to Middle.foo
    // — the next contract in Derived's MRO that defines foo).
    function foo() public override returns (string memory) {
        super.foo();
        return "Derived.foo";
    }

    // callsBar/callsBaz exercise internal-call override binding along the MRO:
    //   bar() must bind to Right.bar (only branch that overrides it)
    //   baz() must bind to Base.baz (never overridden)
    function callsBar() public returns (uint256) {
        return bar();
    }

    function callsBaz() public returns (uint256) {
        return baz();
    }
}
