// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Cooperative multiple inheritance with a chained `super` call — the OpenZeppelin
// ERC20 / ERC20Votes `_update` pattern. Every contract in the diamond overrides
// step() and calls super.step(). The KEY subtlety this fixture pins:
//
//   `super` is resolved against the linearization of the MOST-DERIVED contract
//   being instantiated, NOT against the contract where the call textually lives.
//
// Hierarchy (Solidity, most-base-first):
//        Root
//       /    \
//    StepA   StepB        (StepA is Root, StepB is Root)
//       \    /
//      Full              (Full is StepA, StepB)
//
// solc 0.8.20 C3 for Full (derived-first):  Full -> StepB -> StepA -> Root
//
// Runtime super chain when Full().step() runs:
//   Full.step  -> super -> StepB.step   (next after Full in Full's MRO)
//   StepB.step -> super -> StepA.step   (next after StepB in Full's MRO)  <-- NOT Root!
//   StepA.step -> super -> Root.step    (next after StepA in Full's MRO)
//
// Note StepB.step's super binds to StepA.step ONLY in Full's context. If StepB
// were instantiated alone, StepB's own MRO is [StepB, Root], so its super would
// bind to Root.step. A per-function call graph that resolves super against the
// textual contract's own MRO therefore reports StepB.step -> Root.step, which is
// the standalone answer, not the in-diamond answer.

contract Root {
    uint256 public log;

    function step() public virtual {
        log += 1; // Root contributes 1
    }
}

contract StepA is Root {
    function step() public virtual override {
        super.step();
        log += 10; // StepA contributes 10
    }
}

contract StepB is Root {
    function step() public virtual override {
        super.step();
        log += 100; // StepB contributes 100
    }
}

contract Full is StepA, StepB {
    function step() public override(StepA, StepB) {
        super.step();
        log += 1000; // Full contributes 1000
    }
}
