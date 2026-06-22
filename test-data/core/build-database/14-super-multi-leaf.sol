// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Harder `super` stress case: a SHARED mixin `M` is pulled into TWO different
// concrete leaves, and M.f()'s super target differs in each leaf. This is the
// case a context-free call graph cannot represent with a single edge — the SOUND
// UNION must hold all three targets.
//
//   Root { f }
//   A is Root { f -> super.f }
//   B is Root { f -> super.f }
//   M is Root { f -> super.f }          // shared mixin, also calls super
//   LeafX is A, M { f -> super.f }       // MRO: [LeafX, M, A, Root]
//   LeafY is B, M { f -> super.f }       // MRO: [LeafY, M, B, Root]
//
// M.f()'s `super.f()` resolves to:
//   * A.f    when M runs as part of LeafX  (after M in LeafX's MRO comes A)
//   * B.f    when M runs as part of LeafY  (after M in LeafY's MRO comes B)
//   * Root.f when M is deployed standalone (M's own MRO is [M, Root])
//
// So M.f must carry THREE super edges: -> A.f, -> B.f, -> Root.f.
//
// Likewise LeafX.f -> M.f, LeafY.f -> M.f, A.f -> Root.f (in LeafX), B.f -> Root.f
// (in LeafY). A.f and B.f also resolve to Root.f standalone.

contract Root {
    uint256 public n;

    function f() public virtual {
        n += 1;
    }
}

contract A is Root {
    function f() public virtual override {
        super.f();
        n += 10;
    }
}

contract B is Root {
    function f() public virtual override {
        super.f();
        n += 100;
    }
}

contract M is Root {
    function f() public virtual override {
        super.f();
        n += 1000;
    }
}

contract LeafX is A, M {
    function f() public override(A, M) {
        super.f();
        n += 10000;
    }
}

contract LeafY is B, M {
    function f() public override(B, M) {
        super.f();
        n += 100000;
    }
}
