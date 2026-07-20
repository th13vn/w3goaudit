// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IERC20Like {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

// ─── Adversarial bypass: inherited-base helper ────────────────────────────
// The dangerous transferFrom is defined in an abstract base that the derived
// contract inherits and exposes through a no-modifier wrapper. Detectors must
// resolve the call across the inheritance chain to see that `from` (user-
// controlled in the wrapper) flows to the inherited transferFrom. Surface-
// syntactic tools that examine only the file or only the call site lose the
// connection. w3goaudit's call-graph + linearization should track it.

abstract contract _ForwardLike {
    IERC20Like public token;

    // Note: NO access check here. The base assumes the derived class will
    // gate this in an `onlyOwner` modifier (a pattern an auditor would catch).
    // BOTH source and destination are caller-controlled — the canonical
    // bad-transferFrom shape the Decurity rule targets.
    function _forward(address from, address to, uint256 amount) internal {
        token.transferFrom(from, to, amount);
    }
}

contract VulnerableBadTransferFromInherited is _ForwardLike {
    // BAD: caller-controlled `from` AND `to` reach the inherited transferFrom
    // with no access control on the entrypoint. Detecting this requires the
    // engine to (a) resolve `_forward` across the inheritance chain and (b)
    // propagate the parameter taint into its body's transferFrom args.
    function deposit(address from, address to, uint256 amount) external {
        _forward(from, to, amount);
    }
}

// Safe: same inheritance, BUT the entrypoint constrains from = msg.sender and
// to = address(this), so neither transferFrom arg is caller-controlled.
contract SafeBadTransferFromInherited is _ForwardLike {
    function deposit(uint256 amount) external {
        _forward(msg.sender, address(this), amount);
    }
}
