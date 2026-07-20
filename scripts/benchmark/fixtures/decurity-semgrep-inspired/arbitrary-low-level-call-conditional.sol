// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// ─── Adversarial bypass: conditional + variant low-level call ─────────────
// The user-controlled target is passed to EITHER `.call` or `.staticcall`
// depending on a runtime flag. Both code paths are vulnerable to caller-
// directed external execution. This stresses:
//   1) Detectors that pattern-match a single low-level form (e.g. only `.call`)
//      and miss `.staticcall` even though the destination is still attacker-
//      controlled.
//   2) Engines that look only at the first branch of an if/else.

contract VulnerableArbitraryLowLevelCallConditional {
    // BAD: either branch lets the caller pick the target.
    function exec(address target, bytes calldata data, bool readOnly) external {
        if (readOnly) {
            target.staticcall(data);
        } else {
            target.call(data);
        }
    }
}

// Safe: target is a hard-coded immutable; bool just toggles the method.
contract SafeArbitraryLowLevelCallConditional {
    address public immutable trusted;

    constructor(address _trusted) { trusted = _trusted; }

    function exec(bytes calldata data, bool readOnly) external {
        if (readOnly) {
            trusted.staticcall(data);
        } else {
            trusted.call(data);
        }
    }
}
