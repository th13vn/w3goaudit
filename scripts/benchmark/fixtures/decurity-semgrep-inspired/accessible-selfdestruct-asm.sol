// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// ─── Adversarial bypass: assembly `selfdestruct` ──────────────────────────
// The vulnerability is identical to `accessible-selfdestruct`, but expressed
// via inline assembly. Regex/textual matchers that only look for the
// Solidity-level `selfdestruct(...)` token (the upstream Decurity rule does)
// will miss this. w3goaudit's `selfdestruct` semantic group covers BOTH
// `call.builtin.selfdestruct` AND `asm.selfdestruct`, so it should still fire.

contract VulnerableAccessibleSelfdestructAsm {
    // BAD: caller can destroy the contract; selfdestruct expressed in Yul.
    function destroy(address receiver) public {
        assembly { selfdestruct(receiver) }
    }
}

// Same call shape, but with an explicit owner check. Must NOT fire.
contract SafeAccessibleSelfdestructAsm {
    address public owner;

    constructor() { owner = msg.sender; }

    function destroy(address receiver) public {
        require(msg.sender == owner, "not owner");
        assembly { selfdestruct(receiver) }
    }
}
