// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// ─── Adversarial bypass: type-cast obfuscation ────────────────────────────
// `selfdestruct(payable(addr))` is the canonical shape. This variant routes
// the address through an explicit uint160 round-trip before casting back —
// surface-text matchers tuned for a literal `payable(receiver)` token may not
// recognize this form. The vulnerability is identical: caller supplies the
// beneficiary, no access check.

contract VulnerableAccessibleSelfdestructCast {
    // BAD: caller-supplied receiverInt -> address -> payable. No auth.
    function destroy(uint160 receiverInt) public {
        selfdestruct(payable(address(receiverInt)));
    }
}

// Same cast pattern, with owner check. Must NOT fire.
contract SafeAccessibleSelfdestructCast {
    address public owner;

    constructor() { owner = msg.sender; }

    function destroy(uint160 receiverInt) public {
        require(msg.sender == owner, "not owner");
        selfdestruct(payable(address(receiverInt)));
    }
}
