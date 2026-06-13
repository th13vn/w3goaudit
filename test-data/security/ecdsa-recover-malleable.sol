// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// SEC-SIG-001 — Signature malleability (raw signature used as replay key)
// Vulnerable_* SHOULD fire; Safe_* SHOULD NOT.

library ECDSA {
    function recover(bytes32 hash, bytes memory signature) internal pure returns (address) {
        return address(0);
    }
}

contract Vulnerable_SignatureMalleability {
    mapping(bytes => bool) public usedSignatures;

    // BAD: replay key is the malleable raw signature
    function claim(bytes32 hash, bytes memory signature) external {
        address signer = ECDSA.recover(hash, signature);
        require(signer != address(0), "bad sig");
        usedSignatures[signature] = true;
    }
}

contract Safe_SignatureMalleability {
    uint256 public nonce;
    address public lastSigner;

    // GOOD: no state is keyed on the raw signature bytes
    function claim(bytes32 hash, bytes memory signature) external {
        address signer = ECDSA.recover(hash, signature);
        require(signer != address(0), "bad sig");
        nonce++;
        lastSigner = signer;
    }
}
