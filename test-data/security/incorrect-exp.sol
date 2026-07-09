// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Tests HIGH-INCORRECT-EXP: `^` (bitwise XOR) used where `**` (power) was meant.
// The detector flags only a LITERAL BASE (`10 ^ 18`, `2 ^ 256`) — the signature
// of an exponentiation typo — and leaves genuine bitwise XOR alone.

contract Vulnerable_IncorrectExp {
    // SHOULD FLAG: literal base, developer meant 10 ** 18.
    function scaleWei(uint256 amount) external pure returns (uint256) {
        return amount * (10 ^ 18);
    }

    // SHOULD FLAG: literal base, meant 2 ** 8.
    function maxByte() external pure returns (uint256) {
        return 2 ^ 8;
    }

    // SHOULD FLAG: variable base/exponent, meant base ** exp (Slither's
    // canonical incorrect-exp example). Both operands simple, no bitwise context.
    function power(uint256 base, uint256 exp) external pure returns (uint256) {
        return base ^ exp;
    }
}

contract Safe_IntentionalXor {
    // SHOULD NOT FLAG: overflow-safe average — XOR of two variables.
    // (OpenZeppelin Math.average) Left operand is an identifier, not a literal.
    function average(uint256 a, uint256 b) external pure returns (uint256) {
        return (a & b) + (a ^ b) / 2;
    }

    // SHOULD NOT FLAG: modular-inverse Newton-Raphson seed (OpenZeppelin
    // Math.mulDiv). Left operand `(3 * denominator)` is an expression, not a
    // literal base — intentional XOR with 2.
    function inverseSeed(uint256 denominator) external pure returns (uint256) {
        return (3 * denominator) ^ 2;
    }

    // SHOULD NOT FLAG: hex mask. `0xFF` is a hex literal (subtype hex), not a
    // decimal base.
    function lowByte(uint256 x) external pure returns (uint256) {
        return x ^ 0xFF;
    }

    // SHOULD NOT FLAG: genuine bit manipulation — the `^` shares a statement
    // with `|` and `&`, so it is clearly bitwise, not exponentiation.
    function mix(uint256 a, uint256 b) external pure returns (uint256) {
        return (a | b) ^ (a & b);
    }
}
