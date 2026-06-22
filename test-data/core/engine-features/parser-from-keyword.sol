// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// PARSER BUG REPRO (solast-go v0.1.4) — `from` as a struct's LAST field.
//
// `from` is a contextual keyword in Solidity's import grammar
// (`import {X} from "..."`). solast-go's lexer/parser tokenizes it as a keyword,
// and when a struct field named `from` is immediately followed by the struct's
// closing `}`, the parser desyncs at `from ; }` and consumes the rest of the
// contract body — SILENTLY. No parse error is reported; the contract simply
// loses its state variables and ALL functions.
//
// Impact: every detector (not just taint) emits FALSE NEGATIVES for any contract
// whose struct ends in a `from` field — a very common shape
// (e.g. `struct Transfer { uint256 amount; address from; }`).
//
// Confirmed trigger matrix (function-extraction result for `contract A`):
//   struct S { address from; }                 -> 0 functions  (BUG: from is last)
//   struct S { address to; address from; }     -> 0 functions  (BUG: from is last)
//   struct S { uint256 from; }                 -> 0 functions  (BUG: from is last)
//   struct S { address from; address to; }     -> 1 function   (ok: from not last)
//   struct S { address from; uint256 amount; } -> 1 function   (ok: from not last)
//   field named `From`/`FROM`/`frome`/`xfrom`  -> 1 function   (ok: only exact `from`)
//
// EXPECTED once fixed: BrokenByTrailingFrom.pull is extracted and detectors see it.
interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

contract BrokenByTrailingFrom {
    struct Transfer { uint256 amount; address from; } // trailing `from` field → triggers the bug
    IERC20 token;

    constructor(address t) { token = IERC20(t); }

    // Currently DROPPED by the parser: this function never reaches the database,
    // so an arbitrary-transferFrom (or any) scan misses it entirely.
    function pull(address from, uint256 amount) external {
        token.transferFrom(from, address(this), amount);
    }
}
