// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Taint-source stress suite.
//
// Each contract has ONE external entry that calls token.transferFrom(<expr>, ...).
// The probe template (templates/test/taint-probe-parameter.yaml) flags when the
// FIRST arg matches `tainted: parameter`. Contract name encodes the PREDICTED
// engine result:
//   Hit_*     → engine SHOULD flag (parameter taint reaches arg0)   [ideal agrees]
//   Miss_*    → engine SHOULD NOT flag (no parameter taint at arg0)  [ideal agrees]
//   Diverge_* → engine result DIVERGES from the semantically-ideal answer
//               (a precision limitation). Each notes TOOL vs IDEAL.
//
// The point: confirm the engine matches the documented model AND surface where
// the model is imprecise (field-insensitive, path-insensitive, call-passthrough).

interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

// ───────────────────────── HIT: parameter taint reaches arg0 ─────────────────────────

// Hit_Direct: baseline — param used directly.
contract Hit_Direct {
    IERC20 token;
    constructor(address t) { token = IERC20(t); }
    function f(address from, uint256 amt) external { token.transferFrom(from, address(this), amt); }
}

// Hit_Alias: single local alias.
contract Hit_Alias {
    IERC20 token;
    constructor(address t) { token = IERC20(t); }
    function f(address from, uint256 amt) external { address a = from; token.transferFrom(a, address(this), amt); }
}

// Hit_AliasChain: a→b→c alias chain.
contract Hit_AliasChain {
    IERC20 token;
    constructor(address t) { token = IERC20(t); }
    function f(address from, uint256 amt) external {
        address a = from; address b = a; address c = b;
        token.transferFrom(c, address(this), amt);
    }
}

// Hit_Cast: nested casts preserve taint.
contract Hit_Cast {
    IERC20 token;
    constructor(address t) { token = IERC20(t); }
    function f(address from, uint256 amt) external {
        token.transferFrom(address(uint160(uint160(from))), address(this), amt);
    }
}

// Hit_TernaryBoth: both branches are params → union has parameter.
contract Hit_TernaryBoth {
    IERC20 token;
    constructor(address t) { token = IERC20(t); }
    function f(address from, address other, bool flag, uint256 amt) external {
        token.transferFrom(flag ? from : other, address(this), amt);
    }
}

// Hit_TernaryOne: one branch param, one state → union still contains parameter. IDEAL=Y (a path is attacker-chosen).
contract Hit_TernaryOne {
    IERC20 token; address owner;
    constructor(address t) { token = IERC20(t); owner = msg.sender; }
    function f(address from, bool flag, uint256 amt) external {
        token.transferFrom(flag ? from : owner, address(this), amt);
    }
}

// Hit_ArrayElem: element of a calldata array param.
contract Hit_ArrayElem {
    IERC20 token;
    constructor(address t) { token = IERC20(t); }
    function f(address[] calldata froms, uint256 i, uint256 amt) external {
        token.transferFrom(froms[i], address(this), amt);
    }
}

// Hit_CalldataStruct: field of a calldata struct param.
contract Hit_CalldataStruct {
    struct Req { address from; uint256 amount; }
    IERC20 token;
    constructor(address t) { token = IERC20(t); }
    function f(Req calldata r) external { token.transferFrom(r.from, address(this), r.amount); }
}

// Hit_MemStructAssigned: memory struct field assigned from param.
// NOTE: the struct intentionally does NOT end with a field named `from` — see
// parser-from-keyword.sol for the solast-go bug where a trailing `from` field
// silently drops the contract body. Here `from` is followed by `amount`.
contract Hit_MemStructAssigned {
    struct S { address from; uint256 amount; }
    IERC20 token;
    constructor(address t) { token = IERC20(t); }
    function f(address from, uint256 amt) external {
        S memory s; s.from = from; token.transferFrom(s.from, address(this), amt);
    }
}

// Hit_InterprocForward: param forwarded into an internal helper that does the call.
contract Hit_InterprocForward {
    IERC20 token;
    constructor(address t) { token = IERC20(t); }
    function f(address from, uint256 amt) external { _fwd(from, amt); }
    function _fwd(address x, uint256 amt) internal { token.transferFrom(x, address(this), amt); }
}

// Hit_InterprocReturn: helper returns its arg (real passthrough).
contract Hit_InterprocReturn {
    IERC20 token;
    constructor(address t) { token = IERC20(t); }
    function f(address from, uint256 amt) external { address a = _id(from); token.transferFrom(a, address(this), amt); }
    function _id(address x) internal pure returns (address) { return x; }
}

// Hit_ReassignToParam: sanitized first, then re-tainted (last write wins = param).
contract Hit_ReassignToParam {
    IERC20 token;
    constructor(address t) { token = IERC20(t); }
    function f(address from, uint256 amt) external {
        address a = msg.sender; a = from; token.transferFrom(a, address(this), amt);
    }
}

// ───────────────────────── MISS: no parameter taint at arg0 ─────────────────────────

// Miss_OverwriteSender: param overwritten by msg.sender (strong update).
contract Miss_OverwriteSender {
    IERC20 token;
    constructor(address t) { token = IERC20(t); }
    function f(address from, uint256 amt) external { from = msg.sender; token.transferFrom(from, address(this), amt); }
}

// Miss_OverwriteState: param overwritten by a state var.
contract Miss_OverwriteState {
    IERC20 token; address owner;
    constructor(address t) { token = IERC20(t); owner = msg.sender; }
    function f(address from, uint256 amt) external { from = owner; token.transferFrom(from, address(this), amt); }
}

// Miss_OverwriteLiteral: param overwritten by a literal.
contract Miss_OverwriteLiteral {
    IERC20 token;
    constructor(address t) { token = IERC20(t); }
    function f(address from, uint256 amt) external { from = address(0); token.transferFrom(from, address(this), amt); }
}

// Miss_SenderDirect: caller identity, not a parameter.
contract Miss_SenderDirect {
    IERC20 token;
    constructor(address t) { token = IERC20(t); }
    function f(uint256 amt) external { token.transferFrom(msg.sender, address(this), amt); }
}

// Miss_StateDirect: state var, not a parameter.
contract Miss_StateDirect {
    IERC20 token; address treasury;
    constructor(address t) { token = IERC20(t); treasury = msg.sender; }
    function f(uint256 amt) external { token.transferFrom(treasury, address(this), amt); }
}

// Miss_ThisDirect: address(this), no param.
contract Miss_ThisDirect {
    IERC20 token;
    constructor(address t) { token = IERC20(t); }
    function f(uint256 amt) external { token.transferFrom(address(this), msg.sender, amt); }
}

// Miss_SwappedSafe: param is in arg1 (the `to`), arg0 is address(this). Positional precision.
contract Miss_SwappedSafe {
    IERC20 token;
    constructor(address t) { token = IERC20(t); }
    function f(address from, uint256 amt) external { token.transferFrom(address(this), from, amt); }
}

// Miss_AliasSanitized: alias of param, then overwritten by msg.sender (strong update).
contract Miss_AliasSanitized {
    IERC20 token;
    constructor(address t) { token = IERC20(t); }
    function f(address from, uint256 amt) external { address a = from; a = msg.sender; token.transferFrom(a, address(this), amt); }
}

// Miss_InterprocSender: helper called with msg.sender (interprocedural seeding sanitizes).
contract Miss_InterprocSender {
    IERC20 token;
    constructor(address t) { token = IERC20(t); }
    function f(uint256 amt) external { _fwd(msg.sender, amt); }
    function _fwd(address x, uint256 amt) internal { token.transferFrom(x, address(this), amt); }
}

// ───────────────────────── DIVERGE: tool result ≠ semantic ideal ─────────────────────────

// Diverge_StructFieldFP: only s.to holds the param; s.from is sender. Field-INsensitive taint
// tracks the whole struct base `s`, so the param write to s.to taints s entirely.
// TOOL=Y (false positive)  IDEAL=N (s.from is msg.sender).
contract Diverge_StructFieldFP {
    struct S { address from; address to; }
    IERC20 token;
    constructor(address t) { token = IERC20(t); }
    function f(address from, uint256 amt) external {
        S memory s; s.from = msg.sender; s.to = from;
        token.transferFrom(s.from, address(this), amt);
    }
}

// Diverge_BranchFN: param overwritten only on one branch; path-INsensitive fixpoint applies
// the assignment unconditionally. TOOL=N (false negative)  IDEAL=Y (cond==false keeps param).
contract Diverge_BranchFN {
    IERC20 token;
    constructor(address t) { token = IERC20(t); }
    function f(address from, bool cond, uint256 amt) external {
        if (cond) { from = msg.sender; }
        token.transferFrom(from, address(this), amt);
    }
}

// Diverge_ReturnConstFP: helper IGNORES its arg and returns a state var, but call-return taint
// is the union of arguments. TOOL=Y (false positive)  IDEAL=N (a == treasury).
contract Diverge_ReturnConstFP {
    IERC20 token; address treasury;
    constructor(address t) { token = IERC20(t); treasury = msg.sender; }
    function f(address from, uint256 amt) external { address a = _pick(from); token.transferFrom(a, address(this), amt); }
    function _pick(address ignored) internal view returns (address) { return treasury; }
}

// Diverge_TupleFP: tuple assignment — a should be msg.sender, b the param. If the engine unions
// the tuple RHS across targets, a inherits the param taint. TOOL=? (predict Y/FP)  IDEAL=N.
contract Diverge_TupleFP {
    IERC20 token;
    constructor(address t) { token = IERC20(t); }
    function f(address from, uint256 amt) external {
        (address a, address b) = (msg.sender, from);
        b;
        token.transferFrom(a, address(this), amt);
    }
}
