// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Fixture for builder coverage of statement/expression forms that were
// previously dropped or misclassified:
//   - revert statements (string + custom error)  -> check.revert
//   - unchecked blocks                            -> calls still in call graph
//   - try/catch success body                      -> calls still in call graph
//   - do/while loops                              -> stmt.loop (loop_type=do_while)
//   - assembly assignment (ok := delegatecall)    -> asm.delegatecall visited
//   - assembly local shadowing                     -> no inherited parameter taint
//   - assembly writes to Solidity symbols          -> outer taint state updated
//   - assembly for-loop order                       -> body runs before post
//   - assembly path joins                           -> branch/zero-loop taint union
//   - compound assignments (%= &= etc.)           -> stmt.assign / state write
//   - tuple assignment ((a,b)=(b,a))              -> expr.tuple targets
//   - new C()                                     -> call.create edge
//   - modifier bodies calling auth helpers        -> Modifier.Calls populated

interface ICallee {
    function ping() external returns (uint256);
}

contract Deployed {
    uint256 public x;
    constructor(uint256 v) {
        x = v;
    }
}

contract StatementForms {
    error Unauthorized(address who);

    uint256 internal total;
    uint256 internal flags;
    address internal owner;

    function _enforceOwner() internal view {
        require(msg.sender == owner, "not owner");
    }

    // Non-auth-named modifier that gates via an auth helper call. Exercises
    // modifier-body call analysis + IsAccessControlled detection.
    modifier gate() {
        _enforceOwner();
        _;
    }

    // revert in both forms; the if-guarded revert is the modern pattern.
    function guardedRevert(address to, uint256 a) external {
        if (a == 0) revert("zero amount");
        if (to == address(0)) revert Unauthorized(to);
        total = a;
    }

    // calls inside unchecked{} and a do/while loop must reach the call graph.
    function loopAndUnchecked(ICallee c) external {
        uint256 i;
        do {
            unchecked {
                total += c.ping();
            }
            i++;
        } while (i < 3);
    }

    // try success body call must reach the call graph.
    function tryBody(ICallee c) external {
        try c.ping() returns (uint256 v) {
            total = helperConsume(v);
        } catch {
            total = 0;
        }
    }

    function helperConsume(uint256 v) internal pure returns (uint256) {
        return v + 1;
    }

    // compound assignments and tuple assignment.
    function compoundAndTuple(uint256 a, uint256 b) external {
        flags &= a;
        flags |= b;
        total %= (a + 1);
        (a, b) = (b, a);
        total = a + b;
    }

    // assembly assignment form: `ok := delegatecall(...)` (no `let`).
    function asmDelegate(address impl) external returns (bool ok) {
        assembly {
            ok := delegatecall(gas(), impl, 0, 0, 0, 0)
        }
    }

    // A Yul local shadows the Solidity parameter for the nested block only.
    function asmShadow(address receiver) external pure {
        assembly {
            pop(receiver)
            {
                let receiver := 0
                pop(receiver)
            }
            pop(receiver)
        }
    }

    // Assignments to Solidity parameters, locals, and named return variables
    // are legal in Yul and must update the surrounding symbol's taint state.
    function asmOuterSymbols(address source, address sanitized)
        external
        pure
        returns (address result)
    {
        address copied;
        assembly {
            sanitized := 0
            pop(sanitized)

            copied := source
            result := copied
            pop(copied)
            pop(result)
        }
    }

    // Yul for-loops execute body before post. The body taints `current`, so the
    // post sink must see taint; the post then sanitizes it, so the sink after
    // the loop must be clean.
    function asmForRuntimeOrder(address source) external pure {
        address current;
        assembly {
            current := 0
            for { let i := 0 } lt(i, 1) {
                pop(current)
                current := 0
                i := add(i, 1)
            } {
                current := source
            }
            pop(current)
        }
    }

    // A conditional body is optional. Sanitization in that body must not erase
    // input taint, while a taint copy in the body must survive the path join.
    // The Yul locals exercise the assembly lexical-scope state in the same join.
    function asmIfPathMerge(address source, uint256 typedSource) external pure {
        address outerSanitized = source;
        address outerCopied;
        address outerType = source;
        assembly {
            let localSanitized := source
            let localCopied := 0
            if source {
                outerSanitized := 0
                outerCopied := source
                outerType := typedSource
                localSanitized := 0
                localCopied := source
            }
            pop(outerSanitized)
            pop(outerCopied)
            pop(outerType)
            pop(localSanitized)
            pop(localCopied)
        }
    }

    // Switch cases are mutually exclusive. With no default, the unmatched
    // input path is feasible too; a later case must not overwrite an earlier
    // case's taint state during analysis.
    function asmSwitchPathMerge(address source, uint256 selector) external pure {
        address sanitized = source;
        address copied;
        assembly {
            switch selector
            case 0 {
                sanitized := 0
                copied := source
            }
            case 1 {
                copied := 0
            }
            pop(sanitized)
            pop(copied)
        }
    }

    // A Yul for-loop may execute zero times. The zero-iteration path preserves
    // input taint, while one possible iteration can introduce new taint.
    function asmZeroIterationMerge(address source) external pure {
        address sanitized = source;
        address copied;
        assembly {
            for { } source { } {
                sanitized := 0
                copied := source
            }
            pop(sanitized)
            pop(copied)
        }
    }

    // Loop-carried taint requires a second iteration: iteration 1 taints b,
    // iteration 2 copies b into a. The existing pop(a) node in the loop body
    // and the sink after the loop must both reflect that later iteration.
    function asmForLoopCarried(address source) external pure {
        assembly {
            let a := 0
            let b := 0
            for { let i := 0 } lt(i, 2) { i := add(i, 1) } {
                a := b
                b := source
                pop(a)
            }
            pop(a)
        }
    }

    // new C() — creation edge / call.create.
    function deploy(uint256 v) external gate returns (address) {
        Deployed d = new Deployed(v);
        return address(d);
    }
}
