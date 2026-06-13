// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Fixture for builder coverage of statement/expression forms that were
// previously dropped or misclassified:
//   - revert statements (string + custom error)  -> check.revert
//   - unchecked blocks                            -> calls still in call graph
//   - try/catch success body                      -> calls still in call graph
//   - do/while loops                              -> stmt.loop (loop_type=do_while)
//   - assembly assignment (ok := delegatecall)    -> asm.delegatecall visited
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

    // new C() — creation edge / call.create.
    function deploy(uint256 v) external gate returns (address) {
        Deployed d = new Deployed(v);
        return address(d);
    }
}
