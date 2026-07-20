// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// ─── Adversarial bypass: struct-field taint forwarding ───────────────────
// The user-controlled delegatecall target is moved into a struct field, then
// passed by reference to an internal helper that uses `req.target`. This
// stresses two things:
//   1) Semgrep-style textual matchers tuned for a literal `target.delegatecall`
//      may not realize `req.target.delegatecall` is the same shape.
//   2) Engines with taint propagation must carry the taint THROUGH a struct
//      field and ACROSS an internal call — both required for w3goaudit's
//      `tainted_from: parameter` to fire here.

struct DelegatecallReq { address target; bytes data; }

contract VulnerableDelegatecallStruct {
    // BAD: req.target is the user-controlled delegatecall destination,
    // forwarded through an internal helper.
    function exec(DelegatecallReq calldata req) external {
        _run(req);
    }

    function _run(DelegatecallReq calldata req) internal {
        (bool ok, ) = req.target.delegatecall(req.data);
        require(ok);
    }
}

// Safe: target is a hard-coded immutable, not user-supplied. Must NOT fire.
contract SafeDelegatecallStruct {
    address public immutable plugin;

    constructor(address _plugin) { plugin = _plugin; }

    function exec(bytes calldata data) external {
        (bool ok, ) = plugin.delegatecall(data);
        require(ok);
    }
}
