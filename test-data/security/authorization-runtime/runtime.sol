// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

abstract contract RuntimeBase {
    function _authorize() internal virtual;
    function upgrade() external { _authorize(); }
}

contract RuntimeProtected is RuntimeBase {
    address authority;
    modifier gate() { require(msg.sender == authority); _; }
    function _authorize() internal override gate {}
}

contract SuperBase {
    address authority;
    function act() public virtual { require(msg.sender == authority); }
}

contract SuperProtected is SuperBase {
    function act() public override { super.act(); }
}

abstract contract AmbiguousBase {
    function _gate() internal virtual;
    function execute() external { _gate(); }
}

contract AmbiguousProtected is AmbiguousBase {
    address authority;
    modifier gate() { require(msg.sender == authority); _; }
    function _gate() internal override gate {}
}

contract AmbiguousOpen is AmbiguousBase {
    function _gate() internal override {}
}
