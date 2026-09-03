// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract MutexOnly {
    bool initialized;
    address owner;
    function initialize(address who) external {
        require(!initialized);
        initialized = true;
        owner = who;
    }
}

contract FirstCallTakeover {
    address owner;
    function initialize(address who) external { owner = who; }
}

contract DisabledImplementation {
    bool initialized;
    constructor() { _disableInitializers(); }
    function _disableInitializers() internal { initialized = true; }
    function initialize(address) external { require(!initialized); }
}

contract ProxyNamedOnly {
    bool initialized;
    function initialize(address) external { require(!initialized); initialized = true; }
}
