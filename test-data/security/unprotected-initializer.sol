// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract VulnerableOfficialInitializer {
    address public owner;

    function initialize(address newOwner) external {
        owner = newOwner;
    }
}

contract SafeOfficialInitializerAccessControlOnly {
    address public owner;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function initialize(address newOwner) external onlyOwner {
        owner = newOwner;
    }
}

contract SafeOfficialInitializerModifierOnly {
    address public owner;
    bool private initialized;

    modifier initializer() {
        require(!initialized, "already initialized");
        initialized = true;
        _;
    }

    function initialize(address newOwner) external initializer {
        owner = newOwner;
    }
}

contract SafeOfficialInitializerDisableGuardOnly {
    address public owner;
    bool private _initializersDisabled;

    constructor() {
        _initializersDisabled = true;
    }

    function initialize(address newOwner) external {
        require(!_initializersDisabled, "initializers disabled");
        owner = newOwner;
    }
}
