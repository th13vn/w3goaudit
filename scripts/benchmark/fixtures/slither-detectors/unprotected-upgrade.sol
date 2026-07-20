// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// =============================================================================
// Test Contracts for Slither→WQL Template Verification
// Each Vulnerable_* contract SHOULD trigger its corresponding detector.
// Each Safe_* contract SHOULD NOT trigger the detector.
// =============================================================================

// --- Interfaces used across tests ---
interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function approve(address spender, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

// =============================================================================
// 10. UNPROTECTED-UPGRADE — initialize without auth
// =============================================================================

// SHOULD TRIGGER: unprotected-upgrade
contract Vulnerable_UnprotectedUpgrade {
    address public owner;
    bool public initialized;

    // BAD: anyone can call initialize and take ownership
    function initialize(address _owner) external {
        require(!initialized, "Already initialized");
        owner = _owner;
        initialized = true;
    }
}

// SHOULD NOT TRIGGER: unprotected-upgrade
contract Safe_UnprotectedUpgrade {
    address public owner;
    bool public initialized;

    modifier onlyAdmin() {
        require(msg.sender == owner, "Not admin");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    // SAFE: onlyAdmin modifier protects initialization
    function initialize(address _newOwner) external onlyAdmin {
        require(!initialized, "Already initialized");
        owner = _newOwner;
        initialized = true;
    }
}
