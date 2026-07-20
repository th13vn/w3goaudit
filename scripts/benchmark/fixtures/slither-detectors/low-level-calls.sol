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
// 27. LOW-LEVEL-CALLS — Low-level call usage
// =============================================================================

// SHOULD TRIGGER: low-level-calls
contract Vulnerable_LowLevelCalls {
    // Has low-level call
    function execute(address target, bytes calldata data) external returns (bytes memory) {
        (bool success, bytes memory result) = target.call(data);
        require(success, "Failed");
        return result;
    }
}

// SHOULD NOT TRIGGER: low-level-calls
contract Safe_LowLevelCalls {
    IERC20 public token;

    constructor(IERC20 _token) {
        token = _token;
    }

    // SAFE: high-level call via interface
    function execute(address to, uint256 amount) external {
        token.transfer(to, amount);
    }
}
