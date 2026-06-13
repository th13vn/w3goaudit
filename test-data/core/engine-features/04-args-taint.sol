// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Exercises WQL feature: args (positional argument match) + tainted_from.
// Pattern: ERC20 transferFrom whose first argument is a caller-controlled
// parameter (arbitrary transferFrom / approval-theft shape).

interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

// VULNERABLE: arg 0 (`from`) is a function parameter the caller controls.
// Should be matched by feature-args-taint.yaml.
contract VulnerableTransferFrom {
    function pull(IERC20 token, address from, uint256 amount) external {
        token.transferFrom(from, msg.sender, amount); // arg0 tainted_from: parameter
    }
}

// SAFE: arg 0 is msg.sender, not a tainted parameter.
// Should NOT be matched.
contract SafeTransferFrom {
    function pull(IERC20 token, uint256 amount) external {
        token.transferFrom(msg.sender, address(this), amount);
    }
}
