// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// =============================================================================
// TEST CONTRACT: 4naly3er → WQL Template Verification
// Each Vulnerable_* contract SHOULD trigger its detector.
// Each Safe_* contract SHOULD NOT trigger the detector.
// Total: 37 detectors × 2 patterns = 74 contracts
// =============================================================================

// ─── Shared Interfaces & Mocks ───────────────────────────────────────────────

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function approve(address spender, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

interface IERC721 {
    function transferFrom(address from, address to, uint256 tokenId) external;
    function safeTransferFrom(address from, address to, uint256 tokenId) external;
}

interface IChainlinkAggregator {
    function latestAnswer() external view returns (int256);
    function latestRoundData() external view returns (
        uint80 roundId, int256 answer, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound
    );
}

interface IWstETH {
    function stEthPerToken() external view returns (uint256);
}

// SafeERC20 stub for safe tests
library SafeERC20 {
    function safeTransfer(IERC20 token, address to, uint256 amount) internal {
        require(token.transfer(to, amount), "safeTransfer failed");
    }
    function safeTransferFrom(IERC20 token, address from, address to, uint256 amount) internal {
        require(token.transferFrom(from, to, amount), "safeTransferFrom failed");
    }
    function safeApprove(IERC20 token, address spender, uint256 amount) internal {
        token.approve(spender, amount);
    }
    function safeIncreaseAllowance(IERC20 token, address spender, uint256 amount) internal {
        token.approve(spender, amount);
    }
    function forceApprove(IERC20 token, address spender, uint256 value) internal {
        token.approve(spender, 0);
        token.approve(spender, value);
    }
}

library ECDSA {
    function recover(bytes32 hash, bytes memory signature) internal pure returns (address) {
        (bytes32 r, bytes32 s, uint8 v) = abi.decode(signature, (bytes32, bytes32, uint8));
        require(uint256(s) <= 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0, "Malleable");
        return ecrecover(hash, v, r, s);
    }
}

// =============================================================================
// ── H-002: DELEGATECALL IN LOOP ──────────────────────────────────────────────
// =============================================================================

// SHOULD TRIGGER: H-delegatecall-in-loop
contract Vulnerable_DelegateCallInLoop {
    function multiExecute(address target, bytes[] calldata data) external {
        for (uint256 i = 0; i < data.length; i++) {
            (bool ok,) = target.delegatecall(data[i]); // delegatecall in loop
            require(ok, "Failed");
        }
    }
}

// SHOULD NOT TRIGGER
contract Safe_DelegateCallInLoop {
    address public impl;
    constructor(address _impl) { impl = _impl; }

    // Single delegatecall, not in a loop
    function execute(bytes calldata data) external {
        (bool ok,) = impl.delegatecall(data);
        require(ok, "Failed");
    }
}
