// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Fixtures for HIGH-NO-SLIPPAGE-CHECK, HIGH-UNISWAP-CALLBACK-UNPROTECTED and
// HIGH-UNISWAP-V4-HOOK-UNPROTECTED.

interface IRouter {
    function swapExactTokensForTokens(
        uint256 amountIn,
        uint256 amountOutMin,
        address[] calldata path,
        address to,
        uint256 deadline
    ) external returns (uint256[] memory amounts);

    function swapExactETHForTokens(
        uint256 amountOutMin,
        address[] calldata path,
        address to,
        uint256 deadline
    ) external payable returns (uint256[] memory amounts);
}

contract Vulnerable_NoSlippageCheck {
    IRouter public router;

    // VULNERABLE: amountOutMin hardcoded to 0 — fully sandwichable.
    function swapTokens(uint256 amountIn, address[] calldata path) external {
        router.swapExactTokensForTokens(amountIn, 0, path, msg.sender, block.timestamp);
    }

    // VULNERABLE: ETH-in variant, amountOutMin is argument 0.
    function swapEth(address[] calldata path) external payable {
        router.swapExactETHForTokens{value: msg.value}(0, path, msg.sender, block.timestamp);
    }
}

contract Safe_NoSlippageCheck {
    IRouter public router;

    // SAFE: the caller supplies a real slippage bound.
    function swapTokens(uint256 amountIn, uint256 minOut, address[] calldata path) external {
        router.swapExactTokensForTokens(amountIn, minOut, path, msg.sender, block.timestamp);
    }

    // SAFE: bound derived from a quote the caller passes in.
    function swapEth(uint256 minOut, address[] calldata path) external payable {
        router.swapExactETHForTokens{value: msg.value}(minOut, path, msg.sender, block.timestamp);
    }
}

contract Vulnerable_UniswapCallbackUnprotected {
    // VULNERABLE: anyone can call the V3 swap callback and dictate the amounts.
    function uniswapV3SwapCallback(int256 amount0Delta, int256 amount1Delta, bytes calldata data) external {
        settle(amount0Delta, amount1Delta, data);
    }

    // VULNERABLE: the V2 flash-swap callback trusts its arguments.
    function uniswapV2Call(address sender, uint256 amount0, uint256 amount1, bytes calldata data) external {
        settle(int256(amount0), int256(amount1), data);
        require(sender != address(0), "bad sender");
    }

    function settle(int256, int256, bytes calldata) internal {}
}

contract Safe_UniswapCallbackUnprotected {
    address public pool;

    // SAFE: the caller is asserted to be the expected pool.
    function uniswapV3SwapCallback(int256 amount0Delta, int256 amount1Delta, bytes calldata data) external {
        require(msg.sender == pool, "not pool");
        settle(amount0Delta, amount1Delta, data);
    }

    // SAFE: validation is delegated to the canonical helper.
    function uniswapV2Call(address, uint256 amount0, uint256 amount1, bytes calldata data) external {
        verifyCallback(msg.sender);
        settle(int256(amount0), int256(amount1), data);
    }

    function verifyCallback(address caller) internal view {
        require(caller == pool, "not pool");
    }

    function settle(int256, int256, bytes calldata) internal {}
}

contract Vulnerable_UniswapV4HookUnprotected {
    uint256 public swapCount;

    // VULNERABLE: the hook is callable by anyone, not just the PoolManager.
    function beforeSwap(address, bytes calldata, bytes calldata) external returns (bytes4) {
        swapCount += 1;
        return this.beforeSwap.selector;
    }

    // VULNERABLE: same for the liquidity hook.
    function afterAddLiquidity(address, bytes calldata, bytes calldata) external returns (bytes4) {
        swapCount += 1;
        return this.afterAddLiquidity.selector;
    }
}

contract Safe_UniswapV4HookUnprotected {
    address public poolManager;
    uint256 public swapCount;

    modifier onlyPoolManager() {
        require(msg.sender == poolManager, "not manager");
        _;
    }

    // SAFE: restricted to the PoolManager.
    function beforeSwap(address, bytes calldata, bytes calldata) external onlyPoolManager returns (bytes4) {
        swapCount += 1;
        return this.beforeSwap.selector;
    }

    // SAFE: inline caller assertion.
    function afterAddLiquidity(address, bytes calldata, bytes calldata) external returns (bytes4) {
        require(msg.sender == poolManager, "not manager");
        swapCount += 1;
        return this.afterAddLiquidity.selector;
    }
}
