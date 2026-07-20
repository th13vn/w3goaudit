// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

abstract contract ERC2771Context {}
abstract contract Multicall {}

interface IERC20Like {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function safeTransferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

interface IRouterLike {
    function swapExactTokensForTokens(uint256 amountIn, uint256 amountOutMin, address[] calldata path, address to, uint256 deadline) external returns (uint256[] memory);
    function swapExactETHForTokens(uint256 amountOutMin, address[] calldata path, address to, uint256 deadline) external payable returns (uint256[] memory);
}

interface IBalancerVaultLike {
    function getPoolTokens(bytes32 poolId) external view returns (address[] memory, uint256[] memory, uint256);
    function manageUserBalance(bytes calldata data) external;
}

interface IRateProviderLike {
    function getRate() external view returns (uint256);
}

interface ICurvePoolLike {
    function get_virtual_price() external view returns (uint256);
    function get_p(uint256 i) external view returns (uint256);
}

interface IKeeperLike {
    function current(address tokenIn, uint256 amountIn, address tokenOut) external view returns (uint256);
}

interface IERC777HookLike {
    function tokensReceived(address operator, address from, address to, uint256 amount, bytes calldata userData, bytes calldata operatorData) external;
}

interface ISuperTokenLike {
    function decodeCtx(bytes calldata ctx) external view returns (address, address);
}

library ECDSA {
    function recover(bytes32 hash, bytes memory signature) internal pure returns (address) {
        return address(0);
    }
}

contract UpgradeabilityProxy {}

contract VulnerableCompoundSweepTokenAlias {
    function sweepToken(IERC20Like token, address to, uint256 amount) external {
        IERC20Like swept = token;
        swept.transfer(to, amount);
    }
}
