// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract CallbackCandidateMatrix {
    address pool;
    address owner;
    uint256 value;

    function uniswapV3SwapCallback(int256, int256, bytes calldata) external { value = 1; }

    function uniswapV3FlashCallback(uint256, uint256, bytes calldata) external {
        require(msg.sender == pool);
        value = 2;
    }

    function uniswapV3MintCallback(uint256, uint256, bytes calldata) external {
        require(msg.sender == owner);
        value = 3;
    }
}

contract V4CallbackCandidateMatrix {
    address manager;
    uint256 value;

    function beforeSwap(address, bytes calldata) external { value = 1; }

    function afterSwap(address, bytes calldata) external {
        require(msg.sender == manager);
        value = 2;
    }
}
