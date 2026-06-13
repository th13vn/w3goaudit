// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Exercises WQL feature: semantic group kinds (eth_transfer).
// The `eth_transfer` group matches .transfer()/.send()/.call{value:}.

// MATCH: contains an ETH transfer via .transfer().
// Should be matched by feature-eth-transfer.yaml.
contract UsesTransfer {
    function pay(address payable to) external {
        to.transfer(1 ether); // eth_transfer
    }
}

// NO MATCH: only a plain state write, no value transfer.
// Should NOT be matched.
contract NoTransfer {
    uint256 stored;

    function set(uint256 v) external {
        stored = v;
    }
}
