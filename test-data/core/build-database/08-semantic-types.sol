// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IOneArgToken {
    function transfer(address to) external;
    function send(address to) external;
}

contract SemanticTypeFacts {
    IOneArgToken public oneArgToken;
    address payable public payout;

    constructor(address token, address payable receiver) {
        oneArgToken = IOneArgToken(token);
        payout = receiver;
    }

    // Should be call.external despite one argument because receiver type is an interface.
    function interfaceTransfer(address to) external {
        oneArgToken.transfer(to);
    }

    // Should be call.external despite one argument because local receiver type is an interface.
    function localCastTransfer(address token, address to) external {
        IOneArgToken localToken = IOneArgToken(token);
        localToken.transfer(to);
    }

    // Should be call.builtin.transfer because receiver type is address payable.
    function payableTransfer(uint256 amount) external {
        payout.transfer(amount);
    }

    // Should be call.builtin.transfer because payable(...) returns address payable.
    function payableCastTransfer(address payable to, uint256 amount) external {
        payable(to).transfer(amount);
    }

    // Should be call.external because receiver type is an interface, not address.
    function interfaceSend(address to) external {
        oneArgToken.send(to);
    }
}
