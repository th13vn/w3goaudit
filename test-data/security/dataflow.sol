pragma solidity ^0.8.0;

contract TestDataFlow {
    // Should trigger: The amount param flows straight to transfer
    function directTransfer(address token, uint256 amount) public {
        uint256 x = amount;
        token.call(
            abi.encodeWithSignature("transfer(address,uint256)", msg.sender, x)
        );
    }

    // Should trigger: Amount param flows through operations to transfer
    function operationalTransfer(address token, uint256 amount) public {
        uint256 fee = amount / 100;
        uint256 total = amount + fee;
        token.call(
            abi.encodeWithSignature(
                "transfer(address,uint256)",
                msg.sender,
                total
            )
        );
    }

    // Should NOT trigger: Safe transfer, unrelated param
    function safeTransfer(address token, uint256 randomId) public {
        uint256 safeAmount = 100;
        token.call(
            abi.encodeWithSignature(
                "transfer(address,uint256)",
                msg.sender,
                safeAmount
            )
        );
    }
}
