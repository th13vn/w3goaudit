// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Tests HIGH-ARBITRARY-SEND-ETH: ETH sent to a caller-chosen destination without
// access control. The safe case mirrors SpiceFiNFT4626: the entry point forwards
// msg.sender into an internal helper that gates on NFT ownership, so the
// forwarded-caller-identity guard must be recognized as access control.

interface IERC721Like {
    function ownerOf(uint256 tokenId) external view returns (address);
}

contract Vulnerable_ArbitrarySendETH {
    // SHOULD FLAG: any caller can send contract ETH to any address. No access
    // control, no caller-scoped accounting.
    function withdraw(address to, uint256 amount) external {
        (bool ok, ) = to.call{value: amount}("");
        require(ok, "send failed");
    }
}

contract Safe_OwnerGatedWithdraw {
    mapping(uint256 => uint256) public tokenShares;
    uint256 public totalShares;

    function ownerOf(uint256 tokenId) public view returns (address) {
        // stand-in for ERC721 ownership
        return _owners[tokenId];
    }

    mapping(uint256 => address) private _owners;

    // SHOULD NOT FLAG: forwards msg.sender into _withdraw, which gates on NFT
    // ownership (`ownerOf(tokenId) != caller`) and debits the caller's shares.
    function redeemETH(
        uint256 tokenId,
        uint256 shares,
        address receiver
    ) external {
        _withdraw(msg.sender, tokenId, receiver, shares);
        (bool ok, ) = receiver.call{value: shares}("");
        require(ok, "send failed");
    }

    // SHOULD NOT FLAG: same as redeemETH but msg.sender is first aliased into a
    // local (`address sender = msg.sender;`) before being forwarded. Exercises
    // the tainted-local path: the forwarded caller identity must be tracked even
    // when it's a converted/aliased variable, not a direct `msg.sender`.
    function withdrawETH(
        uint256 tokenId,
        uint256 shares,
        address receiver
    ) external {
        address sender = msg.sender;
        _withdraw(sender, tokenId, receiver, shares);
        (bool ok, ) = receiver.call{value: shares}("");
        require(ok, "send failed");
    }

    function _withdraw(
        address caller,
        uint256 tokenId,
        address receiver,
        uint256 shares
    ) internal {
        if (ownerOf(tokenId) != caller) {
            revert("not owner");
        }
        totalShares -= shares;
        tokenShares[tokenId] -= shares;
        // receiver kept distinct from the ownership check, like the real vault
        receiver;
    }
}
