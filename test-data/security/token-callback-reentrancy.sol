// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Deferred callback and accounting fixtures. Protocol-specific variants remain
// useful while generic callback evidence is developed.

interface IERC777Recipient {
    function tokensReceived(address operator, address from, address to, uint256 amount) external;
}

abstract contract ReentrancyGuard {
    uint256 private locked = 1;

    modifier nonReentrant() {
        require(locked == 1, "reentrant");
        locked = 2;
        _;
        locked = 1;
    }
}

contract Vulnerable_ERC20PublicBurn {
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;

    // VULNERABLE: burns from a caller-chosen account with no auth or allowance.
    function burn(address account, uint256 amount) external {
        _burn(account, amount);
    }

    function _burn(address account, uint256 amount) internal {
        balanceOf[account] -= amount;
        totalSupply -= amount;
    }
}

contract Safe_ERC20PublicBurn {
    address public owner;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    uint256 public totalSupply;

    // SAFE: burns only from the caller.
    function burn(uint256 amount) external {
        _burn(msg.sender, amount);
    }

    // SAFE: privileged burn behind a role.
    function burnFor(address account, uint256 amount) external {
        require(msg.sender == owner, "not owner");
        _burn(account, amount);
    }

    function _burn(address account, uint256 amount) internal {
        balanceOf[account] -= amount;
        totalSupply -= amount;
    }
}

contract Vulnerable_ERC721CallbackReentrancy {
    mapping(address => uint256) public minted;
    uint256 public maxPerWallet = 3;

    // VULNERABLE: the receiver hook runs before the per-wallet counter is
    // updated, so reentering the mint bypasses the cap.
    function mint(address to, uint256 tokenId) external {
        require(minted[to] < maxPerWallet, "cap");
        _checkOnERC721Received(msg.sender, to, tokenId, "");
        minted[to] += 1;
    }

    function _checkOnERC721Received(address, address, uint256, bytes memory) internal {}
}

contract Safe_ERC721CallbackReentrancy is ReentrancyGuard {
    mapping(address => uint256) public minted;
    uint256 public maxPerWallet = 3;

    // SAFE: guarded, and the counter is updated before the hook.
    function mint(address to, uint256 tokenId) external nonReentrant {
        require(minted[to] < maxPerWallet, "cap");
        minted[to] += 1;
        _checkOnERC721Received(msg.sender, to, tokenId, "");
    }

    function _checkOnERC721Received(address, address, uint256, bytes memory) internal {}
}

contract Vulnerable_ERC777CallbackReentrancy {
    mapping(address => uint256) public deposits;

    // VULNERABLE: the ERC777 hook hands control to the recipient before the
    // deposit accounting settles.
    function deposit(address recipient, uint256 amount) external {
        IERC777Recipient(recipient).tokensReceived(msg.sender, msg.sender, recipient, amount);
        deposits[recipient] += amount;
    }
}

contract Safe_ERC777CallbackReentrancy is ReentrancyGuard {
    mapping(address => uint256) public deposits;

    // SAFE: guarded, and accounting precedes the hook.
    function deposit(address recipient, uint256 amount) external nonReentrant {
        deposits[recipient] += amount;
        IERC777Recipient(recipient).tokensReceived(msg.sender, msg.sender, recipient, amount);
    }
}
