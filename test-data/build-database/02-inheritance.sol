// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title Test 02: Inheritance
 * @notice Tests contract inheritance and C3 linearization
 */

// Base contracts
interface IERC20 {
    function totalSupply() external view returns (uint256);
}

interface IOwnable {
    function owner() external view returns (address);
}

abstract contract Context {
    function _msgSender() internal view virtual returns (address) {
        return msg.sender;
    }
}

abstract contract Pausable is Context {
    bool private _paused;

    function paused() public view returns (bool) {
        return _paused;
    }

    function _pause() internal {
        _paused = true;
    }

    function _unpause() internal {
        _paused = false;
    }
}

abstract contract Ownable is Context {
    address private _owner;

    constructor() {
        _owner = _msgSender();
    }

    function owner() public view returns (address) {
        return _owner;
    }

    modifier onlyOwner() {
        require(_msgSender() == _owner, "Not owner");
        _;
    }
}

// Diamond inheritance pattern
// MyToken inherits from both Pausable and Ownable
// Both inherit from Context
// C3 linearization: MyToken -> Pausable -> Ownable -> Context
contract MyToken is Pausable, Ownable, IERC20, IOwnable {
    mapping(address => uint256) private _balances;
    uint256 private _totalSupply;

    function totalSupply() external view override returns (uint256) {
        return _totalSupply;
    }

    function mint(address to, uint256 amount) external onlyOwner {
        require(!paused(), "Paused");
        _balances[to] += amount;
        _totalSupply += amount;
    }

    function pause() external onlyOwner {
        _pause();
    }

    function unpause() external onlyOwner {
        _unpause();
    }
}
