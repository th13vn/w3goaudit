// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// File-level user-defined value type (UDVT).
type Amount is uint256;

library SafeCastLib {
    function toU128(uint256 x) internal pure returns (uint128) {
        return uint128(x);
    }
}

interface IToken {
    function balanceOf(address who) external view returns (uint256);
}

// Fixture for Phase-B xref binding: member calls, library `using` calls, UDVT
// wrap/unwrap, type casts, modifier usage, plus revert/emit + identifier spans.
contract XrefBindings {
    using SafeCastLib for uint256;

    error Unauthorized(address who);
    event Moved(address indexed to, uint256 amount);

    address public owner;
    IToken public token;
    mapping(address => uint256) public balances;

    modifier onlyOwner() {
        if (msg.sender != owner) revert Unauthorized(msg.sender);
        _;
    }

    function move(address to, uint256 amount) external onlyOwner {
        balances[to] = amount;
        uint128 half = amount.toU128(); // library `using` call -> SafeCastLib.toU128
        Amount a = Amount.wrap(amount); // UDVT wrap -> Amount
        uint256 back = Amount.unwrap(a); // UDVT unwrap -> Amount
        uint256 bal = token.balanceOf(to); // external member call -> IToken.balanceOf
        IToken casted = IToken(owner); // type cast -> IToken
        emit Moved(to, amount);
        half;
        back;
        bal;
        casted;
    }
}
