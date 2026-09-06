// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IContextSink {
    function credit(uint256 amount) external;
}

abstract contract TransactionContextBase {
    mapping(address => uint256) internal inheritedShares;

    function _baseCredit(address user, uint256 amount) internal {
        inheritedShares[user] += amount;
    }
}

contract TransactionContextMatrix is TransactionContextBase {
    mapping(address => uint256) public shares;
    uint256[] internal storedValues;
    event Observed(uint256 value);

    function directState(address[] calldata users) external payable {
        for (uint256 i = 0; i < users.length; i++) {
            shares[users[i]] += msg.value;
        }
    }

    function callValue(address payable[] calldata users) external payable {
        for (uint256 i = 0; i < users.length; i++) {
            (bool ok,) = users[i].call{value: msg.value}("");
            require(ok);
        }
    }

    function statefulHelper(address[] calldata users) external payable {
        for (uint256 i = 0; i < users.length; i++) {
            _credit(users[i], msg.value);
        }
    }

    function transitiveHelper(address[] calldata users) external payable {
        for (uint256 i = 0; i < users.length; i++) {
            _creditThroughHelper(users[i], msg.value);
        }
    }

    function localAlias(address[] calldata users) external payable {
        for (uint256 i = 0; i < users.length; i++) {
            uint256 amount = msg.value;
            shares[users[i]] += amount;
        }
    }

    function twoAliasEffects(address[] calldata users) external payable {
        for (uint256 i = 0; i < users.length; i++) {
            uint256 amount = msg.value;
            shares[users[i]] += amount;
            inheritedShares[users[i]] += amount;
        }
    }

    function reassignedAlias(address[] calldata users) external payable {
        for (uint256 i = 0; i < users.length; i++) {
            uint256 amount = msg.value;
            amount = 1;
            shares[users[i]] += amount;
        }
    }

    function branchAlias(address[] calldata users, bool enabled) external payable {
        for (uint256 i = 0; i < users.length; i++) {
            uint256 amount;
            if (enabled) amount = msg.value;
            shares[users[i]] += amount;
        }
    }

    function ternaryAlias(address[] calldata users, bool enabled) external payable {
        for (uint256 i = 0; i < users.length; i++) {
            uint256 amount = enabled ? msg.value : 0;
            shares[users[i]] += amount;
        }
    }

    function ternaryDirect(address[] calldata users, bool enabled) external payable {
        for (uint256 i = 0; i < users.length; i++) {
            shares[users[i]] += enabled ? msg.value : 0;
        }
    }

    function tupleAlias(address[] calldata users) external payable {
        for (uint256 i = 0; i < users.length; i++) {
            (uint256 amount, uint256 ignored) = (msg.value, 0);
            shares[users[i]] += amount;
        }
    }

    function unresolvedReturnAlias(address[] calldata users) external payable {
        for (uint256 i = 0; i < users.length; i++) {
            uint256 amount = _observe(msg.value);
            shares[users[i]] += amount;
        }
    }

    function arithmetic(address[] calldata users) external payable {
        for (uint256 i = 0; i < users.length; i++) {
            shares[users[i]] += msg.value / users.length;
        }
    }

    function pushValue(address[] calldata users) external payable {
        for (uint256 i = 0; i < users.length; i++) {
            storedValues.push(msg.value);
        }
    }

    function transferValue(address payable[] calldata users) external payable {
        for (uint256 i = 0; i < users.length; i++) {
            users[i].transfer(msg.value);
        }
    }

    function sendValue(address payable[] calldata users) external payable {
        for (uint256 i = 0; i < users.length; i++) {
            users[i].send(msg.value);
        }
    }

    function assemblyStateWrite(address[] calldata users) external payable {
        for (uint256 i = 0; i < users.length; i++) {
            uint256 amount = msg.value;
            assembly {
                sstore(0, amount)
            }
        }
    }

    function assemblyCallValue(address payable[] calldata users) external payable {
        for (uint256 i = 0; i < users.length; i++) {
            uint256 amount = msg.value;
            address target = users[i];
            assembly {
                let ok := call(gas(), target, amount, 0, 0, 0, 0)
                if iszero(ok) { revert(0, 0) }
            }
        }
    }

    function assemblyCreateValue(address[] calldata users) external payable {
        for (uint256 i = 0; i < users.length; i++) {
            uint256 amount = msg.value;
            assembly {
                let deployed := create(amount, 0, 0)
            }
        }
    }

    function assemblyCreate2Value(address[] calldata users) external payable {
        for (uint256 i = 0; i < users.length; i++) {
            uint256 amount = msg.value;
            assembly {
                let deployed := create2(amount, 0, 0, i)
            }
        }
    }

    function assemblySstoreKeyOnly(address[] calldata users) external payable {
        for (uint256 i = 0; i < users.length; i++) {
            uint256 amount = msg.value;
            assembly {
                sstore(amount, 0)
            }
        }
    }

    function assemblyCallTargetOnly(address[] calldata users) external payable {
        for (uint256 i = 0; i < users.length; i++) {
            uint256 amount = msg.value;
            assembly {
                let ok := call(gas(), amount, 0, 0, 0, 0, 0)
            }
        }
    }

    function assemblyCreateOffsetOnly(address[] calldata users) external payable {
        for (uint256 i = 0; i < users.length; i++) {
            uint256 amount = msg.value;
            assembly {
                let deployed := create(0, amount, 0)
            }
        }
    }

    function assemblyCreate2SaltOnly(address[] calldata users) external payable {
        for (uint256 i = 0; i < users.length; i++) {
            uint256 amount = msg.value;
            assembly {
                let deployed := create2(0, 0, 0, amount)
            }
        }
    }

    function emitOnly(address[] calldata users) external payable {
        for (uint256 i = 0; i < users.length; i++) {
            emit Observed(msg.value);
        }
    }

    function conditionOnly(address[] calldata users) external payable {
        for (uint256 i = 0; i < users.length; i++) {
            if (msg.value > 0) emit Observed(i);
        }
    }

    function localOnly(address[] calldata users) external payable {
        for (uint256 i = 0; i < users.length; i++) {
            uint256 amount = msg.value;
            emit Observed(amount);
        }
    }

    function returnOnly(address[] calldata users) external payable returns (uint256) {
        for (uint256 i = 0; i < users.length; i++) {
            return msg.value;
        }
        return 0;
    }

    function oneIteration(address user) external payable {
        for (uint256 i = 0; i < 1; i++) {
            shares[user] += msg.value;
        }
    }

    function doOnce(address user) external payable {
        do {
            shares[user] += msg.value;
        } while (false);
    }

    function nested(address[] calldata users) external payable {
        for (uint256 outer = 0; outer < users.length; outer++) {
            for (uint256 inner = 0; inner < 1; inner++) {
                shares[users[outer]] += msg.value;
            }
        }
    }

    function whileFalse(address user) external payable {
        while (false) {
            shares[user] += msg.value;
        }
    }

    function missingIncrement(address user) external payable {
        for (uint256 i = 0; i < 1;) {
            shares[user] += msg.value;
            break;
        }
    }

    function falseFor(address user) external payable {
        for (uint256 i = 1; i < 1; i++) {
            shares[user] += msg.value;
        }
    }

    function pureHelper(address[] calldata users) external payable {
        for (uint256 i = 0; i < users.length; i++) {
            _observe(msg.value);
        }
    }

    function unresolvedHelper(address[] calldata users) external payable {
        for (uint256 i = 0; i < users.length; i++) {
            _missing(msg.value);
        }
    }

    function mappingKeyOnly(address[] calldata users) external payable {
        for (uint256 i = 0; i < users.length; i++) {
            shares[address(uint160(msg.value))] += 1;
        }
    }

    function externalCalldata(address[] calldata users, IContextSink sink) external payable {
        for (uint256 i = 0; i < users.length; i++) {
            sink.credit(msg.value);
        }
    }

    function inheritedHelper(address[] calldata users) external payable {
        for (uint256 i = 0; i < users.length; i++) {
            _baseCredit(users[i], msg.value);
        }
    }

    function superHelper(address[] calldata users) external payable {
        for (uint256 i = 0; i < users.length; i++) {
            super._baseCredit(users[i], msg.value);
        }
    }

    function selfHelper(address[] calldata users) external payable {
        for (uint256 i = 0; i < users.length; i++) {
            this.selfCredit(users[i], msg.value);
        }
    }

    function selfCredit(address user, uint256 amount) external {
        shares[user] += amount;
    }

    function _credit(address user, uint256 amount) internal {
        shares[user] += amount;
    }

    function _creditThroughHelper(address user, uint256 amount) internal {
        _credit(user, amount);
    }

    function _observe(uint256 amount) internal pure returns (uint256) {
        return amount;
    }
}
