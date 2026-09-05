// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Deferred oracle and pricing fixtures. Protocol-specific variants remain
// useful while generic tuple, freshness, and price-use evidence is developed.

interface IAggregator {
    function latestRoundData()
        external
        view
        returns (uint80 roundId, int256 answer, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound);
    function latestAnswer() external view returns (int256);
}

interface ICurvePool {
    function get_p() external view returns (uint256);
    function price_oracle() external view returns (uint256);
}

contract Vulnerable_OraclePriceUpdateUnrestricted {
    mapping(address => uint256) public assetPrice;
    uint256 public oracleTimestamp;

    // VULNERABLE: anyone can set the reference price.
    function setAssetPrice(address asset, uint256 price) external {
        assetPrice[asset] = price;
    }

    // VULNERABLE: matched by the oracle/price name shape, still unauthenticated.
    function updateOracleTimestamp(uint256 stamp) external {
        oracleTimestamp = stamp;
    }
}

contract Safe_OraclePriceUpdateUnrestricted {
    address public owner;
    mapping(address => uint256) public assetPrice;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    // SAFE: gated by a privileged role.
    function setAssetPrice(address asset, uint256 price) external onlyOwner {
        assetPrice[asset] = price;
    }

    // SAFE: inline caller-vs-storage assertion.
    function setPriceChecked(address asset, uint256 price) external {
        require(msg.sender == owner, "not owner");
        assetPrice[asset] = price;
    }
}

contract Vulnerable_StaleOracleData {
    IAggregator public feed;

    // VULNERABLE: the round is consumed with no freshness or sanity check.
    function price() external view returns (uint256) {
        (, int256 answer, , , ) = feed.latestRoundData();
        return uint256(answer);
    }
}

contract Safe_StaleOracleData {
    IAggregator public feed;
    uint256 public maxStaleness = 3600;

    // SAFE: validates the answer and its age.
    function price() external view returns (uint256) {
        (, int256 answer, , uint256 updatedAt, ) = feed.latestRoundData();
        require(answer > 0, "bad answer");
        require(block.timestamp - updatedAt <= maxStaleness, "stale");
        return uint256(answer);
    }
}

contract Vulnerable_DeprecatedChainlinkLatestAnswer {
    IAggregator public feed;

    // VULNERABLE: deprecated API that cannot report staleness.
    function price() external view returns (int256) {
        return feed.latestAnswer();
    }
}

contract Safe_DeprecatedChainlinkLatestAnswer {
    IAggregator public feed;

    // SAFE: uses the current API with full validation.
    function price() external view returns (uint256) {
        (uint80 roundId, int256 answer, , uint256 updatedAt, uint80 answeredInRound) = feed.latestRoundData();
        require(answer > 0, "bad answer");
        require(updatedAt != 0, "incomplete round");
        require(answeredInRound >= roundId, "stale round");
        return uint256(answer);
    }
}

contract Vulnerable_OracleLpSpotPrice {
    uint256 public reserve0;
    uint256 public totalSupply;

    // VULNERABLE: spot reserves over supply — flash-loan manipulable.
    function getLpPrice() external view returns (uint256) {
        return reserve0 / totalSupply;
    }
}

contract Safe_OracleLpSpotPrice {
    IAggregator public feed;
    uint256 public reserve0;
    uint256 public totalSupply;

    // SAFE: priced from an external feed, not from spot reserves.
    function getLpPrice() external view returns (uint256) {
        (, int256 answer, , , ) = feed.latestRoundData();
        require(answer > 0, "bad answer");
        return uint256(answer);
    }
}

contract Vulnerable_OracleCurveSpotPrice {
    ICurvePool public pool;

    // VULNERABLE: returns the instantaneous spot price.
    function price() external view returns (uint256) {
        return pool.get_p();
    }
}

contract Safe_OracleCurveSpotPrice {
    ICurvePool public pool;

    // SAFE: reads the pool's smoothed EMA oracle instead.
    function price() external view returns (uint256) {
        return pool.price_oracle();
    }
}
