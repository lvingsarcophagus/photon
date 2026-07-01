// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title Oracle Test — Single-source price oracle without staleness check
/// @notice Tests PHOTON-ORACLE-001

interface AggregatorV3Interface {
    function latestRoundData() external view returns (
        uint80 roundId,
        int256 answer,
        uint256 startedAt,
        uint256 updatedAt,
        uint80 answeredInRound
    );
}

contract OracleTest {
    AggregatorV3Interface public priceFeed;
    uint256 public lastPrice;

    constructor(address _priceFeed) {
        priceFeed = AggregatorV3Interface(_priceFeed);
    }

    /// @notice VULNERABLE: No staleness check on oracle data
    function getUnsafePrice() public view returns (int256) {
        (, int256 price, , , ) = priceFeed.latestRoundData();
        return price;
    }

    /// @notice SAFE: Includes staleness check
    function getSafePrice() public view returns (int256) {
        (
            uint80 roundId,
            int256 price,
            ,
            uint256 updatedAt,
            uint80 answeredInRound
        ) = priceFeed.latestRoundData();

        require(updatedAt > 0, "Round not complete");
        require(answeredInRound >= roundId, "Stale price");
        require(block.timestamp - updatedAt < 3600, "Price too old");

        return price;
    }
}
