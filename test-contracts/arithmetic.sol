// SPDX-License-Identifier: MIT
pragma solidity ^0.7.0;

/// @title Arithmetic Test — Unchecked Math in pre-0.8.0
/// @notice Tests PHOTON-ARITH-001
contract ArithmeticTest {
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;

    /// @notice VULNERABLE: No SafeMath in Solidity 0.7.x
    function mint(address to, uint256 amount) public {
        totalSupply += amount;      // Can overflow
        balanceOf[to] += amount;    // Can overflow
    }

    function burn(address from, uint256 amount) public {
        totalSupply -= amount;      // Can underflow
        balanceOf[from] -= amount;  // Can underflow
    }

    function transfer(address to, uint256 amount) public {
        balanceOf[msg.sender] -= amount;  // Can underflow
        balanceOf[to] += amount;          // Can overflow
    }
}
