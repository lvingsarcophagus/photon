// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title Vulnerable Vault — Classic Reentrancy Example
/// @notice This contract contains a known CEI violation for testing Photon's
/// reentrancy detection (PHOTON-REENTRANCY-001).
contract VulnerableVault {
    mapping(address => uint256) public balances;

    event Deposit(address indexed user, uint256 amount);
    event Withdrawal(address indexed user, uint256 amount);

    function deposit() public payable {
        balances[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    /// @notice VULNERABLE: External call before state update (CEI violation)
    function withdraw() public {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "No balance");

        // BUG: External call BEFORE state update
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        // State update AFTER external call — reentrancy possible
        balances[msg.sender] = 0;

        emit Withdrawal(msg.sender, amount);
    }

    /// @notice SAFE: State update before external call (correct CEI)
    function safeWithdraw() public {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "No balance");

        // State update BEFORE external call — safe
        balances[msg.sender] = 0;

        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        emit Withdrawal(msg.sender, amount);
    }

    function getBalance(address user) public view returns (uint256) {
        return balances[user];
    }
}
