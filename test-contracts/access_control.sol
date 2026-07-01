// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title Access Control Test — Missing Modifiers
/// @notice Tests PHOTON-ACCESS-001 and PHOTON-ACCESS-002
contract AccessControlTest {
    address public owner;
    uint256 public criticalValue;
    mapping(address => bool) public admins;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    /// @notice SAFE: Has onlyOwner modifier
    function setOwner(address newOwner) public onlyOwner {
        owner = newOwner;
    }

    /// @notice VULNERABLE: No access control on sensitive state write
    function setCriticalValue(uint256 _value) public {
        criticalValue = _value;
    }

    /// @notice VULNERABLE: No access control on admin management
    function addAdmin(address admin) public {
        admins[admin] = true;
    }

    /// @notice VULNERABLE: Unprotected selfdestruct
    function destroy(address payable recipient) public {
        selfdestruct(recipient);
    }
}
