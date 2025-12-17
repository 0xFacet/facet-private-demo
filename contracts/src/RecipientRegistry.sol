// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title RecipientRegistry
/// @notice Stores encryption public keys for shielded transfer recipients
/// @dev Users must register before they can receive shielded transfers
contract RecipientRegistry {
    /// @notice Mapping from Ethereum address to encryption public key
    /// @dev pk_enc is a 32-byte compressed public key for ECIES encryption
    mapping(address => bytes32) public encryptionKeys;

    /// @notice Emitted when a user registers their encryption key
    event Registered(address indexed user, bytes32 pkEnc);

    /// @notice Check if an address is registered
    function isRegistered(address user) external view returns (bool) {
        return encryptionKeys[user] != bytes32(0);
    }

    /// @notice Register an encryption public key
    /// @param pkEnc The 32-byte compressed encryption public key
    /// @dev Can only be called once per address (no updates allowed)
    function register(bytes32 pkEnc) external {
        require(pkEnc != bytes32(0), "Invalid public key");
        require(encryptionKeys[msg.sender] == bytes32(0), "Already registered");

        encryptionKeys[msg.sender] = pkEnc;
        emit Registered(msg.sender, pkEnc);
    }

    /// @notice Get the encryption public key for an address
    /// @param user The address to look up
    /// @return The encryption public key (0x0 if not registered)
    function getEncryptionKey(address user) external view returns (bytes32) {
        return encryptionKeys[user];
    }
}
