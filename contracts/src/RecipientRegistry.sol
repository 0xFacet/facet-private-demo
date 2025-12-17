// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title RecipientRegistry
/// @notice Stores encryption public keys for shielded transfer recipients
/// @dev World-writable for demo purposes - anyone can register a key for any address (once)
contract RecipientRegistry {
    /// @notice Mapping from Ethereum address to encryption public key
    /// @dev pk_enc is a 33-byte compressed secp256k1 public key for ECIES encryption
    mapping(address => bytes) public encryptionKeys;

    /// @notice Emitted when a user registers their encryption key
    event Registered(address indexed user, bytes pkEnc);

    /// @notice Check if an address is registered
    function isRegistered(address user) external view returns (bool) {
        return encryptionKeys[user].length > 0;
    }

    /// @notice Register an encryption public key for any address
    /// @param user The address to register
    /// @param pkEnc The 33-byte compressed encryption public key (0x02/0x03 prefix + 32 bytes x-coord)
    /// @dev Can only be called once per address (no updates allowed)
    /// @dev World-writable for demo - in production would require signature from user
    function register(address user, bytes calldata pkEnc) external {
        require(pkEnc.length == 33, "Invalid public key length");
        require(pkEnc[0] == 0x02 || pkEnc[0] == 0x03, "Invalid public key prefix");
        require(encryptionKeys[user].length == 0, "Already registered");

        encryptionKeys[user] = pkEnc;
        emit Registered(user, pkEnc);
    }

    /// @notice Get the encryption public key for an address
    /// @param user The address to look up
    /// @return The 33-byte compressed encryption public key (empty if not registered)
    function getEncryptionKey(address user) external view returns (bytes memory) {
        return encryptionKeys[user];
    }
}
