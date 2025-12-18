// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title RecipientRegistry
/// @notice Stores encryption public keys and nullifier key hashes for shielded transfer recipients
/// @dev World-writable for demo purposes - anyone can register a key for any address (once)
contract RecipientRegistry {
    /// @notice Mapping from Ethereum address to encryption public key
    /// @dev pk_enc is a 33-byte compressed secp256k1 public key for ECIES encryption
    mapping(address => bytes) public encryptionKeys;

    /// @notice Mapping from Ethereum address to nullifier key hash
    /// @dev Used to bind note commitments to a user's nullifier key
    mapping(address => uint256) public nullifierKeyHashes;

    /// @notice Emitted when a user registers their keys
    event Registered(address indexed user, bytes pkEnc, uint256 nullifierKeyHash);

    /// @notice Check if an address is registered
    function isRegistered(address user) external view returns (bool) {
        return encryptionKeys[user].length > 0 && nullifierKeyHashes[user] != 0;
    }

    /// @notice Register encryption public key and nullifier key hash for any address
    /// @param user The address to register
    /// @param pkEnc The 33-byte compressed encryption public key (0x02/0x03 prefix + 32 bytes x-coord)
    /// @param nullifierKeyHash The hash of the user's nullifier key (poseidon(nullifierKey, 1))
    /// @dev Can only be called once per address (no updates allowed)
    /// @dev World-writable for demo - in production would require signature from user
    function register(address user, bytes calldata pkEnc, uint256 nullifierKeyHash) external {
        require(pkEnc.length == 33, "Invalid public key length");
        require(pkEnc[0] == 0x02 || pkEnc[0] == 0x03, "Invalid public key prefix");
        require(encryptionKeys[user].length == 0, "Already registered");
        require(nullifierKeyHash != 0, "Invalid nullifierKeyHash");

        encryptionKeys[user] = pkEnc;
        nullifierKeyHashes[user] = nullifierKeyHash;
        emit Registered(user, pkEnc, nullifierKeyHash);
    }

    /// @notice Get the encryption public key for an address
    /// @param user The address to look up
    /// @return The 33-byte compressed encryption public key (empty if not registered)
    function getEncryptionKey(address user) external view returns (bytes memory) {
        return encryptionKeys[user];
    }

    /// @notice Get the nullifier key hash for an address
    /// @param user The address to look up
    /// @return The nullifier key hash (0 if not registered)
    function getNullifierKeyHash(address user) external view returns (uint256) {
        return nullifierKeyHashes[user];
    }
}
