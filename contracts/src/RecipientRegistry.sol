// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {PoseidonT3} from "poseidon-solidity/PoseidonT3.sol";

/// @title RecipientRegistry
/// @notice Merkle tree registry for recipient encryption keys (Grumpkin curve)
/// @dev Enables private membership proofs - recipients can prove registration without revealing address
contract RecipientRegistry {
    // ========================== CONSTANTS ==========================

    uint256 public constant TREE_DEPTH = 20;
    uint256 public constant FIELD_SIZE =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    // Domain separator for registry leaf (keccak256("facet.registry.leaf.v1") % FIELD_SIZE)
    uint256 public constant REG_LEAF_DOMAIN =
        0x1a2b3c4d5e6f7890abcdef1234567890abcdef1234567890abcdef12345678;

    // Grumpkin curve: y^2 = x^3 - 17 (mod FIELD_SIZE)
    uint256 internal constant CURVE_B_NEG = 17;

    // ========================== STATE ==========================

    // Merkle tree
    uint256 public nextLeafIndex;
    mapping(uint256 => uint256) public filledSubtrees;
    mapping(uint256 => uint256) public zeros;

    // Root tracking (unbounded - never evict old roots)
    uint256 public currentRoot;
    mapping(uint256 => bool) public isKnownRoot;

    // Lookup tables (for adapter convenience, not security-critical)
    mapping(address => uint256[2]) public encPublicKeys;
    mapping(address => uint256) public nullifierKeyHashes;
    mapping(address => uint256) public leafIndices;
    mapping(address => bool) public isRegistered;

    // Trusted relayer for registerFor()
    address public relayer;

    // ========================== EVENTS ==========================

    event UserRegistered(
        address indexed user,
        uint256[2] encPublicKey,
        uint256 nullifierKeyHash,
        uint256 indexed leafIndex
    );
    event RootUpdated(uint256 indexed root, uint256 indexed leafIndex);

    // ========================== ERRORS ==========================

    error AlreadyRegistered();
    error InvalidNullifierKeyHash();
    error InvalidPoint();
    error TreeFull();
    error NotRelayer();

    // ========================== CONSTRUCTOR ==========================

    constructor(address _relayer) {
        relayer = _relayer;

        // CRITICAL: Empty leaf is 0, NOT hash(0,0)
        zeros[0] = 0;

        for (uint256 i = 1; i < TREE_DEPTH; i++) {
            zeros[i] = PoseidonT3.hash([zeros[i - 1], zeros[i - 1]]);
        }
        for (uint256 i = 0; i < TREE_DEPTH; i++) {
            filledSubtrees[i] = zeros[i];
        }

        // Initial empty root
        currentRoot = zeros[TREE_DEPTH - 1];
        isKnownRoot[currentRoot] = true;
    }

    // ========================== REGISTRATION ==========================

    /// @notice Register encryption key and nullifier key hash
    /// @dev Bound to msg.sender - prevents front-running/squatting
    /// @param encPublicKey Grumpkin curve point (x, y) for ECDH encryption
    /// @param nullifierKeyHash Hash of user's nullifier key
    /// @return leafIndex The index of the new leaf in the Merkle tree
    function register(
        uint256[2] calldata encPublicKey,
        uint256 nullifierKeyHash
    ) external returns (uint256 leafIndex) {
        if (isRegistered[msg.sender]) revert AlreadyRegistered();
        if (nullifierKeyHash == 0 || nullifierKeyHash >= FIELD_SIZE) {
            revert InvalidNullifierKeyHash();
        }
        if (!_isValidPoint(encPublicKey[0], encPublicKey[1])) {
            revert InvalidPoint();
        }

        // Compute leaf with domain separator using binary tree hashing
        // leaf = hash(hash(hash(domain, address), hash(pkX, pkY)), nkHash)
        uint256 h1 = PoseidonT3.hash([REG_LEAF_DOMAIN, uint256(uint160(msg.sender))]);
        uint256 h2 = PoseidonT3.hash([encPublicKey[0], encPublicKey[1]]);
        uint256 h3 = PoseidonT3.hash([h1, h2]);
        uint256 leaf = PoseidonT3.hash([h3, nullifierKeyHash]);

        leafIndex = _insertLeaf(leaf);

        // Store for lookup
        encPublicKeys[msg.sender] = encPublicKey;
        nullifierKeyHashes[msg.sender] = nullifierKeyHash;
        leafIndices[msg.sender] = leafIndex;
        isRegistered[msg.sender] = true;

        emit UserRegistered(msg.sender, encPublicKey, nullifierKeyHash, leafIndex);
    }

    /// @notice Register on behalf of a user (relayer only)
    /// @dev Used by adapter to auto-register users during session creation
    /// @param user The address to register
    /// @param encPublicKey Grumpkin curve point (x, y) for ECDH encryption
    /// @param nullifierKeyHash Hash of user's nullifier key
    /// @return leafIndex The index of the new leaf in the Merkle tree
    function registerFor(
        address user,
        uint256[2] calldata encPublicKey,
        uint256 nullifierKeyHash
    ) external returns (uint256 leafIndex) {
        if (msg.sender != relayer) revert NotRelayer();
        if (isRegistered[user]) revert AlreadyRegistered();
        if (nullifierKeyHash == 0 || nullifierKeyHash >= FIELD_SIZE) {
            revert InvalidNullifierKeyHash();
        }
        if (!_isValidPoint(encPublicKey[0], encPublicKey[1])) {
            revert InvalidPoint();
        }

        // Compute leaf with domain separator using binary tree hashing
        // leaf = hash(hash(hash(domain, address), hash(pkX, pkY)), nkHash)
        uint256 h1 = PoseidonT3.hash([REG_LEAF_DOMAIN, uint256(uint160(user))]);
        uint256 h2 = PoseidonT3.hash([encPublicKey[0], encPublicKey[1]]);
        uint256 h3 = PoseidonT3.hash([h1, h2]);
        uint256 leaf = PoseidonT3.hash([h3, nullifierKeyHash]);

        leafIndex = _insertLeaf(leaf);

        // Store for lookup
        encPublicKeys[user] = encPublicKey;
        nullifierKeyHashes[user] = nullifierKeyHash;
        leafIndices[user] = leafIndex;
        isRegistered[user] = true;

        emit UserRegistered(user, encPublicKey, nullifierKeyHash, leafIndex);
    }

    // ========================== INTERNAL ==========================

    function _insertLeaf(uint256 leaf) internal returns (uint256 leafIndex) {
        leafIndex = nextLeafIndex;
        if (leafIndex >= 2 ** TREE_DEPTH) revert TreeFull();

        uint256 currentIndex = leafIndex;
        uint256 currentHash = leaf;

        for (uint256 i = 0; i < TREE_DEPTH; i++) {
            if (currentIndex % 2 == 0) {
                filledSubtrees[i] = currentHash;
                currentHash = PoseidonT3.hash([currentHash, zeros[i]]);
            } else {
                currentHash = PoseidonT3.hash([filledSubtrees[i], currentHash]);
            }
            currentIndex /= 2;
        }

        // Update root (unbounded - never evict old roots)
        currentRoot = currentHash;
        isKnownRoot[currentRoot] = true;

        nextLeafIndex = leafIndex + 1;

        emit RootUpdated(currentRoot, leafIndex);
    }

    /// @notice Validate point is on Grumpkin curve and not identity
    /// @dev Grumpkin: y^2 = x^3 - 17 (mod FIELD_SIZE)
    function _isValidPoint(uint256 x, uint256 y) internal pure returns (bool) {
        // Reject identity
        if (x == 0 && y == 0) return false;

        // Reject non-canonical coordinates
        if (x >= FIELD_SIZE || y >= FIELD_SIZE) return false;

        // Grumpkin: y^2 = x^3 - 17 (mod FIELD_SIZE)
        uint256 lhs = mulmod(y, y, FIELD_SIZE);
        uint256 x3 = mulmod(mulmod(x, x, FIELD_SIZE), x, FIELD_SIZE);
        uint256 rhs = addmod(x3, FIELD_SIZE - CURVE_B_NEG, FIELD_SIZE);

        return lhs == rhs;
    }

    // ========================== VIEW FUNCTIONS ==========================

    /// @notice Get the current Merkle root
    function getLatestRoot() external view returns (uint256) {
        return currentRoot;
    }

    /// @notice Get a zero value at a given depth
    function getZero(uint256 depth) external view returns (uint256) {
        return zeros[depth];
    }

    /// @notice Get the encryption public key for an address
    function getEncryptionKey(address user) external view returns (uint256[2] memory) {
        return encPublicKeys[user];
    }

    /// @notice Get the nullifier key hash for an address
    function getNullifierKeyHash(address user) external view returns (uint256) {
        return nullifierKeyHashes[user];
    }

    /// @notice Get the leaf index for an address
    function getLeafIndex(address user) external view returns (uint256) {
        return leafIndices[user];
    }
}
