// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IVerifier} from "./IVerifier.sol";
import {RecipientRegistry} from "./RecipientRegistry.sol";
import {PoseidonT3} from "poseidon-solidity/PoseidonT3.sol";

/// @title PrivacyPool
/// @notice Shielded ETH pool with ECDSA-authorized transfers and in-circuit encryption
/// @dev Uses ZK proofs with private recipient membership proofs to prevent adapter attacks
contract PrivacyPool {
    // ========================== CONSTANTS ==========================

    uint256 public constant TREE_DEPTH = 20;
    uint256 public constant ROOT_HISTORY_SIZE = 500;
    uint256 public constant FIELD_SIZE =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    // Virtual chain ID that circuit enforces (not a real network)
    uint256 public constant VIRTUAL_CHAIN_ID = 13371337;

    // Sentinel address for withdrawals
    address public constant WITHDRAW_SENTINEL = address(0x1);

    // ========================== STATE ==========================

    IVerifier public transferVerifier;
    IVerifier public withdrawVerifier;
    RecipientRegistry public immutable registry;
    address public owner;

    // Merkle tree
    uint256 public nextLeafIndex;
    mapping(uint256 => uint256) public filledSubtrees;
    mapping(uint256 => uint256) public zeros;

    // Root history (circular buffer)
    mapping(uint256 => uint256) public rootHistory;
    uint256 public rootHistoryIndex;
    mapping(uint256 => bool) public isKnownRoot;

    // Nullifier sets
    mapping(uint256 => bool) public nullifierSpent;
    mapping(uint256 => bool) public intentUsed;

    // ========================== EVENTS ==========================

    event Deposit(
        uint256 indexed commitment,
        uint256 indexed leafIndex,
        uint256 amount,
        uint256 owner,
        uint256 randomness,
        bytes encryptedNote
    );

    event Transfer(
        uint256[2] nullifiers,
        uint256[2] commitments,
        uint256[2] leafIndices,
        uint256 intentNullifier,
        uint256[5][2] encryptedNotes
    );

    event Withdrawal(
        uint256[2] nullifiers,
        uint256 changeCommitment,
        uint256 changeLeafIndex,
        uint256 intentNullifier,
        address indexed recipient,
        uint256 amount,
        uint256[5] encryptedChange
    );

    event LeafInserted(uint256 indexed leafIndex, uint256 commitment);
    event VerifiersUpdated(address transferVerifier, address withdrawVerifier);

    // ========================== ERRORS ==========================

    error InvalidCommitment();
    error InvalidAmount();
    error InvalidOwner();
    error InvalidRandomness();
    error InvalidNullifierKeyHash();
    error InvalidProof();
    error UnknownRoot();
    error UnknownRegistryRoot();
    error NonCanonicalField();
    error NullifierAlreadySpent();
    error IntentAlreadyUsed();
    error RecipientNotRegistered();
    error InsufficientPoolBalance();
    error NotOwner();
    error DuplicateNullifier();

    // ========================== CONSTRUCTOR ==========================

    constructor(address _transferVerifier, address _withdrawVerifier, address _registry) {
        transferVerifier = IVerifier(_transferVerifier);
        withdrawVerifier = IVerifier(_withdrawVerifier);
        registry = RecipientRegistry(_registry);
        owner = msg.sender;

        // CRITICAL: Empty leaf is 0, NOT hash(0,0)
        // This must match RecipientRegistry and circuits
        zeros[0] = 0;
        for (uint256 i = 1; i < TREE_DEPTH; i++) {
            zeros[i] = PoseidonT3.hash([zeros[i - 1], zeros[i - 1]]);
        }

        // Initialize filled subtrees with zeros
        for (uint256 i = 0; i < TREE_DEPTH; i++) {
            filledSubtrees[i] = zeros[i];
        }

        // Initial root
        uint256 initialRoot = zeros[TREE_DEPTH - 1];
        rootHistory[0] = initialRoot;
        isKnownRoot[initialRoot] = true;
    }

    // ========================== ADMIN ==========================

    /// @notice Update verifier contracts (for development/upgrades)
    function setVerifiers(address _transferVerifier, address _withdrawVerifier) external {
        if (msg.sender != owner) revert NotOwner();
        transferVerifier = IVerifier(_transferVerifier);
        withdrawVerifier = IVerifier(_withdrawVerifier);
        emit VerifiersUpdated(_transferVerifier, _withdrawVerifier);
    }

    // ========================== DEPOSIT ==========================

    /// @notice Deposit ETH and create a shielded note
    /// @param noteOwner The recipient's address as a field element
    /// @param randomness Random value for commitment uniqueness
    /// @param nullifierKeyHash The hash of the recipient's nullifier key (binds note to their key)
    /// @param encryptedNote ECIES-encrypted note data for recipient
    /// @dev Commitment is computed on-chain using binary tree hashing:
    ///      hash(hash(amount, owner), hash(randomness, nkHash)) - matches circuit hash_4
    function deposit(uint256 noteOwner, uint256 randomness, uint256 nullifierKeyHash, bytes calldata encryptedNote) external payable {
        if (msg.value == 0 || msg.value >= FIELD_SIZE) revert InvalidAmount();
        if (noteOwner == 0 || noteOwner >= FIELD_SIZE) revert InvalidOwner();
        if (randomness == 0 || randomness >= FIELD_SIZE) revert InvalidRandomness();
        if (nullifierKeyHash == 0 || nullifierKeyHash >= FIELD_SIZE) revert InvalidNullifierKeyHash();

        // Compute 4-input commitment using binary tree structure (matches circuit hash_4)
        // hash_4([a,b,c,d]) = hash(hash(a,b), hash(c,d))
        uint256 h1 = PoseidonT3.hash([msg.value, noteOwner]);
        uint256 h2 = PoseidonT3.hash([randomness, nullifierKeyHash]);
        uint256 commitment = PoseidonT3.hash([h1, h2]);

        uint256 leafIndex = _insertLeaf(commitment);

        emit Deposit(commitment, leafIndex, msg.value, noteOwner, randomness, encryptedNote);
    }

    // ========================== TRANSFER ==========================

    /// @notice Private transfer between registered users
    /// @dev Circuit computes ciphertext deterministically; contract verifies hash
    /// @param proof ZK proof of valid transfer with in-circuit encryption
    /// @param merkleRoot Current pool merkle root
    /// @param registryRoot Registry merkle root (for private recipient membership proof)
    /// @param nullifiers Nullifiers for the 2 input notes
    /// @param outputCommitments Commitments for the 2 output notes
    /// @param intentNullifier Nullifier binding the signed intent
    /// @param encryptedNotes In-circuit encrypted output notes [recipient, change]
    function transfer(
        bytes calldata proof,
        uint256 merkleRoot,
        uint256 registryRoot,
        uint256[2] calldata nullifiers,
        uint256[2] calldata outputCommitments,
        uint256 intentNullifier,
        uint256[5][2] calldata encryptedNotes
    ) external {
        // ===== CANONICAL FIELD CHECKS (ALL inputs) =====
        if (merkleRoot >= FIELD_SIZE) revert NonCanonicalField();
        if (registryRoot >= FIELD_SIZE) revert NonCanonicalField();
        if (nullifiers[0] >= FIELD_SIZE) revert NonCanonicalField();
        if (nullifiers[1] >= FIELD_SIZE) revert NonCanonicalField();
        if (outputCommitments[0] >= FIELD_SIZE) revert NonCanonicalField();
        if (outputCommitments[1] >= FIELD_SIZE) revert NonCanonicalField();
        if (intentNullifier >= FIELD_SIZE) revert NonCanonicalField();
        for (uint256 i = 0; i < 2; i++) {
            for (uint256 j = 0; j < 5; j++) {
                if (encryptedNotes[i][j] >= FIELD_SIZE) revert NonCanonicalField();
            }
        }

        // ===== ROOT CHECKS =====
        if (!isKnownRoot[merkleRoot]) revert UnknownRoot();
        if (!registry.isKnownRoot(registryRoot)) revert UnknownRegistryRoot();

        // ===== NULLIFIER CHECKS =====
        if (nullifierSpent[nullifiers[0]]) revert NullifierAlreadySpent();
        if (nullifierSpent[nullifiers[1]]) revert NullifierAlreadySpent();
        if (nullifiers[0] == nullifiers[1]) revert DuplicateNullifier();
        if (intentUsed[intentNullifier]) revert IntentAlreadyUsed();

        // ===== COMPUTE CIPHERTEXT HASH (PoseidonT3 only - binary tree) =====
        uint256 ciphertextHash = _hashCiphertext10(encryptedNotes);

        // ===== BUILD PUBLIC INPUTS =====
        bytes32[] memory publicInputs = new bytes32[](8);
        publicInputs[0] = bytes32(merkleRoot);
        publicInputs[1] = bytes32(nullifiers[0]);
        publicInputs[2] = bytes32(nullifiers[1]);
        publicInputs[3] = bytes32(outputCommitments[0]);
        publicInputs[4] = bytes32(outputCommitments[1]);
        publicInputs[5] = bytes32(intentNullifier);
        publicInputs[6] = bytes32(registryRoot);
        publicInputs[7] = bytes32(ciphertextHash);

        // ===== VERIFY PROOF =====
        if (!transferVerifier.verify(proof, publicInputs)) revert InvalidProof();

        // ===== STATE UPDATES =====
        nullifierSpent[nullifiers[0]] = true;
        nullifierSpent[nullifiers[1]] = true;
        intentUsed[intentNullifier] = true;

        uint256 leafIndex0 = _insertLeaf(outputCommitments[0]);
        uint256 leafIndex1 = _insertLeaf(outputCommitments[1]);

        emit Transfer(
            nullifiers,
            outputCommitments,
            [leafIndex0, leafIndex1],
            intentNullifier,
            encryptedNotes
        );
    }

    // ========================== WITHDRAWAL ==========================

    /// @notice Withdraw ETH from shielded balance to public address
    /// @dev Change note uses self-encryption (no ECDH, sender encrypts to self)
    /// @param proof ZK proof of valid withdrawal with in-circuit encryption
    /// @param merkleRoot Current pool merkle root
    /// @param registryRoot Registry merkle root (for private change-to-self membership proof)
    /// @param nullifiers Nullifiers for the 2 input notes
    /// @param changeCommitment Commitment for change note (0 if no change)
    /// @param intentNullifier Nullifier binding the signed intent
    /// @param recipient Address to receive the withdrawn ETH
    /// @param amount Amount to withdraw
    /// @param encryptedChange In-circuit encrypted change note
    function withdraw(
        bytes calldata proof,
        uint256 merkleRoot,
        uint256 registryRoot,
        uint256[2] calldata nullifiers,
        uint256 changeCommitment,
        uint256 intentNullifier,
        address recipient,
        uint256 amount,
        uint256[5] calldata encryptedChange
    ) external {
        // ===== CANONICAL FIELD CHECKS (INCLUDING AMOUNT!) =====
        if (merkleRoot >= FIELD_SIZE) revert NonCanonicalField();
        if (registryRoot >= FIELD_SIZE) revert NonCanonicalField();
        if (nullifiers[0] >= FIELD_SIZE) revert NonCanonicalField();
        if (nullifiers[1] >= FIELD_SIZE) revert NonCanonicalField();
        if (changeCommitment >= FIELD_SIZE) revert NonCanonicalField();
        if (intentNullifier >= FIELD_SIZE) revert NonCanonicalField();
        if (amount >= FIELD_SIZE) revert NonCanonicalField(); // CRITICAL!
        for (uint256 j = 0; j < 5; j++) {
            if (encryptedChange[j] >= FIELD_SIZE) revert NonCanonicalField();
        }

        // ===== ROOT CHECKS =====
        if (!isKnownRoot[merkleRoot]) revert UnknownRoot();
        if (!registry.isKnownRoot(registryRoot)) revert UnknownRegistryRoot();

        // ===== NULLIFIER CHECKS =====
        if (nullifierSpent[nullifiers[0]]) revert NullifierAlreadySpent();
        if (nullifierSpent[nullifiers[1]]) revert NullifierAlreadySpent();
        if (nullifiers[0] == nullifiers[1]) revert DuplicateNullifier();
        if (intentUsed[intentNullifier]) revert IntentAlreadyUsed();

        // ===== BALANCE CHECK =====
        if (address(this).balance < amount) revert InsufficientPoolBalance();

        // ===== COMPUTE CHANGE CIPHERTEXT HASH =====
        uint256 changeCiphertextHash = _hashCiphertext5(encryptedChange);

        // ===== BUILD PUBLIC INPUTS =====
        bytes32[] memory publicInputs = new bytes32[](9);
        publicInputs[0] = bytes32(merkleRoot);
        publicInputs[1] = bytes32(nullifiers[0]);
        publicInputs[2] = bytes32(nullifiers[1]);
        publicInputs[3] = bytes32(changeCommitment);
        publicInputs[4] = bytes32(intentNullifier);
        publicInputs[5] = bytes32(uint256(uint160(recipient)));
        publicInputs[6] = bytes32(amount);
        publicInputs[7] = bytes32(registryRoot);
        publicInputs[8] = bytes32(changeCiphertextHash);

        // ===== VERIFY PROOF =====
        if (!withdrawVerifier.verify(proof, publicInputs)) revert InvalidProof();

        // ===== STATE UPDATES =====
        nullifierSpent[nullifiers[0]] = true;
        nullifierSpent[nullifiers[1]] = true;
        intentUsed[intentNullifier] = true;

        uint256 changeLeafIndex = 0;
        if (changeCommitment != 0) {
            changeLeafIndex = _insertLeaf(changeCommitment);
        }

        // ===== SEND ETH =====
        (bool success,) = recipient.call{value: amount}("");
        require(success, "ETH transfer failed");

        emit Withdrawal(
            nullifiers,
            changeCommitment,
            changeLeafIndex,
            intentNullifier,
            recipient,
            amount,
            encryptedChange
        );
    }

    // ========================== INTERNAL ==========================

    /// @notice Insert a leaf into the merkle tree
    /// @param leaf The commitment to insert
    /// @return leafIndex The index of the inserted leaf
    function _insertLeaf(uint256 leaf) internal returns (uint256 leafIndex) {
        leafIndex = nextLeafIndex;
        require(leafIndex < 2 ** TREE_DEPTH, "Tree is full");

        uint256 currentIndex = leafIndex;
        uint256 currentHash = leaf;

        for (uint256 i = 0; i < TREE_DEPTH; i++) {
            if (currentIndex % 2 == 0) {
                // Current is left child
                filledSubtrees[i] = currentHash;
                currentHash = PoseidonT3.hash([currentHash, zeros[i]]);
            } else {
                // Current is right child
                currentHash = PoseidonT3.hash([filledSubtrees[i], currentHash]);
            }
            currentIndex /= 2;
        }

        // Update root history
        rootHistoryIndex = (rootHistoryIndex + 1) % ROOT_HISTORY_SIZE;
        rootHistory[rootHistoryIndex] = currentHash;
        isKnownRoot[currentHash] = true;

        nextLeafIndex = leafIndex + 1;

        emit LeafInserted(leafIndex, leaf);
    }

    /// @notice Hash 5-element ciphertext using binary tree (PoseidonT3 only)
    /// @dev Binary tree: hash(hash(hash(c0,c1), hash(c2,c3)), c4)
    function _hashCiphertext5(uint256[5] calldata c) internal pure returns (uint256) {
        uint256 h01 = PoseidonT3.hash([c[0], c[1]]);
        uint256 h23 = PoseidonT3.hash([c[2], c[3]]);
        uint256 h0123 = PoseidonT3.hash([h01, h23]);
        return PoseidonT3.hash([h0123, c[4]]);
    }

    /// @notice Hash 10-element ciphertext (two notes) using binary tree
    /// @dev Hashes each note, then combines
    function _hashCiphertext10(uint256[5][2] calldata notes) internal pure returns (uint256) {
        uint256 h0 = _hashCiphertext5(notes[0]);
        uint256 h1 = _hashCiphertext5(notes[1]);
        return PoseidonT3.hash([h0, h1]);
    }

    // ========================== VIEW FUNCTIONS ==========================

    /// @notice Get the current merkle root
    function getLastRoot() external view returns (uint256) {
        return rootHistory[rootHistoryIndex];
    }

    /// @notice Get a zero value at a given depth
    function getZero(uint256 depth) external view returns (uint256) {
        return zeros[depth];
    }

    /// @notice Allow contract to receive ETH (for gas refunds, etc.)
    receive() external payable {}
}
