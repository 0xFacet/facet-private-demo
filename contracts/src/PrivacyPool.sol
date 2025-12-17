// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IVerifier} from "./IVerifier.sol";
import {RecipientRegistry} from "./RecipientRegistry.sol";
import {PoseidonT3} from "poseidon-solidity/PoseidonT3.sol";
import {PoseidonT4} from "poseidon-solidity/PoseidonT4.sol";
import {PoseidonT6} from "poseidon-solidity/PoseidonT6.sol";

/// @title PrivacyPool
/// @notice Shielded ETH pool with ECDSA-authorized transfers
/// @dev Uses ZK proofs to verify transfers while hiding amounts and graph
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
        bytes encryptedNote
    );

    event Transfer(
        uint256[2] nullifiers,
        uint256[2] commitments,
        uint256[2] leafIndices,
        uint256 intentNullifier,
        bytes[2] encryptedNotes
    );

    event Withdrawal(
        uint256[2] nullifiers,
        uint256 changeCommitment,
        uint256 changeLeafIndex,
        uint256 intentNullifier,
        address indexed recipient,
        uint256 amount,
        bytes encryptedChange
    );

    event LeafInserted(uint256 indexed leafIndex, uint256 commitment);
    event VerifiersUpdated(address transferVerifier, address withdrawVerifier);

    // ========================== ERRORS ==========================

    error InvalidCommitment();
    error InvalidAmount();
    error InvalidProof();
    error UnknownRoot();
    error NullifierAlreadySpent();
    error IntentAlreadyUsed();
    error RecipientNotRegistered();
    error InsufficientPoolBalance();
    error NotOwner();

    // ========================== CONSTRUCTOR ==========================

    constructor(address _transferVerifier, address _withdrawVerifier, address _registry) {
        transferVerifier = IVerifier(_transferVerifier);
        withdrawVerifier = IVerifier(_withdrawVerifier);
        registry = RecipientRegistry(_registry);
        owner = msg.sender;

        // Initialize zero values for empty Merkle tree
        // zeros[0] = poseidon(0, 0) for empty leaf
        zeros[0] = PoseidonT3.hash([uint256(0), uint256(0)]);
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
    /// @param commitment poseidon(amount, recipientAddress, randomness)
    /// @param encryptedNote ECIES-encrypted note data for recipient
    function deposit(uint256 commitment, bytes calldata encryptedNote) external payable {
        if (commitment == 0 || commitment >= FIELD_SIZE) revert InvalidCommitment();
        if (msg.value == 0 || msg.value >= FIELD_SIZE) revert InvalidAmount();

        uint256 leafIndex = _insertLeaf(commitment);

        emit Deposit(commitment, leafIndex, msg.value, encryptedNote);
    }

    // ========================== TRANSFER ==========================

    /// @notice Private transfer between registered users
    /// @param proof ZK proof of valid transfer
    /// @param merkleRoot Current merkle root
    /// @param nullifiers Nullifiers for the 2 input notes
    /// @param outputCommitments Commitments for the 2 output notes
    /// @param intentNullifier Nullifier binding the signed intent
    /// @param encryptedNotes ECIES-encrypted output notes
    function transfer(
        bytes calldata proof,
        uint256 merkleRoot,
        uint256[2] calldata nullifiers,
        uint256[2] calldata outputCommitments,
        uint256 intentNullifier,
        bytes[2] calldata encryptedNotes
    ) external {
        // Verify merkle root is recent
        if (!isKnownRoot[merkleRoot]) revert UnknownRoot();

        // Check nullifiers not spent
        if (nullifierSpent[nullifiers[0]]) revert NullifierAlreadySpent();
        if (nullifierSpent[nullifiers[1]]) revert NullifierAlreadySpent();

        // Check intent not used
        if (intentUsed[intentNullifier]) revert IntentAlreadyUsed();

        // Build public inputs for verifier
        bytes32[] memory publicInputs = new bytes32[](7);
        publicInputs[0] = bytes32(merkleRoot);
        publicInputs[1] = bytes32(nullifiers[0]);
        publicInputs[2] = bytes32(nullifiers[1]);
        publicInputs[3] = bytes32(outputCommitments[0]);
        publicInputs[4] = bytes32(outputCommitments[1]);
        publicInputs[5] = bytes32(intentNullifier);
        publicInputs[6] = bytes32(VIRTUAL_CHAIN_ID);

        // Verify proof
        if (!transferVerifier.verify(proof, publicInputs)) revert InvalidProof();

        // Mark nullifiers and intent as used
        nullifierSpent[nullifiers[0]] = true;
        nullifierSpent[nullifiers[1]] = true;
        intentUsed[intentNullifier] = true;

        // Insert output commitments
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
    /// @param proof ZK proof of valid withdrawal
    /// @param merkleRoot Current merkle root
    /// @param nullifiers Nullifiers for the 2 input notes
    /// @param changeCommitment Commitment for change note (0 if no change)
    /// @param intentNullifier Nullifier binding the signed intent
    /// @param recipient Address to receive the withdrawn ETH
    /// @param amount Amount to withdraw
    /// @param encryptedChange ECIES-encrypted change note
    function withdraw(
        bytes calldata proof,
        uint256 merkleRoot,
        uint256[2] calldata nullifiers,
        uint256 changeCommitment,
        uint256 intentNullifier,
        address recipient,
        uint256 amount,
        bytes calldata encryptedChange
    ) external {
        // Verify merkle root is recent
        if (!isKnownRoot[merkleRoot]) revert UnknownRoot();

        // Check nullifiers not spent
        if (nullifierSpent[nullifiers[0]]) revert NullifierAlreadySpent();
        if (nullifierSpent[nullifiers[1]]) revert NullifierAlreadySpent();

        // Check intent not used
        if (intentUsed[intentNullifier]) revert IntentAlreadyUsed();

        // Check pool has enough balance
        if (address(this).balance < amount) revert InsufficientPoolBalance();

        // Build public inputs for verifier
        bytes32[] memory publicInputs = new bytes32[](8);
        publicInputs[0] = bytes32(merkleRoot);
        publicInputs[1] = bytes32(nullifiers[0]);
        publicInputs[2] = bytes32(nullifiers[1]);
        publicInputs[3] = bytes32(changeCommitment);
        publicInputs[4] = bytes32(intentNullifier);
        publicInputs[5] = bytes32(uint256(uint160(recipient)));
        publicInputs[6] = bytes32(amount);
        publicInputs[7] = bytes32(VIRTUAL_CHAIN_ID);

        // Verify proof
        if (!withdrawVerifier.verify(proof, publicInputs)) revert InvalidProof();

        // Mark nullifiers and intent as used
        nullifierSpent[nullifiers[0]] = true;
        nullifierSpent[nullifiers[1]] = true;
        intentUsed[intentNullifier] = true;

        // Insert change commitment if non-zero
        uint256 changeLeafIndex = 0;
        if (changeCommitment != 0) {
            changeLeafIndex = _insertLeaf(changeCommitment);
        }

        // Send ETH to recipient
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
