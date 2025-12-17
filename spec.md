## Introduction: Why This Architecture Exists

### The Problem with Private Transactions Today

Every existing privacy solution on Ethereum—Tornado Cash, Railgun, Aztec—requires users to manage a separate set of cryptographic keys. You generate a "shielded wallet," back up a new seed phrase, and interact through custom interfaces. This isn't just inconvenient; it's a fundamental barrier to adoption. Users don't want another wallet. They want their existing wallet to just... work privately.

The mental model shift is significant: instead of "send 70 ETH to Bob," users have to think about "deposit to shielded pool, wait for anonymity set, generate proof with my shielded key, withdraw to fresh address." The privacy is real, but the UX is a research project.

### The Core Insight

What if we could keep the spending authority exactly where it already is—in the user's Ethereum private key, secured by MetaMask—and move only the *visibility* into a separate layer?

That's what this system does. When you click "Send" in MetaMask, you're signing a real Ethereum transaction. That signature is your authorization to spend. The ZK circuit verifies that signature *inside the proof*, which means:

1. **No new keys to manage.** Your ETH private key is your spending key.
2. **No new interfaces to learn.** MetaMask's Send flow is the UX.
3. **No trust in the adapter for spending.** The adapter can see your balance (it has your viewing key), but it literally cannot move your funds without your MetaMask signature.

The adapter is more like a privacy-preserving RPC node than a wallet. It watches the chain, decrypts your notes, and constructs proofs—but every spend requires you to sign with MetaMask.

### Why a Virtual Chain ID?

There's an obvious attack if we're not careful: if the user signs a transaction targeting Sepolia (chainId 11155111), that transaction is valid on Sepolia. A malicious actor could intercept it and broadcast it, draining the user's *public* ETH to whatever address was in the `to` field.

The fix is elegant: we present MetaMask with a fake chain ID (13371337) that doesn't correspond to any real network. The signed transaction is cryptographically valid, but useless on any actual blockchain. The adapter extracts the signature, verifies it inside the ZK circuit, and submits a *different* transaction (the proof) to Sepolia. The user's signature authorizes the private transfer; it never touches L1 directly.

### What This Proves

This demo is a standalone extraction of the private payments layer from a larger system—a privacy-oriented L2 rollup where all EOA balances are shielded by default. Building a full rollup is months of work. But the core innovation—ECDSA authorization inside ZK, preserving the MetaMask UX—can be demonstrated in a much smaller package.

If this works, we've proven:

1. **ECDSA-in-ZK is practical.** Yes, it's expensive (~400k constraints for secp256k1 + keccak), but modern provers handle it in reasonable time.

2. **The UX can be seamless.** Users add a custom RPC, sign one setup message, and then just... use MetaMask normally. Send works. Balances update. No PhD required.

3. **The trust model is sound.** The adapter is trusted with *privacy* (it sees everything), but not with *funds* (it can't forge your signature). This is a meaningful separation.

### Relationship to the Full Rollup Vision

In the complete system, this private payment mechanism would be one part of a larger privacy-preserving execution environment. The rollup would support general smart contract execution with shielded state, not just transfers. The "unshield → swap → reshield" flow would let users interact with DeFi without revealing their holdings.

But payments are the foundation. If we can't do private sends cleanly, nothing else matters. This demo isolates that foundation and proves it works.

### What the Developer Should Understand

As you implement this, keep in mind:

1. **The signed transaction is sacred.** Every constraint in the circuit exists to ensure that the user's MetaMask signature—and nothing else—authorizes the spend. The intent nullifier binds to (signer, chainId, nonce, to, value). The circuit verifies ECDSA. The adapter cannot substitute different parameters.

2. **The adapter is powerful but not dangerous.** It holds the viewing key, so it sees all notes and can compute nullifiers. But the spending authority is the ECDSA signature, which only MetaMask can produce. This is the whole point: separate visibility from control.

3. **The virtual chain ID is load-bearing.** If you accidentally use a real chain ID, signed transactions become weapons. The 13371337 ID isn't arbitrary—it's a security boundary.

4. **Two input notes is a simplification.** Real systems support variable input counts with padding. We're requiring exactly two notes to keep the circuit simple and avoid edge cases around "dummy notes." This means users need at least two deposits before they can transfer, which is fine for a demo.

5. **Events are your indexing strategy.** The `LeafInserted` event tells you where each commitment landed in the tree. Without it, you'd have to replay every transaction to reconstruct indices. Don't skip it.

### The Goal

When this is done, a user should be able to:

1. Add "Facet Private" as a network in MetaMask
2. Sign one message to derive their viewing key
3. Register their encryption pubkey (one-time, on Sepolia)
4. Deposit ETH through a simple web page
5. Send ETH to any registered recipient using MetaMask's normal Send flow
6. See their shielded balance update
7. Withdraw back to their EOA when needed

No new wallet. No seed phrases. No learning curve beyond "add network, sign message, deposit." That's the bar.

---

## Private Transfer System — Demo Specification v1.0

---

### 1. System Overview

A shielded ETH payment system where:
- Users transact via standard MetaMask "Send" flow
- Spending authority = ECDSA signature on real Ethereum transactions
- No new keys to manage beyond the standard Ethereum wallet
- Adapter handles ZK proof generation and note management
- All balances and transfers are private (amounts, sender/recipient linkage hidden)

**Key Design Decision**: The adapter presents a private chain ID (13371337) to MetaMask. Signed transactions are not valid on any real network, preventing broadcast attacks. The adapter proxies all reads to Sepolia for actual L1 state.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                                                                             │
│    User's MetaMask                                                          │
│    ┌─────────────┐                                                          │
│    │ ETH Privkey │ ── Signs EIP-1559 tx (chainId: 13371337) ──────────┐    │
│    └─────────────┘         (not valid on any real network)            │    │
│          │                                                             │    │
│          │ One-time setup signature                                    │    │
│          ▼                                                             │    │
│    ┌─────────────┐      ┌─────────────┐      ┌─────────────┐          │    │
│    │    seed     │ ───► │     nk      │      │   sk_enc    │          │    │
│    │  (secret)   │      │ (nullifier) │      │  (decrypt)  │          │    │
│    └─────────────┘      └─────────────┘      └──────┬──────┘          │    │
│                                                     │                  │    │
│                                                     ▼                  │    │
│                                              ┌─────────────┐           │    │
│                                              │   pk_enc    │           │    │
│                                              │  (public)   │           │    │
│                                              └──────┬──────┘           │    │
│                                                     │                  │    │
│    Adapter (trusted)                                │                  │    │
│    ┌────────────────────────────────────────────────┼──────────────┐  │    │
│    │  • Stores seed, nk, sk_enc                     │              │  │    │
│    │  • Proxies reads to Sepolia                    │              │  │    │
│    │  • Presents chainId 13371337 to MetaMask       │              │  │    │
│    │  • Generates ZK proofs                         │              │  │    │
│    │  • Submits txs to Sepolia                      │              │  │    │
│    │  • CANNOT spend (lacks ETH privkey)      ◄─────┘              │  │    │
│    └───────────────────────────────────────────────────────────────┘  │    │
│                                                                        │    │
│    On-Chain (Sepolia)                                                  │    │
│    ┌───────────────────────────────────────────────────────────────┐  │    │
│    │  Registry: address → pk_enc                                   │  │    │
│    │  PrivacyPool: commitments, nullifiers, intent tracking        │◄─┘    │
│    │  Verifier: validates ZK proofs                                │       │
│    └───────────────────────────────────────────────────────────────┘       │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

### 2. Constants

```solidity
// Chain IDs
uint256 constant VIRTUAL_CHAIN_ID = 13371337;  // Presented to MetaMask
uint256 constant L1_CHAIN_ID = 11155111;       // Sepolia (actual deployment)

// Tree parameters
uint256 constant TREE_DEPTH = 20;
uint256 constant ROOT_HISTORY_SIZE = 500;

// BN254 scalar field
uint256 constant FIELD_SIZE = 
    21888242871839275222246405745257275088548364400416034343698204186575808495617;

// Sentinel address for withdrawals
address constant WITHDRAW_SENTINEL = address(0x1);
```

---

### 3. Cryptographic Primitives

#### 3.1 Key Derivation

```
┌────────────────────────────────────────────────────────────────────────────┐
│  INPUT: User signs deterministic message with ETH private key              │
│                                                                            │
│  Message format (EIP-191):                                                 │
│  ┌──────────────────────────────────────────────────────────────────────┐ │
│  │ "Facet Private Transfer v1\n"                                        │ │
│  │ "Virtual Chain: 13371337\n"                                          │ │
│  │ "L1 Chain: 11155111\n"                                               │ │
│  │ "Address: 0xAlice...\n"                                              │ │
│  │ "Origin: adapter.facet.org"                                          │ │
│  └──────────────────────────────────────────────────────────────────────┘ │
│                                                                            │
│  signature = eth_sign(message)                                             │
│                                                                            │
└────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌────────────────────────────────────────────────────────────────────────────┐
│  DERIVATION:                                                               │
│                                                                            │
│  seed = keccak256(signature)                        [32 bytes, SECRET]     │
│                                                                            │
│  nk = keccak256(seed || "nullifier_key") mod FIELD_SIZE                    │
│                                              [BN254 field element]         │
│                                                                            │
│  sk_enc = keccak256(seed || "encryption_key") mod secp256k1_order          │
│           where order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
│           (reject and rehash with counter if zero)                         │
│                                              [secp256k1 scalar]            │
│                                                                            │
│  pk_enc = sk_enc * G                         [secp256k1 point]             │
│                                                                            │
└────────────────────────────────────────────────────────────────────────────┘
```

#### 3.2 Key Summary

| Key | Type | Size | Visibility | Purpose |
|-----|------|------|------------|---------|
| `seed` | bytes | 32 | Secret (adapter only) | Master secret, derive others |
| `nk` | Field | 32 | Secret (adapter only) | Compute nullifiers |
| `sk_enc` | Scalar | 32 | Secret (adapter only) | ECDH decryption |
| `pk_enc` | Point | 33 | Public (on-chain registry) | ECDH encryption for incoming notes |

#### 3.3 Note Structure

```
Note = {
    amount: uint256,           // Value in wei (must be < FIELD_SIZE)
    owner: address,            // Ethereum address (20 bytes)
    randomness: bytes32        // Random blinding factor
}

commitment = poseidon(amount, owner_as_field, randomness)    [BN254 field]
nullifier = poseidon(commitment, nk)                         [BN254 field]

// Address to field conversion (deterministic, used everywhere)
owner_as_field = uint256(uint160(ethereumAddress))
```

**Amount Constraint**: All amounts must be < FIELD_SIZE. This is enforced in the circuit and validated by the adapter. Maximum practical value: ~2^254 wei, far exceeding total ETH supply.

#### 3.4 Intent Nullifier (Replay Protection)

```
intentNullifier = poseidon(
    signer_address,     // Derived from ECDSA recovery
    VIRTUAL_CHAIN_ID,   // 13371337
    tx_nonce,           // From signed tx
    tx_to,              // Recipient address (or sentinel)
    tx_value            // Amount in wei
)
```

This binds the intent to the exact transaction contents. Same nonce cannot authorize different recipients or amounts.

#### 3.5 Encryption Scheme (ECIES over secp256k1)

```typescript
interface EncryptedNote {
    ephemeralPubkey: bytes33;   // Compressed secp256k1 point
    ciphertext: bytes;          // AES-256-GCM encrypted payload
    nonce: bytes12;             // GCM nonce
    tag: bytes16;               // GCM auth tag
}

function encrypt(
    plaintext: { amount: bigint; randomness: bytes32 },
    recipientPkEnc: Point
): EncryptedNote {
    // 1. Generate ephemeral keypair
    const eSk = randomBytes(32);
    const ePk = secp256k1.ProjectivePoint.BASE.multiply(bytesToBigInt(eSk));
    
    // 2. ECDH
    const sharedPoint = recipientPkEnc.multiply(bytesToBigInt(eSk));
    const sharedSecret = keccak256(sharedPoint.toRawBytes(true));
    
    // 3. Derive symmetric key
    const aesKey = sharedSecret.slice(0, 32);
    
    // 4. Encrypt
    const nonce = randomBytes(12);
    const payload = abi.encode(['uint256', 'bytes32'], [amount, randomness]);
    const { ciphertext, tag } = aesGcmEncrypt(payload, aesKey, nonce);
    
    return { ephemeralPubkey: ePk.toRawBytes(true), ciphertext, nonce, tag };
}

function decrypt(
    encrypted: EncryptedNote,
    skEnc: bigint
): { amount: bigint; randomness: bytes32 } {
    // 1. ECDH
    const ePk = secp256k1.ProjectivePoint.fromHex(encrypted.ephemeralPubkey);
    const sharedPoint = ePk.multiply(skEnc);
    const sharedSecret = keccak256(sharedPoint.toRawBytes(true));
    
    // 2. Decrypt
    const aesKey = sharedSecret.slice(0, 32);
    const payload = aesGcmDecrypt(encrypted.ciphertext, aesKey, encrypted.nonce, encrypted.tag);
    
    // 3. Decode
    const [amount, randomness] = abi.decode(['uint256', 'bytes32'], payload);
    return { amount, randomness };
}
```

---

### 4. Smart Contracts

#### 4.1 RecipientRegistry

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title RecipientRegistry
/// @notice Maps Ethereum addresses to secp256k1 encryption public keys
contract RecipientRegistry {
    
    /// @notice Compressed secp256k1 public key (33 bytes)
    mapping(address => bytes) public encryptionPubkey;
    
    event Registered(address indexed account, bytes pubkey);
    
    error InvalidPubkeyLength();
    error InvalidCompressionPrefix();
    
    /// @notice Register your encryption public key
    /// @param compressedPubkey 33-byte compressed secp256k1 point
    function register(bytes calldata compressedPubkey) external {
        if (compressedPubkey.length != 33) revert InvalidPubkeyLength();
        if (compressedPubkey[0] != 0x02 && compressedPubkey[0] != 0x03) {
            revert InvalidCompressionPrefix();
        }
        
        encryptionPubkey[msg.sender] = compressedPubkey;
        emit Registered(msg.sender, compressedPubkey);
    }
    
    /// @notice Check if an address is registered
    function isRegistered(address account) external view returns (bool) {
        return encryptionPubkey[account].length == 33;
    }
    
    /// @notice Get pubkey, reverting if not registered
    function getPubkey(address account) external view returns (bytes memory) {
        bytes memory pk = encryptionPubkey[account];
        require(pk.length == 33, "Not registered");
        return pk;
    }
}
```

#### 4.2 PrivacyPool

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IVerifier} from "./IVerifier.sol";
import {RecipientRegistry} from "./RecipientRegistry.sol";
import {PoseidonT3, PoseidonT4, PoseidonT6} from "./Poseidon.sol";

/// @title PrivacyPool
/// @notice Shielded ETH pool with ECDSA-authorized transfers
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
    
    // ========================== IMMUTABLES ==========================
    
    IVerifier public transferVerifier;
    IVerifier public withdrawVerifier;
    RecipientRegistry public immutable registry;
    address public owner;
    
    // ========================== STATE ==========================
    
    // Merkle tree
    uint256 public nextLeafIndex;
    mapping(uint256 => uint256) public filledSubtrees;
    uint256[ROOT_HISTORY_SIZE] public rootHistory;
    mapping(uint256 => bool) public isKnownRoot;
    uint256 public currentRootIndex;
    
    // Precomputed zeros
    uint256[TREE_DEPTH] public zeros;
    
    // Spent nullifiers (note double-spend prevention)
    mapping(uint256 => bool) public nullifierSpent;
    
    // Used intents (signature replay prevention)
    mapping(uint256 => bool) public intentUsed;
    
    // ========================== EVENTS ==========================
    
    /// @notice Emitted for every leaf insertion (enables indexing)
    event LeafInserted(
        uint256 indexed leafIndex,
        uint256 indexed commitment
    );
    
    event Deposit(
        uint256 indexed commitment,
        uint256 indexed leafIndex,
        uint256 amount,
        bytes encryptedNote
    );
    
    event Transfer(
        uint256 indexed nullifier0,
        uint256 indexed nullifier1,
        uint256 outputCommitment0,
        uint256 outputCommitment1,
        uint256 leafIndex0,
        uint256 leafIndex1,
        uint256 intentNullifier,
        bytes encryptedOutput0,
        bytes encryptedOutput1
    );
    
    event Withdrawal(
        address indexed recipient,
        uint256 amount,
        uint256 indexed nullifier0,
        uint256 indexed nullifier1,
        uint256 changeCommitment,
        uint256 changeLeafIndex,
        uint256 intentNullifier,
        bytes encryptedChange
    );
    
    // ========================== ERRORS ==========================
    
    error InvalidRoot();
    error NullifierAlreadySpent();
    error IntentAlreadyUsed();
    error InvalidProof();
    error TransferFailed();
    error TreeFull();
    error ZeroDeposit();
    error InvalidCommitment();
    error AmountTooLarge();
    error InsufficientPoolBalance();
    
    // ========================== CONSTRUCTOR ==========================
    
    constructor(
        address _transferVerifier,
        address _withdrawVerifier,
        address _registry
    ) {
        transferVerifier = IVerifier(_transferVerifier);
        withdrawVerifier = IVerifier(_withdrawVerifier);
        registry = RecipientRegistry(_registry);
        owner = msg.sender;
        
        // Initialize zero values for empty Merkle tree
        // zeros[0] = poseidon(0, 0) for empty leaf
        zeros[0] = 0x2098f5fb9e239eab3ceac3f27b81e481dc3124d55ffed523a839ee8446b64864;
        for (uint256 i = 1; i < TREE_DEPTH; i++) {
            zeros[i] = PoseidonT3.hash([zeros[i-1], zeros[i-1]]);
        }
        
        // Initialize subtrees
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
        require(msg.sender == owner, "Not owner");
        transferVerifier = IVerifier(_transferVerifier);
        withdrawVerifier = IVerifier(_withdrawVerifier);
    }

    // ========================== DEPOSIT ==========================
    
    /// @notice Deposit ETH and create a shielded note
    /// @param commitment poseidon(amount, recipientAddress, randomness)
    /// @param encryptedNote ECIES-encrypted note data for recipient
    function deposit(
        uint256 commitment,
        bytes calldata encryptedNote
    ) external payable {
        if (msg.value == 0) revert ZeroDeposit();
        if (msg.value >= FIELD_SIZE) revert AmountTooLarge();
        if (commitment >= FIELD_SIZE) revert InvalidCommitment();
        
        uint256 leafIndex = _insertLeaf(commitment);
        
        emit Deposit(commitment, leafIndex, msg.value, encryptedNote);
    }
    
    // ========================== TRANSFER ==========================
    
    /// @notice Execute a shielded transfer (requires exactly 2 input notes)
    /// @param proof ZK proof from transfer circuit
    /// @param merkleRoot Recent valid Merkle root
    /// @param nullifiers Two nullifiers for input notes
    /// @param outputCommitments Two commitments for output notes
    /// @param intentNullifier poseidon(signer, chainId, nonce, to, value)
    /// @param encryptedOutputs ECIES-encrypted notes for recipients
    function transfer(
        bytes calldata proof,
        uint256 merkleRoot,
        uint256[2] calldata nullifiers,
        uint256[2] calldata outputCommitments,
        uint256 intentNullifier,
        bytes[2] calldata encryptedOutputs
    ) external {
        // Verify Merkle root
        if (!isKnownRoot[merkleRoot]) revert InvalidRoot();
        
        // Check nullifiers
        if (nullifierSpent[nullifiers[0]]) revert NullifierAlreadySpent();
        if (nullifierSpent[nullifiers[1]]) revert NullifierAlreadySpent();
        
        // Check intent
        if (intentUsed[intentNullifier]) revert IntentAlreadyUsed();
        
        // Verify proof
        uint256[] memory publicInputs = new uint256[](6);
        publicInputs[0] = merkleRoot;
        publicInputs[1] = nullifiers[0];
        publicInputs[2] = nullifiers[1];
        publicInputs[3] = outputCommitments[0];
        publicInputs[4] = outputCommitments[1];
        publicInputs[5] = intentNullifier;
        
        if (!transferVerifier.verify(proof, publicInputs)) revert InvalidProof();
        
        // Update state
        nullifierSpent[nullifiers[0]] = true;
        nullifierSpent[nullifiers[1]] = true;
        intentUsed[intentNullifier] = true;
        
        // Insert outputs and capture indices
        uint256 leafIndex0 = _insertLeaf(outputCommitments[0]);
        uint256 leafIndex1 = _insertLeaf(outputCommitments[1]);
        
        emit Transfer(
            nullifiers[0],
            nullifiers[1],
            outputCommitments[0],
            outputCommitments[1],
            leafIndex0,
            leafIndex1,
            intentNullifier,
            encryptedOutputs[0],
            encryptedOutputs[1]
        );
    }
    
    // ========================== WITHDRAWAL ==========================
    
    /// @notice Withdraw ETH from shielded pool
    /// @param proof ZK proof from withdraw circuit
    /// @param merkleRoot Recent valid Merkle root
    /// @param nullifiers Two nullifiers for input notes
    /// @param withdrawAmount Amount to withdraw (public)
    /// @param withdrawRecipient Address to receive ETH (public)
    /// @param changeCommitment Commitment for change note (0 if no change)
    /// @param intentNullifier poseidon(signer, chainId, nonce, to, value)
    /// @param encryptedChange ECIES-encrypted change note
    function withdraw(
        bytes calldata proof,
        uint256 merkleRoot,
        uint256[2] calldata nullifiers,
        uint256 withdrawAmount,
        address withdrawRecipient,
        uint256 changeCommitment,
        uint256 intentNullifier,
        bytes calldata encryptedChange
    ) external {
        if (!isKnownRoot[merkleRoot]) revert InvalidRoot();
        if (nullifierSpent[nullifiers[0]]) revert NullifierAlreadySpent();
        if (nullifierSpent[nullifiers[1]]) revert NullifierAlreadySpent();
        if (intentUsed[intentNullifier]) revert IntentAlreadyUsed();
        if (withdrawAmount > address(this).balance) revert InsufficientPoolBalance();
        if (withdrawAmount >= FIELD_SIZE) revert AmountTooLarge();
        
        // Verify proof
        uint256[] memory publicInputs = new uint256[](7);
        publicInputs[0] = merkleRoot;
        publicInputs[1] = nullifiers[0];
        publicInputs[2] = nullifiers[1];
        publicInputs[3] = withdrawAmount;
        publicInputs[4] = uint256(uint160(withdrawRecipient));
        publicInputs[5] = changeCommitment;
        publicInputs[6] = intentNullifier;
        
        if (!withdrawVerifier.verify(proof, publicInputs)) revert InvalidProof();
        
        // Update state
        nullifierSpent[nullifiers[0]] = true;
        nullifierSpent[nullifiers[1]] = true;
        intentUsed[intentNullifier] = true;
        
        // Insert change commitment if non-zero
        uint256 changeLeafIndex = type(uint256).max;  // Sentinel for no change
        if (changeCommitment != 0) {
            changeLeafIndex = _insertLeaf(changeCommitment);
        }
        
        // Transfer ETH
        (bool success, ) = withdrawRecipient.call{value: withdrawAmount}("");
        if (!success) revert TransferFailed();
        
        emit Withdrawal(
            withdrawRecipient,
            withdrawAmount,
            nullifiers[0],
            nullifiers[1],
            changeCommitment,
            changeLeafIndex,
            intentNullifier,
            encryptedChange
        );
    }
    
    // ========================== MERKLE TREE ==========================
    
    function _insertLeaf(uint256 leaf) internal returns (uint256 leafIndex) {
        if (nextLeafIndex >= 2**TREE_DEPTH) revert TreeFull();
        
        leafIndex = nextLeafIndex;
        uint256 currentIndex = leafIndex;
        uint256 currentHash = leaf;
        uint256 left;
        uint256 right;
        
        for (uint256 i = 0; i < TREE_DEPTH; i++) {
            if (currentIndex % 2 == 0) {
                left = currentHash;
                right = zeros[i];
                filledSubtrees[i] = currentHash;
            } else {
                left = filledSubtrees[i];
                right = currentHash;
            }
            currentHash = PoseidonT3.hash([left, right]);
            currentIndex /= 2;
        }
        
        currentRootIndex = (currentRootIndex + 1) % ROOT_HISTORY_SIZE;
        rootHistory[currentRootIndex] = currentHash;
        isKnownRoot[currentHash] = true;
        
        emit LeafInserted(leafIndex, leaf);
        
        nextLeafIndex++;
    }
    
    // ========================== VIEW FUNCTIONS ==========================
    
    function getLatestRoot() external view returns (uint256) {
        return rootHistory[currentRootIndex];
    }
    
    function getTreeSize() external view returns (uint256) {
        return nextLeafIndex;
    }
}
```

#### 4.3 Verifier Interface

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IVerifier {
    function verify(
        bytes calldata proof,
        uint256[] calldata publicInputs
    ) external view returns (bool);
}
```

---

### 5. ZK Circuits

> **Implementation Note**: The circuit code below is pseudocode illustrating the logical structure and constraints. The actual Noir implementation will differ in syntax, library imports, and low-level details (e.g., RLP encoding, keccak256 calls, BoundedVec handling). These will be corrected during circuit implementation.

#### 5.1 Transfer Circuit

```noir
// circuits/transfer/src/main.nr
//
// Private transfer circuit with real EIP-1559 transaction verification
// Requires exactly 2 input notes (no padding with dummy notes)

use dep::std::hash::poseidon;
use dep::std::hash::keccak256;
use dep::std::ecdsa_secp256k1;

// ========================== CONSTANTS ==========================

global TREE_DEPTH: u32 = 20;
global VIRTUAL_CHAIN_ID: u64 = 13371337;

// BN254 field size (for bounds checking)
global FIELD_SIZE: Field = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

// ========================== DATA STRUCTURES ==========================

struct InputNote {
    amount: Field,
    randomness: Field,
    path_indices: [u1; TREE_DEPTH],
    path_siblings: [Field; TREE_DEPTH],
}

struct OutputNote {
    amount: Field,
    recipient: Field,
    randomness: Field,
}

struct TxFields {
    chain_id: u64,
    nonce: u64,
    max_priority_fee_per_gas: Field,
    max_fee_per_gas: Field,
    gas_limit: u64,
    to: [u8; 20],
    value: [u8; 32],
}

// ========================== MAIN CIRCUIT ==========================

fn main(
    // ===== PUBLIC INPUTS =====
    merkle_root: pub Field,
    nullifier_0: pub Field,
    nullifier_1: pub Field,
    output_commitment_0: pub Field,
    output_commitment_1: pub Field,
    intent_nullifier: pub Field,
    
    // ===== PRIVATE INPUTS =====
    input_0: InputNote,
    input_1: InputNote,
    output_0: OutputNote,
    output_1: OutputNote,
    nk: Field,
    tx: TxFields,
    signature: [u8; 64],
    recovery_id: u8,
    signer_pubkey_x: [u8; 32],
    signer_pubkey_y: [u8; 32],
) {
    // ===== 0. ENFORCE VIRTUAL CHAIN ID =====
    
    assert(tx.chain_id == VIRTUAL_CHAIN_ID, "Must use virtual chain ID");
    
    // ===== 1. ENFORCE AMOUNT BOUNDS =====
    
    assert(input_0.amount as u128 < FIELD_SIZE as u128, "Input 0 amount exceeds field");
    assert(input_1.amount as u128 < FIELD_SIZE as u128, "Input 1 amount exceeds field");
    assert(output_0.amount as u128 < FIELD_SIZE as u128, "Output 0 amount exceeds field");
    assert(output_1.amount as u128 < FIELD_SIZE as u128, "Output 1 amount exceeds field");
    
    // ===== 2. COMPUTE AND VERIFY TX HASH =====
    
    let tx_hash = compute_eip1559_tx_hash(tx);
    
    // ===== 3. VERIFY ECDSA SIGNATURE =====
    
    let valid = ecdsa_secp256k1::verify_signature(
        signer_pubkey_x,
        signer_pubkey_y,
        signature,
        tx_hash
    );
    assert(valid, "Invalid ECDSA signature");
    
    // ===== 4. DERIVE SIGNER ADDRESS =====
    
    let signer_address = pubkey_to_eth_address(signer_pubkey_x, signer_pubkey_y);
    let signer_address_field = bytes20_to_field(signer_address);
    
    // ===== 5. VERIFY INTENT NULLIFIER =====
    
    // Intent binds to: signer, chainId, nonce, to, value
    let tx_to_field = bytes20_to_field(tx.to);
    let tx_value_field = bytes32_to_field(tx.value);
    
    let computed_intent = poseidon::bn254::hash_5([
        signer_address_field,
        VIRTUAL_CHAIN_ID as Field,
        tx.nonce as Field,
        tx_to_field,
        tx_value_field
    ]);
    assert(intent_nullifier == computed_intent, "Intent nullifier mismatch");
    
    // ===== 6. VERIFY INPUT NOTES =====
    
    // Input 0 - must be owned by signer and exist in tree
    let commitment_0 = poseidon::bn254::hash_3([
        input_0.amount,
        signer_address_field,
        input_0.randomness
    ]);
    
    assert(
        verify_merkle_proof(
            commitment_0,
            input_0.path_indices,
            input_0.path_siblings,
            merkle_root
        ),
        "Input 0 not in tree"
    );
    
    let computed_nullifier_0 = poseidon::bn254::hash_2([commitment_0, nk]);
    assert(nullifier_0 == computed_nullifier_0, "Nullifier 0 mismatch");
    
    // Input 1 - must be owned by signer and exist in tree
    let commitment_1 = poseidon::bn254::hash_3([
        input_1.amount,
        signer_address_field,
        input_1.randomness
    ]);
    
    assert(
        verify_merkle_proof(
            commitment_1,
            input_1.path_indices,
            input_1.path_siblings,
            merkle_root
        ),
        "Input 1 not in tree"
    );
    
    let computed_nullifier_1 = poseidon::bn254::hash_2([commitment_1, nk]);
    assert(nullifier_1 == computed_nullifier_1, "Nullifier 1 mismatch");
    
    // ===== 7. VERIFY OUTPUTS MATCH SIGNED TX =====
    
    // Output 0 recipient = tx.to
    assert(output_0.recipient == tx_to_field, "Recipient mismatch");
    
    // Output 0 amount = tx.value
    assert(output_0.amount == tx_value_field, "Amount mismatch");
    
    // Output 1 (change) must go back to signer
    assert(output_1.recipient == signer_address_field, "Change must go to signer");
    
    // ===== 8. VERIFY OUTPUT COMMITMENTS =====
    
    let computed_output_0 = poseidon::bn254::hash_3([
        output_0.amount,
        output_0.recipient,
        output_0.randomness
    ]);
    assert(output_commitment_0 == computed_output_0, "Output 0 commitment mismatch");
    
    let computed_output_1 = poseidon::bn254::hash_3([
        output_1.amount,
        output_1.recipient,
        output_1.randomness
    ]);
    assert(output_commitment_1 == computed_output_1, "Output 1 commitment mismatch");
    
    // ===== 9. VERIFY CONSERVATION =====
    
    let total_in = input_0.amount + input_1.amount;
    let total_out = output_0.amount + output_1.amount;
    assert(total_in == total_out, "Conservation violated");
}

// ========================== HELPER FUNCTIONS ==========================

/// Compute EIP-1559 transaction hash for signing
fn compute_eip1559_tx_hash(tx: TxFields) -> [u8; 32] {
    // EIP-1559 signing format:
    // keccak256(0x02 || RLP([chainId, nonce, maxPriorityFee, maxFee, gasLimit, to, value, data, accessList]))
    // For ETH transfer: data = 0x, accessList = []
    
    let mut buffer: BoundedVec<u8, 512> = BoundedVec::new();
    
    // Type prefix (0x02 for EIP-1559) - prepended after RLP list
    
    // Build RLP list contents
    let mut list_content: BoundedVec<u8, 500> = BoundedVec::new();
    
    // chainId
    rlp_encode_u64(tx.chain_id, &mut list_content);
    
    // nonce
    rlp_encode_u64(tx.nonce, &mut list_content);
    
    // maxPriorityFeePerGas
    rlp_encode_field(tx.max_priority_fee_per_gas, &mut list_content);
    
    // maxFeePerGas
    rlp_encode_field(tx.max_fee_per_gas, &mut list_content);
    
    // gasLimit
    rlp_encode_u64(tx.gas_limit, &mut list_content);
    
    // to (20 bytes)
    list_content.push(0x94);  // 0x80 + 20
    for i in 0..20 {
        list_content.push(tx.to[i]);
    }
    
    // value
    rlp_encode_uint256(tx.value, &mut list_content);
    
    // data (empty)
    list_content.push(0x80);  // Empty string
    
    // accessList (empty)
    list_content.push(0xc0);  // Empty list
    
    // Now wrap in list header and prepend type
    buffer.push(0x02);  // EIP-1559 type
    
    let list_len = list_content.len();
    if list_len < 56 {
        buffer.push((0xc0 + list_len) as u8);
    } else {
        let len_bytes = byte_length(list_len);
        buffer.push((0xf7 + len_bytes) as u8);
        encode_length(list_len, len_bytes, &mut buffer);
    }
    
    // Append list content
    for i in 0..list_content.len() {
        buffer.push(list_content.get(i));
    }
    
    // Keccak256
    keccak256(buffer.storage(), buffer.len() as u32)
}

/// Derive Ethereum address from public key
fn pubkey_to_eth_address(pub_x: [u8; 32], pub_y: [u8; 32]) -> [u8; 20] {
    let mut pubkey: [u8; 64] = [0; 64];
    for i in 0..32 {
        pubkey[i] = pub_x[i];
        pubkey[i + 32] = pub_y[i];
    }
    
    let hash = keccak256(pubkey, 64);
    
    let mut address: [u8; 20] = [0; 20];
    for i in 0..20 {
        address[i] = hash[i + 12];
    }
    address
}

/// Convert 20-byte address to field
fn bytes20_to_field(bytes: [u8; 20]) -> Field {
    let mut result: Field = 0;
    for i in 0..20 {
        result = result * 256 + (bytes[i] as Field);
    }
    result
}

/// Convert 32-byte uint256 to field
fn bytes32_to_field(bytes: [u8; 32]) -> Field {
    let mut result: Field = 0;
    for i in 0..32 {
        result = result * 256 + (bytes[i] as Field);
    }
    result
}

/// Verify Merkle membership proof
fn verify_merkle_proof(
    leaf: Field,
    path_indices: [u1; TREE_DEPTH],
    path_siblings: [Field; TREE_DEPTH],
    root: Field
) -> bool {
    let mut current = leaf;
    
    for i in 0..TREE_DEPTH {
        let sibling = path_siblings[i];
        let is_right = path_indices[i];
        
        let (left, right) = if is_right == 1 {
            (sibling, current)
        } else {
            (current, sibling)
        };
        
        current = poseidon::bn254::hash_2([left, right]);
    }
    
    current == root
}

// RLP encoding helpers
fn rlp_encode_u64(value: u64, buffer: &mut BoundedVec<u8, 500>) {
    if value == 0 {
        buffer.push(0x80);
    } else if value < 128 {
        buffer.push(value as u8);
    } else {
        let len = byte_length_u64(value);
        buffer.push((0x80 + len) as u8);
        encode_u64(value, len, buffer);
    }
}

fn byte_length_u64(value: u64) -> u8 {
    let mut len: u8 = 0;
    let mut v = value;
    while v > 0 {
        len += 1;
        v >>= 8;
    }
    if len == 0 { 1 } else { len }
}

fn encode_u64(value: u64, len: u8, buffer: &mut BoundedVec<u8, 500>) {
    for i in 0..len {
        let shift = (len - 1 - i) * 8;
        buffer.push(((value >> shift) & 0xff) as u8);
    }
}
```

#### 5.2 Withdraw Circuit

```noir
// circuits/withdraw/src/main.nr

fn main(
    // ===== PUBLIC INPUTS =====
    merkle_root: pub Field,
    nullifier_0: pub Field,
    nullifier_1: pub Field,
    withdraw_amount: pub Field,
    withdraw_recipient: pub Field,
    change_commitment: pub Field,
    intent_nullifier: pub Field,
    
    // ===== PRIVATE INPUTS =====
    input_0: InputNote,
    input_1: InputNote,
    change_note: OutputNote,
    nk: Field,
    tx: TxFields,
    signature: [u8; 64],
    recovery_id: u8,
    signer_pubkey_x: [u8; 32],
    signer_pubkey_y: [u8; 32],
) {
    // ===== 0. ENFORCE VIRTUAL CHAIN ID =====
    
    assert(tx.chain_id == VIRTUAL_CHAIN_ID, "Must use virtual chain ID");
    
    // ===== 1. ENFORCE AMOUNT BOUNDS =====
    
    assert(input_0.amount as u128 < FIELD_SIZE as u128, "Input 0 amount exceeds field");
    assert(input_1.amount as u128 < FIELD_SIZE as u128, "Input 1 amount exceeds field");
    assert(withdraw_amount as u128 < FIELD_SIZE as u128, "Withdraw amount exceeds field");
    assert(change_note.amount as u128 < FIELD_SIZE as u128, "Change amount exceeds field");
    
    // ===== 2-4. VERIFY SIGNATURE AND DERIVE SIGNER =====
    
    let tx_hash = compute_eip1559_tx_hash(tx);
    
    let valid = ecdsa_secp256k1::verify_signature(
        signer_pubkey_x,
        signer_pubkey_y,
        signature,
        tx_hash
    );
    assert(valid, "Invalid ECDSA signature");
    
    let signer_address = pubkey_to_eth_address(signer_pubkey_x, signer_pubkey_y);
    let signer_address_field = bytes20_to_field(signer_address);
    
    // ===== 5. VERIFY INTENT NULLIFIER =====
    
    // For withdrawal: tx.to = sentinel (0x0...01), tx.value = withdraw amount
    let tx_to_field = bytes20_to_field(tx.to);
    let tx_value_field = bytes32_to_field(tx.value);
    
    // Verify tx.to is sentinel
    let sentinel_field = 1;  // address(0x1) as field
    assert(tx_to_field == sentinel_field, "Withdrawal must target sentinel");
    
    let computed_intent = poseidon::bn254::hash_5([
        signer_address_field,
        VIRTUAL_CHAIN_ID as Field,
        tx.nonce as Field,
        tx_to_field,
        tx_value_field
    ]);
    assert(intent_nullifier == computed_intent, "Intent nullifier mismatch");
    
    // ===== 6. VERIFY INPUT NOTES =====
    
    let commitment_0 = poseidon::bn254::hash_3([
        input_0.amount,
        signer_address_field,
        input_0.randomness
    ]);
    assert(verify_merkle_proof(commitment_0, input_0.path_indices, input_0.path_siblings, merkle_root));
    assert(nullifier_0 == poseidon::bn254::hash_2([commitment_0, nk]));
    
    let commitment_1 = poseidon::bn254::hash_3([
        input_1.amount,
        signer_address_field,
        input_1.randomness
    ]);
    assert(verify_merkle_proof(commitment_1, input_1.path_indices, input_1.path_siblings, merkle_root));
    assert(nullifier_1 == poseidon::bn254::hash_2([commitment_1, nk]));
    
    // ===== 7. VERIFY WITHDRAWAL MATCHES TX =====
    
    // tx.value = withdraw_amount
    assert(withdraw_amount == tx_value_field, "Withdraw amount mismatch");
    
    // Recipient is the signer (can only withdraw to self)
    assert(withdraw_recipient == signer_address_field, "Can only withdraw to self");
    
    // ===== 8. VERIFY CHANGE COMMITMENT =====
    
    let computed_change = poseidon::bn254::hash_3([
        change_note.amount,
        change_note.recipient,
        change_note.randomness
    ]);
    
    // Allow zero change (full withdrawal) or valid change commitment
    if change_note.amount != 0 {
        assert(change_commitment == computed_change, "Change commitment mismatch");
        assert(change_note.recipient == signer_address_field, "Change must go to signer");
    } else {
        assert(change_commitment == 0, "Zero change must have zero commitment");
    }
    
    // ===== 9. CONSERVATION =====
    
    let total_in = input_0.amount + input_1.amount;
    let total_out = withdraw_amount + change_note.amount;
    assert(total_in == total_out, "Conservation violated");
}
```

---

### 6. Adapter Implementation

#### 6.1 Component Overview

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                                   ADAPTER                                        │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│  Network Layer                                                                  │
│  ┌─────────────────────────────────────────────────────────────────────────┐   │
│  │  Presents to MetaMask:     chainId = 13371337 (virtual)                 │   │
│  │  Proxies reads to:         chainId = 11155111 (Sepolia)                 │   │
│  │  Submits proofs to:        chainId = 11155111 (Sepolia)                 │   │
│  └─────────────────────────────────────────────────────────────────────────┘   │
│                                                                                 │
│  ┌─────────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────────┐   │
│  │  RPC Server │────►│  Tx Router  │────►│Proof Engine │────►│  Submitter  │   │
│  │  (JSON-RPC) │     │             │     │   (Noir)    │     │  (Hot Key)  │   │
│  └─────────────┘     └─────────────┘     └─────────────┘     └─────────────┘   │
│         │                   │                                       │           │
│         ▼                   ▼                                       ▼           │
│  ┌─────────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────────┐   │
│  │   Session   │     │    Note     │     │   Merkle    │     │   Contract  │   │
│  │   Manager   │     │    Store    │     │    Tree     │     │   Client    │   │
│  └─────────────┘     └─────────────┘     └─────────────┘     └─────────────┘   │
│         │                   │                   │                   │           │
│         ▼                   ▼                   ▼                   ▼           │
│  ┌─────────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────────┐   │
│  │  Key Store  │     │  Event      │     │  Registry   │     │    Hash     │   │
│  │  (Encrypted)│     │  Indexer    │     │  Client     │     │   Mapper    │   │
│  └─────────────┘     └─────────────┘     └─────────────┘     └─────────────┘   │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

#### 6.2 Constants

```typescript
// ========================== CHAIN CONFIGURATION ==========================

const VIRTUAL_CHAIN_ID = 13371337n;  // Presented to MetaMask
const L1_CHAIN_ID = 11155111n;       // Sepolia (actual deployment)

const WITHDRAW_SENTINEL = '0x0000000000000000000000000000000000000001';

const FIELD_SIZE = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
```

#### 6.3 Data Types

```typescript
// ========================== KEYS ==========================

interface UserKeys {
    address: Address;
    seed: Hex;                  // 32 bytes, encrypted at rest
    nk: bigint;                 // Nullifier key (BN254 field)
    skEnc: bigint;              // Encryption secret key (secp256k1 scalar)
    pkEnc: {
        x: Hex;
        y: Hex;
        compressed: Hex;        // 33 bytes
    };
}

// ========================== NOTES ==========================

interface Note {
    commitment: bigint;
    amount: bigint;
    owner: Address;
    randomness: bigint;
    leafIndex: number;          // From LeafInserted event
    blockNumber: number;
}

// ========================== SESSION ==========================

interface Session {
    keys: UserKeys;
    notes: Note[];
    spentNullifiers: Set<bigint>;
    virtualNonce: number;
    lastSyncedBlock: number;
}

// ========================== HASH MAPPING ==========================

// Maps MetaMask's expected tx hash to actual L1 tx hash
interface TxHashMapping {
    virtualTxHash: Hex;         // What MetaMask thinks it sent
    l1TxHash: Hex;              // Actual L1 submission
    status: 'pending' | 'confirmed' | 'failed';
    blockNumber?: number;
}
```

#### 6.4 RPC Implementation

```typescript
class PrivateTransferRPC {
    private sessions: Map<Address, Session> = new Map();
    private txHashMap: Map<Hex, TxHashMapping> = new Map();
    private l1Provider: JsonRpcProvider;
    private contracts: {
        pool: PrivacyPool;
        registry: RecipientRegistry;
    };
    private prover: NoirProver;
    private submitter: TransactionSubmitter;
    private merkleTree: MerkleTree;
    
    // ========================== JSON-RPC ROUTING ==========================
    //
    // IMPORTANT: MetaMask's "Send" flow calls more methods than just sendRawTransaction.
    // Minimum required for MetaMask compatibility:
    //   - eth_chainId, net_version (chain identification)
    //   - eth_accounts, eth_requestAccounts (account discovery)
    //   - eth_getBalance (balance display)
    //   - eth_getTransactionCount (nonce for signing)
    //   - eth_estimateGas (gas estimation before send)
    //   - eth_gasPrice, eth_maxPriorityFeePerGas, eth_feeHistory (fee calculation)
    //   - eth_sendRawTransaction (tx submission)
    //   - eth_getTransactionReceipt, eth_getTransactionByHash (tx status polling)
    //   - eth_blockNumber, eth_getBlockByNumber (block context)
    //   - eth_call (for contract reads, e.g., registry.isRegistered)
    //   - eth_getCode (MetaMask checks if recipient is contract)
    //

    async handleRequest(method: string, params: any[]): Promise<any> {
        switch (method) {
            // Chain identification - return VIRTUAL chain ID
            case 'eth_chainId':
                return toHex(VIRTUAL_CHAIN_ID);
            
            case 'net_version':
                return VIRTUAL_CHAIN_ID.toString();
            
            // Account methods
            case 'eth_accounts':
            case 'eth_requestAccounts':
                return this.getAccounts();
            
            // Balance - return shielded balance
            case 'eth_getBalance':
                return this.getBalance(params[0]);
            
            // Nonce - return virtual nonce
            case 'eth_getTransactionCount':
                return this.getTransactionCount(params[0]);
            
            // Gas estimation
            case 'eth_estimateGas':
                return this.estimateGas(params[0]);
            
            case 'eth_gasPrice':
            case 'eth_maxPriorityFeePerGas':
                // Proxy to L1 for realistic gas prices
                return this.l1Provider.send(method, params);
            
            // Transaction submission - intercept and process
            case 'eth_sendRawTransaction':
                return this.sendRawTransaction(params[0]);
            
            // Transaction status - use hash mapping
            case 'eth_getTransactionReceipt':
                return this.getTransactionReceipt(params[0]);
            
            case 'eth_getTransactionByHash':
                return this.getTransactionByHash(params[0]);
            
            // Block methods - proxy to L1
            case 'eth_blockNumber':
            case 'eth_getBlockByNumber':
            case 'eth_getBlockByHash':
            case 'eth_feeHistory':
            case 'eth_getCode':
            case 'eth_call':
                return this.l1Provider.send(method, params);

            // Custom methods
            case 'privacy_registerViewingKey':
                return this.registerViewingKey(params[0], params[1]);
            
            case 'privacy_getShieldedBalance':
                return this.getBalance(params[0]);
            
            default:
                // Proxy unknown methods to L1
                return this.l1Provider.send(method, params);
        }
    }
    
    // ========================== ACCOUNT MANAGEMENT ==========================
    
    async registerViewingKey(address: Address, signature: Hex): Promise<boolean> {
        // Verify signature matches the setup message
        const message = this.getSignMessage(address);
        const recoveredAddress = verifyMessage(message, signature);
        
        if (recoveredAddress.toLowerCase() !== address.toLowerCase()) {
            throw new Error('Invalid signature');
        }
        
        // Derive all keys from signature
        const seed = keccak256(signature);
        const nk = this.deriveNullifierKey(seed);
        const { skEnc, pkEnc } = this.deriveEncryptionKeys(seed);
        
        const session: Session = {
            keys: { address, seed, nk, skEnc, pkEnc },
            notes: [],
            spentNullifiers: new Set(),
            virtualNonce: 0,
            lastSyncedBlock: 0,
        };
        
        this.sessions.set(address.toLowerCase(), session);
        
        // Initial sync
        await this.syncNotes(address);
        
        return true;
    }
    
    private getSignMessage(address: Address): string {
        return [
            'Facet Private Transfer v1',
            `Virtual Chain: ${VIRTUAL_CHAIN_ID}`,
            `L1 Chain: ${L1_CHAIN_ID}`,
            `Address: ${address}`,
            `Origin: ${this.config.origin}`,
        ].join('\n');
    }
    
    private deriveNullifierKey(seed: Hex): bigint {
        const hash = keccak256(concat([seed, toUtf8Bytes('nullifier_key')]));
        return BigInt(hash) % FIELD_SIZE;
    }
    
    private deriveEncryptionKeys(seed: Hex): { skEnc: bigint; pkEnc: any } {
        let counter = 0;
        let skEnc: bigint;
        
        // Ensure non-zero scalar
        do {
            const input = counter === 0 
                ? concat([seed, toUtf8Bytes('encryption_key')])
                : concat([seed, toUtf8Bytes('encryption_key'), toBeHex(counter)]);
            const hash = keccak256(input);
            skEnc = BigInt(hash) % SECP256K1_ORDER;
            counter++;
        } while (skEnc === 0n);
        
        const pkEnc = secp256k1.ProjectivePoint.BASE.multiply(skEnc);
        
        return {
            skEnc,
            pkEnc: {
                x: toBeHex(pkEnc.x, 32),
                y: toBeHex(pkEnc.y, 32),
                compressed: bytesToHex(pkEnc.toRawBytes(true)),
            },
        };
    }
    
    // ========================== BALANCE ==========================
    
    async getBalance(address: Address): Promise<Hex> {
        const session = this.getSession(address);
        await this.syncNotes(address);
        
        let balance = 0n;
        for (const note of session.notes) {
            const nullifier = poseidon([note.commitment, session.keys.nk]);
            if (!session.spentNullifiers.has(nullifier)) {
                balance += note.amount;
            }
        }
        
        return toHex(balance);
    }
    
    // ========================== NOTE SYNCING ==========================
    
    async syncNotes(address: Address): Promise<void> {
        const session = this.getSession(address);
        const currentBlock = await this.l1Provider.getBlockNumber();
        
        if (session.lastSyncedBlock >= currentBlock) return;
        
        // Fetch LeafInserted events for efficient indexing
        const leafEvents = await this.contracts.pool.queryFilter(
            this.contracts.pool.filters.LeafInserted(),
            session.lastSyncedBlock + 1,
            currentBlock
        );
        
        // Update local merkle tree
        for (const event of leafEvents) {
            this.merkleTree.insertAt(
                Number(event.args.leafIndex),
                event.args.commitment
            );
        }
        
        // Fetch deposit events
        const depositEvents = await this.contracts.pool.queryFilter(
            this.contracts.pool.filters.Deposit(),
            session.lastSyncedBlock + 1,
            currentBlock
        );
        
        for (const event of depositEvents) {
            await this.tryDecryptNote(
                session,
                event.args.encryptedNote,
                event.args.commitment,
                Number(event.args.leafIndex),
                event.blockNumber
            );
        }
        
        // Fetch transfer events
        const transferEvents = await this.contracts.pool.queryFilter(
            this.contracts.pool.filters.Transfer(),
            session.lastSyncedBlock + 1,
            currentBlock
        );
        
        for (const event of transferEvents) {
            // Try decrypt output 0
            await this.tryDecryptNote(
                session,
                event.args.encryptedOutput0,
                event.args.outputCommitment0,
                Number(event.args.leafIndex0),
                event.blockNumber
            );
            
            // Try decrypt output 1
            await this.tryDecryptNote(
                session,
                event.args.encryptedOutput1,
                event.args.outputCommitment1,
                Number(event.args.leafIndex1),
                event.blockNumber
            );
            
            // Mark nullifiers spent
            session.spentNullifiers.add(BigInt(event.args.nullifier0));
            session.spentNullifiers.add(BigInt(event.args.nullifier1));
        }
        
        // Fetch withdrawal events
        const withdrawEvents = await this.contracts.pool.queryFilter(
            this.contracts.pool.filters.Withdrawal(),
            session.lastSyncedBlock + 1,
            currentBlock
        );
        
        for (const event of withdrawEvents) {
            if (event.args.changeCommitment !== 0n) {
                await this.tryDecryptNote(
                    session,
                    event.args.encryptedChange,
                    event.args.changeCommitment,
                    Number(event.args.changeLeafIndex),
                    event.blockNumber
                );
            }
            
            session.spentNullifiers.add(BigInt(event.args.nullifier0));
            session.spentNullifiers.add(BigInt(event.args.nullifier1));
        }
        
        session.lastSyncedBlock = currentBlock;
    }
    
    private async tryDecryptNote(
        session: Session,
        encryptedHex: Hex,
        commitment: bigint,
        leafIndex: number,
        blockNumber: number
    ): Promise<void> {
        try {
            const encrypted = decodeEncryptedNote(encryptedHex);
            const decrypted = decrypt(encrypted, session.keys.skEnc);
            
            // Verify commitment
            const ownerField = BigInt(session.keys.address);
            const expectedCommitment = poseidon([
                decrypted.amount,
                ownerField,
                decrypted.randomness
            ]);
            
            if (expectedCommitment !== commitment) return;
            
            // Check for duplicate
            if (session.notes.some(n => n.commitment === commitment)) return;
            
            session.notes.push({
                commitment,
                amount: decrypted.amount,
                owner: session.keys.address,
                randomness: decrypted.randomness,
                leafIndex,
                blockNumber,
            });
        } catch {
            // Decryption failed - not for this user
        }
    }
    
    // ========================== TRANSACTION COUNT ==========================
    
    async getTransactionCount(address: Address): Promise<Hex> {
        const session = this.getSession(address);
        return toHex(session.virtualNonce);
    }
    
    // ========================== GAS ESTIMATION ==========================
    
    async estimateGas(tx: TransactionRequest): Promise<Hex> {
        if (!tx.data || tx.data === '0x') {
            return toHex(21000);  // Standard ETH transfer
        }
        throw new Error('Only ETH transfers supported');
    }
    
    // ========================== SEND TRANSACTION ==========================
    
    async sendRawTransaction(signedTx: Hex): Promise<Hex> {
        // 1. Decode and validate
        const decoded = decodeRawTransaction(signedTx);
        this.validateTransaction(decoded);
        
        // 2. Recover signer
        const signer = recoverTransactionSigner(decoded);
        const session = this.getSession(signer);
        
        // 3. Verify nonce
        if (decoded.nonce !== session.virtualNonce) {
            throw new Error(`Nonce mismatch: expected ${session.virtualNonce}, got ${decoded.nonce}`);
        }
        
        // 4. Compute virtual tx hash (what MetaMask expects)
        const virtualTxHash = keccak256(signedTx);
        
        // 5. Process based on recipient
        let l1TxHash: Hex;
        
        if (decoded.to.toLowerCase() === WITHDRAW_SENTINEL.toLowerCase()) {
            l1TxHash = await this.processWithdrawal(session, decoded);
        } else {
            l1TxHash = await this.processTransfer(session, decoded);
        }
        
        // 6. Store hash mapping
        this.txHashMap.set(virtualTxHash, {
            virtualTxHash,
            l1TxHash,
            status: 'pending',
        });
        
        // 7. Increment virtual nonce
        session.virtualNonce++;
        
        // 8. Return virtual hash (what MetaMask expects)
        return virtualTxHash;
    }
    
    private validateTransaction(tx: DecodedTransaction): void {
        // Must be EIP-1559
        if (tx.type !== 2) {
            throw new Error('Only EIP-1559 transactions supported');
        }
        
        // Must use virtual chain ID
        if (BigInt(tx.chainId) !== VIRTUAL_CHAIN_ID) {
            throw new Error(`Invalid chain ID: expected ${VIRTUAL_CHAIN_ID}, got ${tx.chainId}`);
        }
        
        // Must be ETH transfer (no data)
        if (tx.data && tx.data !== '0x') {
            throw new Error('Only ETH transfers supported');
        }
        
        // Amount must fit in field
        if (tx.value >= FIELD_SIZE) {
            throw new Error('Amount exceeds field size');
        }
    }
    
    // ========================== TRANSFER PROCESSING ==========================
    
    private async processTransfer(
        session: Session,
        tx: DecodedTransaction
    ): Promise<Hex> {
        const recipient = tx.to;
        const amount = tx.value;
        
        // 1. Verify recipient is registered
        const recipientPkEnc = await this.contracts.registry.getPubkey(recipient);
        if (!recipientPkEnc || recipientPkEnc === '0x') {
            throw new Error('Recipient not registered');
        }
        
        // 2. Select exactly 2 input notes
        const inputs = this.selectInputNotes(session, amount);
        const totalInput = inputs[0].amount + inputs[1].amount;
        
        if (totalInput < amount) {
            throw new Error('Insufficient shielded balance');
        }
        
        const change = totalInput - amount;
        
        // 3. Get current merkle root
        await this.syncNotes(session.keys.address);
        const merkleRoot = await this.contracts.pool.getLatestRoot();
        
        // 4. Compute nullifiers
        const nullifiers: [bigint, bigint] = [
            poseidon([inputs[0].commitment, session.keys.nk]),
            poseidon([inputs[1].commitment, session.keys.nk]),
        ];
        
        // 5. Create outputs
        const output0Randomness = randomBigInt();
        const output1Randomness = randomBigInt();
        
        const recipientField = BigInt(recipient);
        const signerField = BigInt(session.keys.address);
        
        const output0 = {
            amount,
            recipient: recipientField,
            randomness: output0Randomness,
        };
        
        const output1 = {
            amount: change,
            recipient: signerField,
            randomness: output1Randomness,
        };
        
        // 6. Compute commitments
        const outputCommitment0 = poseidon([output0.amount, output0.recipient, output0.randomness]);
        const outputCommitment1 = poseidon([output1.amount, output1.recipient, output1.randomness]);
        
        // 7. Compute intent nullifier (binds to full tx contents)
        const intentNullifier = poseidon([
            signerField,
            VIRTUAL_CHAIN_ID,
            BigInt(tx.nonce),
            recipientField,
            amount,
        ]);
        
        // 8. Build proof inputs
        const proofInputs = this.buildTransferProofInputs(
            session,
            inputs,
            [output0, output1],
            merkleRoot,
            nullifiers,
            [outputCommitment0, outputCommitment1],
            intentNullifier,
            tx
        );
        
        // 9. Generate proof
        const proof = await this.prover.generateTransferProof(proofInputs);
        
        // 10. Encrypt outputs
        const recipientPkEncPoint = decodeCompressedPubkey(recipientPkEnc);
        
        const encryptedOutput0 = encrypt(
            { amount: output0.amount, randomness: output0.randomness },
            recipientPkEncPoint
        );
        
        const encryptedOutput1 = encrypt(
            { amount: output1.amount, randomness: output1.randomness },
            session.keys.pkEnc
        );
        
        // 11. Submit to L1
        const l1TxHash = await this.submitter.submitTransfer({
            proof,
            merkleRoot,
            nullifiers,
            outputCommitments: [outputCommitment0, outputCommitment1],
            intentNullifier,
            encryptedOutputs: [
                encodeEncryptedNote(encryptedOutput0),
                encodeEncryptedNote(encryptedOutput1),
            ],
        });
        
        // 12. Optimistically update local state
        session.spentNullifiers.add(nullifiers[0]);
        session.spentNullifiers.add(nullifiers[1]);
        
        session.notes.push({
            commitment: outputCommitment1,
            amount: change,
            owner: session.keys.address,
            randomness: output1Randomness,
            leafIndex: -1,  // Will be updated on sync
            blockNumber: -1,
        });
        
        return l1TxHash;
    }
    
    // ========================== WITHDRAWAL PROCESSING ==========================
    
    private async processWithdrawal(
        session: Session,
        tx: DecodedTransaction
    ): Promise<Hex> {
        const withdrawAmount = tx.value;
        const withdrawRecipient = session.keys.address;  // Self only
        
        // 1. Select exactly 2 input notes
        const inputs = this.selectInputNotes(session, withdrawAmount);
        const totalInput = inputs[0].amount + inputs[1].amount;
        
        if (totalInput < withdrawAmount) {
            throw new Error('Insufficient shielded balance');
        }
        
        const change = totalInput - withdrawAmount;
        
        // 2. Get merkle root
        await this.syncNotes(session.keys.address);
        const merkleRoot = await this.contracts.pool.getLatestRoot();
        
        // 3. Compute nullifiers
        const nullifiers: [bigint, bigint] = [
            poseidon([inputs[0].commitment, session.keys.nk]),
            poseidon([inputs[1].commitment, session.keys.nk]),
        ];
        
        // 4. Create change note
        const changeRandomness = change > 0n ? randomBigInt() : 0n;
        const signerField = BigInt(session.keys.address);
        
        const changeCommitment = change > 0n
            ? poseidon([change, signerField, changeRandomness])
            : 0n;
        
        // 5. Compute intent nullifier
        const sentinelField = 1n;  // address(0x1)
        
        const intentNullifier = poseidon([
            signerField,
            VIRTUAL_CHAIN_ID,
            BigInt(tx.nonce),
            sentinelField,
            withdrawAmount,
        ]);
        
        // 6. Build proof inputs
        const proofInputs = this.buildWithdrawProofInputs(
            session,
            inputs,
            { amount: change, recipient: signerField, randomness: changeRandomness },
            merkleRoot,
            nullifiers,
            withdrawAmount,
            signerField,
            changeCommitment,
            intentNullifier,
            tx
        );
        
        // 7. Generate proof
        const proof = await this.prover.generateWithdrawProof(proofInputs);
        
        // 8. Encrypt change note
        const encryptedChange = change > 0n
            ? encodeEncryptedNote(encrypt(
                { amount: change, randomness: changeRandomness },
                session.keys.pkEnc
              ))
            : '0x';
        
        // 9. Submit to L1
        const l1TxHash = await this.submitter.submitWithdraw({
            proof,
            merkleRoot,
            nullifiers,
            withdrawAmount,
            withdrawRecipient,
            changeCommitment,
            intentNullifier,
            encryptedChange,
        });
        
        // 10. Update local state
        session.spentNullifiers.add(nullifiers[0]);
        session.spentNullifiers.add(nullifiers[1]);
        
        if (change > 0n) {
            session.notes.push({
                commitment: changeCommitment,
                amount: change,
                owner: session.keys.address,
                randomness: changeRandomness,
                leafIndex: -1,
                blockNumber: -1,
            });
        }
        
        return l1TxHash;
    }
    
    // ========================== NOTE SELECTION ==========================
    
    private selectInputNotes(session: Session, targetAmount: bigint): [Note, Note] {
        // Get unspent notes
        const unspent = session.notes.filter(note => {
            const nullifier = poseidon([note.commitment, session.keys.nk]);
            return !session.spentNullifiers.has(nullifier);
        });
        
        if (unspent.length < 2) {
            throw new Error(
                `Insufficient notes: need 2, have ${unspent.length}. ` +
                `Deposit more funds or wait for pending transactions to confirm.`
            );
        }
        
        // Sort by amount descending
        unspent.sort((a, b) => Number(b.amount - a.amount));
        
        // Greedy selection: find 2 notes that cover the target
        for (let i = 0; i < unspent.length; i++) {
            for (let j = i + 1; j < unspent.length; j++) {
                if (unspent[i].amount + unspent[j].amount >= targetAmount) {
                    return [unspent[i], unspent[j]];
                }
            }
        }
        
        throw new Error('Cannot find 2 notes covering required amount');
    }
    
    // ========================== TRANSACTION STATUS ==========================
    
    async getTransactionReceipt(txHash: Hex): Promise<TransactionReceipt | null> {
        const mapping = this.txHashMap.get(txHash);
        
        if (!mapping) {
            // Not a virtual tx - might be a direct L1 tx, proxy through
            return this.l1Provider.getTransactionReceipt(txHash);
        }
        
        // Get L1 receipt
        const l1Receipt = await this.l1Provider.getTransactionReceipt(mapping.l1TxHash);
        
        if (!l1Receipt) {
            return null;  // Still pending
        }
        
        // Update mapping
        mapping.status = l1Receipt.status === 1 ? 'confirmed' : 'failed';
        mapping.blockNumber = l1Receipt.blockNumber;
        
        // Return receipt with virtual tx hash
        return {
            ...l1Receipt,
            transactionHash: txHash,  // Return virtual hash
            // Include L1 hash in logs for debugging
        };
    }
    
    async getTransactionByHash(txHash: Hex): Promise<Transaction | null> {
        const mapping = this.txHashMap.get(txHash);
        
        if (!mapping) {
            return this.l1Provider.getTransaction(txHash);
        }
        
        const l1Tx = await this.l1Provider.getTransaction(mapping.l1TxHash);
        
        if (!l1Tx) {
            return null;
        }
        
        return {
            ...l1Tx,
            hash: txHash,  // Return virtual hash
        };
    }
    
    // ========================== HELPERS ==========================
    
    private getSession(address: Address): Session {
        const session = this.sessions.get(address.toLowerCase());
        if (!session) {
            throw new Error('Not registered. Sign viewing key message first.');
        }
        return session;
    }
}
```

---

### 7. User Flows

#### 7.1 Setup Flow

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                              SETUP FLOW                                          │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│  STEP 1: Add Custom Network to MetaMask                                         │
│  ┌───────────────────────────────────────────────────────────────────────────┐ │
│  │  Network Name:    Facet Private                                           │ │
│  │  RPC URL:         https://adapter.facet.org/rpc                           │ │
│  │  Chain ID:        13371337        ◄── VIRTUAL (not Sepolia!)              │ │
│  │  Currency Symbol: ETH                                                     │ │
│  │  Block Explorer:  (optional)                                              │ │
│  └───────────────────────────────────────────────────────────────────────────┘ │
│                                                                                 │
│  STEP 2: Connect & Sign Viewing Key                                             │
│  ┌───────────────────────────────────────────────────────────────────────────┐ │
│  │  MetaMask prompt: "Sign message to enable private transfers"              │ │
│  │                                                                           │ │
│  │  ┌─────────────────────────────────────────────────────────────────────┐ │ │
│  │  │ Facet Private Transfer v1                                           │ │ │
│  │  │ Virtual Chain: 13371337                                             │ │ │
│  │  │ L1 Chain: 11155111                                                  │ │ │
│  │  │ Address: 0xAlice...                                                 │ │ │
│  │  │ Origin: adapter.facet.org                                           │ │ │
│  │  └─────────────────────────────────────────────────────────────────────┘ │ │
│  └───────────────────────────────────────────────────────────────────────────┘ │
│                                                                                 │
│  STEP 3: Register Encryption Key (one-time, on Sepolia)                         │
│  ┌───────────────────────────────────────────────────────────────────────────┐ │
│  │  User switches to Sepolia network temporarily                             │ │
│  │  Calls: registry.register(pkEnc)                                          │ │
│  │  Gas: ~50k on Sepolia                                                     │ │
│  │  Switches back to Facet Private network                                   │ │
│  └───────────────────────────────────────────────────────────────────────────┘ │
│                                                                                 │
│  SETUP COMPLETE                                                                 │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

#### 7.2 Deposit Flow

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                              DEPOSIT FLOW                                        │
│                                                                                 │
│  Deposits are made directly to Sepolia (L1), not through the adapter RPC        │
│                                                                                 │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│  User visits: https://facet.org/deposit                                         │
│  ┌───────────────────────────────────────────────────────────────────────────┐ │
│  │                     Facet Private Transfer                                │ │
│  │                                                                           │ │
│  │   Network: Sepolia (switch in MetaMask)                                   │ │
│  │                                                                           │ │
│  │   Amount: [____100____] ETH                                               │ │
│  │                                                                           │ │
│  │   [Deposit to Shielded Balance]                                           │ │
│  │                                                                           │ │
│  └───────────────────────────────────────────────────────────────────────────┘ │
│                                      │                                          │
│                                      ▼                                          │
│  Frontend JavaScript:                                                           │
│  ┌───────────────────────────────────────────────────────────────────────────┐ │
│  │  // 1. Generate note                                                      │ │
│  │  const randomness = crypto.getRandomValues(new Uint8Array(32));           │ │
│  │  const amount = parseEther("100");                                        │ │
│  │  const commitment = poseidon([amount, userAddress, randomness]);          │ │
│  │                                                                           │ │
│  │  // 2. Encrypt for self                                                   │ │
│  │  const encrypted = encrypt({amount, randomness}, userPkEnc);              │ │
│  │                                                                           │ │
│  │  // 3. Call contract (on Sepolia)                                         │ │
│  │  await privacyPool.deposit(commitment, encrypted, { value: amount });     │ │
│  │                                                                           │ │
│  └───────────────────────────────────────────────────────────────────────────┘ │
│                                      │                                          │
│                                      ▼                                          │
│  Contract emits:                                                                │
│  ┌───────────────────────────────────────────────────────────────────────────┐ │
│  │  Deposit(commitment, leafIndex, amount, encryptedNote)                    │ │
│  │  LeafInserted(leafIndex, commitment)                                      │ │
│  └───────────────────────────────────────────────────────────────────────────┘ │
│                                      │                                          │
│                                      ▼                                          │
│  User's adapter (on next balance query) syncs and decrypts the note             │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

#### 7.3 Transfer Flow

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                              TRANSFER FLOW                                       │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│  1. USER SENDS IN METAMASK (on "Facet Private" network)                         │
│  ┌───────────────────────────────────────────────────────────────────────────┐ │
│  │  To: 0xBob                                                                │ │
│  │  Amount: 70 ETH                                                           │ │
│  │  Network: Facet Private (chainId: 13371337)                               │ │
│  │                                                                           │ │
│  │  [Confirm]                                                                │ │
│  └───────────────────────────────────────────────────────────────────────────┘ │
│         │                                                                       │
│         │  User signs EIP-1559 tx with chainId 13371337                         │
│         │  (NOT valid on any real network - safe!)                              │
│         │                                                                       │
│         ▼                                                                       │
│  ┌─────────────────────────────────────────────────────────────────────────────┐
│  │  2. ADAPTER RECEIVES SIGNED TX                                              │
│  │                                                                             │
│  │  Validates:                                                                 │
│  │  ✓ chainId == 13371337 (virtual)                                            │
│  │  ✓ data is empty                                                            │
│  │  ✓ nonce == session.virtualNonce                                            │
│  │  ✓ value < FIELD_SIZE                                                       │
│  │  ✓ recipient is registered                                                  │
│  │  ✓ sender has >= 2 unspent notes covering amount                            │
│  └─────────────────────────────────────────────────────────────────────────────┘
│         │                                                                       │
│         ▼                                                                       │
│  ┌─────────────────────────────────────────────────────────────────────────────┐
│  │  3. ADAPTER BUILDS PROOF                                                    │
│  │                                                                             │
│  │  Inputs (must be exactly 2):                                                │
│  │  ┌───────────────────────────────────────────────────────────────────────┐ │
│  │  │  Note #0: 50 ETH (leafIndex: 42)                                      │ │
│  │  │  Note #1: 50 ETH (leafIndex: 43)                                      │ │
│  │  └───────────────────────────────────────────────────────────────────────┘ │
│  │                                                                             │
│  │  Outputs:                                                                   │
│  │  ┌───────────────────────────────────────────────────────────────────────┐ │
│  │  │  Output #0: 70 ETH → Bob                                              │ │
│  │  │  Output #1: 30 ETH → Alice (change)                                   │ │
│  │  └───────────────────────────────────────────────────────────────────────┘ │
│  │                                                                             │
│  │  Intent nullifier = poseidon(signer, 13371337, nonce, bob, 70 ETH)          │
│  │                                                                             │
│  │  Circuit proves:                                                            │
│  │  • ECDSA signature valid over real EIP-1559 tx                              │
│  │  • chainId == 13371337 enforced                                             │
│  │  • Input notes exist and owned by signer                                    │
│  │  • Outputs match signed tx (to, value)                                      │
│  │  • Conservation: 50 + 50 == 70 + 30                                         │
│  │  • All amounts < FIELD_SIZE                                                 │
│  └─────────────────────────────────────────────────────────────────────────────┘
│         │                                                                       │
│         ▼                                                                       │
│  ┌─────────────────────────────────────────────────────────────────────────────┐
│  │  4. ADAPTER SUBMITS TO SEPOLIA (L1)                                         │
│  │                                                                             │
│  │  privacyPool.transfer(                                                      │
│  │    proof,                                                                   │
│  │    merkleRoot,                                                              │
│  │    [nullifier0, nullifier1],                                                │
│  │    [outputCommitment0, outputCommitment1],                                  │
│  │    intentNullifier,                                                         │
│  │    [encryptedOutput0, encryptedOutput1]                                     │
│  │  )                                                                          │
│  │                                                                             │
│  │  This is a real Sepolia tx signed by adapter's hot wallet                   │
│  └─────────────────────────────────────────────────────────────────────────────┘
│         │                                                                       │
│         ▼                                                                       │
│  ┌─────────────────────────────────────────────────────────────────────────────┐
│  │  5. CONTRACT VERIFIES (on Sepolia)                                          │
│  │                                                                             │
│  │  ✓ Verify ZK proof                                                          │
│  │  ✓ Check merkle root is recent                                              │
│  │  ✓ Check nullifiers not spent                                               │
│  │  ✓ Check intent not used                                                    │
│  │                                                                             │
│  │  Updates:                                                                   │
│  │  • nullifierSpent[null0] = true                                             │
│  │  • nullifierSpent[null1] = true                                             │
│  │  • intentUsed[intent] = true                                                │
│  │  • Inserts output commitments into tree                                     │
│  │                                                                             │
│  │  Emits: Transfer(nullifiers, commitments, leafIndices, intent, encrypted)   │
│  └─────────────────────────────────────────────────────────────────────────────┘
│         │                                                                       │
│         ▼                                                                       │
│  ┌─────────────────────────────────────────────────────────────────────────────┐
│  │  6. METAMASK SHOWS SUCCESS                                                  │
│  │                                                                             │
│  │  "Transaction confirmed"                                                    │
│  │                                                                             │
│  │  User sees:                                                                 │
│  │  • Virtual tx hash (from adapter's hash mapping)                            │
│  │  • Balance: 100 → 30 ETH                                                    │
│  │                                                                             │
│  │  Bob's adapter (on next sync):                                              │
│  │  • Decrypts encryptedOutput0                                                │
│  │  • Discovers new 70 ETH note                                                │
│  │  • Balance: 0 → 70 ETH                                                      │
│  └─────────────────────────────────────────────────────────────────────────────┘
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

#### 7.4 Withdrawal Flow

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                             WITHDRAWAL FLOW                                      │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│  Send to sentinel address 0x0...01 triggers withdrawal                          │
│                                                                                 │
│  ┌───────────────────────────────────────────────────────────────────────────┐ │
│  │  MetaMask (on Facet Private network):                                     │ │
│  │                                                                           │ │
│  │  To: 0x0000000000000000000000000000000000000001                            │ │
│  │  Amount: 50 ETH                                                           │ │
│  │                                                                           │ │
│  │  [Confirm]                                                                │ │
│  └───────────────────────────────────────────────────────────────────────────┘ │
│         │                                                                       │
│         ▼                                                                       │
│  Adapter detects sentinel → withdrawal flow                                     │
│         │                                                                       │
│         ▼                                                                       │
│  ┌───────────────────────────────────────────────────────────────────────────┐ │
│  │  Inputs: 2 notes totaling >= 50 ETH                                       │ │
│  │  Withdraw: 50 ETH → user's EOA (PUBLIC)                                   │ │
│  │  Change: remaining → user (shielded)                                      │ │
│  │                                                                           │ │
│  │  Intent = poseidon(signer, 13371337, nonce, 0x1, 50 ETH)                   │ │
│  └───────────────────────────────────────────────────────────────────────────┘ │
│         │                                                                       │
│         ▼                                                                       │
│  Contract (on Sepolia):                                                         │
│  • Verifies withdrawal proof                                                    │
│  • Marks nullifiers + intent used                                               │
│  • Inserts change commitment (if any)                                           │
│  • Sends 50 ETH to user's EOA on Sepolia                                        │
│         │                                                                       │
│         ▼                                                                       │
│  Result:                                                                        │
│  • User's Sepolia EOA: +50 ETH (public, normal ETH)                             │
│  • User's shielded balance: reduced by 50 ETH                                   │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

### 8. Security Analysis

#### 8.1 Threat Model

| Threat | Mitigation |
|--------|------------|
| **Broadcast attack** (signed tx used on real network) | Virtual chainId 13371337 - tx invalid on all real networks |
| **Signature replay** (same sig, different intent) | Intent nullifier binds to (signer, chainId, nonce, to, value) |
| **Double spend** (same note spent twice) | Nullifier set checked before state update |
| **Note forgery** (fake notes) | ZK proof verifies merkle membership |
| **Amount overflow** | Circuit enforces all amounts < FIELD_SIZE |
| **Unauthorized spend** | ECDSA verified in circuit; only ETH privkey holder can sign |

#### 8.2 What's Protected

| Property | How |
|----------|-----|
| Balance privacy | Amounts encrypted; only recipient can decrypt |
| Transaction graph | Commitments/nullifiers unlinkable without viewing key |
| Spend authorization | ECDSA signature required for every transfer |
| Note authenticity | Merkle proofs verified in ZK |

#### 8.3 Trust Assumptions

1. **Adapter sees all** — Has viewing key, can see all notes and history. Cannot spend.
2. **ZK soundness** — Noir/UltraPlonk proofs cannot be forged.
3. **ECDSA security** — secp256k1 discrete log is hard.
4. **Poseidon collision resistance** — Cannot create duplicate commitments.

#### 8.4 Known Limitations (Demo Scope)

| Limitation | Impact | Future Work |
|------------|--------|-------------|
| Requires exactly 2 input notes | Must have 2+ notes to transfer | Support variable inputs |
| Adapter is single point of privacy | Adapter sees everything | Client-side proving |
| No fee model | Adapter pays all gas | Deduct from transfer |
| Withdrawal links identity | Unshielding reveals EOA | Use relayers |

---

### 9. Implementation Phases

#### Phase 0: Feasibility Validation (Day 1)

Before building anything, validate critical unknowns:

```
□ ECDSA-in-Noir spike:
  □ Create minimal circuit that verifies one secp256k1 signature
  □ Measure: constraint count, proving time, memory usage
  □ If >5min proving or >4GB RAM, evaluate alternatives

□ Poseidon cross-language test vectors:
  □ Generate test vectors: known inputs → expected outputs
  □ Verify Solidity poseidon-solidity matches
  □ Verify TS circomlibjs matches
  □ Verify Noir std::hash::poseidon matches
  □ Include Merkle tree: zeros[], root after N insertions

□ EIP-1559 signing fixtures:
  □ Sign real txs with MetaMask on chainId 13371337
  □ Capture: raw signed tx, decoded fields, recovered pubkey
  □ These become test vectors for TS decode + Noir tx-hash
```

#### Phase 1-4: Build

```
□ Deploy Poseidon libraries (T3, T4, T6) to Sepolia
□ Deploy RecipientRegistry to Sepolia
□ Deploy PrivacyPool with MockVerifier (can upgrade via setVerifiers)
□ Build adapter with full MetaMask RPC surface
□ Compile circuits, generate verifiers
□ Deploy real verifiers, call setVerifiers()
□ Fund adapter hot wallet with Sepolia ETH
□ Deploy adapter service
□ Create deposit frontend
```

#### Phase 5: Integration Test

```
□ Full flow test:
  □ Setup (sign viewing key, register pk_enc)
  □ Deposit (direct to Sepolia)
  □ Transfer (via adapter RPC)
  □ Withdrawal (via adapter RPC)
  □ Verify recipient can decrypt and spend
```

---

### 10. File Structure

```
facet-private-demo/
├── circuits/
│   ├── ecdsa_spike/              # Phase 0: feasibility check
│   │   ├── src/main.nr
│   │   └── Nargo.toml
│   ├── transfer/
│   │   ├── src/main.nr
│   │   └── Nargo.toml
│   ├── withdraw/
│   │   ├── src/main.nr
│   │   └── Nargo.toml
│   └── lib/
│       ├── rlp.nr
│       └── merkle.nr
├── contracts/
│   ├── src/
│   │   ├── PrivacyPool.sol
│   │   ├── RecipientRegistry.sol
│   │   ├── MockVerifier.sol
│   │   └── Poseidon.sol
│   └── foundry.toml
├── adapter/
│   ├── src/
│   │   ├── index.ts
│   │   ├── rpc.ts
│   │   ├── session.ts
│   │   ├── notes.ts
│   │   ├── merkle.ts
│   │   ├── prover.ts
│   │   └── crypto/
│   │       ├── keys.ts
│   │       ├── encrypt.ts
│   │       └── poseidon.ts
│   └── package.json
├── fixtures/                      # Phase 0: test vectors
│   ├── poseidon-vectors.json     # Cross-language Poseidon test cases
│   ├── merkle-vectors.json       # Tree zeros[], root evolution
│   └── eip1559-signed-txs.json   # Real MetaMask-signed txs on 13371337
├── frontend/
│   ├── deposit/
│   │   └── index.html
│   └── register/
│       └── index.html
└── README.md
```
