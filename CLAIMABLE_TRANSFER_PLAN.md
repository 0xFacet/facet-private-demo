# Send to Unregistered Users - Complete Plan with nkHash Binding

## Overview

Enable Alice to send funds to unregistered Bob. Bob claims into his private balance after registering.

**Key security fixes**:
1. Bind `nkHash = H(nullifierKey, DOMAIN)` to commitment to prevent double-spend attacks
2. Signature-verified registration to prevent front-running DoS
3. Bounds checking for circuit compatibility

---

## Security Background

### The Double-Spend Attack (Why nkHash Binding is Required)

Without nkHash in commitment:
1. Alice owns note with `commitment = H(amount, alice, randomness)`
2. Alice spends using `nullifier_1 = H(commitment, nk_1)`
3. Alice claims "never spent" using `nullifier_2 = H(commitment, nk_2)`
4. Since `nullifier_2 != nullifier_1`, contract hasn't marked it spent
5. **Double spend!**

**Fix**: `commitment = H(amount, owner, randomness, nkHash)` where `nkHash = H(nullifierKey, DOMAIN)`
- Now there's exactly ONE valid nullifier per commitment
- Circuit proves `nkHash == H(nullifierKey)` before computing nullifier

### DoS Attack Prevention (Unspendable Notes)

Without registry enforcement:
- Alice could send Bob a note with fake `nkHash`
- Bob can never spend it (his nullifierKey doesn't match)

**Fix**: Store `nkHash` in registry per user. All note creation uses registered nkHash:
- Deposit: Use depositor's registered nkHash
- Transfer: Use recipient's registered nkHash (private witness, fetched by adapter)
- Claim: Use recipient's registered nkHash (verified on-chain)

### Registration DoS Attack (Why Signature Verification is Required)

If `register(encryptionKey, nkHash)` uses `msg.sender`:
1. **Relayer problem**: If relayer submits, `msg.sender` is relayer's address (wrong user)
2. **Front-running DoS**: If world-writable, attacker front-runs and registers victim with bad nkHash
3. **Permanent DoS**: One-time registration means victim can never fix it

**Fix**: Signature-verified registration:
```solidity
function register(address user, bytes encryptionKey, uint256 nkHash, bytes signature)
```
- Relayer can submit (privacy preserved)
- Contract verifies signature is from `user`
- Only user can authorize their own registration

### Transfer Recipient nkHash Enforcement

**Problem**: If recipient stays private, contract can't verify `recipient_nk_hash == registry.nkHashes(recipient)`.

**Trade-off options**:
1. **Make recipient public**: Contract can verify nkHash matches registry (privacy cost + ABI change)
2. **Accept sender can burn**: Keep recipient private, sender could use wrong nkHash (no incentive to do so)

**Decision for this implementation**:
- Normal transfers: Accept option 2
  - `recipient_nk_hash` stays as **private witness** in circuit (NOT public input)
  - Preserves recipient privacy - nkHash not in calldata
  - Sender has no incentive to burn own funds
  - Adapter always fetches correct nkHash from registry
- Claimable transfers: Recipient is already public by design, so can verify on-chain

---

## Phase 0: Commitment Format Change (Breaking)

### New Formulas

```
nkHash = poseidon2([nullifierKey, NK_DOMAIN])
commitment = poseidon5([amount, owner, randomness, nkHash, COMMITMENT_DOMAIN])
nullifier = poseidon2([commitment, nullifierKey])
```

### Domain Constants (CRITICAL: Must be identical across all layers)

```typescript
// TypeScript
const FIELD_SIZE = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const NK_DOMAIN = BigInt(keccak256(toUtf8Bytes("nkHash"))) % FIELD_SIZE;
const COMMITMENT_DOMAIN = BigInt(keccak256(toUtf8Bytes("commitment"))) % FIELD_SIZE;
```

```solidity
// Solidity - use bytes() for explicit conversion, mod by FIELD_SIZE
uint256 constant FIELD_SIZE = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
uint256 constant NK_DOMAIN = uint256(keccak256(bytes("nkHash"))) % FIELD_SIZE;
uint256 constant COMMITMENT_DOMAIN = uint256(keccak256(bytes("commitment"))) % FIELD_SIZE;
```

```noir
// Noir - hardcode pre-computed values (compute once, embed as constants)
global NK_DOMAIN: Field = 0x...; // = keccak256("nkHash") % FIELD_SIZE
global COMMITMENT_DOMAIN: Field = 0x...; // = keccak256("commitment") % FIELD_SIZE
```

### Chain IDs (Two Different Purposes)

```
VIRTUAL_CHAIN_ID = 13371337    // For EIP-1559 tx signing inside circuits (intent binding)
block.chainid (e.g. 11155111)  // For EIP-712 signatures verified on-chain (registry, claim)
```

- **Circuits**: Use VIRTUAL_CHAIN_ID (13371337) for EIP-1559 tx hash computation
- **On-chain EIP-712**: Use `block.chainid` for registry/claim signature verification

### Bounds Checking (Required in Contract)

```solidity
// In deposit/claim/transferToClaimable:
require(amount <= type(uint128).max, "Amount overflow");
require(owner == uint256(uint160(owner)), "Invalid owner address");
require(randomness < FIELD_SIZE, "Randomness out of range");
require(nkHash < FIELD_SIZE, "nkHash out of range");
```

### Files to Update

| Layer | File | Change |
|-------|------|--------|
| Noir | `circuits/lib/src/lib.nr` | Add `hash_4` or use `hash_5` with domain |
| Noir | `circuits/transfer/src/main.nr` | New commitment formula + nkHash verification |
| Noir | `circuits/withdraw/src/main.nr` | Same changes |
| Solidity | `contracts/src/PrivacyPool.sol` | Use PoseidonT5/T6 for commitments |
| TypeScript | `adapter/src/crypto/poseidon.ts` | Add `computeCommitmentWithNkHash()` |
| TypeScript | `adapter/src/notes.ts` | Update Note interface to include nkHash |

---

## Phase 1: Registry Changes

### RecipientRegistry.sol Updates (Signature-Verified)

```solidity
mapping(address => bytes) public encryptionKeys;    // 33-byte ECIES pubkey
mapping(address => uint256) public nkHashes;        // H(nullifierKey, DOMAIN)

// EIP-712 typehash for registration
bytes32 public constant REGISTER_TYPEHASH = keccak256(
    "Register(address user,bytes encryptionKey,uint256 nkHash,uint256 chainId,address registry)"
);

// Signature-verified registration - relayer can submit, but user must sign
function register(
    address user,
    bytes calldata encryptionKey,
    uint256 nkHash,
    bytes calldata signature
) external {
    require(encryptionKeys[user].length == 0, "Already registered");
    require(encryptionKey.length == 33, "Invalid key length");
    require(nkHash != 0 && nkHash < FIELD_SIZE, "Invalid nkHash");

    // Verify signature from user (prevents front-running DoS)
    bytes32 structHash = keccak256(abi.encode(
        REGISTER_TYPEHASH,
        user,
        keccak256(encryptionKey),
        nkHash,
        block.chainid,
        address(this)
    ));
    bytes32 digest = _hashTypedDataV4(structHash);
    address signer = ECDSA.recover(digest, signature);
    require(signer == user, "Invalid signature");

    encryptionKeys[user] = encryptionKey;
    nkHashes[user] = nkHash;

    emit Registered(user, encryptionKey, nkHash);
}
```

### Adapter Registration Flow

```typescript
// In registerViewingKey():
const nullifierKey = deriveNullifierKey(signature);
const nkHash = poseidon2([nullifierKey, NK_DOMAIN]);

// Get user's EIP-712 signature for registration
const registerSignData = {
    domain: { name: 'RecipientRegistry', version: '1', chainId, verifyingContract: REGISTRY_ADDRESS },
    types: {
        Register: [
            { name: 'user', type: 'address' },
            { name: 'encryptionKey', type: 'bytes' },
            { name: 'nkHash', type: 'uint256' },
            { name: 'chainId', type: 'uint256' },
            { name: 'registry', type: 'address' },
        ],
    },
    value: { user: address, encryptionKey, nkHash, chainId, registry: REGISTRY_ADDRESS },
};

// Frontend signs, adapter relays
const registerSig = await wallet.signTypedData(registerSignData);
await registry.register(address, encryptionPubKey, nkHash, registerSig);

// Store in session
session.nullifierKey = nullifierKey;
session.nkHash = nkHash;
```

---

## Phase 2: Circuit Updates

### Transfer Circuit Changes

```noir
fn main(
    // Public inputs (6 total - UNCHANGED from current circuit)
    merkle_root: pub Field,
    nullifier_0: pub Field,
    nullifier_1: pub Field,
    output_commitment_0: pub Field,
    output_commitment_1: pub Field,
    intent_nullifier: pub Field,

    // Private inputs
    nullifier_key: Field,              // Sender's nullifier key
    sender_nk_hash: Field,             // Sender's nkHash (computed from nullifier_key)
    recipient_nk_hash: Field,          // PRIVATE witness - NOT public (preserves recipient privacy)
    // ... rest of inputs
) {
    // 1. Verify sender's nkHash matches their nullifier_key
    let computed_sender_nk = hash_2([nullifier_key, NK_DOMAIN]);
    assert(computed_sender_nk == sender_nk_hash);

    // 2. Verify input commitments include sender's nkHash
    let input_0_commitment = hash_5([
        input_0_amount as Field,
        signer_address,
        input_0_randomness,
        sender_nk_hash,
        COMMITMENT_DOMAIN
    ]);
    // ... same for input_1

    // 3. Verify nullifiers use nullifier_key
    let nullifier_0_computed = hash_2([input_0_commitment, nullifier_key]);
    assert(nullifier_0 == nullifier_0_computed);

    // 4. Verify output commitments
    // Output 0 (to recipient) - uses recipient_nk_hash (PRIVATE witness)
    // NOTE: Not verified against registry on-chain - sender accepts burn risk
    let output_0 = hash_5([
        output_0_amount as Field,
        output_0_owner,
        output_0_randomness,
        recipient_nk_hash,      // Private - adapter fetches from registry
        COMMITMENT_DOMAIN
    ]);

    // Output 1 (change to sender) - uses sender's nkHash
    let output_1 = hash_5([
        output_1_amount as Field,
        signer_address,
        output_1_randomness,
        sender_nk_hash,
        COMMITMENT_DOMAIN
    ]);
}
```

**Key point**: `recipient_nk_hash` is a private witness, not public. This preserves recipient privacy but means contract cannot verify it matches registry. Adapter always fetches correct value.

### Withdraw Circuit Changes

Same pattern - verify input note nkHash, use sender's nkHash for change note.

---

## Phase 3: Contract Updates for Deposit

### PrivacyPool.sol Deposit

```solidity
function deposit(
    uint256 noteOwner,
    uint256 randomness,
    bytes calldata encryptedNote
) external payable {
    // Bounds checking
    require(msg.value <= type(uint128).max, "Amount overflow");
    require(noteOwner == uint256(uint160(noteOwner)), "Invalid owner");
    require(randomness < FIELD_SIZE, "Randomness out of range");

    // Get owner's registered nkHash
    uint256 ownerNkHash = registry.nkHashes(address(uint160(noteOwner)));
    require(ownerNkHash != 0, "Recipient not registered");

    // Compute commitment with nkHash
    uint256 commitment = PoseidonT6.hash([
        msg.value,
        noteOwner,
        randomness,
        ownerNkHash,
        COMMITMENT_DOMAIN
    ]);

    uint256 leafIndex = _insertLeaf(commitment);
    emit Deposit(commitment, leafIndex, msg.value, noteOwner, randomness, encryptedNote);
}
```

---

## Phase 4: ClaimableTransfer Circuit (New)

```noir
fn main(
    // Public inputs (7 total)
    merkle_root: pub Field,
    nullifier_0: pub Field,
    nullifier_1: pub Field,
    change_commitment: pub Field,
    intent_nullifier: pub Field,
    claimable_recipient: pub Field,    // Bob's address (PUBLIC)
    claimable_amount: pub Field,       // Amount for Bob (PUBLIC)

    // Private inputs
    nullifier_key: Field,
    sender_nk_hash: Field,
    // ... input notes, tx data
) {
    // 1. Verify sender's nkHash
    let computed_sender_nk = hash_2([nullifier_key, NK_DOMAIN]);
    assert(computed_sender_nk == sender_nk_hash);

    // 2. Verify input commitments (same as transfer)
    // ...

    // 3. Verify nullifiers
    // ...

    // 4. Change commitment (to sender)
    let change = hash_5([
        change_amount as Field,
        signer_address,
        change_randomness,
        sender_nk_hash,
        COMMITMENT_DOMAIN
    ]);
    assert(change_commitment == change);

    // 5. TX binding
    assert(tx_to == claimable_recipient);
    assert(tx_value == claimable_amount);

    // Note: claimable doesn't create a leaf yet - that happens at claim time
}
```

---

## Phase 5: Claim with nkHash

### PrivacyPool.sol - Claimable State and Functions

```solidity
struct Claimable {
    address recipient;
    uint256 amount;
    bool claimed;
}

mapping(bytes32 => Claimable) public claimables;

// EIP-712 for claim signatures
bytes32 public constant CLAIM_TYPEHASH = keccak256(
    "Claim(bytes32 claimId,uint256 randomness,uint256 chainId,address pool)"
);

function transferToClaimable(
    bytes calldata proof,
    uint256 merkleRoot,
    uint256[2] calldata nullifiers,
    uint256 changeCommitment,
    uint256 intentNullifier,
    address recipient,
    uint256 amount,
    bytes calldata encryptedChange
) external {
    // Verify proof, nullifiers, etc.
    // ...

    // Create claimable record
    bytes32 claimId = keccak256(abi.encodePacked(nullifiers[0], intentNullifier, recipient, amount));
    require(claimables[claimId].recipient == address(0), "Claimable exists");

    claimables[claimId] = Claimable({
        recipient: recipient,
        amount: amount,
        claimed: false
    });

    // Insert change commitment
    if (changeCommitment != 0) {
        _insertLeaf(changeCommitment);
    }

    emit ClaimableCreated(claimId, recipient, amount, changeCommitment, encryptedChange);
}

function claim(
    bytes32 claimId,
    uint256 randomness,
    bytes calldata signature
) external {
    Claimable storage c = claimables[claimId];
    require(c.recipient != address(0), "Not found");
    require(!c.claimed, "Already claimed");

    // Bounds checking
    require(randomness < FIELD_SIZE, "Randomness out of range");

    // Verify EIP-712 signature from recipient
    bytes32 structHash = keccak256(abi.encode(
        CLAIM_TYPEHASH,
        claimId,
        randomness,
        block.chainid,
        address(this)
    ));
    bytes32 digest = _hashTypedDataV4(structHash);
    address signer = ECDSA.recover(digest, signature);
    require(signer == c.recipient, "Invalid signature");

    // Get recipient's registered nkHash
    uint256 recipientNkHash = registry.nkHashes(c.recipient);
    require(recipientNkHash != 0, "Recipient not registered");

    c.claimed = true;

    // Compute commitment with nkHash
    uint256 commitment = PoseidonT6.hash([
        c.amount,
        uint256(uint160(c.recipient)),
        randomness,
        recipientNkHash,
        COMMITMENT_DOMAIN
    ]);

    uint256 leafIndex = _insertLeaf(commitment);
    emit Claimed(claimId, commitment, leafIndex);
}
```

---

## Phase 6: Adapter Updates

### Note Structure

```typescript
export interface Note {
  amount: bigint;
  owner: bigint;
  randomness: bigint;
  nkHash: bigint;          // NEW
  commitment: bigint;
  leafIndex: number;
  spent: boolean;
}
```

### Commitment Computation

```typescript
export function computeCommitment(
  amount: bigint,
  owner: bigint,
  randomness: bigint,
  nkHash: bigint
): bigint {
  return poseidon5([amount, owner, randomness, nkHash, COMMITMENT_DOMAIN]);
}

export function computeNkHash(nullifierKey: bigint): bigint {
  return poseidon2([nullifierKey, NK_DOMAIN]);
}

export function computeNullifier(commitment: bigint, nullifierKey: bigint): bigint {
  return poseidon2([commitment, nullifierKey]);
}
```

### Transfer Proof Generation

```typescript
// Fetch recipient's nkHash from registry
const recipientNkHash = await registry.nkHashes(recipientAddress);
if (recipientNkHash === 0n) {
    // Unregistered - use claimable transfer
    return executeClaimableTransfer(...);
}

// Build proof inputs
inputs.recipient_nk_hash = recipientNkHash;  // Private witness
inputs.sender_nk_hash = session.nkHash;
inputs.nullifier_key = session.nullifierKey;
```

### Claim Flow

```typescript
async function executeClaim(address: string, claimId: string): Promise<string> {
    const session = this.sessions.get(address.toLowerCase());
    if (!session) throw new Error('Not registered');

    // Generate randomness
    const randomness = generateRandomness();

    // Get EIP-712 signature from user
    const claimSignData = {
        domain: { name: 'PrivacyPool', version: '1', chainId, verifyingContract: PRIVACY_POOL_ADDRESS },
        types: {
            Claim: [
                { name: 'claimId', type: 'bytes32' },
                { name: 'randomness', type: 'uint256' },
                { name: 'chainId', type: 'uint256' },
                { name: 'pool', type: 'address' },
            ],
        },
        value: { claimId, randomness: randomness.toString(), chainId, pool: PRIVACY_POOL_ADDRESS },
    };
    const claimSig = await wallet.signTypedData(claimSignData);

    // Submit claim
    const l1Hash = await submitClaim(claimId, randomness, claimSig);
    const receipt = await waitForReceipt(l1Hash);
    const leafIndex = parseClaimLeafIndex(receipt);

    // Add note to session
    const claimable = await getClaimable(claimId);
    const note = createNote({
        amount: claimable.amount,
        owner: BigInt(address),
        randomness,
        nkHash: session.nkHash,
        leafIndex,
    });
    session.noteStore.addNote(note);

    return l1Hash;
}
```

---

## Critical Files Summary

| File | Changes |
|------|---------|
| `contracts/src/RecipientRegistry.sol` | Add nkHashes mapping, signature-verified register() |
| `contracts/src/PrivacyPool.sol` | Use nkHash in deposit(), add transferToClaimable(), claim() |
| `circuits/lib/src/lib.nr` | Add domain constants |
| `circuits/transfer/src/main.nr` | New commitment format, nkHash verification |
| `circuits/withdraw/src/main.nr` | Same changes |
| `circuits/claimable_transfer/src/main.nr` | **NEW** |
| `adapter/src/crypto/poseidon.ts` | Add computeNkHash(), update computeCommitment() |
| `adapter/src/notes.ts` | Add nkHash to Note interface |
| `adapter/src/rpc.ts` | Registration includes nkHash, proof generation updates, claim flow |
| `frontend/src/App.tsx` | Registration signature, claim UI |

---

## Security Properties

1. **No double-spend**: Each commitment has exactly one valid nullifier (bound via nkHash)
2. **No DoS via unspendable notes**: Registry enforces correct nkHash for deposit/claim
3. **No registration front-running**: Signature-verified registration prevents DoS
4. **No claim front-running**: EIP-712 signature required from recipient
5. **No inflation**: Contract computes commitment on-chain with stored amount
6. **Public randomness OK**: Nullifier uses nullifierKey, not randomness
7. **Bounds enforced**: Amount fits u128, addresses are 160-bit, field elements < FIELD_SIZE
8. **Chain ID separation**: Virtual chain (13371337) for circuits, block.chainid for on-chain signatures

**Accepted trade-off**: For normal transfers, recipient nkHash is private witness (not verified on-chain).
- Preserves recipient privacy (nkHash not in calldata)
- Sender has no incentive to use wrong nkHash
- Adapter always fetches correct value from registry

---

## Testing Checklist

### Commitment Format Migration
- [ ] All Poseidon arities available (need 5-input with domain)
- [ ] Domain constants identical across Solidity/Noir/TS
- [ ] Registration stores nkHash with signature verification
- [ ] Deposit uses registered nkHash
- [ ] Transfer verifies sender's nkHash, uses recipient's registered nkHash
- [ ] Withdraw verifies sender's nkHash

### Registration Security
- [ ] Cannot register without valid signature
- [ ] Relayer can submit registration (privacy preserved)
- [ ] Front-running registration fails (attacker's signature invalid)
- [ ] Cannot register twice (one-time)

### Bounds Checking
- [ ] Deposit rejects amount > uint128.max
- [ ] Deposit rejects invalid owner address (high bits set)
- [ ] Deposit rejects randomness >= FIELD_SIZE
- [ ] Deposit rejects nkHash >= FIELD_SIZE

### Claimable Transfer
- [ ] Alice can send to unregistered Bob
- [ ] Change note created with Alice's nkHash
- [ ] Bob sees pending claimable after registration

### Claim
- [ ] Bob can claim with wallet signature
- [ ] Commitment uses Bob's registered nkHash
- [ ] Bob can spend claimed note

### Security
- [ ] Cannot double-spend with different nullifierKey
- [ ] Cannot create unspendable note (deposit/claim check nkHash)
- [ ] Cannot claim without signature
- [ ] Cannot register victim with bad nkHash (signature required)
