# Protocol-Level Privacy Primitive: Draft Spec (v2)

## Overview

Ethereum provides a verifier precompile and a standardized interface for private transactions. Apps deploy pool contracts that call this precompile. The protocol owns the validity rules (what counts as a valid private spend). Apps own the state (note trees, nullifier sets) and policy (compliance, fees, restrictions).

## Note Commitment

```
commitment = poseidon(amount, ownerAddress, randomness, nullifierKeyHash)
```

- `ownerAddress`: 20-byte Ethereum address. Ties note ownership to existing identity.
- `randomness`: blinding factor. Two notes with same amount/owner produce different commitments.
- `nullifierKeyHash`: hash of the owner's nullifier key.
- Hash function: Poseidon. Exact arity (T3 binary tree vs. T5 wide) TBD.

## Nullifier

```
nullifier = poseidon(NULLIFIER_DOMAIN, nullifierKey, leafIndex_u32, randomness)
```

- `nullifierKey`: secret known only to the note owner.
- `leafIndex_u32`: position in the Merkle tree, as u32 (not Field) to prevent index aliasing double-spends.
- `randomness`: the note's blinding factor.
- `NULLIFIER_DOMAIN`: domain separator to prevent cross-protocol collisions.

## Storage Layout (per pool, managed by app)

- **Commitment tree**: append-only Poseidon Merkle tree, depth 20 (~1M leaves). Empty leaf = 0.
- **Root history**: circular buffer of recent roots (e.g., 500) so proofs against slightly stale roots remain valid.
- **Nullifier set**: `mapping(uint256 => bool)`.
- **Intent set**: `mapping(uint256 => bool)`.

This layout never changes.

## Registry (protocol-level primitive)

A Poseidon Merkle tree mapping `address → (viewingPubKey, nullifierKeyHash)`, with its own root history. Used by the ECDSA circuit to bind Ethereum addresses to encryption keys. Can be upgraded to stealth-style meta-addresses in a future fork without changing the note format, storage layout, or public input interface.

## Two Circuits, One Interface

Instead of one circuit with conditional logic, the protocol provides two separate circuits that share the same public input interface. The precompile accepts proofs from either. Apps don't know or care which was used. Same pool, same notes, same anonymity set.

### Circuit A — ECDSA + Registry (Privacy RPC Mode)

For normal users via the privacy RPC. The user signs a standard EIP-1559 transaction with their existing wallet.

**What the circuit proves:**

1. **Authorization.** Reconstructs the EIP-1559 signing hash from private inputs and verifies the ECDSA signature. Derives the signer's Ethereum address from the recovered public key.
2. **Note ownership.** Each input note exists in the Merkle tree at `merkleRoot`. The commitment includes the signer's address, so only notes owned by the signer match.
3. **Nullifier correctness.** Nullifiers are correctly derived from the signer's nullifier key.
4. **Value conservation.** Sum of inputs = transfer amount + change. Range checks prevent underflow.
5. **Output commitments well-formed.** Recipient and change notes correctly constructed.
6. **Recipient binding.** Proves the `tx_to` address from the signed transaction has an entry in the registry at `registryRoot`, binding it to a viewing public key and nullifier key hash.
7. **Encryption correctness.** Re-performs encryption of output notes to the recipient's proven key and the sender's key. Checks against `encryptedNotesHash`.
8. **Intent nullifier correctness.** `hash(INTENT_DOMAIN, nullifierKey, chainId, nonce)` matches `intentNullifier`.

`registryRoot` is nonzero. The app contract verifies it against the registry's root history.

### Circuit B — Nullifier Key + Direct Key (Expert Mode)

For expert users doing client-side proving. No signed transaction. Knowledge of the nullifier key is the authorization.

**What the circuit proves:**

1. **Authorization.** The prover knows the nullifier key corresponding to the input notes. No ECDSA signature involved.
2. **Note ownership.** Same as Circuit A.
3. **Nullifier correctness.** Same as Circuit A.
4. **Value conservation.** Same as Circuit A.
5. **Output commitments well-formed.** Same as Circuit A.
6. **Recipient binding.** None. The recipient's viewing public key is a private input provided by the user. The user chose it; they're responsible for it being correct.
7. **Encryption correctness.** Same as Circuit A, but encrypts to the directly provided key.
8. **Intent nullifier.** Still included (cheap, good hygiene), but less critical since the user constructed the proof themselves.

`registryRoot` is 0. The app contract skips registry root verification.

## Public Inputs (shared by both circuits)

```
merkleRoot            // tree state the proof is against
nullifier0            // first input note nullifier
nullifier1            // second input note nullifier (phantom if unused)
commitment0           // new note (recipient or self)
commitment1           // new note (change to sender, or zero)
publicAmountIn        // ETH entering the pool (deposit), 0 otherwise
publicAmountOut       // ETH leaving the pool (withdrawal), 0 otherwise
publicRecipient       // withdrawal destination address, 0 otherwise
encryptedNotesHash    // hash of encrypted note ciphertexts
intentNullifier       // replay protection
registryRoot          // nonzero for Circuit A, 0 for Circuit B
```

## Verifier Precompile

Single precompile with an internal registry of verification keys.

**Input:** proof bytes + public inputs + circuit identifier.
**Output:** valid / invalid.

The precompile routes to the correct verification key based on the circuit identifier. When a fork adds a new auth method (e.g., P-256 via Circuit C), a new verification key is registered. The public input interface does not change. Apps do not upgrade.

## App Contract Responsibilities

After the precompile returns valid:

1. Check `merkleRoot` is in root history
2. If `registryRoot` ≠ 0: check it is in registry root history
3. Check both nullifiers are unspent, mark them spent
4. Check `intentNullifier` is unused, mark it used
5. Insert `commitment0` and `commitment1` into the Merkle tree
6. If deposit (`publicAmountIn` > 0): accept ETH from sender
7. If withdrawal (`publicAmountOut` > 0): send ETH to `publicRecipient`
8. Emit encrypted note data for recipient scanning

Apps can add requirements on top (proof of innocence, compliance, fees). The core validation is always the precompile call.

## Future Auth Methods

Each new auth method is a new circuit with the same public input interface:

- **Circuit C — P-256 (passkeys/Face ID):** Same as Circuit A but verifies P-256 instead of ECDSA. Added by hard fork.
- **Circuit D — Post-quantum:** Same interface, different signature verification. Added by hard fork.

All circuits share the same pool, same notes, same anonymity set. Apps never upgrade.

## Future: Stealth Addresses

The registry can be upgraded from static viewing keys to ERC-5564 style meta-addresses. The sender derives a one-time key per transaction from the meta-address. This requires a new circuit (same interface) that verifies the stealth derivation instead of a simple registry lookup. Better recipient privacy, same note format, same storage layout, same public inputs. Added by hard fork.

## What This Enables

- **Privacy RPC**: wallet connects to privacy RPC, signs normal transactions, server generates Circuit A proofs. Works with MetaMask, hardware wallets, any existing wallet.
- **Expert mode**: user constructs Circuit B proofs directly. Maximum privacy, no server trust.
- **Proof of innocence**: app-level policy layered on top. Compliant pools require an additional proof at withdrawal. Same circuits, same pool if desired.
- **Multiple pools**: apps can run separate pools with different policies. All use the same protocol circuits and storage layout.
- **Shared anonymity set**: because all circuits produce the same note format, pools can share a note tree if they choose.

## Open Questions

- Exact Poseidon arity (T3 binary tree vs. T5 wide).
- Should deposits go through the circuit (enables atomic shield-and-send) or stay on-chain only (simpler, cheaper)?
- Tree depth: 20 (~1M notes) vs. larger.
- Should withdrawal allow any destination address, or restrict to self?
- Phantom nullifier domain separation: separate domain (as in Facet Private) or handled by intent nullifier?
- In Circuit B, should `intentNullifier` be mandatory or optional (0 to skip)?