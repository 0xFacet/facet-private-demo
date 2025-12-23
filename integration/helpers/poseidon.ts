// Poseidon hash implementation using circomlibjs
// This must match the Solidity and Noir implementations
//
// CRITICAL: Uses ONLY PoseidonT3 (2-input) with binary tree structure
// This matches the contract and circuit implementations.

import { buildPoseidon } from 'circomlibjs';

let poseidonInstance: Awaited<ReturnType<typeof buildPoseidon>> | null = null;

/**
 * Initialize the Poseidon hash function
 * Must be called before using any hash functions
 */
export async function initPoseidon(): Promise<void> {
  if (!poseidonInstance) {
    poseidonInstance = await buildPoseidon();
  }
}

/**
 * Get the Poseidon instance (throws if not initialized)
 */
function getPoseidon() {
  if (!poseidonInstance) {
    throw new Error('Poseidon not initialized. Call initPoseidon() first.');
  }
  return poseidonInstance;
}

/**
 * Hash 2 field elements (equivalent to PoseidonT3 in Solidity)
 */
export function poseidon2(inputs: [bigint, bigint]): bigint {
  const poseidon = getPoseidon();
  const result = poseidon(inputs);
  return BigInt(poseidon.F.toString(result));
}

// ========================== BINARY TREE HASH FUNCTIONS ==========================
// ALL multi-input hashes use binary tree structure with poseidon2
// This matches circuit and contract implementations

/**
 * Hash 3 inputs via binary tree: hash(hash(a,b), c)
 */
export function hash3(inputs: [bigint, bigint, bigint]): bigint {
  const h_ab = poseidon2([inputs[0], inputs[1]]);
  return poseidon2([h_ab, inputs[2]]);
}

/**
 * Hash 4 inputs via binary tree: hash(hash(a,b), hash(c,d))
 * Used for commitments, nullifiers, etc.
 */
export function hash4(inputs: [bigint, bigint, bigint, bigint]): bigint {
  const h_ab = poseidon2([inputs[0], inputs[1]]);
  const h_cd = poseidon2([inputs[2], inputs[3]]);
  return poseidon2([h_ab, h_cd]);
}

// ========================== DOMAIN SEPARATORS ==========================
// Must match circuits/common/src/constants.nr and adapter/src/crypto/embedded-curve.ts

const NULLIFIER_KEY_DOMAIN = 0x0d5e6f7890abcdef34567890abcdef1234567890abcdef1234567890abcdefn;
const NULLIFIER_DOMAIN = 0x0e6f7890abcdef0134567890abcdef1234567890abcdef1234567890abcdefn;
const INTENT_DOMAIN = 0x0f7890abcdef012345678901abcdef1234567890abcdef1234567890abcdefn;
const PHANTOM_NULLIFIER_DOMAIN = 0x107890abcdef012345678901abcdef1234567890abcdef1234567890abcde0n;

/**
 * Compute the nullifier key hash from a nullifier key
 * nkHash = hash(nullifierKey, NULLIFIER_KEY_DOMAIN)
 * This is stored in the registry and bound to note commitments
 */
export function computeNullifierKeyHash(nullifierKey: bigint): bigint {
  return poseidon2([nullifierKey, NULLIFIER_KEY_DOMAIN]);
}

/**
 * Compute a note commitment
 * commitment = hash4([amount, owner, randomness, nullifierKeyHash])
 * Uses binary tree structure: hash(hash(amount, owner), hash(randomness, nkHash))
 */
export function computeCommitment(amount: bigint, owner: bigint, randomness: bigint, nullifierKeyHash: bigint): bigint {
  return hash4([amount, owner, randomness, nullifierKeyHash]);
}

/**
 * Compute a nullifier for a note
 * nullifier = hash4([NULLIFIER_DOMAIN, nullifierKey, leafIndex, randomness])
 * Includes domain separator and leaf index for uniqueness
 */
export function computeNullifier(nullifierKey: bigint, leafIndex: number, randomness: bigint): bigint {
  return hash4([NULLIFIER_DOMAIN, nullifierKey, BigInt(leafIndex), randomness]);
}

/**
 * Compute phantom nullifier for zero-amount inputs
 * phantom = hash4([PHANTOM_NULLIFIER_DOMAIN, nullifierKey, txNonce, 0])
 * Prevents nullifier poisoning attacks
 */
export function computePhantomNullifier(nullifierKey: bigint, txNonce: bigint): bigint {
  return hash4([PHANTOM_NULLIFIER_DOMAIN, nullifierKey, txNonce, 0n]);
}

/**
 * Compute an intent nullifier for transfers and withdrawals
 * intentNullifier = hash4([INTENT_DOMAIN, nullifierKey, chainId, nonce])
 *
 * Uses secret nullifier_key for privacy (prevents dictionary attacks).
 * One nonce = one spend, regardless of tx content.
 */
export function computeIntentNullifier(
  nullifierKey: bigint,
  chainId: bigint,
  nonce: bigint
): bigint {
  return hash4([INTENT_DOMAIN, nullifierKey, chainId, nonce]);
}
