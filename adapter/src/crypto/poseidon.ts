// Poseidon hash implementation using circomlibjs
// This must match the Solidity and Noir implementations

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

/**
 * Hash 3 field elements (equivalent to PoseidonT4 in Solidity)
 */
export function poseidon3(inputs: [bigint, bigint, bigint]): bigint {
  const poseidon = getPoseidon();
  const result = poseidon(inputs);
  return BigInt(poseidon.F.toString(result));
}

/**
 * Hash 4 field elements (equivalent to PoseidonT5 in Solidity)
 * Used for note commitments: poseidon(amount, owner, randomness, nullifierKeyHash)
 */
export function poseidon4(inputs: [bigint, bigint, bigint, bigint]): bigint {
  const poseidon = getPoseidon();
  const result = poseidon(inputs);
  return BigInt(poseidon.F.toString(result));
}

/**
 * Hash 5 field elements (equivalent to PoseidonT6 in Solidity)
 * Used for intent nullifiers: poseidon(signer, chainId, nonce, to, value)
 */
export function poseidon5(inputs: [bigint, bigint, bigint, bigint, bigint]): bigint {
  const poseidon = getPoseidon();
  const result = poseidon(inputs);
  return BigInt(poseidon.F.toString(result));
}

// Domain separator for nullifier key hash computation (must match circuit constant)
const NULLIFIER_KEY_DOMAIN = 1n;

/**
 * Compute the nullifier key hash from a nullifier key
 * nullifierKeyHash = poseidon(nullifierKey, DOMAIN)
 * This is stored in the registry and bound to note commitments
 */
export function computeNullifierKeyHash(nullifierKey: bigint): bigint {
  return poseidon2([nullifierKey, NULLIFIER_KEY_DOMAIN]);
}

/**
 * Compute a note commitment
 * commitment = poseidon(amount, ownerAddress, randomness, nullifierKeyHash)
 * The nullifierKeyHash binds the note to a specific nullifier key for spending
 */
export function computeCommitment(amount: bigint, owner: bigint, randomness: bigint, nullifierKeyHash: bigint): bigint {
  return poseidon4([amount, owner, randomness, nullifierKeyHash]);
}

/**
 * Compute a nullifier for a note
 * nullifier = poseidon(commitment, nullifierKey)
 * nullifierKey is bound to the commitment via nullifierKeyHash, making nullifiers deterministic per note
 */
export function computeNullifier(commitment: bigint, nullifierKey: bigint): bigint {
  return poseidon2([commitment, nullifierKey]);
}

/**
 * Compute an intent nullifier for transfers
 * intentNullifier = poseidon(signer, chainId, nonce, to, value)
 */
export function computeIntentNullifier(
  signer: bigint,
  chainId: bigint,
  nonce: bigint,
  to: bigint,
  value: bigint
): bigint {
  return poseidon5([signer, chainId, nonce, to, value]);
}

/**
 * Compute an intent nullifier for withdrawals
 * intentNullifier = poseidon(signer, chainId, nonce, WITHDRAW_SENTINEL, value)
 */
export function computeWithdrawIntentNullifier(
  signer: bigint,
  chainId: bigint,
  nonce: bigint,
  value: bigint
): bigint {
  const WITHDRAW_SENTINEL = 1n;
  return poseidon5([signer, chainId, nonce, WITHDRAW_SENTINEL, value]);
}
