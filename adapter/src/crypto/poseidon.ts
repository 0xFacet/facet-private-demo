// Poseidon hash implementation using circomlibjs
// This must match the Solidity and Noir implementations
//
// CRITICAL: We use binary tree hashing for 3+ inputs to ensure
// cross-language consistency (only need PoseidonT3).
// All higher-arity hashes are composed from poseidon2.

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
 * This is the base primitive - all other hashes use binary tree composition.
 */
export function poseidon2(inputs: [bigint, bigint]): bigint {
  const poseidon = getPoseidon();
  const result = poseidon(inputs);
  return BigInt(poseidon.F.toString(result));
}

