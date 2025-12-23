// Encryption helpers for integration tests
// Matches circuit encryption for computing ciphertext hash

import { Barretenberg, GRUMPKIN_G1_GENERATOR } from '@aztec/bb.js';
import { poseidon2, hash4 } from './poseidon.js';
import { FIELD_SIZE } from './config.js';

// Domain separators (must match circuit/adapter)
const ENC_KEY_DOMAIN = 0x05c0366c550e7c08ba7fdf905e32a9cf2e13de6807d8df5f31fb94eeb9ffd31cn;
const EPHEMERAL_DOMAIN = 0x12d6fc0a3c3236aa13408ef9c5357a87a9442d02cdc33439d1144724efd2c045n;
const KEYSTREAM_DOMAIN = 0x12a75193c39272d475e037ae5044175cf98efd26a563452dc1e3fd396c718824n;
const SHARED_DOMAIN = 0x1a2b3c4d5e6f7890abcdef1234567890abcdef1234567890abcdef1234567890n;
const SELF_EPHEMERAL_DOMAIN = 0x0b3c4d5e6f7890ab1234567890abcdef1234567890abcdef1234567890abcdefn;
const SELF_SECRET_DOMAIN = 0x0c4d5e6f7890abcd234567890abcdef1234567890abcdef1234567890abcdefn;

export type Point = { x: bigint; y: bigint };
export type Cipher5 = [bigint, bigint, bigint, bigint, bigint];

// Barretenberg singleton
let bbInstance: Barretenberg | null = null;

/**
 * Initialize Barretenberg for curve operations
 */
export async function initBarretenberg(): Promise<void> {
  if (!bbInstance) {
    bbInstance = await Barretenberg.new();
  }
}

/**
 * Get Barretenberg instance
 */
function getBb(): Barretenberg {
  if (!bbInstance) {
    throw new Error('Barretenberg not initialized. Call initBarretenberg() first.');
  }
  return bbInstance;
}

/**
 * Convert bigint to 32-byte big-endian Uint8Array
 */
function bigintToBytes32(n: bigint): Uint8Array {
  const hex = n.toString(16).padStart(64, '0');
  const bytes = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

/**
 * Convert 32-byte big-endian Uint8Array to bigint
 */
function bytes32ToBigint(bytes: Uint8Array): bigint {
  let hex = '0x';
  for (const b of bytes) {
    hex += b.toString(16).padStart(2, '0');
  }
  return BigInt(hex);
}

/**
 * Modular reduction helper
 */
function mod(x: bigint): bigint {
  const r = x % FIELD_SIZE;
  return r >= 0n ? r : r + FIELD_SIZE;
}

/**
 * Ensure scalar is non-zero
 */
function ensureNonzero(x: bigint): bigint {
  return x === 0n ? 1n : x;
}

/**
 * Hash 3 inputs via binary tree: hash(hash(a,b), c)
 */
function hash3(inputs: [bigint, bigint, bigint]): bigint {
  const h_ab = poseidon2([inputs[0], inputs[1]]);
  return poseidon2([h_ab, inputs[2]]);
}

/**
 * Hash 5 inputs via binary tree
 */
function hash5(inputs: [bigint, bigint, bigint, bigint, bigint]): bigint {
  const h_01 = poseidon2([inputs[0], inputs[1]]);
  const h_23 = poseidon2([inputs[2], inputs[3]]);
  const h_0123 = poseidon2([h_01, h_23]);
  return poseidon2([h_0123, inputs[4]]);
}

/**
 * Hash 7 inputs via binary tree
 */
function hash7(inputs: [bigint, bigint, bigint, bigint, bigint, bigint, bigint]): bigint {
  const h_01 = poseidon2([inputs[0], inputs[1]]);
  const h_23 = poseidon2([inputs[2], inputs[3]]);
  const h_45 = poseidon2([inputs[4], inputs[5]]);
  const h_0123 = poseidon2([h_01, h_23]);
  const h_456 = poseidon2([h_45, inputs[6]]);
  return poseidon2([h_0123, h_456]);
}

/**
 * Fixed-base scalar multiplication: G * scalar
 * Uses the standard Grumpkin generator point from bb.js
 */
async function fixedBaseMul(scalar: bigint): Promise<Point> {
  const bb = getBb();
  const result = await bb.grumpkinMul({
    point: {
      x: GRUMPKIN_G1_GENERATOR.x,
      y: GRUMPKIN_G1_GENERATOR.y,
    },
    scalar: bigintToBytes32(scalar % FIELD_SIZE),
  });
  return {
    x: bytes32ToBigint(result.point.x),
    y: bytes32ToBigint(result.point.y),
  };
}

/**
 * Variable-base scalar multiplication: P * scalar
 */
async function scalarMul(point: Point, scalar: bigint): Promise<Point> {
  const bb = getBb();
  const result = await bb.grumpkinMul({
    point: {
      x: bigintToBytes32(point.x),
      y: bigintToBytes32(point.y),
    },
    scalar: bigintToBytes32(scalar % FIELD_SIZE),
  });
  return {
    x: bytes32ToBigint(result.point.x),
    y: bytes32ToBigint(result.point.y),
  };
}

/**
 * Derive encryption seed from nullifier key
 */
export function deriveEncSeed(nullifierKey: bigint): bigint {
  return poseidon2([nullifierKey, ENC_KEY_DOMAIN]);
}

/**
 * Derive encryption public key from nullifier key
 */
export async function deriveEncPubkey(nullifierKey: bigint): Promise<Point> {
  const encSeed = deriveEncSeed(nullifierKey);
  const encScalar = ensureNonzero(encSeed);
  return fixedBaseMul(encScalar);
}

/**
 * Encrypt note to recipient using ECDH (matches circuit encrypt_note_ecdh)
 */
export async function encryptNoteEcdh(
  encSeed: bigint,
  recipientPubkey: Point,
  amount: bigint,
  owner: bigint,
  randomness: bigint,
  txNonce: bigint,
  outputIndex: bigint
): Promise<Cipher5> {
  // 1. Derive ephemeral scalar
  const ephemeralSeed = hash7([
    encSeed,
    recipientPubkey.x,
    recipientPubkey.y,
    txNonce,
    outputIndex,
    randomness,
    EPHEMERAL_DOMAIN,
  ]);
  const ephemeralScalar = ensureNonzero(ephemeralSeed);

  // 2. Compute ephemeral public key
  const ephemeralPubkey = await fixedBaseMul(ephemeralScalar);

  // 3. ECDH: shared_point = ephemeral_scalar * recipient_pubkey
  const sharedPoint = await scalarMul(recipientPubkey, ephemeralScalar);

  // 4. x-only KDF
  const sharedSecret = poseidon2([sharedPoint.x, SHARED_DOMAIN]);

  // 5. Derive keystream
  const k0 = hash3([sharedSecret, 0n, KEYSTREAM_DOMAIN]);
  const k1 = hash3([sharedSecret, 1n, KEYSTREAM_DOMAIN]);
  const k2 = hash3([sharedSecret, 2n, KEYSTREAM_DOMAIN]);

  // 6. Encrypt
  return [
    mod(ephemeralPubkey.x),
    mod(ephemeralPubkey.y),
    mod(amount + k0),
    mod(owner + k1),
    mod(randomness + k2),
  ];
}

/**
 * Encrypt change note to self (matches circuit encrypt_note_self)
 */
export async function encryptNoteSelf(
  encSeed: bigint,
  amount: bigint,
  owner: bigint,
  randomness: bigint,
  txNonce: bigint
): Promise<Cipher5> {
  // 1. Derive self scalar (NO randomness)
  const selfScalarSeed = hash3([encSeed, txNonce, SELF_EPHEMERAL_DOMAIN]);
  const selfScalar = ensureNonzero(selfScalarSeed);

  // 2. Compute self ephemeral point
  const selfEphemeral = await fixedBaseMul(selfScalar);

  // 3. Derive secret
  const selfSecret = hash3([encSeed, selfEphemeral.x, SELF_SECRET_DOMAIN]);

  // 4. Derive keystream
  const k0 = hash3([selfSecret, 0n, KEYSTREAM_DOMAIN]);
  const k1 = hash3([selfSecret, 1n, KEYSTREAM_DOMAIN]);
  const k2 = hash3([selfSecret, 2n, KEYSTREAM_DOMAIN]);

  // 5. Encrypt
  return [
    mod(selfEphemeral.x),
    mod(selfEphemeral.y),
    mod(amount + k0),
    mod(owner + k1),
    mod(randomness + k2),
  ];
}

/**
 * Compute ciphertext hash for single note (withdraw change)
 */
export function ciphertextHash5(c: Cipher5): bigint {
  return hash5(c);
}

/**
 * Compute ciphertext hash for two notes (transfer)
 */
export function ciphertextHash10(c0: Cipher5, c1: Cipher5): bigint {
  const h0 = hash5(c0);
  const h1 = hash5(c1);
  return poseidon2([h0, h1]);
}

/**
 * Cleanup Barretenberg instance
 */
export async function destroyBarretenberg(): Promise<void> {
  if (bbInstance) {
    await bbInstance.destroy();
    bbInstance = null;
  }
}
