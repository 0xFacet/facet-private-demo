// Grumpkin embedded curve operations and note decryption
//
// Uses bb.js for curve operations.
// Domain separators MUST match circuits/common/src/constants.nr

import { poseidon2 } from './poseidon.js';

// ========================== CONSTANTS ==========================

export const FIELD_SIZE = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

// Domain separators (must match circuits/common/src/constants.nr)
export const ENC_KEY_DOMAIN = 0x05c0366c550e7c08ba7fdf905e32a9cf2e13de6807d8df5f31fb94eeb9ffd31cn;
export const EPHEMERAL_DOMAIN = 0x12d6fc0a3c3236aa13408ef9c5357a87a9442d02cdc33439d1144724efd2c045n;
export const KEYSTREAM_DOMAIN = 0x12a75193c39272d475e037ae5044175cf98efd26a563452dc1e3fd396c718824n;
export const SHARED_DOMAIN = 0x1a2b3c4d5e6f7890abcdef1234567890abcdef1234567890abcdef1234567890n;
export const SELF_EPHEMERAL_DOMAIN = 0x0b3c4d5e6f7890ab1234567890abcdef1234567890abcdef1234567890abcdefn;
export const SELF_SECRET_DOMAIN = 0x0c4d5e6f7890abcd234567890abcdef1234567890abcdef1234567890abcdefn;
export const NULLIFIER_KEY_DOMAIN = 0x0d5e6f7890abcdef34567890abcdef1234567890abcdef1234567890abcdefn;
export const NULLIFIER_DOMAIN = 0x0e6f7890abcdef0134567890abcdef1234567890abcdef1234567890abcdefn;
export const INTENT_DOMAIN = 0x0f7890abcdef012345678901abcdef1234567890abcdef1234567890abcdefn;
export const PHANTOM_NULLIFIER_DOMAIN = 0x107890abcdef012345678901abcdef1234567890abcdef1234567890abcde0n;
export const REG_LEAF_DOMAIN = 0x1a2b3c4d5e6f7890abcdef1234567890abcdef1234567890abcdef12345678n;

// Grumpkin curve parameters
// y² = x³ - 17 (mod FIELD_SIZE)
export const CURVE_B_NEG = 17n;
export const GRUMPKIN_GENERATOR_X = 1n;
export const GRUMPKIN_GENERATOR_Y = 17631683881184975370165255887551781615748388533673675138860n;

// ========================== TYPES ==========================

export interface Point {
  x: bigint;
  y: bigint;
}

export type Cipher5 = [bigint, bigint, bigint, bigint, bigint];

export interface DecryptedNote {
  amount: bigint;
  owner: bigint;
  randomness: bigint;
}

// ========================== CURVE OPERATIONS ==========================

/**
 * Scalar multiplication function type
 * Implementation should use bb.js for actual curve operations
 */
export type ScalarMulFn = (point: Point, scalar: bigint) => Point;

/**
 * Fixed base scalar multiplication (G * scalar)
 */
export type FixedBaseMulFn = (scalar: bigint) => Point;

/**
 * Modular arithmetic helper
 */
export function mod(x: bigint): bigint {
  const r = x % FIELD_SIZE;
  return r >= 0n ? r : r + FIELD_SIZE;
}

/**
 * Check if a point is on the Grumpkin curve
 * y² = x³ - 17 (mod FIELD_SIZE)
 */
export function isOnCurve(p: Point): boolean {
  if (p.x === 0n && p.y === 0n) return false; // Identity check
  const lhs = mod(p.y * p.y);
  const x3 = mod(mod(p.x * p.x) * p.x);
  const rhs = mod(x3 - CURVE_B_NEG);
  return lhs === rhs;
}

// ========================== ENCRYPTION KEY DERIVATION ==========================

/**
 * Derive encryption seed from nullifier key
 * enc_seed = hash(nullifier_key, ENC_KEY_DOMAIN)
 */
export function deriveEncSeed(nullifierKey: bigint): bigint {
  return poseidon2([nullifierKey, ENC_KEY_DOMAIN]);
}

/**
 * Derive encryption private key (scalar) from nullifier key
 * Ensures non-zero for safety
 */
export function deriveEncPrivateKey(nullifierKey: bigint): bigint {
  const seed = deriveEncSeed(nullifierKey);
  return seed === 0n ? 1n : seed;
}

/**
 * Derive encryption public key from nullifier key
 * Uses fixed-base multiplication: G * enc_seed
 */
export function deriveEncPublicKey(nullifierKey: bigint, fixedBaseMul: FixedBaseMulFn): Point {
  const encSeed = deriveEncSeed(nullifierKey);
  const scalar = encSeed === 0n ? 1n : encSeed;
  return fixedBaseMul(scalar);
}

// ========================== BINARY TREE HASHING ==========================

/**
 * Hash 3 inputs via binary tree: hash(hash(a,b), c)
 */
export function hash3(inputs: [bigint, bigint, bigint]): bigint {
  const h_ab = poseidon2([inputs[0], inputs[1]]);
  return poseidon2([h_ab, inputs[2]]);
}

/**
 * Hash 4 inputs via binary tree: hash(hash(a,b), hash(c,d))
 */
export function hash4(inputs: [bigint, bigint, bigint, bigint]): bigint {
  const h_ab = poseidon2([inputs[0], inputs[1]]);
  const h_cd = poseidon2([inputs[2], inputs[3]]);
  return poseidon2([h_ab, h_cd]);
}

/**
 * Hash 5 inputs via binary tree
 */
export function hash5(inputs: [bigint, bigint, bigint, bigint, bigint]): bigint {
  const h_01 = poseidon2([inputs[0], inputs[1]]);
  const h_23 = poseidon2([inputs[2], inputs[3]]);
  const h_0123 = poseidon2([h_01, h_23]);
  return poseidon2([h_0123, inputs[4]]);
}

/**
 * Hash 7 inputs via binary tree (matches circuit hash_7)
 * Structure: hash(hash(hash(a,b), hash(c,d)), hash(hash(e,f), g))
 */
export function hash7(inputs: [bigint, bigint, bigint, bigint, bigint, bigint, bigint]): bigint {
  const h_01 = poseidon2([inputs[0], inputs[1]]);
  const h_23 = poseidon2([inputs[2], inputs[3]]);
  const h_45 = poseidon2([inputs[4], inputs[5]]);
  const h_0123 = poseidon2([h_01, h_23]);
  const h_456 = poseidon2([h_45, inputs[6]]);
  return poseidon2([h_0123, h_456]);
}

// ========================== NOTE DECRYPTION ==========================

/**
 * Decrypt recipient note (ECDH-based)
 *
 * The note was encrypted as:
 * 1. ephemeral = G * ephemeral_scalar
 * 2. shared = recipient_pubkey * ephemeral_scalar
 * 3. shared_secret = hash(shared.x, SHARED_DOMAIN)
 * 4. keystream = hash(shared_secret, i, KEYSTREAM_DOMAIN) for i = 0,1,2
 * 5. ciphertext = [ephemeral.x, ephemeral.y, amount + k0, owner + k1, randomness + k2]
 *
 * To decrypt, recipient computes:
 * 1. shared = ephemeral * enc_private_key
 * 2. Derive same keystream
 * 3. Subtract keystream from ciphertext
 */
export function decryptRecipientNote(
  cipher: Cipher5,
  encPrivateKey: bigint,
  scalarMul: ScalarMulFn
): DecryptedNote | null {
  try {
    const [ephX, ephY, cAmt, cOwner, cRnd] = cipher;
    const ephPub: Point = { x: ephX, y: ephY };

    // Verify ephemeral point is on curve
    if (!isOnCurve(ephPub)) {
      return null;
    }

    // ECDH: shared = enc_private_key * ephemeral_pub
    const shared = scalarMul(ephPub, encPrivateKey);

    // x-only KDF (robust to y-sign)
    const sharedSecret = poseidon2([shared.x, SHARED_DOMAIN]);

    // Derive keystream (binary tree hashing)
    const k0 = hash3([sharedSecret, 0n, KEYSTREAM_DOMAIN]);
    const k1 = hash3([sharedSecret, 1n, KEYSTREAM_DOMAIN]);
    const k2 = hash3([sharedSecret, 2n, KEYSTREAM_DOMAIN]);

    // Decrypt
    const amount = mod(cAmt - k0);
    const owner = mod(cOwner - k1);
    const randomness = mod(cRnd - k2);

    return { amount, owner, randomness };
  } catch {
    return null;
  }
}

/**
 * Decrypt self/change note (no ECDH)
 *
 * The note was encrypted as:
 * 1. self_scalar = hash(enc_seed, tx_nonce, SELF_EPHEMERAL_DOMAIN)
 * 2. ephemeral = G * self_scalar
 * 3. self_secret = hash(enc_seed, ephemeral.x, SELF_SECRET_DOMAIN)
 * 4. keystream = hash(self_secret, i, KEYSTREAM_DOMAIN) for i = 0,1,2
 * 5. ciphertext = [ephemeral.x, ephemeral.y, amount + k0, owner + k1, randomness + k2]
 *
 * To decrypt, we read ephemeral.x from ciphertext and recompute:
 * 1. self_secret = hash(enc_seed, ephemeral.x, SELF_SECRET_DOMAIN)
 * 2. Same keystream derivation
 * 3. Subtract keystream
 */
export function decryptSelfNote(
  cipher: Cipher5,
  encSeed: bigint
): DecryptedNote | null {
  try {
    const [ephX, _ephY, cAmt, cOwner, cRnd] = cipher;

    // Self secret from enc_seed + ephemeral.x (read from ciphertext)
    const selfSecret = hash3([encSeed, ephX, SELF_SECRET_DOMAIN]);

    // Derive keystream (binary tree hashing)
    const k0 = hash3([selfSecret, 0n, KEYSTREAM_DOMAIN]);
    const k1 = hash3([selfSecret, 1n, KEYSTREAM_DOMAIN]);
    const k2 = hash3([selfSecret, 2n, KEYSTREAM_DOMAIN]);

    // Decrypt
    const amount = mod(cAmt - k0);
    const owner = mod(cOwner - k1);
    const randomness = mod(cRnd - k2);

    return { amount, owner, randomness };
  } catch {
    return null;
  }
}

/**
 * Try to decrypt a note using both methods
 * Returns decrypted note if either method succeeds
 */
export function tryDecryptNote(
  cipher: Cipher5,
  nullifierKey: bigint,
  scalarMul: ScalarMulFn
): { note: DecryptedNote; isChange: boolean } | null {
  const encSeed = deriveEncSeed(nullifierKey);
  const encPrivKey = encSeed === 0n ? 1n : encSeed;

  // Try ECDH decryption first (recipient note)
  const recipientNote = decryptRecipientNote(cipher, encPrivKey, scalarMul);
  if (recipientNote) {
    return { note: recipientNote, isChange: false };
  }

  // Try self-decryption (change note)
  const selfNote = decryptSelfNote(cipher, encSeed);
  if (selfNote) {
    return { note: selfNote, isChange: true };
  }

  return null;
}

/**
 * Async version of decryptRecipientNote for use with bb.js curve operations
 */
export async function decryptRecipientNoteAsync(
  cipher: Cipher5,
  encPrivateKey: bigint,
  scalarMul: AsyncScalarMulFn
): Promise<DecryptedNote | null> {
  try {
    const [ephX, ephY, cAmt, cOwner, cRnd] = cipher;
    const ephPub: Point = { x: ephX, y: ephY };

    // Verify ephemeral point is on curve
    if (!isOnCurve(ephPub)) {
      return null;
    }

    // ECDH: shared = enc_private_key * ephemeral_pub
    const shared = await scalarMul(ephPub, encPrivateKey);

    // x-only KDF (robust to y-sign)
    const sharedSecret = poseidon2([shared.x, SHARED_DOMAIN]);

    // Derive keystream (binary tree hashing)
    const k0 = hash3([sharedSecret, 0n, KEYSTREAM_DOMAIN]);
    const k1 = hash3([sharedSecret, 1n, KEYSTREAM_DOMAIN]);
    const k2 = hash3([sharedSecret, 2n, KEYSTREAM_DOMAIN]);

    // Decrypt
    const amount = mod(cAmt - k0);
    const owner = mod(cOwner - k1);
    const randomness = mod(cRnd - k2);

    return { amount, owner, randomness };
  } catch {
    return null;
  }
}

/**
 * Async version of tryDecryptNote for use with bb.js curve operations
 * Tries both ECDH decryption (for recipient notes) and self-decryption (for change notes)
 *
 * IMPORTANT: This function returns the first successful decryption without verification.
 * Use tryDecryptNoteWithCommitmentAsync for proper commitment verification.
 */
export async function tryDecryptNoteAsync(
  cipher: Cipher5,
  nullifierKey: bigint,
  scalarMul: AsyncScalarMulFn
): Promise<{ note: DecryptedNote; isChange: boolean } | null> {
  const encSeed = deriveEncSeed(nullifierKey);
  const encPrivKey = encSeed === 0n ? 1n : encSeed;

  // Try self-decryption first (change note) - cheaper, no curve ops
  const selfNote = decryptSelfNote(cipher, encSeed);
  if (selfNote) {
    return { note: selfNote, isChange: true };
  }

  // Try ECDH decryption (recipient note)
  const recipientNote = await decryptRecipientNoteAsync(cipher, encPrivKey, scalarMul);
  if (recipientNote) {
    return { note: recipientNote, isChange: false };
  }

  return null;
}

/**
 * Try to decrypt a note and verify against expected commitment
 * Tries both self-decryption and ECDH, verifying each against the commitment
 * This is the recommended function for scanning - ensures correct decryption
 */
export async function tryDecryptNoteWithCommitmentAsync(
  cipher: Cipher5,
  nullifierKey: bigint,
  nullifierKeyHash: bigint,
  expectedCommitment: bigint,
  expectedOwner: bigint,
  scalarMul: AsyncScalarMulFn
): Promise<{ note: DecryptedNote; isChange: boolean } | null> {
  const encSeed = deriveEncSeed(nullifierKey);
  const encPrivKey = encSeed === 0n ? 1n : encSeed;

  // Try self-decryption first (change note) - cheaper, no curve ops
  const selfNote = decryptSelfNote(cipher, encSeed);
  if (selfNote && selfNote.owner === expectedOwner) {
    const commitment = computeCommitment(selfNote.amount, selfNote.owner, selfNote.randomness, nullifierKeyHash);
    if (commitment === expectedCommitment) {
      return { note: selfNote, isChange: true };
    }
  }

  // Try ECDH decryption (recipient note) - only if self-decryption didn't verify
  const recipientNote = await decryptRecipientNoteAsync(cipher, encPrivKey, scalarMul);
  if (recipientNote && recipientNote.owner === expectedOwner) {
    const commitment = computeCommitment(recipientNote.amount, recipientNote.owner, recipientNote.randomness, nullifierKeyHash);
    if (commitment === expectedCommitment) {
      return { note: recipientNote, isChange: false };
    }
  }

  return null;
}

// ========================== NOTE ENCRYPTION ==========================

/**
 * Ensure scalar is non-zero (prevents point at infinity)
 */
export function ensureNonzero(x: bigint): bigint {
  return x === 0n ? 1n : x;
}

/**
 * Async fixed base multiplication type
 */
export type AsyncFixedBaseMulFn = (scalar: bigint) => Promise<Point>;

/**
 * Async scalar multiplication type
 */
export type AsyncScalarMulFn = (point: Point, scalar: bigint) => Promise<Point>;

/**
 * Encrypt note to recipient using ECDH (matches circuit encrypt_note_ecdh)
 * Sync version for use with pre-computed curve operations
 *
 * Algorithm:
 * 1. Derive ephemeral scalar from: enc_seed, recipient pubkey, tx context
 * 2. Compute ephemeral public key: E = G * ephemeral_scalar
 * 3. ECDH: shared_point = ephemeral_scalar * recipient_pubkey
 * 4. x-only KDF: shared_secret = hash(shared_point.x, SHARED_DOMAIN)
 * 5. Derive keystream from shared_secret
 * 6. Encrypt plaintext with keystream (additive in field)
 *
 * @param encSeed - Sender's encryption seed (derived from nullifier_key)
 * @param recipientPubkey - Recipient's Grumpkin public key
 * @param amount - Note amount (plaintext)
 * @param owner - Note owner address (plaintext)
 * @param randomness - Note randomness (plaintext)
 * @param txNonce - Transaction nonce (for ephemeral uniqueness)
 * @param outputIndex - Output index (0 or 1, for ephemeral uniqueness)
 * @param fixedBaseMul - Function to compute G * scalar
 * @param scalarMul - Function to compute P * scalar
 * @returns Ciphertext: [ephemeral_x, ephemeral_y, enc_amount, enc_owner, enc_randomness]
 */
export function encryptNoteEcdh(
  encSeed: bigint,
  recipientPubkey: Point,
  amount: bigint,
  owner: bigint,
  randomness: bigint,
  txNonce: bigint,
  outputIndex: bigint,
  fixedBaseMul: FixedBaseMulFn,
  scalarMul: ScalarMulFn
): Cipher5 {
  // 1. Derive ephemeral scalar (deterministic from tx context)
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

  // 2. Compute ephemeral public key (fixed-base mul)
  const ephemeralPubkey = fixedBaseMul(ephemeralScalar);

  // 3. ECDH: shared_point = ephemeral_scalar * recipient_pubkey
  const sharedPoint = scalarMul(recipientPubkey, ephemeralScalar);

  // 4. x-only KDF (robust to y-sign mismatch)
  const sharedSecret = poseidon2([sharedPoint.x, SHARED_DOMAIN]);

  // 5. Derive keystream
  const k0 = hash3([sharedSecret, 0n, KEYSTREAM_DOMAIN]);
  const k1 = hash3([sharedSecret, 1n, KEYSTREAM_DOMAIN]);
  const k2 = hash3([sharedSecret, 2n, KEYSTREAM_DOMAIN]);

  // 6. Encrypt (additive in field, mod to ensure < FIELD_SIZE)
  return [
    mod(ephemeralPubkey.x),
    mod(ephemeralPubkey.y),
    mod(amount + k0),
    mod(owner + k1),
    mod(randomness + k2),
  ];
}

/**
 * Async version of encryptNoteEcdh for use with bb.js curve operations
 */
export async function encryptNoteEcdhAsync(
  encSeed: bigint,
  recipientPubkey: Point,
  amount: bigint,
  owner: bigint,
  randomness: bigint,
  txNonce: bigint,
  outputIndex: bigint,
  fixedBaseMul: AsyncFixedBaseMulFn,
  scalarMul: AsyncScalarMulFn
): Promise<Cipher5> {
  // 1. Derive ephemeral scalar (deterministic from tx context)
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

  // 2. Compute ephemeral public key (fixed-base mul)
  const ephemeralPubkey = await fixedBaseMul(ephemeralScalar);

  // 3. ECDH: shared_point = ephemeral_scalar * recipient_pubkey
  const sharedPoint = await scalarMul(recipientPubkey, ephemeralScalar);

  // 4. x-only KDF (robust to y-sign mismatch)
  const sharedSecret = poseidon2([sharedPoint.x, SHARED_DOMAIN]);

  // 5. Derive keystream
  const k0 = hash3([sharedSecret, 0n, KEYSTREAM_DOMAIN]);
  const k1 = hash3([sharedSecret, 1n, KEYSTREAM_DOMAIN]);
  const k2 = hash3([sharedSecret, 2n, KEYSTREAM_DOMAIN]);

  // 6. Encrypt (additive in field, mod to ensure < FIELD_SIZE)
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
 *
 * CRITICAL: Does NOT include randomness in seed derivation (would be circular)
 * Decryptor reads ephemeral.x from ciphertext, recomputes secret
 *
 * Algorithm:
 * 1. Derive self scalar from: enc_seed, tx_nonce
 * 2. Compute self ephemeral: S = G * self_scalar
 * 3. Derive self secret: hash(enc_seed, S.x, SELF_SECRET_DOMAIN)
 * 4. Derive keystream from self secret
 * 5. Encrypt plaintext with keystream
 *
 * @param encSeed - Sender's encryption seed
 * @param amount - Note amount
 * @param owner - Note owner (sender's address)
 * @param randomness - Note randomness
 * @param txNonce - Transaction nonce
 * @param fixedBaseMul - Function to compute G * scalar
 * @returns Ciphertext: [self_ephemeral_x, self_ephemeral_y, enc_amount, enc_owner, enc_randomness]
 */
export function encryptNoteSelf(
  encSeed: bigint,
  amount: bigint,
  owner: bigint,
  randomness: bigint,
  txNonce: bigint,
  fixedBaseMul: FixedBaseMulFn
): Cipher5 {
  // 1. Derive self scalar (NO randomness - would be circular!)
  const selfScalarSeed = hash3([encSeed, txNonce, SELF_EPHEMERAL_DOMAIN]);
  const selfScalar = ensureNonzero(selfScalarSeed);

  // 2. Compute self ephemeral point (fixed-base mul only)
  const selfEphemeral = fixedBaseMul(selfScalar);

  // 3. Derive secret from enc_seed + ephemeral.x (both known to decryptor)
  const selfSecret = hash3([encSeed, selfEphemeral.x, SELF_SECRET_DOMAIN]);

  // 4. Derive keystream
  const k0 = hash3([selfSecret, 0n, KEYSTREAM_DOMAIN]);
  const k1 = hash3([selfSecret, 1n, KEYSTREAM_DOMAIN]);
  const k2 = hash3([selfSecret, 2n, KEYSTREAM_DOMAIN]);

  // 5. Encrypt (uniform format - starts with curve point)
  return [
    mod(selfEphemeral.x),
    mod(selfEphemeral.y),
    mod(amount + k0),
    mod(owner + k1),
    mod(randomness + k2),
  ];
}

/**
 * Async version of encryptNoteSelf for use with bb.js curve operations
 */
export async function encryptNoteSelfAsync(
  encSeed: bigint,
  amount: bigint,
  owner: bigint,
  randomness: bigint,
  txNonce: bigint,
  fixedBaseMul: AsyncFixedBaseMulFn
): Promise<Cipher5> {
  // 1. Derive self scalar (NO randomness - would be circular!)
  const selfScalarSeed = hash3([encSeed, txNonce, SELF_EPHEMERAL_DOMAIN]);
  const selfScalar = ensureNonzero(selfScalarSeed);

  // 2. Compute self ephemeral point (fixed-base mul only)
  const selfEphemeral = await fixedBaseMul(selfScalar);

  // 3. Derive secret from enc_seed + ephemeral.x (both known to decryptor)
  const selfSecret = hash3([encSeed, selfEphemeral.x, SELF_SECRET_DOMAIN]);

  // 4. Derive keystream
  const k0 = hash3([selfSecret, 0n, KEYSTREAM_DOMAIN]);
  const k1 = hash3([selfSecret, 1n, KEYSTREAM_DOMAIN]);
  const k2 = hash3([selfSecret, 2n, KEYSTREAM_DOMAIN]);

  // 5. Encrypt (uniform format - starts with curve point)
  return [
    mod(selfEphemeral.x),
    mod(selfEphemeral.y),
    mod(amount + k0),
    mod(owner + k1),
    mod(randomness + k2),
  ];
}

// ========================== COMMITMENT HELPERS ==========================

/**
 * Compute note commitment
 * commitment = hash(hash(amount, owner), hash(randomness, nkHash))
 */
export function computeCommitment(
  amount: bigint,
  owner: bigint,
  randomness: bigint,
  nullifierKeyHash: bigint
): bigint {
  return hash4([amount, owner, randomness, nullifierKeyHash]);
}

/**
 * Compute nullifier key hash
 * nkHash = hash(nullifier_key, NULLIFIER_KEY_DOMAIN)
 */
export function computeNullifierKeyHash(nullifierKey: bigint): bigint {
  return poseidon2([nullifierKey, NULLIFIER_KEY_DOMAIN]);
}

/**
 * Compute nullifier
 * nullifier = hash(NULLIFIER_DOMAIN, nullifier_key, leaf_index, randomness)
 */
export function computeNullifier(
  nullifierKey: bigint,
  leafIndex: number,
  randomness: bigint
): bigint {
  return hash4([NULLIFIER_DOMAIN, nullifierKey, BigInt(leafIndex), randomness]);
}

/**
 * Compute phantom nullifier for zero-amount inputs
 * Used when input amount is 0 to prevent nullifier poisoning attacks
 * phantom = hash(PHANTOM_NULLIFIER_DOMAIN, nullifier_key, tx_nonce, 0)
 */
export function computePhantomNullifier(
  nullifierKey: bigint,
  txNonce: bigint
): bigint {
  return hash4([PHANTOM_NULLIFIER_DOMAIN, nullifierKey, txNonce, 0n]);
}

/**
 * Compute intent nullifier
 * intent = hash(INTENT_DOMAIN, nullifier_key, chain_id, nonce)
 */
export function computeIntentNullifier(
  nullifierKey: bigint,
  chainId: bigint,
  nonce: bigint
): bigint {
  return hash4([INTENT_DOMAIN, nullifierKey, chainId, nonce]);
}

// ========================== REGISTRY LEAF ==========================

/**
 * Compute registry leaf matching Solidity/Noir
 * leaf = hash(hash(hash(domain, address), hash(pkX, pkY)), nkHash)
 */
export function computeRegistryLeaf(
  address: bigint,
  pubkeyX: bigint,
  pubkeyY: bigint,
  nkHash: bigint
): bigint {
  const h1 = poseidon2([REG_LEAF_DOMAIN, address]);
  const h2 = poseidon2([pubkeyX, pubkeyY]);
  const h3 = poseidon2([h1, h2]);
  return poseidon2([h3, nkHash]);
}

// ========================== CIPHERTEXT HASH ==========================

/**
 * Compute ciphertext hash for 5-element ciphertext
 * Matches circuits and contract
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

// ========================== VALIDATION HELPERS ==========================

/**
 * Check if value is a valid field element
 */
export function isValidField(x: bigint): boolean {
  return x >= 0n && x < FIELD_SIZE;
}

/**
 * Check if value is a valid Ethereum address (160 bits)
 */
export function isValidAddress(x: bigint): boolean {
  return x >= 0n && x < (1n << 160n);
}
