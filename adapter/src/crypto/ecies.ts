// ECIES encryption for note data
// Uses secp256k1 for key exchange, AES-256-GCM for encryption

import * as secp256k1 from '@noble/secp256k1';
import { sha256 } from '@noble/hashes/sha2.js';
import { randomBytes, createCipheriv, createDecipheriv } from 'crypto';
import { keccak256, concat, type Hex } from 'viem';

// secp256k1 curve order
const CURVE_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n;

/**
 * Derive encryption keypair from signature
 * Returns 32-byte private key and 33-byte compressed public key
 */
export function deriveEncryptionKeypair(signature: Hex): {
  privateKey: Uint8Array;
  publicKey: Uint8Array;
} {
  // Derive private key: keccak256(signature || "encryption") mod curve order
  const privateKeyHash = keccak256(concat([signature, '0x656e6372797074696f6e'])); // "encryption" in hex
  const privateKeyBigInt = BigInt(privateKeyHash) % CURVE_ORDER;
  // Ensure non-zero
  const finalKey = privateKeyBigInt === 0n ? 1n : privateKeyBigInt;
  const privateKey = new Uint8Array(32);
  const keyHex = finalKey.toString(16).padStart(64, '0');
  for (let i = 0; i < 32; i++) {
    privateKey[i] = parseInt(keyHex.slice(i * 2, i * 2 + 2), 16);
  }

  // Derive compressed public key (33 bytes)
  const publicKey = secp256k1.getPublicKey(privateKey, true);

  return { privateKey, publicKey };
}

/**
 * Encrypt note data for a recipient
 * Uses ECIES: ephemeral keypair + ECDH + AES-256-GCM
 *
 * Format: ephemeralPubKey (33 bytes) || nonce (12 bytes) || ciphertext || tag (16 bytes)
 */
export async function encryptNoteData(
  recipientPubKey: Uint8Array,
  noteData: { owner: bigint; amount: bigint; randomness: bigint }
): Promise<Hex> {
  // Generate ephemeral keypair
  const ephemeralPrivKey = secp256k1.utils.randomSecretKey();
  const ephemeralPubKey = secp256k1.getPublicKey(ephemeralPrivKey, true); // 33 bytes compressed

  // ECDH: compute shared secret
  const sharedPoint = secp256k1.getSharedSecret(ephemeralPrivKey, recipientPubKey);
  const sharedSecret = sha256(sharedPoint); // 32 bytes

  // Encode note data: owner (32 bytes) || amount (32 bytes) || randomness (32 bytes)
  const plaintext = Buffer.concat([
    Buffer.from(noteData.owner.toString(16).padStart(64, '0'), 'hex'),
    Buffer.from(noteData.amount.toString(16).padStart(64, '0'), 'hex'),
    Buffer.from(noteData.randomness.toString(16).padStart(64, '0'), 'hex'),
  ]);

  // AES-256-GCM encryption
  const nonce = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', sharedSecret, nonce);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();

  // Combine: ephemeralPubKey || nonce || ciphertext || tag
  const encrypted = Buffer.concat([
    Buffer.from(ephemeralPubKey),
    nonce,
    ciphertext,
    tag,
  ]);

  return ('0x' + encrypted.toString('hex')) as Hex;
}

/**
 * Decrypt note data using recipient's private key
 * Returns null if decryption fails (wrong key or corrupted data)
 */
export function decryptNoteData(
  recipientPrivKey: Uint8Array,
  encryptedData: Hex
): { owner: bigint; amount: bigint; randomness: bigint } | null {
  try {
    const data = Buffer.from(encryptedData.slice(2), 'hex');

    // Parse: ephemeralPubKey (33) || nonce (12) || ciphertext (96) || tag (16)
    if (data.length < 33 + 12 + 96 + 16) {
      return null;
    }

    const ephemeralPubKey = data.subarray(0, 33);
    const nonce = data.subarray(33, 45);
    const ciphertext = data.subarray(45, data.length - 16);
    const tag = data.subarray(data.length - 16);

    // ECDH: compute shared secret
    const sharedPoint = secp256k1.getSharedSecret(recipientPrivKey, ephemeralPubKey);
    const sharedSecret = sha256(sharedPoint);

    // AES-256-GCM decryption
    const decipher = createDecipheriv('aes-256-gcm', sharedSecret, nonce);
    decipher.setAuthTag(tag);
    const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);

    // Parse note data
    if (plaintext.length !== 96) {
      return null;
    }

    const owner = BigInt('0x' + plaintext.subarray(0, 32).toString('hex'));
    const amount = BigInt('0x' + plaintext.subarray(32, 64).toString('hex'));
    const randomness = BigInt('0x' + plaintext.subarray(64, 96).toString('hex'));

    return { owner, amount, randomness };
  } catch {
    return null; // Decryption failed
  }
}

/**
 * Convert 33-byte compressed public key to hex for registry storage
 */
export function pubKeyToHex(compressedPubKey: Uint8Array): Hex {
  if (compressedPubKey.length !== 33) {
    throw new Error('Expected 33-byte compressed public key');
  }
  return ('0x' + Buffer.from(compressedPubKey).toString('hex')) as Hex;
}

/**
 * Convert hex from registry back to 33-byte compressed public key
 */
export function hexToPubKey(hex: Hex): Uint8Array {
  const data = Buffer.from(hex.slice(2), 'hex');
  if (data.length !== 33) {
    throw new Error('Expected 33-byte public key');
  }
  return new Uint8Array(data);
}
