// Note management for shielded balances
// Handles note creation, encryption, decryption, and syncing

import { computeCommitment, computeNullifier } from './crypto/poseidon.js';
import { FIELD_SIZE } from './config.js';

/**
 * A shielded note representing ownership of ETH
 */
export interface Note {
  // Core fields
  amount: bigint;
  owner: bigint; // Ethereum address as field element
  randomness: bigint;

  // Derived fields
  commitment: bigint;
  leafIndex: number;

  // Status
  spent: boolean;
}

/**
 * Session keys derived from a viewing key signature
 */
export interface SessionKeys {
  address: string; // Ethereum address
  viewingKey: Uint8Array; // For decryption
  nullifierKey: bigint; // For computing nullifiers
  encryptionPubKey: Uint8Array; // Public key for ECIES
}

/**
 * Note store for a single user
 */
export class NoteStore {
  private notes: Map<bigint, Note> = new Map(); // commitment -> Note
  private sessionKeys: SessionKeys;

  constructor(sessionKeys: SessionKeys) {
    this.sessionKeys = sessionKeys;
  }

  /**
   * Add a note to the store
   */
  addNote(note: Note): void {
    this.notes.set(note.commitment, note);
  }

  /**
   * Mark a note as spent by its nullifier
   */
  markSpent(commitment: bigint): void {
    const note = this.notes.get(commitment);
    if (note) {
      note.spent = true;
    }
  }

  /**
   * Get all unspent notes
   */
  getUnspentNotes(): Note[] {
    return Array.from(this.notes.values()).filter((n) => !n.spent);
  }

  /**
   * Get the total shielded balance
   */
  getBalance(): bigint {
    return this.getUnspentNotes().reduce((sum, note) => sum + note.amount, 0n);
  }

  /**
   * Select notes for spending (simple greedy algorithm)
   * Returns exactly 2 notes that cover the required amount
   */
  selectNotesForSpend(requiredAmount: bigint): Note[] | null {
    const unspent = this.getUnspentNotes().sort((a, b) =>
      a.amount > b.amount ? -1 : a.amount < b.amount ? 1 : 0
    );

    if (unspent.length < 2) {
      return null; // Need at least 2 notes
    }

    // Try to find 2 notes that cover the amount
    for (let i = 0; i < unspent.length; i++) {
      for (let j = i + 1; j < unspent.length; j++) {
        if (unspent[i].amount + unspent[j].amount >= requiredAmount) {
          return [unspent[i], unspent[j]];
        }
      }
    }

    return null; // Cannot cover amount with 2 notes
  }

  /**
   * Compute the nullifier for a note
   */
  computeNoteNullifier(note: Note): bigint {
    return computeNullifier(note.commitment, this.sessionKeys.nullifierKey);
  }

  /**
   * Get all notes (for debugging)
   */
  getAllNotes(): Note[] {
    return Array.from(this.notes.values());
  }
}

/**
 * Create a new note
 */
export function createNote(amount: bigint, owner: bigint, leafIndex: number): Note {
  // Generate random value for commitment
  const randomBytes = new Uint8Array(32);
  crypto.getRandomValues(randomBytes);
  const randomness = bytesToBigInt(randomBytes) % FIELD_SIZE;

  const commitment = computeCommitment(amount, owner, randomness);

  return {
    amount,
    owner,
    randomness,
    commitment,
    leafIndex,
    spent: false,
  };
}

/**
 * Create a note with specific randomness (for deterministic testing)
 */
export function createNoteWithRandomness(
  amount: bigint,
  owner: bigint,
  randomness: bigint,
  leafIndex: number
): Note {
  const commitment = computeCommitment(amount, owner, randomness);

  return {
    amount,
    owner,
    randomness,
    commitment,
    leafIndex,
    spent: false,
  };
}

/**
 * Encrypt a note for a recipient using their public key
 * Simple XOR-based encryption for demo (use ECIES in production)
 */
export function encryptNote(note: Note, recipientPubKey: Uint8Array): Uint8Array {
  // Encode note data: amount (32 bytes) + randomness (32 bytes)
  const data = new Uint8Array(64);
  const amountBytes = bigIntToBytes(note.amount, 32);
  const randomnessBytes = bigIntToBytes(note.randomness, 32);

  data.set(amountBytes, 0);
  data.set(randomnessBytes, 32);

  // In production, use ECIES. For demo, just return raw data
  // TODO: Implement proper ECIES encryption
  return data;
}

/**
 * Try to decrypt a note using session keys
 * Returns null if decryption fails or note doesn't belong to us
 */
export function tryDecryptNote(
  encryptedNote: Uint8Array,
  commitment: bigint,
  leafIndex: number,
  sessionKeys: SessionKeys
): Note | null {
  if (encryptedNote.length !== 64) {
    return null;
  }

  try {
    // Decode note data
    const amount = bytesToBigInt(encryptedNote.slice(0, 32));
    const randomness = bytesToBigInt(encryptedNote.slice(32, 64));

    const owner = BigInt(sessionKeys.address);

    // Verify commitment matches
    const expectedCommitment = computeCommitment(amount, owner, randomness);
    if (expectedCommitment !== commitment) {
      return null; // Not our note
    }

    return {
      amount,
      owner,
      randomness,
      commitment,
      leafIndex,
      spent: false,
    };
  } catch {
    return null;
  }
}

// ==================== Helpers ====================

function bigIntToBytes(value: bigint, length: number): Uint8Array {
  const hex = value.toString(16).padStart(length * 2, '0');
  const bytes = new Uint8Array(length);
  for (let i = 0; i < length; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

function bytesToBigInt(bytes: Uint8Array): bigint {
  let hex = '0x';
  for (const byte of bytes) {
    hex += byte.toString(16).padStart(2, '0');
  }
  return BigInt(hex);
}
