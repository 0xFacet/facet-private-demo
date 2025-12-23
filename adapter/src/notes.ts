// Note management for shielded balances
// Handles note creation, encryption, decryption, and syncing

import {
  computeCommitment,
  computeNullifier,
  computeNullifierKeyHash,
  type Cipher5,
  type DecryptedNote,
} from './crypto/embedded-curve.js';
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
  reserved?: boolean; // True when note is being used in an in-flight transaction
}

/**
 * Session keys derived from a viewing key signature
 */
export interface SessionKeys {
  address: string; // Ethereum address
  viewingKey: Uint8Array; // For viewing key derivation
  nullifierKey: bigint; // For computing nullifiers and encryption seed (private, never broadcast)
  nullifierKeyHash: bigint; // Hash of nullifierKey, stored in registry and bound to commitments
  // Note: Encryption keys are derived from nullifierKey via deriveEncSeed()
  // encSeed = poseidon(nullifierKey, ENC_KEY_DOMAIN)
  // encPrivKey = encSeed (ensureNonzero)
  // encPubKey = G * encPrivKey (computed via Grumpkin)
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
   * Mark a note as spent by its commitment
   */
  markSpent(commitment: bigint): void {
    const note = this.notes.get(commitment);
    if (note) {
      note.spent = true;
      note.reserved = false; // Clean up reservation
    }
  }

  /**
   * Get all unspent notes (excludes reserved notes)
   */
  getUnspentNotes(): Note[] {
    return Array.from(this.notes.values()).filter((n) => !n.spent && !n.reserved);
  }

  /**
   * Reserve notes for an in-flight transaction
   */
  reserveNotes(notes: Note[]): void {
    for (const note of notes) {
      note.reserved = true;
    }
  }

  /**
   * Unreserve notes (on transaction failure)
   */
  unreserveNotes(notes: Note[]): void {
    for (const note of notes) {
      note.reserved = false;
    }
  }

  /**
   * Get the total shielded balance
   */
  getBalance(): bigint {
    return this.getUnspentNotes().reduce((sum, note) => sum + note.amount, 0n);
  }

  /**
   * Select notes for spending (simple greedy algorithm)
   * Returns 1 or 2 notes that cover the required amount.
   * Single-note case: caller should use phantom input for second note.
   */
  selectNotesForSpend(requiredAmount: bigint): Note[] | null {
    const unspent = this.getUnspentNotes().sort((a, b) =>
      a.amount > b.amount ? -1 : a.amount < b.amount ? 1 : 0
    );

    if (unspent.length === 0) {
      return null;
    }

    // Single note case: if 1 note covers amount, return it alone
    // Caller will add phantom input for the second note
    if (unspent.length === 1) {
      if (unspent[0].amount >= requiredAmount) {
        return [unspent[0]];
      }
      return null; // Single note doesn't cover amount
    }

    // Two+ notes: try to find 2 notes that cover the amount
    for (let i = 0; i < unspent.length; i++) {
      for (let j = i + 1; j < unspent.length; j++) {
        if (unspent[i].amount + unspent[j].amount >= requiredAmount) {
          return [unspent[i], unspent[j]];
        }
      }
    }

    // If no pair covers it, try single note (largest might cover it alone)
    if (unspent[0].amount >= requiredAmount) {
      return [unspent[0]];
    }

    return null; // Cannot cover amount
  }

  /**
   * Compute the nullifier for a note
   * Uses: hash(NULLIFIER_DOMAIN, nullifier_key, leaf_index, randomness)
   */
  computeNoteNullifier(note: Note): bigint {
    return computeNullifier(
      this.sessionKeys.nullifierKey,
      note.leafIndex,
      note.randomness
    );
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
 * @param nullifierKeyHash Hash of the owner's nullifier key (bound to commitment)
 */
export function createNote(amount: bigint, owner: bigint, nullifierKeyHash: bigint, leafIndex: number): Note {
  // Generate random value for commitment
  const randomBytes = new Uint8Array(32);
  crypto.getRandomValues(randomBytes);
  const randomness = bytesToBigInt(randomBytes) % FIELD_SIZE;

  const commitment = computeCommitment(amount, owner, randomness, nullifierKeyHash);

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
 * @param nullifierKeyHash Hash of the owner's nullifier key (bound to commitment)
 */
export function createNoteWithRandomness(
  amount: bigint,
  owner: bigint,
  randomness: bigint,
  nullifierKeyHash: bigint,
  leafIndex: number
): Note {
  const commitment = computeCommitment(amount, owner, randomness, nullifierKeyHash);

  return {
    amount,
    owner,
    randomness,
    commitment,
    leafIndex,
    spent: false,
  };
}

// ==================== Helpers ====================

function bytesToBigInt(bytes: Uint8Array): bigint {
  let hex = '0x';
  for (const byte of bytes) {
    hex += byte.toString(16).padStart(2, '0');
  }
  return BigInt(hex);
}
