// Registry Merkle Tree implementation
// Tracks recipient registry for membership proofs
//
// Key difference from pool MerkleTree:
// - zeros[0] = 0 (empty leaf is 0, NOT hash(0,0))
// - Leaf = hash(hash(hash(REG_LEAF_DOMAIN, address), hash(pkX, pkY)), nkHash)

import { poseidon2 } from './crypto/poseidon.js';
import { REGISTRY_DEPTH, DOMAIN } from './config.js';

export interface RegistryProof {
  pubkeyX: bigint;
  pubkeyY: bigint;
  nkHash: bigint;
  leafIndex: number;
  siblings: bigint[];
  root: bigint;
}

export interface RegistryEntry {
  address: bigint; // Ethereum address as field
  pubkeyX: bigint;
  pubkeyY: bigint;
  nkHash: bigint;
  leafIndex: number;
}

/**
 * Compute registry leaf hash (matches Solidity and Noir)
 * leaf = hash(hash(hash(REG_LEAF_DOMAIN, address), hash(pkX, pkY)), nkHash)
 */
export function computeRegistryLeaf(
  address: bigint,
  pubkeyX: bigint,
  pubkeyY: bigint,
  nkHash: bigint
): bigint {
  const h1 = poseidon2([DOMAIN.REG_LEAF, address]);
  const h2 = poseidon2([pubkeyX, pubkeyY]);
  const h3 = poseidon2([h1, h2]);
  return poseidon2([h3, nkHash]);
}

/**
 * Registry Merkle Tree
 * CRITICAL: zeros[0] = 0 (unlike pool tree which uses poseidon(0,0))
 */
export class RegistryTree {
  private depth: number;
  private zeros: bigint[];
  private filledSubtrees: bigint[];
  private leaves: bigint[];
  private entries: Map<string, RegistryEntry>; // address (lowercase) -> entry
  private nextIndex: number;

  constructor(depth: number = REGISTRY_DEPTH) {
    this.depth = depth;
    this.zeros = [];
    this.filledSubtrees = [];
    this.leaves = [];
    this.entries = new Map();
    this.nextIndex = 0;

    // CRITICAL: Empty leaf is 0, NOT hash(0,0)
    // This matches RecipientRegistry.sol
    this.zeros[0] = 0n;
    for (let i = 1; i < depth; i++) {
      this.zeros[i] = poseidon2([this.zeros[i - 1], this.zeros[i - 1]]);
    }

    // Initialize filled subtrees with zeros
    this.filledSubtrees = [...this.zeros];
  }

  /**
   * Get the zero value at a given depth
   */
  getZero(depth: number): bigint {
    return this.zeros[depth];
  }

  /**
   * Get the current root
   */
  getRoot(): bigint {
    if (this.nextIndex === 0) {
      // Empty tree - return root of all zeros
      return this.zeros[this.depth - 1];
    }

    // Compute root from filled subtrees
    let currentIndex = this.nextIndex - 1;
    let currentHash = this.leaves[currentIndex];

    for (let i = 0; i < this.depth; i++) {
      if (currentIndex % 2 === 0) {
        currentHash = poseidon2([currentHash, this.zeros[i]]);
      } else {
        currentHash = poseidon2([this.filledSubtrees[i], currentHash]);
      }
      currentIndex = Math.floor(currentIndex / 2);
    }

    return currentHash;
  }

  /**
   * Insert a registry entry and return its leaf index
   */
  insertEntry(
    address: bigint,
    pubkeyX: bigint,
    pubkeyY: bigint,
    nkHash: bigint
  ): number {
    const leaf = computeRegistryLeaf(address, pubkeyX, pubkeyY, nkHash);
    const leafIndex = this.insert(leaf);

    // Store entry for lookup
    const addrHex = '0x' + address.toString(16).padStart(40, '0');
    this.entries.set(addrHex.toLowerCase(), {
      address,
      pubkeyX,
      pubkeyY,
      nkHash,
      leafIndex,
    });

    return leafIndex;
  }

  /**
   * Insert a leaf and return its index
   */
  private insert(leaf: bigint): number {
    const leafIndex = this.nextIndex;

    if (leafIndex >= 2 ** this.depth) {
      throw new Error('Registry tree is full');
    }

    this.leaves.push(leaf);

    let currentIndex = leafIndex;
    let currentHash = leaf;

    for (let i = 0; i < this.depth; i++) {
      if (currentIndex % 2 === 0) {
        // Current is left child
        this.filledSubtrees[i] = currentHash;
        currentHash = poseidon2([currentHash, this.zeros[i]]);
      } else {
        // Current is right child
        currentHash = poseidon2([this.filledSubtrees[i], currentHash]);
      }
      currentIndex = Math.floor(currentIndex / 2);
    }

    this.nextIndex = leafIndex + 1;
    return leafIndex;
  }

  /**
   * Generate a Merkle proof for a registered address
   */
  generateProof(address: string): RegistryProof | null {
    const entry = this.entries.get(address.toLowerCase());
    if (!entry) {
      return null;
    }

    const siblings: bigint[] = [];
    let currentIndex = entry.leafIndex;

    for (let level = 0; level < this.depth; level++) {
      const siblingIndex = currentIndex % 2 === 0 ? currentIndex + 1 : currentIndex - 1;

      // Get sibling value
      let sibling: bigint;
      if (siblingIndex < this.getSubtreeSize(level)) {
        sibling = this.getNodeAtLevel(level, siblingIndex);
      } else {
        sibling = this.zeros[level];
      }

      siblings.push(sibling);
      currentIndex = Math.floor(currentIndex / 2);
    }

    return {
      pubkeyX: entry.pubkeyX,
      pubkeyY: entry.pubkeyY,
      nkHash: entry.nkHash,
      leafIndex: entry.leafIndex,
      siblings,
      root: this.getRoot(),
    };
  }

  /**
   * Get entry by address
   */
  getEntry(address: string): RegistryEntry | null {
    return this.entries.get(address.toLowerCase()) ?? null;
  }

  /**
   * Check if address is registered
   */
  isRegistered(address: string): boolean {
    return this.entries.has(address.toLowerCase());
  }

  /**
   * Get the number of registered entries
   */
  get entryCount(): number {
    return this.nextIndex;
  }

  /**
   * Reset the tree to empty state
   * Used before re-syncing from chain
   */
  reset(): void {
    this.leaves = [];
    this.entries.clear();
    this.nextIndex = 0;
    this.filledSubtrees = [...this.zeros];
  }

  /**
   * Get the number of nodes at a given level
   */
  private getSubtreeSize(level: number): number {
    return Math.ceil(this.nextIndex / 2 ** level);
  }

  /**
   * Get a node value at a specific level and index
   */
  private getNodeAtLevel(level: number, index: number): bigint {
    if (level === 0) {
      return index < this.leaves.length ? this.leaves[index] : this.zeros[0];
    }

    // Compute the node by hashing children
    const leftChildIndex = index * 2;
    const rightChildIndex = index * 2 + 1;

    const leftChild = this.getNodeAtLevel(level - 1, leftChildIndex);
    const rightChild = this.getNodeAtLevel(level - 1, rightChildIndex);

    return poseidon2([leftChild, rightChild]);
  }

  /**
   * Verify a registry proof
   */
  static verifyProof(proof: RegistryProof, address: bigint): boolean {
    const leaf = computeRegistryLeaf(
      address,
      proof.pubkeyX,
      proof.pubkeyY,
      proof.nkHash
    );

    let currentHash = leaf;
    let currentIndex = proof.leafIndex;

    for (let i = 0; i < proof.siblings.length; i++) {
      if (currentIndex % 2 === 0) {
        // Current is left child
        currentHash = poseidon2([currentHash, proof.siblings[i]]);
      } else {
        // Current is right child
        currentHash = poseidon2([proof.siblings[i], currentHash]);
      }
      currentIndex = Math.floor(currentIndex / 2);
    }

    return currentHash === proof.root;
  }
}
