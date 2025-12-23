// Registry Tree implementation for integration tests
// Mirrors the RecipientRegistry contract's merkle tree

import { poseidon2 } from './poseidon.js';
import { TREE_DEPTH } from './config.js';

// Domain separator for registry leaf (must match contract/circuit)
const REG_LEAF_DOMAIN = 0x1a2b3c4d5e6f7890abcdef1234567890abcdef1234567890abcdef12345678n;

export interface RegistryEntry {
  address: bigint;
  pubkeyX: bigint;
  pubkeyY: bigint;
  nkHash: bigint;
  leafIndex: number;
  leaf: bigint;
}

export interface RegistryProof {
  pubkeyX: bigint;
  pubkeyY: bigint;
  nkHash: bigint;
  leafIndex: number;
  siblings: bigint[];
  root: bigint;
}

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

/**
 * Registry Merkle Tree
 * Same structure as pool tree but different leaf computation
 */
export class RegistryTree {
  private depth: number;
  private zeros: bigint[];
  private filledSubtrees: bigint[];
  private leaves: bigint[];
  private entries: Map<string, RegistryEntry>; // address -> entry
  private nextIndex: number;

  constructor(depth: number = TREE_DEPTH) {
    this.depth = depth;
    this.zeros = [];
    this.filledSubtrees = [];
    this.leaves = [];
    this.entries = new Map();
    this.nextIndex = 0;

    // Initialize zeros (same as contract) - zeros[0] = 0
    this.zeros[0] = 0n;
    for (let i = 1; i < depth; i++) {
      this.zeros[i] = poseidon2([this.zeros[i - 1], this.zeros[i - 1]]);
    }

    // Initialize filled subtrees with zeros
    this.filledSubtrees = [...this.zeros];
  }

  /**
   * Get the current root
   */
  getRoot(): bigint {
    if (this.nextIndex === 0) {
      return this.zeros[this.depth - 1];
    }

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
   * Register a user and return their leaf index
   */
  register(
    address: bigint,
    pubkeyX: bigint,
    pubkeyY: bigint,
    nkHash: bigint
  ): number {
    const addrKey = address.toString();
    if (this.entries.has(addrKey)) {
      throw new Error(`Address ${addrKey} already registered`);
    }

    const leaf = computeRegistryLeaf(address, pubkeyX, pubkeyY, nkHash);
    const leafIndex = this.insertLeaf(leaf);

    this.entries.set(addrKey, {
      address,
      pubkeyX,
      pubkeyY,
      nkHash,
      leafIndex,
      leaf,
    });

    return leafIndex;
  }

  /**
   * Insert a leaf into the tree
   */
  private insertLeaf(leaf: bigint): number {
    const leafIndex = this.nextIndex;

    if (leafIndex >= 2 ** this.depth) {
      throw new Error('Tree is full');
    }

    this.leaves.push(leaf);

    let currentIndex = leafIndex;
    let currentHash = leaf;

    for (let i = 0; i < this.depth; i++) {
      if (currentIndex % 2 === 0) {
        this.filledSubtrees[i] = currentHash;
        currentHash = poseidon2([currentHash, this.zeros[i]]);
      } else {
        currentHash = poseidon2([this.filledSubtrees[i], currentHash]);
      }
      currentIndex = Math.floor(currentIndex / 2);
    }

    this.nextIndex = leafIndex + 1;
    return leafIndex;
  }

  /**
   * Generate a registry proof for an address
   */
  generateProof(address: bigint | string): RegistryProof | null {
    const addrKey = typeof address === 'string'
      ? BigInt(address).toString()
      : address.toString();

    const entry = this.entries.get(addrKey);
    if (!entry) {
      return null;
    }

    const siblings = this.getSiblings(entry.leafIndex);

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
   * Get siblings for a leaf index
   */
  private getSiblings(leafIndex: number): bigint[] {
    const siblings: bigint[] = [];
    let currentIndex = leafIndex;

    for (let level = 0; level < this.depth; level++) {
      const siblingIndex = currentIndex % 2 === 0 ? currentIndex + 1 : currentIndex - 1;

      let sibling: bigint;
      if (siblingIndex < this.getSubtreeSize(level)) {
        sibling = this.getNodeAtLevel(level, siblingIndex);
      } else {
        sibling = this.zeros[level];
      }

      siblings.push(sibling);
      currentIndex = Math.floor(currentIndex / 2);
    }

    return siblings;
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

    const leftChildIndex = index * 2;
    const rightChildIndex = index * 2 + 1;

    const leftChild = this.getNodeAtLevel(level - 1, leftChildIndex);
    const rightChild = this.getNodeAtLevel(level - 1, rightChildIndex);

    return poseidon2([leftChild, rightChild]);
  }

  /**
   * Check if an address is registered
   */
  isRegistered(address: bigint | string): boolean {
    const addrKey = typeof address === 'string'
      ? BigInt(address).toString()
      : address.toString();
    return this.entries.has(addrKey);
  }

  /**
   * Get entry for an address
   */
  getEntry(address: bigint | string): RegistryEntry | null {
    const addrKey = typeof address === 'string'
      ? BigInt(address).toString()
      : address.toString();
    return this.entries.get(addrKey) || null;
  }
}
