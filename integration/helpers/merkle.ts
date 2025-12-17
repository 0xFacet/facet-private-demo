// Incremental Merkle Tree implementation
// Mirrors the contract's merkle tree for proof generation

import { poseidon2 } from './poseidon.js';
import { TREE_DEPTH } from './config.js';

export interface MerkleProof {
  leaf: bigint;
  leafIndex: number;
  siblings: bigint[];
  pathIndices: number[]; // 0 = left, 1 = right
  root: bigint;
}

/**
 * Incremental Merkle Tree
 * Maintains the same state as the on-chain tree
 */
export class MerkleTree {
  private depth: number;
  private zeros: bigint[];
  private filledSubtrees: bigint[];
  private leaves: bigint[];
  private nextIndex: number;

  constructor(depth: number = TREE_DEPTH) {
    this.depth = depth;
    this.zeros = [];
    this.filledSubtrees = [];
    this.leaves = [];
    this.nextIndex = 0;

    // Initialize zeros (same as contract)
    // zeros[0] = poseidon(0, 0)
    this.zeros[0] = poseidon2([0n, 0n]);
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
    let currentHash = this.zeros[0];

    if (this.nextIndex === 0) {
      // Empty tree - return root of all zeros
      return this.zeros[this.depth - 1];
    }

    // Compute root from filled subtrees
    let currentIndex = this.nextIndex - 1;
    currentHash = this.leaves[currentIndex];

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
   * Insert a leaf and return its index
   */
  insert(leaf: bigint): number {
    const leafIndex = this.nextIndex;

    if (leafIndex >= 2 ** this.depth) {
      throw new Error('Tree is full');
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
   * Generate a Merkle proof for a leaf at a given index
   */
  generateProof(leafIndex: number): MerkleProof {
    if (leafIndex >= this.nextIndex) {
      throw new Error(`Leaf index ${leafIndex} not yet inserted`);
    }

    const siblings: bigint[] = [];
    const pathIndices: number[] = [];

    let currentIndex = leafIndex;

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
      pathIndices.push(currentIndex % 2); // 0 if left, 1 if right

      currentIndex = Math.floor(currentIndex / 2);
    }

    return {
      leaf: this.leaves[leafIndex],
      leafIndex,
      siblings,
      pathIndices,
      root: this.getRoot(),
    };
  }

  /**
   * Verify a Merkle proof
   */
  static verifyProof(proof: MerkleProof): boolean {
    let currentHash = proof.leaf;

    for (let i = 0; i < proof.siblings.length; i++) {
      if (proof.pathIndices[i] === 0) {
        // Current is left child
        currentHash = poseidon2([currentHash, proof.siblings[i]]);
      } else {
        // Current is right child
        currentHash = poseidon2([proof.siblings[i], currentHash]);
      }
    }

    return currentHash === proof.root;
  }

  /**
   * Get the number of leaves at a given level
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
   * Get the number of inserted leaves
   */
  get leafCount(): number {
    return this.nextIndex;
  }

  /**
   * Get a leaf by index
   */
  getLeaf(index: number): bigint {
    if (index >= this.nextIndex) {
      throw new Error(`Leaf index ${index} not yet inserted`);
    }
    return this.leaves[index];
  }
}
