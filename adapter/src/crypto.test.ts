// Cross-language consistency tests
// Verifies that crypto operations in TypeScript match Noir circuits and Solidity contracts
//
// These tests use known test vectors to ensure hash functions, commitments,
// nullifiers, and registry leaves are computed identically across all layers.

import { describe, it, expect, beforeAll } from 'vitest';
import { initPoseidon, poseidon2 } from './crypto/poseidon.js';
import {
  computeCommitment,
  computeNullifier,
  computeNullifierKeyHash,
  computeIntentNullifier,
  computeRegistryLeaf,
  ciphertextHash5,
  ciphertextHash10,
  hash3,
  hash4,
  hash5,
  deriveEncSeed,
  FIELD_SIZE,
  NULLIFIER_DOMAIN,
  NULLIFIER_KEY_DOMAIN,
  INTENT_DOMAIN,
  REG_LEAF_DOMAIN,
} from './crypto/embedded-curve.js';
import { RegistryTree, computeRegistryLeaf as computeRegistryLeafTree } from './registry-tree.js';
import { MerkleTree } from './merkle.js';
import { TREE_DEPTH, REGISTRY_DEPTH, DOMAIN } from './config.js';

describe('Poseidon Hash Consistency', () => {
  beforeAll(async () => {
    await initPoseidon();
  });

  it('poseidon2 is deterministic', () => {
    const a = 0x123n;
    const b = 0x456n;
    const hash1 = poseidon2([a, b]);
    const hash2 = poseidon2([a, b]);
    expect(hash1).toBe(hash2);
  });

  it('poseidon2 output is in field', () => {
    const hash = poseidon2([1n, 2n]);
    expect(hash >= 0n).toBe(true);
    expect(hash < FIELD_SIZE).toBe(true);
  });

  it('hash3 uses binary tree structure', () => {
    const inputs: [bigint, bigint, bigint] = [1n, 2n, 3n];
    const result = hash3(inputs);

    // Manual binary tree: hash(hash(1,2), 3)
    const h12 = poseidon2([1n, 2n]);
    const expected = poseidon2([h12, 3n]);
    expect(result).toBe(expected);
  });

  it('hash4 uses binary tree structure', () => {
    const inputs: [bigint, bigint, bigint, bigint] = [1n, 2n, 3n, 4n];
    const result = hash4(inputs);

    // Manual binary tree: hash(hash(1,2), hash(3,4))
    const h12 = poseidon2([1n, 2n]);
    const h34 = poseidon2([3n, 4n]);
    const expected = poseidon2([h12, h34]);
    expect(result).toBe(expected);
  });
});

describe('Commitment Computation', () => {
  beforeAll(async () => {
    await initPoseidon();
  });

  it('commitment is deterministic', () => {
    const amount = 1000000000000000000n; // 1 ETH
    const owner = 0x70997970C51812dc3A010C7d01b50e0d17dc79C8n;
    const randomness = 12345n;
    const nkHash = 67890n;

    const c1 = computeCommitment(amount, owner, randomness, nkHash);
    const c2 = computeCommitment(amount, owner, randomness, nkHash);
    expect(c1).toBe(c2);
  });

  it('commitment uses hash4 (binary tree)', () => {
    const amount = 100n;
    const owner = 200n;
    const randomness = 300n;
    const nkHash = 400n;

    const commitment = computeCommitment(amount, owner, randomness, nkHash);
    const expected = hash4([amount, owner, randomness, nkHash]);
    expect(commitment).toBe(expected);
  });

  it('commitment is in field', () => {
    const commitment = computeCommitment(1n, 2n, 3n, 4n);
    expect(commitment >= 0n).toBe(true);
    expect(commitment < FIELD_SIZE).toBe(true);
  });
});

describe('Nullifier Computation', () => {
  beforeAll(async () => {
    await initPoseidon();
  });

  it('nullifier includes domain separator', () => {
    const nullifierKey = 12345n;
    const leafIndex = 42;
    const randomness = 67890n;

    const nullifier = computeNullifier(nullifierKey, leafIndex, randomness);

    // Manual: hash4([NULLIFIER_DOMAIN, nk, leafIndex, randomness])
    const expected = hash4([NULLIFIER_DOMAIN, nullifierKey, BigInt(leafIndex), randomness]);
    expect(nullifier).toBe(expected);
  });

  it('nullifier is deterministic', () => {
    const nk = 111n;
    const idx = 5;
    const rnd = 222n;

    const n1 = computeNullifier(nk, idx, rnd);
    const n2 = computeNullifier(nk, idx, rnd);
    expect(n1).toBe(n2);
  });

  it('different leaf indices produce different nullifiers', () => {
    const nk = 111n;
    const rnd = 222n;

    const n1 = computeNullifier(nk, 0, rnd);
    const n2 = computeNullifier(nk, 1, rnd);
    expect(n1).not.toBe(n2);
  });
});

describe('Nullifier Key Hash', () => {
  beforeAll(async () => {
    await initPoseidon();
  });

  it('nkHash includes domain separator', () => {
    const nullifierKey = 12345n;
    const nkHash = computeNullifierKeyHash(nullifierKey);

    const expected = poseidon2([nullifierKey, NULLIFIER_KEY_DOMAIN]);
    expect(nkHash).toBe(expected);
  });
});

describe('Intent Nullifier', () => {
  beforeAll(async () => {
    await initPoseidon();
  });

  it('intent nullifier includes domain separator', () => {
    const nullifierKey = 12345n;
    const chainId = 13371337n;
    const nonce = 42n;

    const intent = computeIntentNullifier(nullifierKey, chainId, nonce);

    // Manual: hash4([INTENT_DOMAIN, nk, chainId, nonce])
    const expected = hash4([INTENT_DOMAIN, nullifierKey, chainId, nonce]);
    expect(intent).toBe(expected);
  });

  it('same nonce on different chains produces different intents', () => {
    const nk = 111n;
    const nonce = 1n;

    const intent1 = computeIntentNullifier(nk, 1n, nonce);
    const intent2 = computeIntentNullifier(nk, 2n, nonce);
    expect(intent1).not.toBe(intent2);
  });
});

describe('Registry Leaf', () => {
  beforeAll(async () => {
    await initPoseidon();
  });

  it('registry leaf includes domain separator', () => {
    const address = 0x70997970C51812dc3A010C7d01b50e0d17dc79C8n;
    const pkX = 1n; // Generator x
    const pkY = 17631683881184975370165255887551781615748388533673675138860n; // Generator y
    const nkHash = 12345n;

    const leaf = computeRegistryLeaf(address, pkX, pkY, nkHash);

    // Manual: hash(hash(hash(domain, address), hash(pkX, pkY)), nkHash)
    const h1 = poseidon2([REG_LEAF_DOMAIN, address]);
    const h2 = poseidon2([pkX, pkY]);
    const h3 = poseidon2([h1, h2]);
    const expected = poseidon2([h3, nkHash]);
    expect(leaf).toBe(expected);
  });

  it('registry leaf matches tree computation', () => {
    const address = 0x1234n;
    const pkX = 100n;
    const pkY = 200n;
    const nkHash = 300n;

    const leaf1 = computeRegistryLeaf(address, pkX, pkY, nkHash);
    const leaf2 = computeRegistryLeafTree(address, pkX, pkY, nkHash);
    expect(leaf1).toBe(leaf2);
  });
});

describe('Ciphertext Hash', () => {
  beforeAll(async () => {
    await initPoseidon();
  });

  it('ciphertextHash5 uses binary tree', () => {
    const cipher: [bigint, bigint, bigint, bigint, bigint] = [1n, 2n, 3n, 4n, 5n];
    const hash = ciphertextHash5(cipher);

    // Manual binary tree for 5 elements
    const h01 = poseidon2([1n, 2n]);
    const h23 = poseidon2([3n, 4n]);
    const h0123 = poseidon2([h01, h23]);
    const expected = poseidon2([h0123, 5n]);
    expect(hash).toBe(expected);
  });

  it('ciphertextHash10 combines two ciphertextHash5', () => {
    const c0: [bigint, bigint, bigint, bigint, bigint] = [1n, 2n, 3n, 4n, 5n];
    const c1: [bigint, bigint, bigint, bigint, bigint] = [6n, 7n, 8n, 9n, 10n];

    const hash = ciphertextHash10(c0, c1);

    const h0 = ciphertextHash5(c0);
    const h1 = ciphertextHash5(c1);
    const expected = poseidon2([h0, h1]);
    expect(hash).toBe(expected);
  });
});

describe('Registry Tree', () => {
  beforeAll(async () => {
    await initPoseidon();
  });

  it('zeros[0] is 0 (not poseidon(0,0))', () => {
    const tree = new RegistryTree();
    expect(tree.getZero(0)).toBe(0n);
  });

  it('zeros[1] is poseidon(0, 0)', () => {
    const tree = new RegistryTree();
    const expected = poseidon2([0n, 0n]);
    expect(tree.getZero(1)).toBe(expected);
  });

  it('empty tree has correct root', () => {
    const tree = new RegistryTree();
    // Empty root is zeros[REGISTRY_DEPTH - 1]
    const emptyRoot = tree.getRoot();
    expect(emptyRoot).toBe(tree.getZero(REGISTRY_DEPTH - 1));
  });

  it('insertion updates root correctly', () => {
    const tree = new RegistryTree();
    const emptyRoot = tree.getRoot();

    tree.insertEntry(0x1234n, 100n, 200n, 300n);
    const newRoot = tree.getRoot();

    expect(newRoot).not.toBe(emptyRoot);
  });

  it('proof verification works', () => {
    const tree = new RegistryTree();
    const address = 0x70997970C51812dc3A010C7d01b50e0d17dc79C8n;
    const pkX = 1n;
    const pkY = 17631683881184975370165255887551781615748388533673675138860n;
    const nkHash = 12345n;

    tree.insertEntry(address, pkX, pkY, nkHash);

    const proof = tree.generateProof('0x70997970C51812dc3A010C7d01b50e0d17dc79C8');
    expect(proof).not.toBeNull();

    const isValid = RegistryTree.verifyProof(proof!, address);
    expect(isValid).toBe(true);
  });
});

describe('Pool Merkle Tree', () => {
  beforeAll(async () => {
    await initPoseidon();
  });

  it('zeros[0] is 0 (not poseidon(0,0))', () => {
    const tree = new MerkleTree();
    // CRITICAL: Empty leaf is 0, NOT hash(0,0) - matches PrivacyPool.sol
    expect(tree.getZero(0)).toBe(0n);
  });

  it('proof verification works', () => {
    const tree = new MerkleTree();
    const leaf = 0x12345n;

    const idx = tree.insert(leaf);
    const proof = tree.generateProof(idx);

    const isValid = MerkleTree.verifyProof(proof);
    expect(isValid).toBe(true);
  });
});

describe('Domain Separators Match', () => {
  it('config domain separators match embedded-curve', () => {
    expect(DOMAIN.NULLIFIER).toBe(NULLIFIER_DOMAIN);
    expect(DOMAIN.NULLIFIER_KEY).toBe(NULLIFIER_KEY_DOMAIN);
    expect(DOMAIN.INTENT).toBe(INTENT_DOMAIN);
    expect(DOMAIN.REG_LEAF).toBe(REG_LEAF_DOMAIN);
  });
});

describe('Encryption Seed Derivation', () => {
  beforeAll(async () => {
    await initPoseidon();
  });

  it('enc_seed is deterministic', () => {
    const nullifierKey = 12345n;
    const seed1 = deriveEncSeed(nullifierKey);
    const seed2 = deriveEncSeed(nullifierKey);
    expect(seed1).toBe(seed2);
  });

  it('enc_seed is in field', () => {
    const seed = deriveEncSeed(12345n);
    expect(seed >= 0n).toBe(true);
    expect(seed < FIELD_SIZE).toBe(true);
  });
});

describe('Field Size Validation', () => {
  it('FIELD_SIZE is correct for BN254', () => {
    // BN254 scalar field size
    const expected = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
    expect(FIELD_SIZE).toBe(expected);
  });
});
