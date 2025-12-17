/**
 * Generate Poseidon test vectors for cross-language validation
 * These vectors should be verified in: Solidity, Noir, and TypeScript
 *
 * Uses circomlibjs which implements Poseidon over BN254 (same as Noir's bn254)
 */

import { buildPoseidon } from 'circomlibjs';
import { writeFileSync } from 'fs';

// BN254 field size
const FIELD_SIZE = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

async function main() {
  console.log('Building Poseidon hash function...');
  const poseidon = await buildPoseidon();

  // Helper to convert poseidon output to bigint
  const hash = (inputs) => {
    const result = poseidon(inputs.map(x => BigInt(x)));
    return poseidon.F.toString(result);
  };

  const vectors = {
    description: "Poseidon test vectors for BN254 field",
    field_size: FIELD_SIZE.toString(),
    generated_at: new Date().toISOString(),

    // Hash with 2 inputs (PoseidonT3)
    hash_2_inputs: [],

    // Hash with 3 inputs (PoseidonT4) - used for note commitments
    hash_3_inputs: [],

    // Hash with 5 inputs (PoseidonT6) - used for intent nullifier
    hash_5_inputs: [],

    // Merkle tree test: zeros array and root evolution
    merkle_tree: {
      depth: 20,
      zeros: [],
      roots_after_insertions: []
    }
  };

  // ==================== 2-input hash tests ====================
  console.log('Generating 2-input hash vectors...');

  // Test case 1: Simple values
  vectors.hash_2_inputs.push({
    name: "simple_values",
    inputs: ["1", "2"],
    expected: hash([1n, 2n])
  });

  // Test case 2: Zero inputs
  vectors.hash_2_inputs.push({
    name: "zero_inputs",
    inputs: ["0", "0"],
    expected: hash([0n, 0n])
  });

  // Test case 3: Large values (but < field size)
  vectors.hash_2_inputs.push({
    name: "large_values",
    inputs: [
      "12345678901234567890",
      "98765432109876543210"
    ],
    expected: hash([12345678901234567890n, 98765432109876543210n])
  });

  // Test case 4: Nullifier computation (commitment, nk)
  const testCommitment = 123456789n;
  const testNk = 987654321n;
  vectors.hash_2_inputs.push({
    name: "nullifier_computation",
    inputs: [testCommitment.toString(), testNk.toString()],
    expected: hash([testCommitment, testNk])
  });

  // ==================== 3-input hash tests ====================
  console.log('Generating 3-input hash vectors...');

  // Test case 1: Note commitment (amount, owner, randomness)
  const testAmount = 1000000000000000000n; // 1 ETH in wei
  const testOwner = 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266n; // Common test address
  const testRandomness = 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdefn;

  vectors.hash_3_inputs.push({
    name: "note_commitment",
    inputs: [testAmount.toString(), testOwner.toString(), testRandomness.toString()],
    expected: hash([testAmount, testOwner, testRandomness])
  });

  // Test case 2: Simple values
  vectors.hash_3_inputs.push({
    name: "simple_values",
    inputs: ["1", "2", "3"],
    expected: hash([1n, 2n, 3n])
  });

  // Test case 3: Zero inputs
  vectors.hash_3_inputs.push({
    name: "zero_inputs",
    inputs: ["0", "0", "0"],
    expected: hash([0n, 0n, 0n])
  });

  // ==================== 5-input hash tests ====================
  console.log('Generating 5-input hash vectors...');

  // Test case 1: Intent nullifier (signer, chainId, nonce, to, value)
  const testSigner = 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266n;
  const testChainId = 13371337n;
  const testNonce = 0n;
  const testTo = 0x70997970C51812dc3A010C7d01b50e0d17dc79C8n;
  const testValue = 1000000000000000000n; // 1 ETH

  vectors.hash_5_inputs.push({
    name: "intent_nullifier",
    inputs: [
      testSigner.toString(),
      testChainId.toString(),
      testNonce.toString(),
      testTo.toString(),
      testValue.toString()
    ],
    expected: hash([testSigner, testChainId, testNonce, testTo, testValue])
  });

  // Test case 2: Simple values
  vectors.hash_5_inputs.push({
    name: "simple_values",
    inputs: ["1", "2", "3", "4", "5"],
    expected: hash([1n, 2n, 3n, 4n, 5n])
  });

  // ==================== Merkle tree tests ====================
  console.log('Generating Merkle tree vectors...');

  // Compute zeros array (same as contract initialization)
  // zeros[0] = poseidon(0, 0) for empty leaf
  const zeros = [];
  zeros[0] = hash([0n, 0n]);

  for (let i = 1; i < 20; i++) {
    zeros[i] = hash([BigInt(zeros[i-1]), BigInt(zeros[i-1])]);
  }
  vectors.merkle_tree.zeros = zeros;

  // Initial root (empty tree)
  vectors.merkle_tree.initial_root = zeros[19];

  // Compute root after inserting some leaves
  // We'll do a simplified version - insert leaf at index 0
  const testLeaf1 = hash([testAmount, testOwner, testRandomness]);

  // For a single leaf at index 0, the path goes:
  // level 0: hash(leaf, zero[0])
  // level 1: hash(prev, zero[1])
  // ...
  let current = testLeaf1;
  for (let i = 0; i < 20; i++) {
    current = hash([BigInt(current), BigInt(zeros[i])]);
  }

  vectors.merkle_tree.roots_after_insertions.push({
    name: "single_leaf_at_index_0",
    leaf: testLeaf1,
    leaf_index: 0,
    root: current
  });

  // Write vectors
  const outputPath = 'poseidon-vectors.json';
  writeFileSync(outputPath, JSON.stringify(vectors, null, 2));
  console.log(`\nWritten to ${outputPath}`);

  // Print summary
  console.log('\n=== Summary ===');
  console.log(`2-input tests: ${vectors.hash_2_inputs.length}`);
  console.log(`3-input tests: ${vectors.hash_3_inputs.length}`);
  console.log(`5-input tests: ${vectors.hash_5_inputs.length}`);
  console.log(`Merkle zeros: ${vectors.merkle_tree.zeros.length}`);
  console.log(`\nInitial root (empty tree):`);
  console.log(`  ${vectors.merkle_tree.initial_root}`);
  console.log(`\nNote commitment example:`);
  console.log(`  poseidon(${testAmount}, ${testOwner}, ${testRandomness})`);
  console.log(`  = ${vectors.hash_3_inputs[0].expected}`);
}

main().catch(console.error);
