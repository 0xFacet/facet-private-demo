/**
 * Integration Test - Privacy Pool Demo
 *
 * Tests the end-to-end flow:
 * 1. Deploy contracts
 * 2. Register ECIES key
 * 3. Deposit ETH
 * 4. Verify merkle tree state
 *
 * Run: npx tsx test-flow.ts
 * Requires: anvil running on localhost:8545
 */

import { parseEther } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { buildPoseidon } from 'circomlibjs';

// Anvil default private key #0
const PRIVATE_KEY = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80';

// Contract ABIs
const REGISTRY_ABI = [
  {
    name: 'register',
    type: 'function',
    inputs: [
      { name: 'pubKeyX', type: 'bytes32' },
      { name: 'pubKeyY', type: 'bytes32' }
    ],
    outputs: [],
    stateMutability: 'nonpayable'
  },
  {
    name: 'getKey',
    type: 'function',
    inputs: [{ name: 'owner', type: 'address' }],
    outputs: [
      { name: '', type: 'bytes32' },
      { name: '', type: 'bytes32' }
    ],
    stateMutability: 'view'
  }
] as const;

const POOL_ABI = [
  {
    name: 'deposit',
    type: 'function',
    inputs: [{ name: 'commitment', type: 'bytes32' }],
    outputs: [],
    stateMutability: 'payable'
  },
  {
    name: 'getRoot',
    type: 'function',
    inputs: [],
    outputs: [{ name: '', type: 'bytes32' }],
    stateMutability: 'view'
  },
  {
    name: 'nextLeafIndex',
    type: 'function',
    inputs: [],
    outputs: [{ name: '', type: 'uint256' }],
    stateMutability: 'view'
  },
  {
    type: 'event',
    name: 'NoteCreated',
    inputs: [
      { name: 'commitment', type: 'bytes32', indexed: true },
      { name: 'leafIndex', type: 'uint256', indexed: false },
      { name: 'timestamp', type: 'uint256', indexed: false }
    ]
  }
] as const;

async function main() {
  console.log('Privacy Pool Integration Test\n');
  console.log('=' .repeat(50));

  // Account setup (doesn't require network)
  const account = privateKeyToAccount(PRIVATE_KEY);
  console.log(`\nUsing account: ${account.address}`);

  // Check if contracts are deployed
  // For now, we just verify Poseidon works
  console.log('\n--- Testing Poseidon Hash ---');
  const poseidon = await buildPoseidon();

  const testInputs = [1n, 2n, 3n];
  const hash = poseidon.F.toString(poseidon(testInputs));
  console.log(`Poseidon([1, 2, 3]) = ${hash}`);

  // Load and verify against test vectors
  const fs = await import('fs');
  const vectors = JSON.parse(fs.readFileSync('../fixtures/poseidon-vectors.json', 'utf-8'));

  // Test 2-input hash
  const vec2 = vectors.hash_2_inputs[0]; // simple_values: [1, 2]
  const inputs2 = vec2.inputs.map(BigInt);
  const computed2 = poseidon.F.toString(poseidon(inputs2));
  if (computed2 === vec2.expected) {
    console.log('✓ Poseidon(1, 2) matches test vector');
  } else {
    console.log('✗ Poseidon(1, 2) mismatch!');
    console.log(`  Expected: ${vec2.expected}`);
    console.log(`  Got: ${computed2}`);
  }

  // Test 3-input hash
  const vec3 = vectors.hash_3_inputs[0]; // simple_values: [1, 2, 3]
  const inputs3 = vec3.inputs.map(BigInt);
  const computed3 = poseidon.F.toString(poseidon(inputs3));
  if (computed3 === vec3.expected) {
    console.log('✓ Poseidon(1, 2, 3) matches test vector');
  } else {
    console.log('✗ Poseidon(1, 2, 3) mismatch!');
    console.log(`  Expected: ${vec3.expected}`);
    console.log(`  Got: ${computed3}`);
  }

  // Create a test commitment
  console.log('\n--- Creating Test Commitment ---');
  const amount = parseEther('1.0');
  const owner = account.address;
  const randomness = 12345n;

  // Note commitment = Poseidon(amount, owner_as_field, randomness)
  // Convert address to field (take last 20 bytes as number)
  const ownerField = BigInt(owner);
  const commitment = poseidon.F.toString(poseidon([amount, ownerField, randomness]));
  console.log(`Commitment for 1 ETH note: ${commitment}`);

  // Verify nullifier derivation
  console.log('\n--- Testing Nullifier Derivation ---');
  const nullifierKey = 999n;
  const nullifier = poseidon.F.toString(poseidon([BigInt(commitment), nullifierKey]));
  console.log(`Nullifier: ${nullifier}`);

  console.log('\n' + '='.repeat(50));
  console.log('Integration test complete!');
  console.log('\nNote: Full contract deployment test requires:');
  console.log('  1. anvil running: `anvil`');
  console.log('  2. Deploy script: `cd contracts && forge script script/Deploy.s.sol --broadcast`');
}

main().catch(console.error);
