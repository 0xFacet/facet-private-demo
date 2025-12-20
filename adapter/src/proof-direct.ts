// Direct (blocking) ZK Proof generation - loads WASM in current thread
// Use this for tests; for production RPC use worker-based functions from proof.ts

import { Noir } from '@noir-lang/noir_js';
import { UltraHonkBackend } from '@aztec/bb.js';
import { readFileSync, existsSync } from 'fs';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';

import {
  buildTransferInputs,
  buildWithdrawInputs,
  type TransferCircuitInputs,
  type WithdrawCircuitInputs,
} from './proof.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Backend options - use keccak hash for Solidity verifier compatibility
const BACKEND_OPTIONS = { keccak: true };

// Circuit artifact paths - try multiple locations
function findCircuit(name: string): string {
  const candidates = [
    resolve(process.cwd(), `circuits/${name}/target/${name}.json`),
    resolve(process.cwd(), `../circuits/${name}/target/${name}.json`),
    resolve(__dirname, `../../circuits/${name}/target/${name}.json`),
    resolve(__dirname, `../../../circuits/${name}/target/${name}.json`),
  ];
  for (const path of candidates) {
    if (existsSync(path)) return path;
  }
  throw new Error(`Circuit ${name} not found. Checked: ${candidates.join(', ')}`);
}

const TRANSFER_CIRCUIT_PATH = findCircuit('transfer');
const WITHDRAW_CIRCUIT_PATH = findCircuit('withdraw');

// Cache loaded circuits to avoid reloading
let transferCircuitCache: any = null;
let withdrawCircuitCache: any = null;

/**
 * Load the transfer circuit (cached)
 */
export function loadTransferCircuit(): any {
  if (!transferCircuitCache) {
    const circuitJson = readFileSync(TRANSFER_CIRCUIT_PATH, 'utf-8');
    transferCircuitCache = JSON.parse(circuitJson);
  }
  return transferCircuitCache;
}

/**
 * Load the withdraw circuit (cached)
 */
export function loadWithdrawCircuit(): any {
  if (!withdrawCircuitCache) {
    const circuitJson = readFileSync(WITHDRAW_CIRCUIT_PATH, 'utf-8');
    withdrawCircuitCache = JSON.parse(circuitJson);
  }
  return withdrawCircuitCache;
}

/**
 * Generate a transfer proof (blocking - loads WASM in current thread)
 */
export async function generateTransferProof(inputs: TransferCircuitInputs): Promise<{
  proof: Uint8Array;
  publicInputs: bigint[];
}> {
  console.log('Loading transfer circuit...');
  const circuit = loadTransferCircuit();

  console.log('Initializing Noir backend...');
  const backend = new UltraHonkBackend(circuit.bytecode);
  const noir = new Noir(circuit);

  console.log('Building circuit inputs...');
  const noirInputs = buildTransferInputs(inputs);

  console.log('Executing circuit (computing witness)...');
  const { witness } = await noir.execute(noirInputs);

  console.log('Generating proof (keccak mode for Solidity compatibility)...');
  const proofData = await backend.generateProof(witness, BACKEND_OPTIONS);

  console.log('Proof generated successfully!');

  const publicInputs = [
    inputs.merkleRoot,
    inputs.nullifier0,
    inputs.nullifier1,
    inputs.outputCommitment0,
    inputs.outputCommitment1,
    inputs.intentNullifier,
  ];

  return {
    proof: proofData.proof,
    publicInputs,
  };
}

/**
 * Generate a withdraw proof (blocking - loads WASM in current thread)
 */
export async function generateWithdrawProof(inputs: WithdrawCircuitInputs): Promise<{
  proof: Uint8Array;
  publicInputs: bigint[];
}> {
  console.log('Loading withdraw circuit...');
  const circuit = loadWithdrawCircuit();

  console.log('Initializing Noir backend...');
  const backend = new UltraHonkBackend(circuit.bytecode);
  const noir = new Noir(circuit);

  console.log('Building circuit inputs...');
  const noirInputs = buildWithdrawInputs(inputs);

  console.log('Executing circuit (computing witness)...');
  const { witness } = await noir.execute(noirInputs);

  console.log('Generating proof (keccak mode for Solidity compatibility)...');
  const proofData = await backend.generateProof(witness, BACKEND_OPTIONS);

  console.log('Proof generated successfully!');

  const publicInputs = [
    inputs.merkleRoot,
    inputs.nullifier0,
    inputs.nullifier1,
    inputs.changeCommitment,
    inputs.intentNullifier,
    inputs.withdrawRecipient,
    inputs.withdrawAmount,
  ];

  return {
    proof: proofData.proof,
    publicInputs,
  };
}

// Re-export types for convenience
export type { TransferCircuitInputs, WithdrawCircuitInputs } from './proof.js';
