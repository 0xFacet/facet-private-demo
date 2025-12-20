// ZK Proof generation using noir_js and bb.js

import { Noir } from '@noir-lang/noir_js';
import { UltraHonkBackend } from '@aztec/bb.js';
import { readFileSync, existsSync } from 'fs';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';
import { Hex, hexToBytes } from 'viem';
import { Piscina } from 'piscina';

import { TREE_DEPTH } from './config.js';

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
  console.log(`[Circuit] Looking for ${name}, cwd=${process.cwd()}, __dirname=${__dirname}`);
  for (const path of candidates) {
    console.log(`[Circuit] Checking ${path}: ${existsSync(path)}`);
    if (existsSync(path)) return path;
  }
  throw new Error(`Circuit ${name} not found. Checked: ${candidates.join(', ')}`);
}
const TRANSFER_CIRCUIT_PATH = findCircuit('transfer');
const WITHDRAW_CIRCUIT_PATH = findCircuit('withdraw');

/**
 * Note data for circuit input
 */
export interface NoteInput {
  amount: bigint;
  randomness: bigint;
  leafIndex: number;
  siblings: bigint[];
}

/**
 * Signature data from signed transaction
 */
export interface SignatureData {
  pubKeyX: Uint8Array;  // 32 bytes
  pubKeyY: Uint8Array;  // 32 bytes
  signature: Uint8Array; // 64 bytes (r || s)
}

/**
 * Transfer circuit inputs
 */
export interface TransferCircuitInputs {
  // Public inputs
  merkleRoot: bigint;
  nullifier0: bigint;
  nullifier1: bigint;
  outputCommitment0: bigint;
  outputCommitment1: bigint;
  intentNullifier: bigint;

  // Private inputs
  signatureData: SignatureData;
  txNonce: bigint;
  txMaxPriorityFee: bigint;
  txMaxFee: bigint;
  txGasLimit: bigint;
  txTo: bigint;
  txValue: bigint;

  input0: NoteInput;
  input1: NoteInput;

  output0Amount: bigint;
  output0Owner: bigint;
  output0Randomness: bigint;

  output1Amount: bigint;
  output1Randomness: bigint;

  // Nullifier key (private - bound to commitment via nkHash)
  nullifierKey: bigint;
  // Recipient's nullifier key hash (for output note 0)
  output0NullifierKeyHash: bigint;
}

/**
 * Withdraw circuit inputs
 */
export interface WithdrawCircuitInputs {
  // Public inputs
  merkleRoot: bigint;
  nullifier0: bigint;
  nullifier1: bigint;
  changeCommitment: bigint;
  intentNullifier: bigint;
  withdrawRecipient: bigint;
  withdrawAmount: bigint;

  // Private inputs
  signatureData: SignatureData;
  txNonce: bigint;
  txMaxPriorityFee: bigint;
  txMaxFee: bigint;
  txGasLimit: bigint;

  input0: NoteInput;
  input1: NoteInput;

  changeAmount: bigint;
  changeRandomness: bigint;

  // Nullifier key (private - bound to commitment via nkHash)
  nullifierKey: bigint;
}

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
 * Convert bigint to string for Noir input
 */
function toNoirField(value: bigint): string {
  return '0x' + value.toString(16);
}

/**
 * Convert byte array to Noir array format
 */
function toNoirByteArray(bytes: Uint8Array): string[] {
  return Array.from(bytes).map(b => b.toString());
}

/**
 * Convert bigint array to Noir array format
 */
function toNoirFieldArray(values: bigint[]): string[] {
  return values.map(v => toNoirField(v));
}

/**
 * Build circuit inputs object for Noir
 */
export function buildTransferInputs(inputs: TransferCircuitInputs): Record<string, any> {
  return {
    // Public inputs
    merkle_root: toNoirField(inputs.merkleRoot),
    nullifier_0: toNoirField(inputs.nullifier0),
    nullifier_1: toNoirField(inputs.nullifier1),
    output_commitment_0: toNoirField(inputs.outputCommitment0),
    output_commitment_1: toNoirField(inputs.outputCommitment1),
    intent_nullifier: toNoirField(inputs.intentNullifier),

    // Signature
    pub_key_x: toNoirByteArray(inputs.signatureData.pubKeyX),
    pub_key_y: toNoirByteArray(inputs.signatureData.pubKeyY),
    signature: toNoirByteArray(inputs.signatureData.signature),

    // Transaction fields
    tx_nonce: inputs.txNonce.toString(),
    tx_max_priority_fee: inputs.txMaxPriorityFee.toString(),
    tx_max_fee: inputs.txMaxFee.toString(),
    tx_gas_limit: inputs.txGasLimit.toString(),
    tx_to: toNoirField(inputs.txTo),
    tx_value: inputs.txValue.toString(),

    // Input note 0
    input_0_amount: inputs.input0.amount.toString(),
    input_0_randomness: toNoirField(inputs.input0.randomness),
    input_0_leaf_index: inputs.input0.leafIndex.toString(),
    input_0_siblings: toNoirFieldArray(inputs.input0.siblings),

    // Input note 1
    input_1_amount: inputs.input1.amount.toString(),
    input_1_randomness: toNoirField(inputs.input1.randomness),
    input_1_leaf_index: inputs.input1.leafIndex.toString(),
    input_1_siblings: toNoirFieldArray(inputs.input1.siblings),

    // Output note 0
    output_0_amount: inputs.output0Amount.toString(),
    output_0_owner: toNoirField(inputs.output0Owner),
    output_0_randomness: toNoirField(inputs.output0Randomness),

    // Output note 1
    output_1_amount: inputs.output1Amount.toString(),
    output_1_randomness: toNoirField(inputs.output1Randomness),

    // Nullifier key (for spending input notes and computing change commitment)
    nullifier_key: toNoirField(inputs.nullifierKey),
    // Recipient's nullifier key hash (for output note 0)
    output_0_nullifier_key_hash: toNoirField(inputs.output0NullifierKeyHash),
  };
}

/**
 * Generate a transfer proof
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
 * Build circuit inputs object for Noir (withdraw circuit)
 */
export function buildWithdrawInputs(inputs: WithdrawCircuitInputs): Record<string, any> {
  return {
    // Public inputs
    merkle_root: toNoirField(inputs.merkleRoot),
    nullifier_0: toNoirField(inputs.nullifier0),
    nullifier_1: toNoirField(inputs.nullifier1),
    change_commitment: toNoirField(inputs.changeCommitment),
    intent_nullifier: toNoirField(inputs.intentNullifier),
    withdraw_recipient: toNoirField(inputs.withdrawRecipient),
    withdraw_amount: inputs.withdrawAmount.toString(),

    // Signature
    pub_key_x: toNoirByteArray(inputs.signatureData.pubKeyX),
    pub_key_y: toNoirByteArray(inputs.signatureData.pubKeyY),
    signature: toNoirByteArray(inputs.signatureData.signature),

    // Transaction fields
    tx_nonce: inputs.txNonce.toString(),
    tx_max_priority_fee: inputs.txMaxPriorityFee.toString(),
    tx_max_fee: inputs.txMaxFee.toString(),
    tx_gas_limit: inputs.txGasLimit.toString(),

    // Input note 0
    input_0_amount: inputs.input0.amount.toString(),
    input_0_randomness: toNoirField(inputs.input0.randomness),
    input_0_leaf_index: inputs.input0.leafIndex.toString(),
    input_0_siblings: toNoirFieldArray(inputs.input0.siblings),

    // Input note 1
    input_1_amount: inputs.input1.amount.toString(),
    input_1_randomness: toNoirField(inputs.input1.randomness),
    input_1_leaf_index: inputs.input1.leafIndex.toString(),
    input_1_siblings: toNoirFieldArray(inputs.input1.siblings),

    // Change note
    change_amount: inputs.changeAmount.toString(),
    change_randomness: toNoirField(inputs.changeRandomness),

    // Nullifier key (for spending input notes and computing change commitment)
    nullifier_key: toNoirField(inputs.nullifierKey),
  };
}

/**
 * Generate a withdraw proof
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

/**
 * Extract signature components from signed transaction
 */
export function extractSignatureFromTx(
  r: Hex,
  s: Hex,
  pubKeyUncompressed: Hex
): SignatureData {
  const rBytes = hexToBytes(r);
  const sBytes = hexToBytes(s);

  const pubKeyBytes = hexToBytes(pubKeyUncompressed);
  if (pubKeyBytes.length !== 65 || pubKeyBytes[0] !== 0x04) {
    throw new Error('Invalid uncompressed public key format');
  }

  const pubKeyX = pubKeyBytes.slice(1, 33);
  const pubKeyY = pubKeyBytes.slice(33, 65);

  const signature = new Uint8Array(64);
  signature.set(rBytes, 0);
  signature.set(sBytes, 32);

  return {
    pubKeyX,
    pubKeyY,
    signature,
  };
}

/**
 * Create phantom note input (for single-note transactions)
 */
export function createPhantomNoteInput(): NoteInput {
  return {
    amount: 0n,
    randomness: 0n,
    leafIndex: 0,
    siblings: Array(TREE_DEPTH).fill(0n),
  };
}

// ==================== Worker-based proof generation ====================

// Lazy-initialized worker pool (created on first use)
let proofWorkerPool: Piscina | null = null;

function getProofWorkerPool(): Piscina {
  if (!proofWorkerPool) {
    // Detect if running in TypeScript (tsx dev) or JavaScript (compiled prod)
    const isTs = import.meta.url.endsWith('.ts');
    const workerFile = isTs ? './proof-worker.ts' : './proof-worker.js';
    const workerUrl = new URL(workerFile, import.meta.url).href;

    console.log(`[Proof] Initializing worker pool with ${workerFile}...`);
    proofWorkerPool = new Piscina({
      filename: workerUrl,
      maxThreads: 1, // Single worker to avoid memory bloat
      // In dev mode, worker needs tsx loader to understand TypeScript
      execArgv: isTs ? ['--import', 'tsx'] : undefined,
    });
  }
  return proofWorkerPool;
}

/**
 * Convert bigint to hex string for serialization
 */
function toHexString(value: bigint): string {
  return '0x' + value.toString(16);
}

/**
 * Generate a transfer proof using worker thread (non-blocking)
 */
export async function generateTransferProofWorker(inputs: TransferCircuitInputs): Promise<{
  proof: Uint8Array;
  publicInputs: bigint[];
}> {
  const pool = getProofWorkerPool();

  // Build Noir inputs (already stringified)
  const noirInputs = buildTransferInputs(inputs);

  // Public inputs as hex strings for serialization
  const publicInputsHex = [
    toHexString(inputs.merkleRoot),
    toHexString(inputs.nullifier0),
    toHexString(inputs.nullifier1),
    toHexString(inputs.outputCommitment0),
    toHexString(inputs.outputCommitment1),
    toHexString(inputs.intentNullifier),
  ];

  console.log('[Proof] Sending transfer proof request to worker...');
  const result = await pool.run({
    type: 'transfer',
    inputs: noirInputs,
    publicInputs: publicInputsHex,
  });

  return {
    proof: new Uint8Array(result.proof),
    publicInputs: [
      inputs.merkleRoot,
      inputs.nullifier0,
      inputs.nullifier1,
      inputs.outputCommitment0,
      inputs.outputCommitment1,
      inputs.intentNullifier,
    ],
  };
}

/**
 * Generate a withdraw proof using worker thread (non-blocking)
 */
export async function generateWithdrawProofWorker(inputs: WithdrawCircuitInputs): Promise<{
  proof: Uint8Array;
  publicInputs: bigint[];
}> {
  const pool = getProofWorkerPool();

  // Build Noir inputs (already stringified)
  const noirInputs = buildWithdrawInputs(inputs);

  // Public inputs as hex strings for serialization
  const publicInputsHex = [
    toHexString(inputs.merkleRoot),
    toHexString(inputs.nullifier0),
    toHexString(inputs.nullifier1),
    toHexString(inputs.changeCommitment),
    toHexString(inputs.intentNullifier),
    toHexString(inputs.withdrawRecipient),
    inputs.withdrawAmount.toString(),
  ];

  console.log('[Proof] Sending withdraw proof request to worker...');
  const result = await pool.run({
    type: 'withdraw',
    inputs: noirInputs,
    publicInputs: publicInputsHex,
  });

  return {
    proof: new Uint8Array(result.proof),
    publicInputs: [
      inputs.merkleRoot,
      inputs.nullifier0,
      inputs.nullifier1,
      inputs.changeCommitment,
      inputs.intentNullifier,
      inputs.withdrawRecipient,
      inputs.withdrawAmount,
    ],
  };
}
