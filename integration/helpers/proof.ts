// ZK Proof generation using noir_js and bb.js

import os from 'os';
import { Noir } from '@noir-lang/noir_js';
import { UltraHonkBackend, ProofData, type BackendOptions } from '@aztec/bb.js';
import { readFileSync, writeFileSync, existsSync } from 'fs';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';
import { Hex, hexToBytes, bytesToHex } from 'viem';

import { TREE_DEPTH, VIRTUAL_CHAIN_ID } from './config.js';
import { MerkleProof } from './merkle.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Backend options for initialization - multi-threaded with native if available
const threads = Math.min(16, os.cpus().length);
const bbPath = process.env.BB_PATH || `${os.homedir()}/.bb/bb`;

// Check if native backend can work (needs both bb binary and kill_wrapper.sh)
const killWrapperPath = resolve(__dirname, '../../node_modules/@aztec/bb.js/scripts/kill_wrapper.sh');
const canUseNative = existsSync(bbPath) && existsSync(killWrapperPath);

const INIT_OPTIONS: BackendOptions = {
  threads,
  bbPath: canUseNative ? bbPath : undefined,
  logger: msg => console.log(`[bb] ${msg}`),
};

// Proof generation options - keccakZK for EVM compatibility + zero-knowledge
const PROOF_OPTIONS = { keccakZK: true };

// Circuit artifact paths
const TRANSFER_CIRCUIT_PATH = resolve(__dirname, '../../circuits/transfer/target/transfer.json');
const WITHDRAW_CIRCUIT_PATH = resolve(__dirname, '../../circuits/withdraw/target/withdraw.json');

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
 * Registry proof for recipient membership
 */
export interface RegistryProof {
  pubkeyX: bigint;
  pubkeyY: bigint;
  nkHash: bigint;
  leafIndex: number;
  siblings: bigint[];
}

/**
 * Transfer circuit inputs - matches circuits/transfer/src/main.nr
 */
export interface TransferCircuitInputs {
  // ===== PUBLIC INPUTS (8 total) =====
  merkleRoot: bigint;
  nullifier0: bigint;
  nullifier1: bigint;
  outputCommitment0: bigint;
  outputCommitment1: bigint;
  intentNullifier: bigint;
  registryRoot: bigint;        // NEW: registry tree root
  ciphertextHash: bigint;      // NEW: hash of encrypted notes

  // ===== PRIVATE INPUTS =====
  signatureData: SignatureData;
  txNonce: bigint;
  txTo: bigint;
  txValue: bigint;
  txMaxPriorityFee: bigint;
  txMaxFee: bigint;
  txGasLimit: bigint;

  input0: NoteInput;
  input1: NoteInput;

  output0Randomness: bigint;
  output1Randomness: bigint;

  // Nullifier key
  nullifierKey: bigint;

  // Registry membership proof for recipient
  recipientProof: RegistryProof;
}

/**
 * Withdraw circuit inputs - matches circuits/withdraw/src/main.nr
 */
export interface WithdrawCircuitInputs {
  // ===== PUBLIC INPUTS (9 total) =====
  merkleRoot: bigint;
  nullifier0: bigint;
  nullifier1: bigint;
  changeCommitment: bigint;
  intentNullifier: bigint;
  withdrawRecipient: bigint;  // Must equal signer address
  withdrawAmount: bigint;
  registryRoot: bigint;       // NEW: registry tree root
  ciphertextHash: bigint;     // NEW: hash of encrypted change note

  // ===== PRIVATE INPUTS =====
  signatureData: SignatureData;
  txNonce: bigint;
  txMaxPriorityFee: bigint;
  txMaxFee: bigint;
  txGasLimit: bigint;

  input0: NoteInput;
  input1: NoteInput;

  changeRandomness: bigint;

  // Nullifier key
  nullifierKey: bigint;

  // Sender's registry membership proof
  senderProof: RegistryProof;
}

/**
 * Load the transfer circuit
 */
export function loadTransferCircuit(): any {
  const circuitJson = readFileSync(TRANSFER_CIRCUIT_PATH, 'utf-8');
  return JSON.parse(circuitJson);
}

/**
 * Load the withdraw circuit
 */
export function loadWithdrawCircuit(): any {
  const circuitJson = readFileSync(WITHDRAW_CIRCUIT_PATH, 'utf-8');
  return JSON.parse(circuitJson);
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
 * Build circuit inputs object for Noir - matches circuits/transfer/src/main.nr
 */
export function buildTransferInputs(inputs: TransferCircuitInputs): Record<string, any> {
  return {
    // ===== PUBLIC INPUTS (8 total) =====
    merkle_root: toNoirField(inputs.merkleRoot),
    nullifier_0: toNoirField(inputs.nullifier0),
    nullifier_1: toNoirField(inputs.nullifier1),
    output_commitment_0: toNoirField(inputs.outputCommitment0),
    output_commitment_1: toNoirField(inputs.outputCommitment1),
    intent_nullifier: toNoirField(inputs.intentNullifier),
    registry_root: toNoirField(inputs.registryRoot),
    ciphertext_hash_pub: toNoirField(inputs.ciphertextHash),

    // ===== PRIVATE INPUTS =====
    // Signature
    pub_key_x: toNoirByteArray(inputs.signatureData.pubKeyX),
    pub_key_y: toNoirByteArray(inputs.signatureData.pubKeyY),
    signature: toNoirByteArray(inputs.signatureData.signature),

    // Transaction fields
    tx_nonce: inputs.txNonce.toString(),
    tx_to: toNoirField(inputs.txTo),
    tx_value: inputs.txValue.toString(),
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

    // Output note randomness
    output_0_randomness: toNoirField(inputs.output0Randomness),
    output_1_randomness: toNoirField(inputs.output1Randomness),

    // Nullifier key
    nullifier_key: toNoirField(inputs.nullifierKey),

    // Registry membership proof for recipient
    recipient_pubkey_x: toNoirField(inputs.recipientProof.pubkeyX),
    recipient_pubkey_y: toNoirField(inputs.recipientProof.pubkeyY),
    recipient_nk_hash: toNoirField(inputs.recipientProof.nkHash),
    recipient_leaf_index: inputs.recipientProof.leafIndex.toString(),
    recipient_siblings: toNoirFieldArray(inputs.recipientProof.siblings),
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

  console.log(`Initializing Noir backend (threads=${threads}, native=${canUseNative})...`);
  const backend = new UltraHonkBackend(circuit.bytecode, INIT_OPTIONS);
  const noir = new Noir(circuit);

  console.log('Building circuit inputs...');
  const noirInputs = buildTransferInputs(inputs);

  console.log('Executing circuit (computing witness)...');
  const { witness } = await noir.execute(noirInputs);

  console.log('Generating proof (keccakZK: EVM-compatible + zero-knowledge)...');
  const proofData = await backend.generateProof(witness, PROOF_OPTIONS);

  console.log('Proof generated successfully!');

  // Extract public inputs in order (8 total - must match circuit declaration order)
  const publicInputs = [
    inputs.merkleRoot,
    inputs.nullifier0,
    inputs.nullifier1,
    inputs.outputCommitment0,
    inputs.outputCommitment1,
    inputs.intentNullifier,
    inputs.registryRoot,
    inputs.ciphertextHash,
  ];

  return {
    proof: proofData.proof,
    publicInputs,
  };
}

/**
 * Build circuit inputs object for Noir (withdraw circuit) - matches circuits/withdraw/src/main.nr
 */
export function buildWithdrawInputs(inputs: WithdrawCircuitInputs): Record<string, any> {
  return {
    // ===== PUBLIC INPUTS (9 total) =====
    merkle_root: toNoirField(inputs.merkleRoot),
    nullifier_0: toNoirField(inputs.nullifier0),
    nullifier_1: toNoirField(inputs.nullifier1),
    change_commitment: toNoirField(inputs.changeCommitment),
    intent_nullifier: toNoirField(inputs.intentNullifier),
    withdraw_recipient: toNoirField(inputs.withdrawRecipient),
    withdraw_amount: toNoirField(inputs.withdrawAmount),
    registry_root: toNoirField(inputs.registryRoot),
    ciphertext_hash_pub: toNoirField(inputs.ciphertextHash),

    // ===== PRIVATE INPUTS =====
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
    change_randomness: toNoirField(inputs.changeRandomness),

    // Nullifier key
    nullifier_key: toNoirField(inputs.nullifierKey),

    // Sender's registry membership proof
    sender_pubkey_x: toNoirField(inputs.senderProof.pubkeyX),
    sender_pubkey_y: toNoirField(inputs.senderProof.pubkeyY),
    sender_leaf_index: inputs.senderProof.leafIndex.toString(),
    sender_siblings: toNoirFieldArray(inputs.senderProof.siblings),
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

  console.log(`Initializing Noir backend (threads=${threads}, native=${canUseNative})...`);
  const backend = new UltraHonkBackend(circuit.bytecode, INIT_OPTIONS);
  const noir = new Noir(circuit);

  console.log('Building circuit inputs...');
  const noirInputs = buildWithdrawInputs(inputs);

  console.log('Executing circuit (computing witness)...');
  const { witness } = await noir.execute(noirInputs);

  console.log('Generating proof (keccakZK: EVM-compatible + zero-knowledge)...');
  const proofData = await backend.generateProof(witness, PROOF_OPTIONS);

  console.log('Proof generated successfully!');

  // Extract public inputs in order (9 total - must match circuit declaration order)
  const publicInputs = [
    inputs.merkleRoot,
    inputs.nullifier0,
    inputs.nullifier1,
    inputs.changeCommitment,
    inputs.intentNullifier,
    inputs.withdrawRecipient,
    inputs.withdrawAmount,
    inputs.registryRoot,
    inputs.ciphertextHash,
  ];

  return {
    proof: proofData.proof,
    publicInputs,
  };
}

/**
 * Convert public inputs to bytes32 array for Solidity
 */
export function publicInputsToBytes32Array(inputs: bigint[]): Hex[] {
  return inputs.map(v => {
    const hex = v.toString(16).padStart(64, '0');
    return `0x${hex}` as Hex;
  });
}

/**
 * Extract signature components from signed transaction
 */
export function extractSignatureFromTx(
  r: Hex,
  s: Hex,
  pubKeyUncompressed: Hex
): SignatureData {
  // Remove 0x prefix and convert
  const rBytes = hexToBytes(r);
  const sBytes = hexToBytes(s);

  // Pubkey uncompressed is 0x04 || x || y (65 bytes total)
  const pubKeyBytes = hexToBytes(pubKeyUncompressed);
  if (pubKeyBytes.length !== 65 || pubKeyBytes[0] !== 0x04) {
    throw new Error('Invalid uncompressed public key format');
  }

  const pubKeyX = pubKeyBytes.slice(1, 33);
  const pubKeyY = pubKeyBytes.slice(33, 65);

  // Signature is r || s
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
 * Generate Solidity verifier contract via bb.js
 * This ensures consistency with proof generation (both use keccakZK mode)
 */
export async function generateSolidityVerifier(circuitPath: string, outputPath: string, contractName?: string): Promise<void> {
  console.log(`Loading circuit from ${circuitPath}...`);
  const circuitJson = readFileSync(circuitPath, 'utf-8');
  const circuit = JSON.parse(circuitJson);

  console.log('Initializing backend...');
  const backend = new UltraHonkBackend(circuit.bytecode, INIT_OPTIONS);

  console.log('Getting verification key (keccakZK mode)...');
  const vk = await backend.getVerificationKey(PROOF_OPTIONS);

  console.log('Generating Solidity verifier...');
  let verifierSol = await backend.getSolidityVerifier(vk, PROOF_OPTIONS);

  // Rename contract if specified
  if (contractName) {
    verifierSol = verifierSol.replace(/contract HonkVerifier/g, `contract ${contractName}`);
  }

  writeFileSync(outputPath, verifierSol);
  console.log(`Solidity verifier written to ${outputPath}`);
}

/**
 * Generate both transfer and withdraw verifiers
 */
export async function generateAllVerifiers(): Promise<void> {
  const contractsVerifiersDir = resolve(__dirname, '../../contracts/verifiers');

  await generateSolidityVerifier(
    TRANSFER_CIRCUIT_PATH,
    resolve(contractsVerifiersDir, 'TransferVerifier.sol'),
    'HonkVerifier'
  );

  await generateSolidityVerifier(
    WITHDRAW_CIRCUIT_PATH,
    resolve(contractsVerifiersDir, 'WithdrawVerifier.sol'),
    'WithdrawHonkVerifier'
  );
}
