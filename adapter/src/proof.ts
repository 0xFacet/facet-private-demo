// ZK Proof generation - worker-based (non-blocking)

import { fileURLToPath } from 'url';
import { Hex, hexToBytes } from 'viem';
import { Piscina } from 'piscina';

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
 * Registry membership proof
 */
export interface RegistryProof {
  pubkeyX: bigint;
  pubkeyY: bigint;
  nkHash: bigint;
  leafIndex: number;
  siblings: bigint[];
}

/**
 * Transfer circuit inputs
 */
export interface TransferCircuitInputs {
  // Public inputs (8 total)
  merkleRoot: bigint;
  nullifier0: bigint;
  nullifier1: bigint;
  outputCommitment0: bigint;
  outputCommitment1: bigint;
  intentNullifier: bigint;
  registryRoot: bigint;
  ciphertextHash: bigint;

  // Private inputs
  signatureData: SignatureData;
  txNonce: bigint;
  txMaxPriorityFee: bigint;
  txMaxFee: bigint;
  txGasLimit: bigint;
  txTo: bigint;
  txValue: bigint;

  // Input notes (with owner address and nkHash for verification)
  input0: NoteInput & { owner: bigint; nullifierKeyHash: bigint };
  input1: NoteInput & { owner: bigint; nullifierKeyHash: bigint };

  // Output notes
  output0Amount: bigint;
  output0Randomness: bigint;

  output1Amount: bigint;
  output1Randomness: bigint;

  // Keys
  nullifierKey: bigint;

  // Recipient registry membership proof
  recipientProof: RegistryProof;
}

/**
 * Withdraw circuit inputs
 */
export interface WithdrawCircuitInputs {
  // Public inputs (9 total)
  merkleRoot: bigint;
  nullifier0: bigint;
  nullifier1: bigint;
  changeCommitment: bigint;
  intentNullifier: bigint;
  withdrawRecipient: bigint;
  withdrawAmount: bigint;
  registryRoot: bigint;
  ciphertextHash: bigint;

  // Private inputs
  signatureData: SignatureData;
  txNonce: bigint;
  txMaxPriorityFee: bigint;
  txMaxFee: bigint;
  txGasLimit: bigint;

  // Input notes (with owner address and nkHash for verification)
  input0: NoteInput & { owner: bigint; nullifierKeyHash: bigint };
  input1: NoteInput & { owner: bigint; nullifierKeyHash: bigint };

  changeRandomness: bigint;

  // Keys
  nullifierKey: bigint;

  // Sender's registry membership proof
  senderProof: RegistryProof;
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
 * Note: owner and nullifierKeyHash are derived in-circuit from signature, not passed
 */
export function buildTransferInputs(inputs: TransferCircuitInputs): Record<string, any> {
  return {
    // Public inputs (8)
    merkle_root: toNoirField(inputs.merkleRoot),
    nullifier_0: toNoirField(inputs.nullifier0),
    nullifier_1: toNoirField(inputs.nullifier1),
    output_commitment_0: toNoirField(inputs.outputCommitment0),
    output_commitment_1: toNoirField(inputs.outputCommitment1),
    intent_nullifier: toNoirField(inputs.intentNullifier),
    registry_root: toNoirField(inputs.registryRoot),
    ciphertext_hash_pub: toNoirField(inputs.ciphertextHash),

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

    // Input note 0 (owner/nkHash derived from signature in circuit)
    input_0_amount: inputs.input0.amount.toString(),
    input_0_randomness: toNoirField(inputs.input0.randomness),
    input_0_leaf_index: inputs.input0.leafIndex.toString(),
    input_0_siblings: toNoirFieldArray(inputs.input0.siblings),

    // Input note 1 (owner/nkHash derived from signature in circuit)
    input_1_amount: inputs.input1.amount.toString(),
    input_1_randomness: toNoirField(inputs.input1.randomness),
    input_1_leaf_index: inputs.input1.leafIndex.toString(),
    input_1_siblings: toNoirFieldArray(inputs.input1.siblings),

    // Output note randomness (amounts computed in-circuit)
    output_0_randomness: toNoirField(inputs.output0Randomness),
    output_1_randomness: toNoirField(inputs.output1Randomness),

    // Nullifier key
    nullifier_key: toNoirField(inputs.nullifierKey),

    // Recipient registry membership proof
    recipient_pubkey_x: toNoirField(inputs.recipientProof.pubkeyX),
    recipient_pubkey_y: toNoirField(inputs.recipientProof.pubkeyY),
    recipient_nk_hash: toNoirField(inputs.recipientProof.nkHash),
    recipient_leaf_index: inputs.recipientProof.leafIndex.toString(),
    recipient_siblings: toNoirFieldArray(inputs.recipientProof.siblings),
  };
}

/**
 * Build circuit inputs object for Noir (withdraw circuit)
 * Note: owner and nullifierKeyHash are derived in-circuit from signature, not passed
 */
export function buildWithdrawInputs(inputs: WithdrawCircuitInputs): Record<string, any> {
  return {
    // Public inputs (9)
    merkle_root: toNoirField(inputs.merkleRoot),
    nullifier_0: toNoirField(inputs.nullifier0),
    nullifier_1: toNoirField(inputs.nullifier1),
    change_commitment: toNoirField(inputs.changeCommitment),
    intent_nullifier: toNoirField(inputs.intentNullifier),
    withdraw_recipient: toNoirField(inputs.withdrawRecipient),
    withdraw_amount: inputs.withdrawAmount.toString(),
    registry_root: toNoirField(inputs.registryRoot),
    ciphertext_hash_pub: toNoirField(inputs.ciphertextHash),

    // Signature
    pub_key_x: toNoirByteArray(inputs.signatureData.pubKeyX),
    pub_key_y: toNoirByteArray(inputs.signatureData.pubKeyY),
    signature: toNoirByteArray(inputs.signatureData.signature),

    // Transaction fields
    tx_nonce: inputs.txNonce.toString(),
    tx_max_priority_fee: inputs.txMaxPriorityFee.toString(),
    tx_max_fee: inputs.txMaxFee.toString(),
    tx_gas_limit: inputs.txGasLimit.toString(),

    // Input note 0 (owner/nkHash derived from signature in circuit)
    input_0_amount: inputs.input0.amount.toString(),
    input_0_randomness: toNoirField(inputs.input0.randomness),
    input_0_leaf_index: inputs.input0.leafIndex.toString(),
    input_0_siblings: toNoirFieldArray(inputs.input0.siblings),

    // Input note 1 (owner/nkHash derived from signature in circuit)
    input_1_amount: inputs.input1.amount.toString(),
    input_1_randomness: toNoirField(inputs.input1.randomness),
    input_1_leaf_index: inputs.input1.leafIndex.toString(),
    input_1_siblings: toNoirFieldArray(inputs.input1.siblings),

    // Change note randomness (amount computed in-circuit)
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

// ==================== Worker-based proof generation ====================

// Lazy-initialized worker pool (created on first use)
let proofWorkerPool: Piscina | null = null;

function getProofWorkerPool(): Piscina {
  if (!proofWorkerPool) {
    // Detect if running in TypeScript (tsx dev) or JavaScript (compiled prod)
    const isTs = import.meta.url.endsWith('.ts');
    const workerFile = isTs ? './proof-worker.ts' : './proof-worker.js';
    const workerPath = fileURLToPath(new URL(workerFile, import.meta.url));

    console.log(`[Proof] Initializing worker pool with ${workerFile}...`);
    proofWorkerPool = new Piscina({
      filename: workerPath,
      maxThreads: 1, // Single worker to avoid memory bloat
      // In dev mode, worker needs tsx loader to understand TypeScript
      execArgv: isTs ? ['--import', 'tsx'] : undefined,
    });
  }
  return proofWorkerPool;
}

/**
 * Generate a transfer proof using worker thread (non-blocking)
 */
export async function generateTransferProofWorker(inputs: TransferCircuitInputs): Promise<{
  proof: Uint8Array;
  publicInputs: bigint[];
}> {
  const pool = getProofWorkerPool();
  const noirInputs = buildTransferInputs(inputs);

  console.log('[Proof] Sending transfer proof request to worker...');
  const proof = await pool.run({ type: 'transfer', inputs: noirInputs });

  return {
    proof: new Uint8Array(proof),
    publicInputs: [
      inputs.merkleRoot,
      inputs.nullifier0,
      inputs.nullifier1,
      inputs.outputCommitment0,
      inputs.outputCommitment1,
      inputs.intentNullifier,
      inputs.registryRoot,
      inputs.ciphertextHash,
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
  const noirInputs = buildWithdrawInputs(inputs);

  console.log('[Proof] Sending withdraw proof request to worker...');
  const proof = await pool.run({ type: 'withdraw', inputs: noirInputs });

  return {
    proof: new Uint8Array(proof),
    publicInputs: [
      inputs.merkleRoot,
      inputs.nullifier0,
      inputs.nullifier1,
      inputs.changeCommitment,
      inputs.intentNullifier,
      inputs.withdrawRecipient,
      inputs.withdrawAmount,
      inputs.registryRoot,
      inputs.ciphertextHash,
    ],
  };
}
