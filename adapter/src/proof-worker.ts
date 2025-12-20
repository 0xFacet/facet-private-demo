// Worker thread for ZK proof generation
// Runs in separate thread to avoid blocking the main event loop

import { Noir } from '@noir-lang/noir_js';
import { UltraHonkBackend } from '@aztec/bb.js';
import { readFileSync, existsSync } from 'fs';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';

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

// Cache circuits, backends, and Noir instances at module scope
// This avoids reloading WASM for each proof
let transferCircuit: any = null;
let transferBackend: UltraHonkBackend | null = null;
let transferNoir: Noir | null = null;

let withdrawCircuit: any = null;
let withdrawBackend: UltraHonkBackend | null = null;
let withdrawNoir: Noir | null = null;

function getTransferProver(): { backend: UltraHonkBackend; noir: Noir } {
  if (!transferCircuit) {
    const path = findCircuit('transfer');
    console.log(`[Worker] Loading transfer circuit from ${path}`);
    transferCircuit = JSON.parse(readFileSync(path, 'utf-8'));
  }
  if (!transferBackend) {
    console.log('[Worker] Initializing transfer backend...');
    transferBackend = new UltraHonkBackend(transferCircuit.bytecode);
  }
  if (!transferNoir) {
    transferNoir = new Noir(transferCircuit);
  }
  return { backend: transferBackend, noir: transferNoir };
}

function getWithdrawProver(): { backend: UltraHonkBackend; noir: Noir } {
  if (!withdrawCircuit) {
    const path = findCircuit('withdraw');
    console.log(`[Worker] Loading withdraw circuit from ${path}`);
    withdrawCircuit = JSON.parse(readFileSync(path, 'utf-8'));
  }
  if (!withdrawBackend) {
    console.log('[Worker] Initializing withdraw backend...');
    withdrawBackend = new UltraHonkBackend(withdrawCircuit.bytecode);
  }
  if (!withdrawNoir) {
    withdrawNoir = new Noir(withdrawCircuit);
  }
  return { backend: withdrawBackend, noir: withdrawNoir };
}

interface ProofRequest {
  type: 'transfer' | 'withdraw';
  inputs: Record<string, any>; // Already stringified Noir inputs
}

async function generateTransferProofInternal(noirInputs: Record<string, any>): Promise<Uint8Array> {
  const startTime = Date.now();
  const { backend, noir } = getTransferProver();

  console.log('[Worker] Executing transfer circuit (computing witness)...');
  const { witness } = await noir.execute(noirInputs);

  console.log('[Worker] Generating transfer proof (keccak mode)...');
  const proofData = await backend.generateProof(witness, BACKEND_OPTIONS);

  const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
  console.log(`[Worker] Transfer proof generated in ${elapsed}s`);

  return proofData.proof;
}

async function generateWithdrawProofInternal(noirInputs: Record<string, any>): Promise<Uint8Array> {
  const startTime = Date.now();
  const { backend, noir } = getWithdrawProver();

  console.log('[Worker] Executing withdraw circuit (computing witness)...');
  const { witness } = await noir.execute(noirInputs);

  console.log('[Worker] Generating withdraw proof (keccak mode)...');
  const proofData = await backend.generateProof(witness, BACKEND_OPTIONS);

  const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
  console.log(`[Worker] Withdraw proof generated in ${elapsed}s`);

  return proofData.proof;
}

// Piscina worker entry point
export default async function (request: ProofRequest): Promise<Uint8Array> {
  if (request.type === 'transfer') {
    return generateTransferProofInternal(request.inputs);
  } else if (request.type === 'withdraw') {
    return generateWithdrawProofInternal(request.inputs);
  } else {
    throw new Error(`Unknown proof type: ${request.type}`);
  }
}
