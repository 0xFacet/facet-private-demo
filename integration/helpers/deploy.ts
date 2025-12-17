// Contract deployment helpers for integration tests

import { createPublicClient, createWalletClient, http, getContract, parseAbi, Abi, Hex } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { foundry } from 'viem/chains';
import { readFileSync } from 'fs';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';
import { execSync } from 'child_process';

import { ANVIL_RPC_URL, TEST_PRIVATE_KEY } from './config.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Contract directory
const CONTRACTS_DIR = resolve(__dirname, '../../contracts');

// ABIs
export const PRIVACY_POOL_ABI = parseAbi([
  'constructor(address _transferVerifier, address _withdrawVerifier, address _registry)',
  'function deposit(uint256 commitment, bytes encryptedNote) payable',
  'function transfer(bytes proof, uint256 merkleRoot, uint256[2] nullifiers, uint256[2] outputCommitments, uint256 intentNullifier, bytes[2] encryptedNotes)',
  'function withdraw(bytes proof, uint256 merkleRoot, uint256[2] nullifiers, uint256 changeCommitment, uint256 intentNullifier, address recipient, uint256 amount, bytes encryptedChange)',
  'function getLastRoot() view returns (uint256)',
  'function nextLeafIndex() view returns (uint256)',
  'function nullifierSpent(uint256) view returns (bool)',
  'function intentUsed(uint256) view returns (bool)',
  'function isKnownRoot(uint256) view returns (bool)',
  'event Deposit(uint256 indexed commitment, uint256 indexed leafIndex, uint256 amount, bytes encryptedNote)',
  'event Transfer(uint256[2] nullifiers, uint256[2] commitments, uint256[2] leafIndices, uint256 intentNullifier, bytes[2] encryptedNotes)',
]);

export const REGISTRY_ABI = parseAbi([
  'function register(bytes32 pubKeyX, bytes32 pubKeyY)',
  'function isRegistered(address user) view returns (bool)',
  'function getKey(address user) view returns (bytes32, bytes32)',
]);

export const VERIFIER_ABI = parseAbi([
  'function verify(bytes proof, bytes32[] publicInputs) view returns (bool)',
]);

export interface DeployedContracts {
  privacyPool: Hex;
  registry: Hex;
  transferVerifier: Hex;
  withdrawVerifier: Hex;
}

/**
 * Deploy all contracts using forge script (handles library linking)
 */
export async function deployContracts(): Promise<DeployedContracts> {
  console.log('Deploying contracts via forge script...');

  // Run forge script to deploy (pass private key via env var)
  const output = execSync(
    `cd ${CONTRACTS_DIR} && PRIVATE_KEY=${TEST_PRIVATE_KEY} forge script script/Deploy.s.sol --broadcast --rpc-url ${ANVIL_RPC_URL} --non-interactive 2>&1 || true`,
    { encoding: 'utf-8', maxBuffer: 50 * 1024 * 1024 }
  );

  console.log(output);

  // Parse addresses from output
  const registryMatch = output.match(/RecipientRegistry:\s+(0x[a-fA-F0-9]{40})/);
  const transferVerifierMatch = output.match(/TransferVerifier:\s+(0x[a-fA-F0-9]{40})/);
  const withdrawVerifierMatch = output.match(/WithdrawVerifier:\s+(0x[a-fA-F0-9]{40})/);
  const poolMatch = output.match(/PrivacyPool:\s+(0x[a-fA-F0-9]{40})/);

  if (!registryMatch || !transferVerifierMatch || !withdrawVerifierMatch || !poolMatch) {
    throw new Error('Failed to parse contract addresses from forge output');
  }

  return {
    registry: registryMatch[1] as Hex,
    transferVerifier: transferVerifierMatch[1] as Hex,
    withdrawVerifier: withdrawVerifierMatch[1] as Hex,
    privacyPool: poolMatch[1] as Hex,
  };
}

/**
 * Get contract instances
 */
export function getContracts(addresses: DeployedContracts) {
  const publicClient = createPublicClient({
    chain: foundry,
    transport: http(ANVIL_RPC_URL),
  });

  const account = privateKeyToAccount(TEST_PRIVATE_KEY as Hex);
  const walletClient = createWalletClient({
    account,
    chain: foundry,
    transport: http(ANVIL_RPC_URL),
  });

  return {
    publicClient,
    walletClient,
    account,
    privacyPool: getContract({
      address: addresses.privacyPool,
      abi: PRIVACY_POOL_ABI,
      client: { public: publicClient, wallet: walletClient },
    }),
    registry: getContract({
      address: addresses.registry,
      abi: REGISTRY_ABI,
      client: { public: publicClient, wallet: walletClient },
    }),
  };
}
