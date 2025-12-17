// L1 (Sepolia) client and transaction submission
// Handles relayer wallet and contract interactions

import { createPublicClient, createWalletClient, http, type Hex, type TransactionReceipt } from 'viem';
import { sepolia } from 'viem/chains';
import { privateKeyToAccount } from 'viem/accounts';
import { L1_RPC_URL, CONTRACTS } from './config.js';

// Load relayer private key from env
const RELAYER_PRIVATE_KEY = process.env.RELAYER_PRIVATE_KEY as Hex;
if (!RELAYER_PRIVATE_KEY) {
  console.warn('RELAYER_PRIVATE_KEY not set - L1 submissions will fail');
}

// Contract ABIs (minimal - only functions we call)
export const PRIVACY_POOL_ABI = [
  // View functions
  {
    name: 'getLastRoot',
    type: 'function',
    stateMutability: 'view',
    inputs: [],
    outputs: [{ name: '', type: 'uint256' }],
  },
  {
    name: 'nextLeafIndex',
    type: 'function',
    stateMutability: 'view',
    inputs: [],
    outputs: [{ name: '', type: 'uint256' }],
  },
  {
    name: 'nullifierSpent',
    type: 'function',
    stateMutability: 'view',
    inputs: [{ name: '', type: 'uint256' }],
    outputs: [{ name: '', type: 'bool' }],
  },
  {
    name: 'intentUsed',
    type: 'function',
    stateMutability: 'view',
    inputs: [{ name: '', type: 'uint256' }],
    outputs: [{ name: '', type: 'bool' }],
  },
  {
    name: 'isKnownRoot',
    type: 'function',
    stateMutability: 'view',
    inputs: [{ name: '', type: 'uint256' }],
    outputs: [{ name: '', type: 'bool' }],
  },
  // Deposit
  {
    name: 'deposit',
    type: 'function',
    stateMutability: 'payable',
    inputs: [
      { name: 'commitment', type: 'uint256' },
      { name: 'encryptedNote', type: 'bytes' },
    ],
    outputs: [],
  },
  // Transfer
  {
    name: 'transfer',
    type: 'function',
    stateMutability: 'nonpayable',
    inputs: [
      { name: 'proof', type: 'bytes' },
      { name: 'merkleRoot', type: 'uint256' },
      { name: 'nullifiers', type: 'uint256[2]' },
      { name: 'outputCommitments', type: 'uint256[2]' },
      { name: 'intentNullifier', type: 'uint256' },
      { name: 'encryptedNotes', type: 'bytes[2]' },
    ],
    outputs: [],
  },
  // Withdraw
  {
    name: 'withdraw',
    type: 'function',
    stateMutability: 'nonpayable',
    inputs: [
      { name: 'proof', type: 'bytes' },
      { name: 'merkleRoot', type: 'uint256' },
      { name: 'nullifiers', type: 'uint256[2]' },
      { name: 'changeCommitment', type: 'uint256' },
      { name: 'intentNullifier', type: 'uint256' },
      { name: 'recipient', type: 'address' },
      { name: 'amount', type: 'uint256' },
      { name: 'encryptedChange', type: 'bytes' },
    ],
    outputs: [],
  },
] as const;

// Event ABIs for log parsing
export const PRIVACY_POOL_EVENTS = {
  Deposit: {
    type: 'event',
    name: 'Deposit',
    inputs: [
      { name: 'commitment', type: 'uint256', indexed: true },
      { name: 'leafIndex', type: 'uint256', indexed: true },
      { name: 'amount', type: 'uint256', indexed: false },
      { name: 'encryptedNote', type: 'bytes', indexed: false },
    ],
  },
  Transfer: {
    type: 'event',
    name: 'Transfer',
    inputs: [
      { name: 'nullifiers', type: 'uint256[2]', indexed: false },
      { name: 'commitments', type: 'uint256[2]', indexed: false },
      { name: 'leafIndices', type: 'uint256[2]', indexed: false },
      { name: 'intentNullifier', type: 'uint256', indexed: false },
      { name: 'encryptedNotes', type: 'bytes[2]', indexed: false },
    ],
  },
  Withdrawal: {
    type: 'event',
    name: 'Withdrawal',
    inputs: [
      { name: 'nullifiers', type: 'uint256[2]', indexed: false },
      { name: 'changeCommitment', type: 'uint256', indexed: false },
      { name: 'changeLeafIndex', type: 'uint256', indexed: false },
      { name: 'intentNullifier', type: 'uint256', indexed: false },
      { name: 'recipient', type: 'address', indexed: true },
      { name: 'amount', type: 'uint256', indexed: false },
      { name: 'encryptedChange', type: 'bytes', indexed: false },
    ],
  },
} as const;

// Public client for reading state
export const l1Public = createPublicClient({
  chain: sepolia,
  transport: http(L1_RPC_URL),
});

// Relayer wallet client for submitting transactions
export const relayer = RELAYER_PRIVATE_KEY
  ? createWalletClient({
      account: privateKeyToAccount(RELAYER_PRIVATE_KEY),
      chain: sepolia,
      transport: http(L1_RPC_URL),
    })
  : null;

/**
 * Get the current merkle root from the contract
 */
export async function getContractRoot(): Promise<bigint> {
  const root = await l1Public.readContract({
    address: CONTRACTS.privacyPool as Hex,
    abi: PRIVACY_POOL_ABI,
    functionName: 'getLastRoot',
  });
  return root as bigint;
}

/**
 * Get the next leaf index from the contract
 */
export async function getNextLeafIndex(): Promise<number> {
  const index = await l1Public.readContract({
    address: CONTRACTS.privacyPool as Hex,
    abi: PRIVACY_POOL_ABI,
    functionName: 'nextLeafIndex',
  });
  return Number(index);
}

/**
 * Check if a nullifier has been spent
 */
export async function isNullifierSpent(nullifier: bigint): Promise<boolean> {
  return await l1Public.readContract({
    address: CONTRACTS.privacyPool as Hex,
    abi: PRIVACY_POOL_ABI,
    functionName: 'nullifierSpent',
    args: [nullifier],
  }) as boolean;
}

/**
 * Check if a root is known (valid for proofs)
 */
export async function isRootKnown(root: bigint): Promise<boolean> {
  return await l1Public.readContract({
    address: CONTRACTS.privacyPool as Hex,
    abi: PRIVACY_POOL_ABI,
    functionName: 'isKnownRoot',
    args: [root],
  }) as boolean;
}

/**
 * Submit a deposit to L1
 */
export async function submitDeposit(
  commitment: bigint,
  amount: bigint,
  encryptedNote: Hex = '0x'
): Promise<Hex> {
  if (!relayer) {
    throw new Error('Relayer not configured - set RELAYER_PRIVATE_KEY');
  }

  const hash = await relayer.writeContract({
    address: CONTRACTS.privacyPool as Hex,
    abi: PRIVACY_POOL_ABI,
    functionName: 'deposit',
    args: [commitment, encryptedNote],
    value: amount,
  });

  console.log(`[L1] Deposit submitted: ${hash}`);
  return hash;
}

/**
 * Submit a transfer to L1
 */
export async function submitTransfer(
  proof: Uint8Array,
  merkleRoot: bigint,
  nullifiers: [bigint, bigint],
  outputCommitments: [bigint, bigint],
  intentNullifier: bigint,
  encryptedNotes: [Hex, Hex] = ['0x', '0x']
): Promise<Hex> {
  if (!relayer) {
    throw new Error('Relayer not configured - set RELAYER_PRIVATE_KEY');
  }

  const proofHex = ('0x' + Buffer.from(proof).toString('hex')) as Hex;

  const hash = await relayer.writeContract({
    address: CONTRACTS.privacyPool as Hex,
    abi: PRIVACY_POOL_ABI,
    functionName: 'transfer',
    args: [proofHex, merkleRoot, nullifiers, outputCommitments, intentNullifier, encryptedNotes],
  });

  console.log(`[L1] Transfer submitted: ${hash}`);
  return hash;
}

/**
 * Submit a withdrawal to L1
 */
export async function submitWithdraw(
  proof: Uint8Array,
  merkleRoot: bigint,
  nullifiers: [bigint, bigint],
  changeCommitment: bigint,
  intentNullifier: bigint,
  recipient: Hex,
  amount: bigint,
  encryptedChange: Hex = '0x'
): Promise<Hex> {
  if (!relayer) {
    throw new Error('Relayer not configured - set RELAYER_PRIVATE_KEY');
  }

  const proofHex = ('0x' + Buffer.from(proof).toString('hex')) as Hex;

  const hash = await relayer.writeContract({
    address: CONTRACTS.privacyPool as Hex,
    abi: PRIVACY_POOL_ABI,
    functionName: 'withdraw',
    args: [proofHex, merkleRoot, nullifiers, changeCommitment, intentNullifier, recipient, amount, encryptedChange],
  });

  console.log(`[L1] Withdraw submitted: ${hash}`);
  return hash;
}

/**
 * Wait for a transaction receipt
 */
export async function waitForReceipt(hash: Hex): Promise<TransactionReceipt> {
  return await l1Public.waitForTransactionReceipt({ hash });
}

/**
 * Get the relayer address
 */
export function getRelayerAddress(): Hex | null {
  return relayer?.account?.address ?? null;
}
