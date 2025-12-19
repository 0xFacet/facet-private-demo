// L1 (Sepolia) client and transaction submission
// Handles relayer wallet and contract interactions

import { createPublicClient, createWalletClient, http, decodeEventLog, type Hex, type TransactionReceipt } from 'viem';
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
      { name: 'noteOwner', type: 'uint256' },
      { name: 'randomness', type: 'uint256' },
      { name: 'nullifierKeyHash', type: 'uint256' },
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
      { name: 'owner', type: 'uint256', indexed: false },
      { name: 'randomness', type: 'uint256', indexed: false },
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
 * Get the merkle root from the contract at a specific block
 * @param blockNumber Optional block number (defaults to 'latest')
 */
export async function getContractRoot(blockNumber?: bigint): Promise<bigint> {
  const root = await l1Public.readContract({
    address: CONTRACTS.privacyPool as Hex,
    abi: PRIVACY_POOL_ABI,
    functionName: 'getLastRoot',
    blockNumber,
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
 * @param owner The recipient's address as a field element
 * @param randomness Random value for commitment uniqueness
 * @param nullifierKeyHash Hash of recipient's nullifier key (binds note to their key)
 * @param amount Amount of ETH to deposit (in wei)
 * @param encryptedNote Optional encrypted note data
 */
export async function submitDeposit(
  owner: bigint,
  randomness: bigint,
  nullifierKeyHash: bigint,
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
    args: [owner, randomness, nullifierKeyHash, encryptedNote],
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
 * Parse Deposit event from receipt and return leafIndex
 */
export function parseDepositLeafIndex(receipt: TransactionReceipt): number {
  for (const log of receipt.logs) {
    if (log.address.toLowerCase() === (CONTRACTS.privacyPool as string).toLowerCase()) {
      try {
        const decoded = decodeEventLog({
          abi: [PRIVACY_POOL_EVENTS.Deposit],
          data: log.data,
          topics: log.topics,
        });
        if (decoded.eventName === 'Deposit') {
          const args = decoded.args as any;
          return Number(args.leafIndex);
        }
      } catch {
        // Not the Deposit event, continue
      }
    }
  }
  throw new Error('Deposit event not found in receipt');
}

/**
 * Parse Transfer event from receipt and return leafIndices
 */
export function parseTransferLeafIndices(receipt: TransactionReceipt): [number, number] {
  for (const log of receipt.logs) {
    if (log.address.toLowerCase() === (CONTRACTS.privacyPool as string).toLowerCase()) {
      try {
        const decoded = decodeEventLog({
          abi: [PRIVACY_POOL_EVENTS.Transfer],
          data: log.data,
          topics: log.topics,
        });
        if (decoded.eventName === 'Transfer') {
          const args = decoded.args as any;
          return [Number(args.leafIndices[0]), Number(args.leafIndices[1])];
        }
      } catch {
        // Not the Transfer event, continue
      }
    }
  }
  throw new Error('Transfer event not found in receipt');
}

/**
 * Parse Withdrawal event from receipt and return changeLeafIndex
 */
export function parseWithdrawLeafIndex(receipt: TransactionReceipt): number {
  for (const log of receipt.logs) {
    if (log.address.toLowerCase() === (CONTRACTS.privacyPool as string).toLowerCase()) {
      try {
        const decoded = decodeEventLog({
          abi: [PRIVACY_POOL_EVENTS.Withdrawal],
          data: log.data,
          topics: log.topics,
        });
        if (decoded.eventName === 'Withdrawal') {
          const args = decoded.args as any;
          return Number(args.changeLeafIndex);
        }
      } catch {
        // Not the Withdrawal event, continue
      }
    }
  }
  throw new Error('Withdrawal event not found in receipt');
}

/**
 * Get the relayer address
 */
export function getRelayerAddress(): Hex | null {
  return relayer?.account?.address ?? null;
}

// Registry ABI
const REGISTRY_ABI = [
  {
    name: 'register',
    type: 'function',
    stateMutability: 'nonpayable',
    inputs: [
      { name: 'user', type: 'address' },
      { name: 'pkEnc', type: 'bytes' },
      { name: 'nullifierKeyHash', type: 'uint256' },
    ],
    outputs: [],
  },
  {
    name: 'getEncryptionKey',
    type: 'function',
    stateMutability: 'view',
    inputs: [{ name: 'user', type: 'address' }],
    outputs: [{ name: '', type: 'bytes' }],
  },
  {
    name: 'getNullifierKeyHash',
    type: 'function',
    stateMutability: 'view',
    inputs: [{ name: 'user', type: 'address' }],
    outputs: [{ name: '', type: 'uint256' }],
  },
  {
    name: 'isRegistered',
    type: 'function',
    stateMutability: 'view',
    inputs: [{ name: 'user', type: 'address' }],
    outputs: [{ name: '', type: 'bool' }],
  },
] as const;

/**
 * Register encryption public key and nullifier key hash in registry
 * @param user Address to register
 * @param pkEnc 33-byte compressed secp256k1 encryption public key
 * @param nullifierKeyHash Hash of user's nullifier key (poseidon(nullifierKey, 1))
 */
export async function registerEncryptionKey(user: Hex, pkEnc: Hex, nullifierKeyHash: bigint): Promise<Hex> {
  if (!relayer) {
    throw new Error('Relayer not configured');
  }

  const hash = await relayer.writeContract({
    address: CONTRACTS.registry as Hex,
    abi: REGISTRY_ABI,
    functionName: 'register',
    args: [user, pkEnc, nullifierKeyHash],
  });

  console.log(`[L1] Registry register submitted: ${hash}`);
  return hash;
}

/**
 * Get encryption public key from registry (returns 33-byte compressed key as hex)
 */
export async function getEncryptionKey(user: Hex): Promise<Hex | null> {
  const result = await l1Public.readContract({
    address: CONTRACTS.registry as Hex,
    abi: REGISTRY_ABI,
    functionName: 'getEncryptionKey',
    args: [user],
  }) as Hex;

  if (!result || result === '0x' || result.length !== 68) { // 0x + 66 chars = 33 bytes
    return null;
  }
  return result;
}

/**
 * Get nullifier key hash from registry
 * @param user Address to look up
 * @returns Nullifier key hash (0n if not registered)
 */
export async function getNullifierKeyHash(user: Hex): Promise<bigint> {
  const result = await l1Public.readContract({
    address: CONTRACTS.registry as Hex,
    abi: REGISTRY_ABI,
    functionName: 'getNullifierKeyHash',
    args: [user],
  });
  return result as bigint;
}

/**
 * Check if user is registered
 */
export async function isUserRegistered(user: Hex): Promise<boolean> {
  return await l1Public.readContract({
    address: CONTRACTS.registry as Hex,
    abi: REGISTRY_ABI,
    functionName: 'isRegistered',
    args: [user],
  });
}
