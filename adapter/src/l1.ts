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
      { name: 'registryRoot', type: 'uint256' },
      { name: 'nullifiers', type: 'uint256[2]' },
      { name: 'outputCommitments', type: 'uint256[2]' },
      { name: 'intentNullifier', type: 'uint256' },
      { name: 'encryptedNotes', type: 'uint256[5][2]' },
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
      { name: 'registryRoot', type: 'uint256' },
      { name: 'nullifiers', type: 'uint256[2]' },
      { name: 'changeCommitment', type: 'uint256' },
      { name: 'intentNullifier', type: 'uint256' },
      { name: 'recipient', type: 'address' },
      { name: 'amount', type: 'uint256' },
      { name: 'encryptedChange', type: 'uint256[5]' },
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
      { name: 'encryptedNotes', type: 'uint256[5][2]', indexed: false },
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
      { name: 'encryptedChange', type: 'uint256[5]', indexed: false },
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

// Type alias for encrypted note (5 field elements)
export type EncryptedNote = [bigint, bigint, bigint, bigint, bigint];

/**
 * Submit a transfer to L1
 */
export async function submitTransfer(
  proof: Uint8Array,
  merkleRoot: bigint,
  registryRoot: bigint,
  nullifiers: [bigint, bigint],
  outputCommitments: [bigint, bigint],
  intentNullifier: bigint,
  encryptedNotes: [EncryptedNote, EncryptedNote]
): Promise<Hex> {
  if (!relayer) {
    throw new Error('Relayer not configured - set RELAYER_PRIVATE_KEY');
  }

  const proofHex = ('0x' + Buffer.from(proof).toString('hex')) as Hex;

  const hash = await relayer.writeContract({
    address: CONTRACTS.privacyPool as Hex,
    abi: PRIVACY_POOL_ABI,
    functionName: 'transfer',
    args: [proofHex, merkleRoot, registryRoot, nullifiers, outputCommitments, intentNullifier, encryptedNotes],
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
  registryRoot: bigint,
  nullifiers: [bigint, bigint],
  changeCommitment: bigint,
  intentNullifier: bigint,
  recipient: Hex,
  amount: bigint,
  encryptedChange: EncryptedNote
): Promise<Hex> {
  if (!relayer) {
    throw new Error('Relayer not configured - set RELAYER_PRIVATE_KEY');
  }

  const proofHex = ('0x' + Buffer.from(proof).toString('hex')) as Hex;

  const hash = await relayer.writeContract({
    address: CONTRACTS.privacyPool as Hex,
    abi: PRIVACY_POOL_ABI,
    functionName: 'withdraw',
    args: [proofHex, merkleRoot, registryRoot, nullifiers, changeCommitment, intentNullifier, recipient, amount, encryptedChange],
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

// Registry ABI (RecipientRegistry with Grumpkin keys and Merkle tree)
const REGISTRY_ABI = [
  // Registration (uses msg.sender, not passed address)
  {
    name: 'register',
    type: 'function',
    stateMutability: 'nonpayable',
    inputs: [
      { name: 'encPublicKey', type: 'uint256[2]' },
      { name: 'nullifierKeyHash', type: 'uint256' },
    ],
    outputs: [{ name: 'leafIndex', type: 'uint256' }],
  },
  // Trusted relayer registration (for auto-registration during session creation)
  {
    name: 'registerFor',
    type: 'function',
    stateMutability: 'nonpayable',
    inputs: [
      { name: 'user', type: 'address' },
      { name: 'encPublicKey', type: 'uint256[2]' },
      { name: 'nullifierKeyHash', type: 'uint256' },
    ],
    outputs: [{ name: 'leafIndex', type: 'uint256' }],
  },
  // View functions
  {
    name: 'encPublicKeys',
    type: 'function',
    stateMutability: 'view',
    inputs: [{ name: 'user', type: 'address' }],
    outputs: [{ name: '', type: 'uint256[2]' }],
  },
  {
    name: 'nullifierKeyHashes',
    type: 'function',
    stateMutability: 'view',
    inputs: [{ name: 'user', type: 'address' }],
    outputs: [{ name: '', type: 'uint256' }],
  },
  {
    name: 'leafIndices',
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
  // Merkle tree functions
  {
    name: 'currentRoot',
    type: 'function',
    stateMutability: 'view',
    inputs: [],
    outputs: [{ name: '', type: 'uint256' }],
  },
  {
    name: 'isKnownRoot',
    type: 'function',
    stateMutability: 'view',
    inputs: [{ name: 'root', type: 'uint256' }],
    outputs: [{ name: '', type: 'bool' }],
  },
  {
    name: 'nextLeafIndex',
    type: 'function',
    stateMutability: 'view',
    inputs: [],
    outputs: [{ name: '', type: 'uint256' }],
  },
  {
    name: 'zeros',
    type: 'function',
    stateMutability: 'view',
    inputs: [{ name: 'depth', type: 'uint256' }],
    outputs: [{ name: '', type: 'uint256' }],
  },
] as const;

// Registry event ABI
export const REGISTRY_EVENTS = {
  UserRegistered: {
    type: 'event',
    name: 'UserRegistered',
    inputs: [
      { name: 'user', type: 'address', indexed: true },
      { name: 'encPublicKey', type: 'uint256[2]', indexed: false },
      { name: 'nullifierKeyHash', type: 'uint256', indexed: false },
      { name: 'leafIndex', type: 'uint256', indexed: true },
    ],
  },
} as const;

/**
 * Get Grumpkin encryption public key from registry
 * @param user Address to look up
 * @returns [x, y] Grumpkin curve point or null if not registered
 */
export async function getEncryptionKey(user: Hex): Promise<[bigint, bigint] | null> {
  try {
    const result = await l1Public.readContract({
      address: CONTRACTS.registry as Hex,
      abi: REGISTRY_ABI,
      functionName: 'encPublicKeys',
      args: [user],
    }) as [bigint, bigint];

    // Check if key is zero (not registered)
    if (result[0] === 0n && result[1] === 0n) {
      return null;
    }
    return result;
  } catch {
    return null;
  }
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
    functionName: 'nullifierKeyHashes',
    args: [user],
  });
  return result as bigint;
}

/**
 * Get leaf index from registry
 * @param user Address to look up
 * @returns Leaf index (0 if not registered - must check isRegistered separately)
 */
export async function getRegistryLeafIndex(user: Hex): Promise<number> {
  const result = await l1Public.readContract({
    address: CONTRACTS.registry as Hex,
    abi: REGISTRY_ABI,
    functionName: 'leafIndices',
    args: [user],
  });
  return Number(result as bigint);
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

/**
 * Get the current registry Merkle root
 */
export async function getRegistryRoot(blockNumber?: bigint): Promise<bigint> {
  const result = await l1Public.readContract({
    address: CONTRACTS.registry as Hex,
    abi: REGISTRY_ABI,
    functionName: 'currentRoot',
    blockNumber,
  });
  return result as bigint;
}

/**
 * Check if a registry root is known/valid
 */
export async function isKnownRegistryRoot(root: bigint): Promise<boolean> {
  return await l1Public.readContract({
    address: CONTRACTS.registry as Hex,
    abi: REGISTRY_ABI,
    functionName: 'isKnownRoot',
    args: [root],
  });
}

/**
 * Get full registry data for a user
 */
export async function getRegistryEntry(user: Hex): Promise<{
  pubkeyX: bigint;
  pubkeyY: bigint;
  nkHash: bigint;
  leafIndex: number;
} | null> {
  const registered = await isUserRegistered(user);
  if (!registered) {
    return null;
  }

  const [pubkey, nkHash, leafIndex] = await Promise.all([
    getEncryptionKey(user),
    getNullifierKeyHash(user),
    getRegistryLeafIndex(user),
  ]);

  if (!pubkey) {
    return null;
  }

  return {
    pubkeyX: pubkey[0],
    pubkeyY: pubkey[1],
    nkHash,
    leafIndex,
  };
}

/**
 * Register a user on L1 using the relayer's registerFor() privilege
 * @param user Address to register
 * @param encPublicKey Grumpkin encryption public key [x, y]
 * @param nullifierKeyHash Hash of user's nullifier key
 * @returns Transaction hash and leaf index
 */
export async function registerUserOnL1(
  user: Hex,
  encPublicKey: [bigint, bigint],
  nullifierKeyHash: bigint
): Promise<{ hash: Hex; leafIndex: number }> {
  if (!relayer) {
    throw new Error('Relayer not configured - set RELAYER_PRIVATE_KEY');
  }

  console.log(`[L1] Registering user ${user} via relayer...`);

  const hash = await relayer.writeContract({
    address: CONTRACTS.registry as Hex,
    abi: REGISTRY_ABI,
    functionName: 'registerFor',
    args: [user, encPublicKey, nullifierKeyHash],
  });

  console.log(`[L1] Registration tx submitted: ${hash}`);

  // Wait for confirmation
  const receipt = await l1Public.waitForTransactionReceipt({ hash });

  if (receipt.status !== 'success') {
    throw new Error(`Registration transaction reverted: ${hash}`);
  }

  // Parse UserRegistered event to get leaf index
  let leafIndex = 0;
  for (const log of receipt.logs) {
    if (log.address.toLowerCase() === (CONTRACTS.registry as string).toLowerCase()) {
      try {
        const decoded = decodeEventLog({
          abi: [REGISTRY_EVENTS.UserRegistered],
          data: log.data,
          topics: log.topics,
        });
        if (decoded.eventName === 'UserRegistered') {
          const args = decoded.args as any;
          leafIndex = Number(args.leafIndex);
        }
      } catch {
        // Not the UserRegistered event, continue
      }
    }
  }

  console.log(`[L1] User ${user} registered at leaf index ${leafIndex}`);
  return { hash, leafIndex };
}
