// Registry chain sync - synchronizes local registry tree with on-chain state
// Fetches UserRegistered events and rebuilds state on startup

import { parseAbiItem, type Hex } from 'viem';
import { l1Public, getRegistryRoot } from './l1.js';
import { CONTRACTS } from './config.js';
import { RegistryTree } from './registry-tree.js';

// Deploy block from env (to avoid scanning from genesis)
const DEPLOY_BLOCK = BigInt(process.env.DEPLOY_BLOCK || '0');

/**
 * Registry event data
 */
export interface UserRegisteredEvent {
  user: Hex;
  userBigInt: bigint;
  pubkeyX: bigint;
  pubkeyY: bigint;
  nkHash: bigint;
  leafIndex: number;
  blockNumber: bigint;
  logIndex: number;
  txHash: Hex;
}

/**
 * Sync registry state from chain
 * Rebuilds registry tree from UserRegistered events
 * Atomic: builds new state first, only swaps on success
 */
export async function syncRegistryFromChain(
  registryTree: RegistryTree
): Promise<void> {
  console.log('[RegistrySync] Starting chain sync from block', DEPLOY_BLOCK.toString());

  // Build new state in temporary structure
  const tempTree = new RegistryTree();

  const registryAddress = CONTRACTS.registry as Hex;

  // Pin block number to ensure consistent snapshot
  const toBlock = await l1Public.getBlockNumber();

  // Fetch all UserRegistered events
  const logs = await l1Public.getLogs({
    address: registryAddress,
    event: parseAbiItem('event UserRegistered(address indexed user, uint256[2] encPublicKey, uint256 nullifierKeyHash, uint256 indexed leafIndex)'),
    fromBlock: DEPLOY_BLOCK,
    toBlock,
  });

  console.log(`[RegistrySync] Found ${logs.length} registrations`);

  // Parse events
  const events: UserRegisteredEvent[] = logs.map((log) => {
    const args = log.args as any;
    return {
      user: args.user,
      userBigInt: BigInt(args.user),
      pubkeyX: args.encPublicKey[0],
      pubkeyY: args.encPublicKey[1],
      nkHash: args.nullifierKeyHash,
      leafIndex: Number(args.leafIndex),
      blockNumber: log.blockNumber,
      logIndex: log.logIndex,
      txHash: log.transactionHash,
    };
  });

  // Sort by leaf index to insert in order
  events.sort((a, b) => a.leafIndex - b.leafIndex);

  // Insert all entries into temp tree
  for (const event of events) {
    const actualIndex = tempTree.insertEntry(
      event.userBigInt,
      event.pubkeyX,
      event.pubkeyY,
      event.nkHash
    );
    if (actualIndex !== event.leafIndex) {
      console.warn(`[RegistrySync] Index mismatch: expected ${event.leafIndex}, got ${actualIndex}`);
    }
  }

  // Verify temp tree root matches contract
  const tempRoot = tempTree.getRoot();
  const contractRoot = await getRegistryRoot(toBlock);

  if (tempRoot !== contractRoot) {
    const msg = `Registry root mismatch! Computed: 0x${tempRoot.toString(16)}, Contract: 0x${contractRoot.toString(16)}`;
    console.error(`[RegistrySync] ${msg}`);
    throw new Error(msg);
  }

  // Root verified! Now swap data atomically
  registryTree.reset();
  for (const event of events) {
    registryTree.insertEntry(
      event.userBigInt,
      event.pubkeyX,
      event.pubkeyY,
      event.nkHash
    );
  }

  console.log(`[RegistrySync] Complete! ${registryTree.entryCount} entries, root matches contract`);
}

/**
 * Check if local registry state needs refresh
 */
export async function registryNeedsRefresh(registryTree: RegistryTree): Promise<boolean> {
  const localRoot = registryTree.getRoot();
  const contractRoot = await getRegistryRoot();
  return localRoot !== contractRoot;
}

/**
 * Get all UserRegistered events
 */
export async function getUserRegisteredEvents(): Promise<UserRegisteredEvent[]> {
  const registryAddress = CONTRACTS.registry as Hex;

  const logs = await l1Public.getLogs({
    address: registryAddress,
    event: parseAbiItem('event UserRegistered(address indexed user, uint256[2] encPublicKey, uint256 nullifierKeyHash, uint256 indexed leafIndex)'),
    fromBlock: DEPLOY_BLOCK,
    toBlock: 'latest',
  });

  return logs.map((log) => {
    const args = log.args as any;
    return {
      user: args.user,
      userBigInt: BigInt(args.user),
      pubkeyX: args.encPublicKey[0],
      pubkeyY: args.encPublicKey[1],
      nkHash: args.nullifierKeyHash,
      leafIndex: Number(args.leafIndex),
      blockNumber: log.blockNumber,
      logIndex: log.logIndex,
      txHash: log.transactionHash,
    };
  });
}
