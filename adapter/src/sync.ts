// Chain sync - synchronizes local merkle tree with on-chain state
// Fetches historical events and rebuilds state on startup

import { parseAbiItem, type Hex } from 'viem';
import { l1Public, PRIVACY_POOL_EVENTS, getContractRoot } from './l1.js';
import { CONTRACTS } from './config.js';
import { MerkleTree } from './merkle.js';

// Deploy block from env (to avoid scanning from genesis)
const DEPLOY_BLOCK = BigInt(process.env.DEPLOY_BLOCK || '0');

/**
 * Event data from chain logs
 */
interface DepositEvent {
  type: 'deposit';
  commitment: bigint;
  leafIndex: number;
  amount: bigint;
  owner: bigint;
  randomness: bigint;
  encryptedNote: Hex;
  blockNumber: bigint;
  logIndex: number;
  txHash: Hex;
}

interface TransferEvent {
  type: 'transfer';
  nullifiers: [bigint, bigint];
  commitments: [bigint, bigint];
  leafIndices: [number, number];
  intentNullifier: bigint;
  encryptedNotes: [Hex, Hex];
  blockNumber: bigint;
  logIndex: number;
  txHash: Hex;
}

interface WithdrawEvent {
  type: 'withdraw';
  nullifiers: [bigint, bigint];
  changeCommitment: bigint;
  changeLeafIndex: number;
  intentNullifier: bigint;
  recipient: Hex;
  amount: bigint;
  encryptedChange: Hex;
  blockNumber: bigint;
  logIndex: number;
  txHash: Hex;
}

type PoolEvent = DepositEvent | TransferEvent | WithdrawEvent;

/**
 * Sync state from chain
 * Rebuilds merkle tree and tracks spent nullifiers/intents
 */
export async function syncFromChain(
  merkleTree: MerkleTree,
  spentNullifiers: Set<bigint>,
  usedIntents: Set<bigint>
): Promise<void> {
  console.log('[Sync] Starting chain sync from block', DEPLOY_BLOCK.toString());

  // Reset local state before rebuilding
  merkleTree.reset();
  spentNullifiers.clear();
  usedIntents.clear();

  const poolAddress = CONTRACTS.privacyPool as Hex;

  // Fetch all event types in parallel
  const [depositLogs, transferLogs, withdrawLogs] = await Promise.all([
    l1Public.getLogs({
      address: poolAddress,
      event: parseAbiItem('event Deposit(uint256 indexed commitment, uint256 indexed leafIndex, uint256 amount, uint256 owner, uint256 randomness, bytes encryptedNote)'),
      fromBlock: DEPLOY_BLOCK,
      toBlock: 'latest',
    }),
    l1Public.getLogs({
      address: poolAddress,
      event: parseAbiItem('event Transfer(uint256[2] nullifiers, uint256[2] commitments, uint256[2] leafIndices, uint256 intentNullifier, bytes[2] encryptedNotes)'),
      fromBlock: DEPLOY_BLOCK,
      toBlock: 'latest',
    }),
    l1Public.getLogs({
      address: poolAddress,
      event: parseAbiItem('event Withdrawal(uint256[2] nullifiers, uint256 changeCommitment, uint256 changeLeafIndex, uint256 intentNullifier, address indexed recipient, uint256 amount, bytes encryptedChange)'),
      fromBlock: DEPLOY_BLOCK,
      toBlock: 'latest',
    }),
  ]);

  console.log(`[Sync] Found ${depositLogs.length} deposits, ${transferLogs.length} transfers, ${withdrawLogs.length} withdrawals`);

  // Parse and collect all events
  const events: PoolEvent[] = [];

  // Parse deposit events
  for (const log of depositLogs) {
    const args = log.args as any;
    events.push({
      type: 'deposit',
      commitment: args.commitment,
      leafIndex: Number(args.leafIndex),
      amount: args.amount,
      owner: args.owner,
      randomness: args.randomness,
      encryptedNote: args.encryptedNote,
      blockNumber: log.blockNumber,
      logIndex: log.logIndex,
      txHash: log.transactionHash,
    });
  }

  // Parse transfer events
  for (const log of transferLogs) {
    const args = log.args as any;
    events.push({
      type: 'transfer',
      nullifiers: [args.nullifiers[0], args.nullifiers[1]],
      commitments: [args.commitments[0], args.commitments[1]],
      leafIndices: [Number(args.leafIndices[0]), Number(args.leafIndices[1])],
      intentNullifier: args.intentNullifier,
      encryptedNotes: args.encryptedNotes,
      blockNumber: log.blockNumber,
      logIndex: log.logIndex,
      txHash: log.transactionHash,
    });
  }

  // Parse withdraw events
  for (const log of withdrawLogs) {
    const args = log.args as any;
    events.push({
      type: 'withdraw',
      nullifiers: [args.nullifiers[0], args.nullifiers[1]],
      changeCommitment: args.changeCommitment,
      changeLeafIndex: Number(args.changeLeafIndex),
      intentNullifier: args.intentNullifier,
      recipient: args.recipient,
      amount: args.amount,
      encryptedChange: args.encryptedChange,
      blockNumber: log.blockNumber,
      logIndex: log.logIndex,
      txHash: log.transactionHash,
    });
  }

  // Sort all events by block number and log index
  events.sort((a, b) => {
    if (a.blockNumber !== b.blockNumber) {
      return Number(a.blockNumber - b.blockNumber);
    }
    return a.logIndex - b.logIndex;
  });

  // Collect all commitments with their expected leaf indices
  const commitments: Array<{ commitment: bigint; expectedIndex: number }> = [];

  for (const event of events) {
    if (event.type === 'deposit') {
      commitments.push({ commitment: event.commitment, expectedIndex: event.leafIndex });
    } else if (event.type === 'transfer') {
      // Mark nullifiers as spent
      spentNullifiers.add(event.nullifiers[0]);
      spentNullifiers.add(event.nullifiers[1]);
      usedIntents.add(event.intentNullifier);

      // Add output commitments
      commitments.push({ commitment: event.commitments[0], expectedIndex: event.leafIndices[0] });
      commitments.push({ commitment: event.commitments[1], expectedIndex: event.leafIndices[1] });
    } else if (event.type === 'withdraw') {
      // Mark nullifiers as spent
      spentNullifiers.add(event.nullifiers[0]);
      spentNullifiers.add(event.nullifiers[1]);
      usedIntents.add(event.intentNullifier);

      // Add change commitment if non-zero
      if (event.changeCommitment !== 0n) {
        commitments.push({ commitment: event.changeCommitment, expectedIndex: event.changeLeafIndex });
      }
    }
  }

  // Sort commitments by expected index and insert in order
  commitments.sort((a, b) => a.expectedIndex - b.expectedIndex);

  for (const { commitment, expectedIndex } of commitments) {
    const actualIndex = merkleTree.insert(commitment);
    if (actualIndex !== expectedIndex) {
      console.warn(`[Sync] Index mismatch: expected ${expectedIndex}, got ${actualIndex}`);
    }
  }

  // Verify root matches contract
  const localRoot = merkleTree.getRoot();
  const contractRoot = await getContractRoot();

  if (localRoot === contractRoot) {
    console.log(`[Sync] Complete! ${merkleTree.leafCount} leaves, root matches contract`);
  } else {
    console.error(`[Sync] WARNING: Root mismatch!`);
    console.error(`  Local:    ${localRoot.toString(16)}`);
    console.error(`  Contract: ${contractRoot.toString(16)}`);
  }
}

/**
 * Check if local state needs refresh
 * Returns true if contract root differs from local root
 */
export async function needsRefresh(merkleTree: MerkleTree): Promise<boolean> {
  const localRoot = merkleTree.getRoot();
  const contractRoot = await getContractRoot();
  return localRoot !== contractRoot;
}

/**
 * Get all events since a specific block (for incremental sync)
 */
export async function getEventsSinceBlock(fromBlock: bigint): Promise<PoolEvent[]> {
  const poolAddress = CONTRACTS.privacyPool as Hex;
  const events: PoolEvent[] = [];

  const [depositLogs, transferLogs, withdrawLogs] = await Promise.all([
    l1Public.getLogs({
      address: poolAddress,
      event: parseAbiItem('event Deposit(uint256 indexed commitment, uint256 indexed leafIndex, uint256 amount, uint256 owner, uint256 randomness, bytes encryptedNote)'),
      fromBlock,
      toBlock: 'latest',
    }),
    l1Public.getLogs({
      address: poolAddress,
      event: parseAbiItem('event Transfer(uint256[2] nullifiers, uint256[2] commitments, uint256[2] leafIndices, uint256 intentNullifier, bytes[2] encryptedNotes)'),
      fromBlock,
      toBlock: 'latest',
    }),
    l1Public.getLogs({
      address: poolAddress,
      event: parseAbiItem('event Withdrawal(uint256[2] nullifiers, uint256 changeCommitment, uint256 changeLeafIndex, uint256 intentNullifier, address indexed recipient, uint256 amount, bytes encryptedChange)'),
      fromBlock,
      toBlock: 'latest',
    }),
  ]);

  // Parse events (same as above)
  for (const log of depositLogs) {
    const args = log.args as any;
    events.push({
      type: 'deposit',
      commitment: args.commitment,
      leafIndex: Number(args.leafIndex),
      amount: args.amount,
      owner: args.owner,
      randomness: args.randomness,
      encryptedNote: args.encryptedNote,
      blockNumber: log.blockNumber,
      logIndex: log.logIndex,
      txHash: log.transactionHash,
    });
  }

  for (const log of transferLogs) {
    const args = log.args as any;
    events.push({
      type: 'transfer',
      nullifiers: [args.nullifiers[0], args.nullifiers[1]],
      commitments: [args.commitments[0], args.commitments[1]],
      leafIndices: [Number(args.leafIndices[0]), Number(args.leafIndices[1])],
      intentNullifier: args.intentNullifier,
      encryptedNotes: args.encryptedNotes,
      blockNumber: log.blockNumber,
      logIndex: log.logIndex,
      txHash: log.transactionHash,
    });
  }

  for (const log of withdrawLogs) {
    const args = log.args as any;
    events.push({
      type: 'withdraw',
      nullifiers: [args.nullifiers[0], args.nullifiers[1]],
      changeCommitment: args.changeCommitment,
      changeLeafIndex: Number(args.changeLeafIndex),
      intentNullifier: args.intentNullifier,
      recipient: args.recipient,
      amount: args.amount,
      encryptedChange: args.encryptedChange,
      blockNumber: log.blockNumber,
      logIndex: log.logIndex,
      txHash: log.transactionHash,
    });
  }

  events.sort((a, b) => {
    if (a.blockNumber !== b.blockNumber) {
      return Number(a.blockNumber - b.blockNumber);
    }
    return a.logIndex - b.logIndex;
  });

  return events;
}

/**
 * Get all deposit events (for note recovery)
 */
export async function getDepositEvents(): Promise<DepositEvent[]> {
  const poolAddress = CONTRACTS.privacyPool as Hex;

  const logs = await l1Public.getLogs({
    address: poolAddress,
    event: parseAbiItem('event Deposit(uint256 indexed commitment, uint256 indexed leafIndex, uint256 amount, uint256 owner, uint256 randomness, bytes encryptedNote)'),
    fromBlock: DEPLOY_BLOCK,
    toBlock: 'latest',
  });

  return logs.map((log) => {
    const args = log.args as any;
    return {
      type: 'deposit' as const,
      commitment: args.commitment,
      leafIndex: Number(args.leafIndex),
      amount: args.amount,
      owner: args.owner,
      randomness: args.randomness,
      encryptedNote: args.encryptedNote,
      blockNumber: log.blockNumber,
      logIndex: log.logIndex,
      txHash: log.transactionHash,
    };
  });
}

/**
 * Get all transfer events (for note recovery)
 */
export async function getTransferEvents(): Promise<TransferEvent[]> {
  const poolAddress = CONTRACTS.privacyPool as Hex;

  const logs = await l1Public.getLogs({
    address: poolAddress,
    event: parseAbiItem('event Transfer(uint256[2] nullifiers, uint256[2] commitments, uint256[2] leafIndices, uint256 intentNullifier, bytes[2] encryptedNotes)'),
    fromBlock: DEPLOY_BLOCK,
    toBlock: 'latest',
  });

  return logs.map((log) => {
    const args = log.args as any;
    return {
      type: 'transfer' as const,
      nullifiers: [args.nullifiers[0], args.nullifiers[1]],
      commitments: [args.commitments[0], args.commitments[1]],
      leafIndices: [Number(args.leafIndices[0]), Number(args.leafIndices[1])],
      intentNullifier: args.intentNullifier,
      encryptedNotes: args.encryptedNotes,
      blockNumber: log.blockNumber,
      logIndex: log.logIndex,
      txHash: log.transactionHash,
    };
  });
}

/**
 * Get all withdraw events (for change note recovery)
 */
export async function getWithdrawEvents(): Promise<WithdrawEvent[]> {
  const poolAddress = CONTRACTS.privacyPool as Hex;

  const logs = await l1Public.getLogs({
    address: poolAddress,
    event: parseAbiItem('event Withdrawal(uint256[2] nullifiers, uint256 changeCommitment, uint256 changeLeafIndex, uint256 intentNullifier, address indexed recipient, uint256 amount, bytes encryptedChange)'),
    fromBlock: DEPLOY_BLOCK,
    toBlock: 'latest',
  });

  return logs.map((log) => {
    const args = log.args as any;
    return {
      type: 'withdraw' as const,
      nullifiers: [args.nullifiers[0], args.nullifiers[1]],
      changeCommitment: args.changeCommitment,
      changeLeafIndex: Number(args.changeLeafIndex),
      intentNullifier: args.intentNullifier,
      recipient: args.recipient,
      amount: args.amount,
      encryptedChange: args.encryptedChange,
      blockNumber: log.blockNumber,
      logIndex: log.logIndex,
      txHash: log.transactionHash,
    };
  });
}
