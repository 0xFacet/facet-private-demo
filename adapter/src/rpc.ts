// JSON-RPC server for MetaMask compatibility
// Handles virtual chain requests and routes them appropriately

import Fastify from 'fastify';
import cors from '@fastify/cors';
import {
  parseTransaction,
  toHex,
  hexToBytes,
  keccak256,
  recoverAddress,
  recoverPublicKey,
  recoverMessageAddress,
  serializeTransaction,
  concat,
  type Hex,
  type TransactionSerializableEIP1559,
} from 'viem';
import {
  VIRTUAL_CHAIN_ID,
  RPC_PORT,
  WITHDRAW_SENTINEL,
  FIELD_SIZE,
  CONTRACTS,
  TREE_DEPTH,
} from './config.js';
import { NoteStore, SessionKeys, createNoteWithRandomness, type Note } from './notes.js';
import { MerkleTree } from './merkle.js';
import { initPoseidon, computeCommitment, computeNullifier, computeNullifierKeyHash, computeIntentNullifier } from './crypto/poseidon.js';
import { deriveEncryptionKeypair, encryptNoteData, decryptNoteData, pubKeyToHex, hexToPubKey } from './crypto/ecies.js';
import {
  l1Public,
  submitDeposit,
  submitTransfer,
  submitWithdraw,
  waitForReceipt,
  getRelayerAddress,
  registerEncryptionKey,
  getEncryptionKey,
  getNullifierKeyHash as getRegistryNullifierKeyHash,
  isUserRegistered,
  parseDepositLeafIndex,
  parseTransferLeafIndices,
  parseWithdrawLeafIndex,
} from './l1.js';
import { syncFromChain, needsRefresh } from './sync.js';
import {
  generateTransferProofWorker,
  generateWithdrawProofWorker,
  extractSignatureFromTx,
  type TransferCircuitInputs,
  type WithdrawCircuitInputs,
} from './proof.js';

// Fixed gas parameters - MUST match circuit constants
const FIXED_MAX_PRIORITY_FEE = 1000000000n; // 1 gwei
const FIXED_MAX_FEE = 30000000000n; // 30 gwei
const FIXED_GAS_LIMIT = 21000n; // simple transfer

interface JsonRpcRequest {
  jsonrpc: string;
  id: number | string;
  method: string;
  params?: unknown[];
}

/**
 * Transaction record for history
 */
interface TransactionRecord {
  type: 'deposit' | 'transfer' | 'transfer_in' | 'transfer_out' | 'transfer_self' | 'withdraw';
  virtualHash: string;
  l1Hash: string;
  amount: bigint;
  recipient?: string; // For transfers
  timestamp: number;
}

/**
 * User session state
 */
interface UserSession {
  address: string;
  keys: SessionKeys;
  noteStore: NoteStore;
  transactions: TransactionRecord[];
  txInFlight: boolean;  // Prevents concurrent transactions
}

/**
 * Pending transaction status for async processing
 */
interface PendingTransaction {
  status: 'proving' | 'submitting' | 'complete' | 'failed';
  l1Hash?: string;
  error?: string;
  reservedNotes?: Note[]; // For cleanup on failure
}

/**
 * RPC Adapter Server
 */
// JSON replacer to handle BigInts
function bigIntReplacer(_key: string, value: unknown): unknown {
  if (typeof value === 'bigint') {
    return toHex(value);
  }
  return value;
}

export class RpcAdapter {
  private fastify = Fastify({
    logger: false,
  });
  private sessions: Map<string, UserSession> = new Map();
  private merkleTree: MerkleTree;
  private spentNullifiers: Set<bigint> = new Set();
  private usedIntents: Set<bigint> = new Set();
  private txHashMapping: Map<string, string> = new Map(); // virtual -> L1
  private inFlightTx: Map<string, Promise<string>> = new Map(); // signed tx -> pending result
  private pendingTxs: Map<string, PendingTransaction> = new Map(); // virtualHash -> status
  private initialized = false;

  constructor() {
    this.merkleTree = new MerkleTree();
  }

  /**
   * Initialize adapter - sync state from chain
   */
  async initialize(): Promise<void> {
    if (this.initialized) return;

    console.log('[RpcAdapter] Initializing...');

    // Initialize Poseidon hash function
    await initPoseidon();

    // Sync state from chain
    await syncFromChain(this.merkleTree, this.spentNullifiers, this.usedIntents);

    // Setup routes
    this.setupRoutes();

    this.initialized = true;
    console.log('[RpcAdapter] Initialization complete');
  }

  /**
   * Derive next available nonce by scanning for first unused intent.
   * Uses in-memory usedIntents set (synced from chain via syncFromChain).
   * Fast: O(n) in-memory lookups instead of n network calls.
   */
  private recoverNonce(nullifierKey: bigint): bigint {
    for (let n = 0n; n < 10000n; n++) {
      const intent = computeIntentNullifier(nullifierKey, VIRTUAL_CHAIN_ID, n);
      if (!this.usedIntents.has(intent)) {
        return n;
      }
    }
    throw new Error('Nonce recovery exceeded limit (10000 transactions)');
  }

  private setupRoutes() {
    // Enable CORS for browser access
    this.fastify.register(cors, {
      origin: true,
    });

    this.fastify.post('/', async (request, reply) => {
      const body = request.body as JsonRpcRequest;

      try {
        const result = await this.handleRequest(body.method, body.params || []);
        // Use custom serializer to handle BigInts
        reply.header('Content-Type', 'application/json');
        return reply.send(JSON.stringify({
          jsonrpc: '2.0',
          id: body.id,
          result,
        }, bigIntReplacer));
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Unknown error';
        const paramsStr = (body.params || []).length > 0 ? JSON.stringify(body.params, bigIntReplacer) : '';
        console.error(`[RPC Error] ${body.method} ${paramsStr}\n  ->`, message);
        reply.header('Content-Type', 'application/json');
        return reply.send(JSON.stringify({
          jsonrpc: '2.0',
          id: body.id,
          error: { code: -32603, message },
        }));
      }
    });
  }

  /**
   * Handle JSON-RPC request
   */
  private async handleRequest(method: string, params: unknown[]): Promise<unknown> {
    const result = await this.handleMethod(method, params);
    const paramsStr = params.length > 0 ? ` ${JSON.stringify(params, bigIntReplacer)}` : '';
    const resultStr = typeof result === 'object' 
      ? JSON.stringify(result, bigIntReplacer).slice(0, 100) 
      : String(result);
    console.log(`[RPC] ${method}${paramsStr} -> ${resultStr}`);
    return result;
  }

  private async handleMethod(method: string, params: unknown[]): Promise<unknown> {
    switch (method) {
      // Chain identification - return VIRTUAL chain ID
      case 'eth_chainId':
        return toHex(VIRTUAL_CHAIN_ID);

      case 'net_version':
        return VIRTUAL_CHAIN_ID.toString();

      // Account methods
      case 'eth_accounts':
      case 'eth_requestAccounts':
        return this.getAccounts();

      // Balance - return shielded balance
      case 'eth_getBalance':
        return this.getBalance(params[0] as string);

      // Nonce - return virtual nonce
      case 'eth_getTransactionCount':
        return this.getTransactionCount(params[0] as string);

      case 'eth_estimateGas':
        return "0x5208"

      case 'eth_gasPrice':
        return '0x1';

      case 'eth_maxPriorityFeePerGas':
        return '0x1';

      case 'eth_feeHistory':
        return {
          oldestBlock: '0x1',
          baseFeePerGas: ['0x1', '0x1'],
          gasUsedRatio: [0],
          reward: [['0x1']],
        };

      // Transaction submission - intercept and process
      case 'eth_sendRawTransaction':
        return this.sendRawTransaction(params[0] as string);

      // Transaction status
      case 'eth_getTransactionReceipt':
        return this.getTransactionReceipt(params[0] as string);

      case 'eth_getTransactionByHash':
        return this.getTransactionByHash(params[0] as string);

      // Block methods - proxy to L1
      case 'eth_blockNumber':
      case 'eth_getBlockByNumber':
      case 'eth_getBlockByHash':
        return l1Public.request({ method: method as any, params: params as any });

      // Contract methods - proxy to L1
      case 'eth_call':
      case 'eth_getCode':
        return l1Public.request({ method: method as any, params: params as any });

      // Custom methods
      case 'privacy_registerViewingKey':
        return this.registerViewingKey(params[0] as string, params[1] as string);

      case 'privacy_getShieldedBalance':
        return this.getShieldedBalance(params[0] as string);

      case 'privacy_getNotes':
        return this.getNotes(params[0] as string);

      case 'privacy_getL1Balance':
        return this.getL1Balance(params[0] as string);

      case 'privacy_encryptNoteData':
        return this.encryptNoteDataForUser(params[0] as string, params[1] as { owner: string; amount: string; randomness: string });

      case 'privacy_watchForDeposit':
        return this.watchForDeposit(params[0] as string, params[1] as string);

      case 'privacy_getEncryptionKey':
        return this.getEncryptionKey(params[0] as string);

      case 'privacy_getNullifierKeyHash':
        return this.getNullifierKeyHashRpc(params[0] as string);

      case 'privacy_getTransactions':
        return this.getTransactions(params[0] as string);

      case 'privacy_refresh':
        return this.refreshSession(params[0] as string);

      case 'privacy_hasSession':
        return this.sessions.has((params[0] as string).toLowerCase());

      case 'privacy_getTransactionStatus':
        return this.getTransactionStatus(params[0] as string);

      default:
        throw new Error(`Method ${method} not supported`);
    }
  }

  // ==================== Account Methods ====================

  private getAccounts(): string[] {
    return Array.from(this.sessions.keys());
  }

  private getBalance(address: string): string {
    const normalized = address.toLowerCase();
    const session = this.sessions.get(normalized);
    if (!session) {
      console.log(`[Balance] No session for ${normalized}, active sessions: ${Array.from(this.sessions.keys()).join(', ') || 'none'}`);
      return '0x0';
    }
    const balance = session.noteStore.getBalance();
    console.log(`[Balance] ${normalized} -> ${balance}`);
    return toHex(balance);
  }

  private getShieldedBalance(address: string): string {
    const session = this.sessions.get(address.toLowerCase());
    if (!session) {
      return '0x0';
    }
    // Return actual shielded balance (no buffer)
    return toHex(session.noteStore.getBalance());
  }

  private async getL1Balance(address: string): Promise<string> {
    const balance = await l1Public.getBalance({ address: address as Hex });
    return toHex(balance);
  }

  private getTransactionCount(address: string): string {
    const session = this.sessions.get(address.toLowerCase());
    if (!session) {
      return '0x0';
    }
    // Use recoverNonce for authoritative nonce (computed from usedIntents)
    return toHex(this.recoverNonce(session.keys.nullifierKey));
  }

  private getNotes(address: string): unknown {
    const session = this.sessions.get(address.toLowerCase());
    if (!session) {
      return [];
    }
    return session.noteStore.getAllNotes().map((n) => ({
      amount: toHex(n.amount),
      commitment: toHex(n.commitment),
      leafIndex: n.leafIndex,
      spent: n.spent,
      reserved: n.reserved || false,
    }));
  }

  // ==================== Transaction Methods ====================

  /**
   * Validate a signed transaction (fast checks only, no proof generation)
   */
  private async validateTransaction(signedTx: string): Promise<{
    parsed: ReturnType<typeof parseTransaction>;
    session: UserSession;
    senderAddress: Hex;
    recoveredPubKey: Hex;
    selectedNotes: Note[];
    isWithdraw: boolean;
  }> {
    // Parse the signed transaction
    const parsed = parseTransaction(signedTx as Hex);

    // Validate chain ID
    if (BigInt(parsed.chainId || 0) !== VIRTUAL_CHAIN_ID) {
      throw new Error(`Invalid chain ID. Expected ${VIRTUAL_CHAIN_ID}, got ${parsed.chainId}`);
    }

    // Recover sender from signature
    if (!parsed.r || !parsed.s || parsed.yParity === undefined) {
      throw new Error('Missing signature components');
    }

    const unsignedTx: TransactionSerializableEIP1559 = {
      chainId: Number(VIRTUAL_CHAIN_ID),
      nonce: parsed.nonce ?? 0,
      to: parsed.to,
      value: parsed.value ?? 0n,
      maxPriorityFeePerGas: parsed.maxPriorityFeePerGas ?? 0n,
      maxFeePerGas: parsed.maxFeePerGas ?? 0n,
      gas: parsed.gas ?? 0n,
      data: parsed.data,
      type: 'eip1559',
    };

    const unsignedHash = keccak256(serializeTransaction(unsignedTx));

    const recoveredPubKey = await recoverPublicKey({
      hash: unsignedHash,
      signature: { r: parsed.r, s: parsed.s, yParity: parsed.yParity },
    });

    const senderAddress = await recoverAddress({
      hash: unsignedHash,
      signature: { r: parsed.r, s: parsed.s, yParity: parsed.yParity },
    });

    const normalizedSender = senderAddress.toLowerCase();
    const session = this.sessions.get(normalizedSender);
    if (!session) {
      throw new Error('Session not found. Register viewing key first.');
    }

    // Check tx-in-flight guard - prevents concurrent transactions
    // Set immediately after check to prevent race condition before async operations
    if (session.txInFlight) {
      throw new Error('Transaction already in progress. Please wait for it to complete.');
    }
    session.txInFlight = true;

    try {
      // Derive expected nonce from synced state (stateless)
      const expectedNonce = this.recoverNonce(session.keys.nullifierKey);
      const txNonce = BigInt(parsed.nonce ?? 0);

      if (txNonce !== expectedNonce) {
        throw new Error(`Invalid nonce. Expected ${expectedNonce}, got ${txNonce}. Please refresh and retry.`);
      }

      // Route based on destination
      const to = parsed.to?.toLowerCase();
      const poolAddress = CONTRACTS.privacyPool.toLowerCase();
      const isWithdraw = to === WITHDRAW_SENTINEL.toLowerCase();

      if (to === poolAddress) {
        throw new Error('Deposits must be made on L1 Sepolia. Switch to L1 tab to deposit.');
      }

      // For transfers, check recipient is registered
      if (!isWithdraw) {
        const recipient = parsed.to as Hex;
        if (!recipient) {
          throw new Error('Transfer must have a recipient');
        }
        const recipientPkBytes32 = await getEncryptionKey(recipient);
        if (!recipientPkBytes32) {
          throw new Error(`Recipient ${recipient} is not registered. They must register a viewing key first.`);
        }
      }

      // Select and validate notes
      const value = parsed.value || 0n;
      const selectedNotes = session.noteStore.selectNotesForSpend(value);
      if (!selectedNotes) {
        const unspent = session.noteStore.getUnspentNotes();
        const total = unspent.reduce((sum, n) => sum + n.amount, 0n);

        if (total >= value && unspent.length > 2) {
          // Have enough total but notes are fragmented (max 2 inputs per tx)
          const sorted = [...unspent].sort((a, b) => a.amount > b.amount ? -1 : 1);
          const maxPair = sorted.length >= 2 ? sorted[0].amount + sorted[1].amount : sorted[0]?.amount || 0n;
          throw new Error(`Notes are fragmented. Max spendable in one tx: ${maxPair} (from 2 largest notes). Total balance: ${total}. Send a smaller amount first to consolidate notes.`);
        }
        throw new Error(`Insufficient balance. Have ${total}, need ${value}`);
      }

      return {
        parsed,
        session,
        senderAddress: senderAddress as Hex,
        recoveredPubKey,
        selectedNotes,
        isWithdraw,
      };
    } catch (err) {
      // Clear tx-in-flight guard on validation error
      session.txInFlight = false;
      throw err;
    }
  }

  /**
   * Send raw transaction - returns immediately, processes in background
   */
  private async sendRawTransaction(signedTx: string): Promise<string> {
    // Compute virtualHash immediately
    const virtualHash = keccak256(signedTx as Hex);

    // Check if already processed or pending
    if (this.txHashMapping.has(virtualHash)) {
      console.log('[RPC] Transaction already completed, returning hash');
      return virtualHash;
    }

    const pending = this.pendingTxs.get(virtualHash);
    if (pending) {
      if (pending.status === 'failed') {
        // Allow retry - delete failed entry
        this.pendingTxs.delete(virtualHash);
        console.log('[RPC] Retrying previously failed transaction');
      } else {
        // Still proving/submitting or complete
        console.log('[RPC] Transaction already pending, returning hash');
        return virtualHash;
      }
    }

    // Check for duplicate in-flight validation
    const existing = this.inFlightTx.get(signedTx);
    if (existing) {
      console.log('[RPC] Duplicate transaction detected, returning existing result');
      return existing;
    }

    // Create validation promise to prevent duplicate validation
    const validationPromise = (async () => {
      // Check if chain needs refresh
      if (await needsRefresh(this.merkleTree)) {
        console.log('[RPC] State refresh needed, syncing...');
        await syncFromChain(this.merkleTree, this.spentNullifiers, this.usedIntents);
      }

      // Quick validation (sets txInFlight inside to prevent race)
      const validated = await this.validateTransaction(signedTx);

      // Reserve notes to prevent double-spend
      validated.session.noteStore.reserveNotes(validated.selectedNotes);

      // Mark as pending
      this.pendingTxs.set(virtualHash, {
        status: 'proving',
        reservedNotes: validated.selectedNotes,
      });

      // Start background processing (don't await)
      this.processTransactionAsync(virtualHash, signedTx as Hex, validated)
        .catch(err => {
          const errorMsg = err instanceof Error ? err.message : String(err);
          console.error(`[RPC] Background tx failed: ${errorMsg}`);
          // Cleanup on failure
          validated.session.noteStore.unreserveNotes(validated.selectedNotes);
          validated.session.txInFlight = false;
          this.pendingTxs.set(virtualHash, {
            status: 'failed',
            error: errorMsg,
          });
        });

      return virtualHash;
    })();

    this.inFlightTx.set(signedTx, validationPromise);

    try {
      return await validationPromise;
    } finally {
      this.inFlightTx.delete(signedTx);
    }
  }

  /**
   * Process transaction in background (proof generation + L1 submission)
   */
  private async processTransactionAsync(
    virtualHash: string,
    signedTx: Hex,
    validated: {
      parsed: ReturnType<typeof parseTransaction>;
      session: UserSession;
      senderAddress: Hex;
      recoveredPubKey: Hex;
      selectedNotes: Note[];
      isWithdraw: boolean;
    }
  ): Promise<void> {
    const { parsed, session, senderAddress, recoveredPubKey, selectedNotes, isWithdraw } = validated;

    // No try/catch here - errors propagate to outer .catch() in sendRawTransaction
    // Execute functions handle all local state updates (merkle, nullifiers, intents)
    if (isWithdraw) {
      await this.executeWithdrawAsync(parsed, session, senderAddress, signedTx, recoveredPubKey, selectedNotes, virtualHash);
    } else {
      await this.executeTransferAsync(parsed, session, senderAddress, signedTx, recoveredPubKey, selectedNotes, virtualHash);
    }

    // Clear tx-in-flight guard on success
    session.txInFlight = false;
  }

  /**
   * Get transaction status (for polling)
   */
  private getTransactionStatus(txHash: string): { status: string; l1Hash?: string; error?: string } {
    const pending = this.pendingTxs.get(txHash);
    if (pending) {
      return {
        status: pending.status,
        l1Hash: pending.l1Hash,
        error: pending.error,
      };
    }

    if (this.txHashMapping.has(txHash)) {
      return { status: 'complete', l1Hash: this.txHashMapping.get(txHash) };
    }

    return { status: 'unknown' };
  }

  /**
   * Execute transfer asynchronously (notes already selected)
   */
  private async executeTransferAsync(
    parsed: ReturnType<typeof parseTransaction>,
    session: UserSession,
    senderAddress: Hex,
    signedTx: Hex,
    recoveredPubKey: Hex,
    selectedNotes: Note[],
    virtualHash: string
  ): Promise<string> {
    const value = parsed.value || 0n;
    const recipient = parsed.to as Hex;

    console.log(`[Transfer] ${senderAddress} -> ${recipient}, value=${value}`);

    // Route to single-note or two-note execution, passing notes and virtualHash
    if (selectedNotes.length === 1) {
      return this.executeTransferSingleNoteAsync(parsed, session, senderAddress, signedTx, selectedNotes[0], recoveredPubKey, virtualHash);
    }
    return this.executeTransferTwoNotesAsync(parsed, session, senderAddress, signedTx, selectedNotes, recoveredPubKey, virtualHash);
  }

  /**
   * Execute withdraw asynchronously (notes already selected)
   */
  private async executeWithdrawAsync(
    parsed: ReturnType<typeof parseTransaction>,
    session: UserSession,
    senderAddress: Hex,
    signedTx: Hex,
    recoveredPubKey: Hex,
    selectedNotes: Note[],
    virtualHash: string
  ): Promise<string> {
    const withdrawAmount = parsed.value || 0n;
    let withdrawRecipient: Hex;
    if (parsed.data && parsed.data.length >= 42) {
      withdrawRecipient = ('0x' + parsed.data.slice(2, 42)) as Hex;
    } else {
      withdrawRecipient = senderAddress;
    }

    console.log(`[Withdraw] ${senderAddress} withdrawing ${withdrawAmount} to ${withdrawRecipient}`);

    if (selectedNotes.length === 1) {
      return this.executeWithdrawSingleNoteAsync(
        parsed, session, senderAddress, signedTx, selectedNotes[0],
        recoveredPubKey, withdrawAmount, withdrawRecipient, virtualHash
      );
    }
    return this.executeWithdrawTwoNotesAsync(
      parsed, session, senderAddress, signedTx, selectedNotes,
      recoveredPubKey, withdrawAmount, withdrawRecipient, virtualHash
    );
  }

  /**
   * Execute transfer with two notes (async version - updates status, returns l1Hash)
   */
  private async executeTransferTwoNotesAsync(
    parsed: ReturnType<typeof parseTransaction>,
    session: UserSession,
    senderAddress: Hex,
    signedTx: Hex,
    notes: Note[],
    recoveredPubKey: Hex,
    virtualHash: string
  ): Promise<string> {
    const value = parsed.value || 0n;
    const recipient = parsed.to as Hex;
    const txNonce = parsed.nonce ?? 0;

    // Look up recipient's encryption public key and nullifier key hash from Registry
    const recipientPkBytes32 = await getEncryptionKey(recipient);
    if (!recipientPkBytes32) {
      throw new Error(`Recipient ${recipient} is not registered. They must register a viewing key first.`);
    }
    const recipientPubKey = hexToPubKey(recipientPkBytes32);
    const recipientNullifierKeyHash = await getRegistryNullifierKeyHash(recipient);
    if (recipientNullifierKeyHash === 0n) {
      throw new Error(`Recipient ${recipient} nullifier key hash not found in registry.`);
    }

    const totalInput = notes[0].amount + notes[1].amount;
    const change = totalInput - value;

    // Generate merkle proofs
    const proof0 = this.merkleTree.generateProof(notes[0].leafIndex);
    const proof1 = this.merkleTree.generateProof(notes[1].leafIndex);

    // Compute nullifiers
    const nullifier0 = computeNullifier(notes[0].commitment, session.keys.nullifierKey);
    const nullifier1 = computeNullifier(notes[1].commitment, session.keys.nullifierKey);

    // Output 0: to recipient
    const output0Owner = BigInt(recipient);
    const output0Randomness = BigInt(keccak256(concat([signedTx, '0x00']))) % FIELD_SIZE;
    const output0Commitment = computeCommitment(value, output0Owner, output0Randomness, recipientNullifierKeyHash);

    // Output 1: change back to sender
    const output1Owner = BigInt(senderAddress);
    const output1Randomness = BigInt(keccak256(concat([signedTx, '0x01']))) % FIELD_SIZE;
    const output1Commitment = computeCommitment(change, output1Owner, output1Randomness, session.keys.nullifierKeyHash);

    // Intent nullifier
    // Intent nullifier = poseidon(nullifierKey, chainId, nonce)
    const intentNullifier = computeIntentNullifier(
      session.keys.nullifierKey,
      VIRTUAL_CHAIN_ID,
      BigInt(txNonce)
    );

    // Extract signature data
    const signatureData = extractSignatureFromTx(
      parsed.r!,
      parsed.s!,
      recoveredPubKey
    );

    // Build circuit inputs
    const merkleRoot = this.merkleTree.getRoot();
    const circuitInputs: TransferCircuitInputs = {
      merkleRoot,
      nullifier0,
      nullifier1,
      outputCommitment0: output0Commitment,
      outputCommitment1: output1Commitment,
      intentNullifier,
      signatureData,
      txNonce: BigInt(txNonce),
      txMaxPriorityFee: parsed.maxPriorityFeePerGas ?? 0n,
      txMaxFee: parsed.maxFeePerGas ?? 0n,
      txGasLimit: parsed.gas ?? 0n,
      txTo: BigInt(recipient),
      txValue: value,
      input0: {
        amount: notes[0].amount,
        randomness: notes[0].randomness,
        leafIndex: notes[0].leafIndex,
        siblings: proof0.siblings,
      },
      input1: {
        amount: notes[1].amount,
        randomness: notes[1].randomness,
        leafIndex: notes[1].leafIndex,
        siblings: proof1.siblings,
      },
      output0Amount: value,
      output0Owner,
      output0Randomness,
      output1Amount: change,
      output1Randomness,
      nullifierKey: session.keys.nullifierKey,
      output0NullifierKeyHash: recipientNullifierKeyHash,
    };

    console.log('[Transfer] Generating proof...');
    const { proof } = await generateTransferProofWorker(circuitInputs);

    // Update status to submitting
    this.pendingTxs.set(virtualHash, { status: 'submitting', reservedNotes: notes });

    // Encrypt note data
    const encryptedNote0 = await encryptNoteData(recipientPubKey, {
      owner: output0Owner,
      amount: value,
      randomness: output0Randomness,
    });
    const encryptedNote1 = await encryptNoteData(session.keys.encryptionPubKey, {
      owner: output1Owner,
      amount: change,
      randomness: output1Randomness,
    });

    // Submit to L1
    const l1Hash = await submitTransfer(
      proof,
      merkleRoot,
      [nullifier0, nullifier1],
      [output0Commitment, output1Commitment],
      intentNullifier,
      [encryptedNote0, encryptedNote1]
    );
    const receipt = await waitForReceipt(l1Hash);

    // Check if L1 tx succeeded before updating local state
    if (receipt.status !== 'success') {
      throw new Error(`L1 transaction reverted: ${l1Hash}`);
    }

    // Mark notes spent IMMEDIATELY after L1 success, before parsing
    // This prevents note corruption if parsing fails (notes are spent on L1 regardless)
    session.noteStore.markSpent(notes[0].commitment);
    session.noteStore.markSpent(notes[1].commitment);

    const [leafIndex0, leafIndex1] = parseTransferLeafIndices(receipt);

    console.log(`[L1] Transfer confirmed: ${l1Hash}`);

    // Mark L1 tx as confirmed immediately (so getTransactionReceipt works)
    this.txHashMapping.set(virtualHash, l1Hash);
    this.pendingTxs.set(virtualHash, { status: 'complete', l1Hash });

    // Update merkle tree locally with new commitments (no full sync needed)
    this.merkleTree.insert(output0Commitment);
    this.merkleTree.insert(output1Commitment);
    this.spentNullifiers.add(nullifier0);
    this.spentNullifiers.add(nullifier1);
    this.usedIntents.add(intentNullifier);

    if (change > 0n) {
      const changeNote = createNoteWithRandomness(change, output1Owner, output1Randomness, session.keys.nullifierKeyHash, leafIndex1);
      session.noteStore.addNote(changeNote);
    }

    // For self-transfer: also add recipient note (output_0) to sender's store
    if (recipient.toLowerCase() === senderAddress.toLowerCase()) {
      const recipientNote = createNoteWithRandomness(value, output0Owner, output0Randomness, recipientNullifierKeyHash, leafIndex0);
      session.noteStore.addNote(recipientNote);
    }

    // Record transaction
    session.transactions.push({
      type: 'transfer_out',
      virtualHash,
      l1Hash,
      amount: value,
      recipient,
      timestamp: Date.now(),
    });

    console.log(`[Transfer] Complete! l1Hash=${l1Hash}`);
    return l1Hash;
  }

  /**
   * Execute transfer with single note (async version - updates status, returns l1Hash)
   */
  private async executeTransferSingleNoteAsync(
    parsed: ReturnType<typeof parseTransaction>,
    session: UserSession,
    senderAddress: Hex,
    signedTx: Hex,
    note: Note,
    recoveredPubKey: Hex,
    virtualHash: string
  ): Promise<string> {
    const value = parsed.value || 0n;
    const recipient = parsed.to as Hex;
    const txNonce = parsed.nonce ?? 0;

    console.log('[Transfer] Using single-note with phantom input');

    // Look up recipient's encryption public key and nullifier key hash
    const recipientPkBytes32 = await getEncryptionKey(recipient);
    if (!recipientPkBytes32) {
      throw new Error(`Recipient ${recipient} is not registered. They must register a viewing key first.`);
    }
    const recipientPubKey = hexToPubKey(recipientPkBytes32);
    const recipientNullifierKeyHash = await getRegistryNullifierKeyHash(recipient);
    if (recipientNullifierKeyHash === 0n) {
      throw new Error(`Recipient ${recipient} nullifier key hash not found in registry.`);
    }

    const change = note.amount - value;

    // Real note (input 0)
    const proof0 = this.merkleTree.generateProof(note.leafIndex);
    const nullifier0 = computeNullifier(note.commitment, session.keys.nullifierKey);

    // Phantom note (input 1)
    const phantomRandomness = BigInt(keccak256(concat([signedTx, '0xff']))) % FIELD_SIZE;
    const phantomCommitment = computeCommitment(0n, BigInt(senderAddress), phantomRandomness, session.keys.nullifierKeyHash);
    const nullifier1 = computeNullifier(phantomCommitment, session.keys.nullifierKey);

    // Output 0: to recipient
    const output0Owner = BigInt(recipient);
    const output0Randomness = BigInt(keccak256(concat([signedTx, '0x00']))) % FIELD_SIZE;
    const output0Commitment = computeCommitment(value, output0Owner, output0Randomness, recipientNullifierKeyHash);

    // Output 1: change back to sender
    const output1Owner = BigInt(senderAddress);
    const output1Randomness = BigInt(keccak256(concat([signedTx, '0x01']))) % FIELD_SIZE;
    const output1Commitment = computeCommitment(change, output1Owner, output1Randomness, session.keys.nullifierKeyHash);

    // Intent nullifier
    // Intent nullifier = poseidon(nullifierKey, chainId, nonce)
    const intentNullifier = computeIntentNullifier(
      session.keys.nullifierKey,
      VIRTUAL_CHAIN_ID,
      BigInt(txNonce)
    );

    // Extract signature data
    const signatureData = extractSignatureFromTx(
      parsed.r!,
      parsed.s!,
      recoveredPubKey
    );

    // Build circuit inputs
    const merkleRoot = this.merkleTree.getRoot();
    const circuitInputs: TransferCircuitInputs = {
      merkleRoot,
      nullifier0,
      nullifier1,
      outputCommitment0: output0Commitment,
      outputCommitment1: output1Commitment,
      intentNullifier,
      signatureData,
      txNonce: BigInt(txNonce),
      txMaxPriorityFee: parsed.maxPriorityFeePerGas ?? 0n,
      txMaxFee: parsed.maxFeePerGas ?? 0n,
      txGasLimit: parsed.gas ?? 0n,
      txTo: BigInt(recipient),
      txValue: value,
      input0: {
        amount: note.amount,
        randomness: note.randomness,
        leafIndex: note.leafIndex,
        siblings: proof0.siblings,
      },
      input1: {
        amount: 0n,
        randomness: phantomRandomness,
        leafIndex: 0,
        siblings: Array(TREE_DEPTH).fill(0n),
      },
      output0Amount: value,
      output0Owner,
      output0Randomness,
      output1Amount: change,
      output1Randomness,
      nullifierKey: session.keys.nullifierKey,
      output0NullifierKeyHash: recipientNullifierKeyHash,
    };

    console.log('[Transfer] Generating proof (single-note)...');
    const { proof } = await generateTransferProofWorker(circuitInputs);

    // Update status to submitting
    this.pendingTxs.set(virtualHash, { status: 'submitting', reservedNotes: [note] });

    // Encrypt note data
    const encryptedNote0 = await encryptNoteData(recipientPubKey, {
      owner: output0Owner,
      amount: value,
      randomness: output0Randomness,
    });
    const encryptedNote1 = await encryptNoteData(session.keys.encryptionPubKey, {
      owner: output1Owner,
      amount: change,
      randomness: output1Randomness,
    });

    // Submit to L1
    const l1Hash = await submitTransfer(
      proof,
      merkleRoot,
      [nullifier0, nullifier1],
      [output0Commitment, output1Commitment],
      intentNullifier,
      [encryptedNote0, encryptedNote1]
    );
    const receipt = await waitForReceipt(l1Hash);

    // Check if L1 tx succeeded before updating local state
    if (receipt.status !== 'success') {
      throw new Error(`L1 transaction reverted: ${l1Hash}`);
    }

    // Mark note spent IMMEDIATELY after L1 success, before parsing
    // This prevents note corruption if parsing fails (note is spent on L1 regardless)
    session.noteStore.markSpent(note.commitment);

    const [leafIndex0, leafIndex1] = parseTransferLeafIndices(receipt);

    console.log(`[L1] Transfer confirmed: ${l1Hash}`);

    // Mark L1 tx as confirmed immediately (so getTransactionReceipt works)
    this.txHashMapping.set(virtualHash, l1Hash);
    this.pendingTxs.set(virtualHash, { status: 'complete', l1Hash });

    // Update merkle tree locally with new commitments (no full sync needed)
    this.merkleTree.insert(output0Commitment);
    this.merkleTree.insert(output1Commitment);
    this.spentNullifiers.add(nullifier0);
    this.spentNullifiers.add(nullifier1);
    this.usedIntents.add(intentNullifier);

    if (change > 0n) {
      const changeNote = createNoteWithRandomness(change, output1Owner, output1Randomness, session.keys.nullifierKeyHash, leafIndex1);
      session.noteStore.addNote(changeNote);
    }

    // For self-transfer: also add recipient note (output_0) to sender's store
    if (recipient.toLowerCase() === senderAddress.toLowerCase()) {
      const recipientNote = createNoteWithRandomness(value, output0Owner, output0Randomness, recipientNullifierKeyHash, leafIndex0);
      session.noteStore.addNote(recipientNote);
    }

    // Record transaction
    session.transactions.push({
      type: 'transfer_out',
      virtualHash,
      l1Hash,
      amount: value,
      recipient,
      timestamp: Date.now(),
    });

    console.log(`[Transfer] Complete (single-note)! l1Hash=${l1Hash}`);
    return l1Hash;
  }

  /**
   * Execute withdrawal with two notes (async version - updates status, returns l1Hash)
   */
  private async executeWithdrawTwoNotesAsync(
    parsed: ReturnType<typeof parseTransaction>,
    session: UserSession,
    senderAddress: Hex,
    signedTx: Hex,
    notes: Note[],
    recoveredPubKey: Hex,
    withdrawAmount: bigint,
    withdrawRecipient: Hex,
    virtualHash: string
  ): Promise<string> {
    const [note0, note1] = notes;
    const totalInput = note0.amount + note1.amount;
    const changeAmount = totalInput - withdrawAmount;
    const txNonce = parsed.nonce ?? 0;

    // Merkle proofs for both notes
    const proof0 = this.merkleTree.generateProof(note0.leafIndex);
    const proof1 = this.merkleTree.generateProof(note1.leafIndex);

    // Nullifiers
    const nullifier0 = computeNullifier(note0.commitment, session.keys.nullifierKey);
    const nullifier1 = computeNullifier(note1.commitment, session.keys.nullifierKey);

    // Change commitment
    const changeOwner = BigInt(senderAddress);
    const changeRandomness = BigInt(keccak256(concat([signedTx, '0x02']))) % FIELD_SIZE;
    // Always compute commitment (even for zero change) - circuit expects hash_4
    const changeCommitment = computeCommitment(changeAmount, changeOwner, changeRandomness, session.keys.nullifierKeyHash);

    // Intent nullifier = poseidon(nullifierKey, chainId, nonce)
    const intentNullifier = computeIntentNullifier(
      session.keys.nullifierKey,
      VIRTUAL_CHAIN_ID,
      BigInt(txNonce)
    );

    const signatureData = extractSignatureFromTx(
      parsed.r!,
      parsed.s!,
      recoveredPubKey
    );

    const merkleRoot = this.merkleTree.getRoot();

    const circuitInputs: WithdrawCircuitInputs = {
      merkleRoot,
      nullifier0,
      nullifier1,
      changeCommitment,
      intentNullifier,
      withdrawRecipient: BigInt(withdrawRecipient),
      withdrawAmount,
      signatureData,
      txNonce: BigInt(txNonce),
      txMaxPriorityFee: parsed.maxPriorityFeePerGas ?? 0n,
      txMaxFee: parsed.maxFeePerGas ?? 0n,
      txGasLimit: parsed.gas ?? 0n,
      input0: {
        amount: note0.amount,
        randomness: note0.randomness,
        leafIndex: note0.leafIndex,
        siblings: proof0.siblings,
      },
      input1: {
        amount: note1.amount,
        randomness: note1.randomness,
        leafIndex: note1.leafIndex,
        siblings: proof1.siblings,
      },
      changeAmount,
      changeRandomness,
      nullifierKey: session.keys.nullifierKey,
    };

    console.log('[Withdraw] Generating proof...');
    const { proof } = await generateWithdrawProofWorker(circuitInputs);

    // Update status to submitting
    this.pendingTxs.set(virtualHash, { status: 'submitting', reservedNotes: notes });

    // Encrypt change note
    const encryptedChange = changeAmount > 0n
      ? await encryptNoteData(session.keys.encryptionPubKey, {
          owner: changeOwner,
          amount: changeAmount,
          randomness: changeRandomness,
        })
      : '0x' as Hex;

    const l1Hash = await submitWithdraw(
      proof,
      merkleRoot,
      [nullifier0, nullifier1],
      changeCommitment,
      intentNullifier,
      withdrawRecipient,
      withdrawAmount,
      encryptedChange
    );
    const receipt = await waitForReceipt(l1Hash);

    // Check if L1 tx succeeded before updating local state
    if (receipt.status !== 'success') {
      throw new Error(`L1 transaction reverted: ${l1Hash}`);
    }

    // Mark notes spent IMMEDIATELY after L1 success, before parsing
    // This prevents note corruption if parsing fails (notes are spent on L1 regardless)
    session.noteStore.markSpent(note0.commitment);
    session.noteStore.markSpent(note1.commitment);

    // Contract always inserts changeCommitment (since it's always non-zero hash)
    const leafIndex = parseWithdrawLeafIndex(receipt);

    console.log(`[L1] Withdraw confirmed: ${l1Hash}`);

    // Mark L1 tx as confirmed immediately (so getTransactionReceipt works)
    this.txHashMapping.set(virtualHash, l1Hash);
    this.pendingTxs.set(virtualHash, { status: 'complete', l1Hash });

    // Update merkle tree locally (contract always inserts since commitment is non-zero hash)
    this.merkleTree.insert(changeCommitment);
    this.spentNullifiers.add(nullifier0);
    this.spentNullifiers.add(nullifier1);
    this.usedIntents.add(intentNullifier);

    // Only add note to store if there's actual change value
    if (changeAmount > 0n) {
      const changeNote = createNoteWithRandomness(changeAmount, changeOwner, changeRandomness, session.keys.nullifierKeyHash, leafIndex);
      session.noteStore.addNote(changeNote);
    }

    // Record transaction
    session.transactions.push({
      type: 'withdraw',
      virtualHash,
      l1Hash,
      amount: withdrawAmount,
      recipient: withdrawRecipient,
      timestamp: Date.now(),
    });

    console.log(`[Withdraw] Complete! l1Hash=${l1Hash}`);
    return l1Hash;
  }

  /**
   * Execute withdrawal with single note (async version - updates status, returns l1Hash)
   */
  private async executeWithdrawSingleNoteAsync(
    parsed: ReturnType<typeof parseTransaction>,
    session: UserSession,
    senderAddress: Hex,
    signedTx: Hex,
    note: Note,
    recoveredPubKey: Hex,
    withdrawAmount: bigint,
    withdrawRecipient: Hex,
    virtualHash: string
  ): Promise<string> {
    console.log('[Withdraw] Using single-note with phantom input');

    const changeAmount = note.amount - withdrawAmount;
    const txNonce = parsed.nonce ?? 0;

    // Real note (input 0)
    const proof0 = this.merkleTree.generateProof(note.leafIndex);
    const nullifier0 = computeNullifier(note.commitment, session.keys.nullifierKey);

    // Phantom note (input 1)
    const phantomRandomness = BigInt(keccak256(concat([signedTx, '0xff']))) % FIELD_SIZE;
    const phantomCommitment = computeCommitment(0n, BigInt(senderAddress), phantomRandomness, session.keys.nullifierKeyHash);
    const nullifier1 = computeNullifier(phantomCommitment, session.keys.nullifierKey);

    // Change commitment
    const changeOwner = BigInt(senderAddress);
    const changeRandomness = BigInt(keccak256(concat([signedTx, '0x02']))) % FIELD_SIZE;
    // Always compute commitment (even for zero change) - circuit expects hash_4
    const changeCommitment = computeCommitment(changeAmount, changeOwner, changeRandomness, session.keys.nullifierKeyHash);

    // Intent nullifier = poseidon(nullifierKey, chainId, nonce)
    const intentNullifier = computeIntentNullifier(
      session.keys.nullifierKey,
      VIRTUAL_CHAIN_ID,
      BigInt(txNonce)
    );

    const signatureData = extractSignatureFromTx(
      parsed.r!,
      parsed.s!,
      recoveredPubKey
    );

    const merkleRoot = this.merkleTree.getRoot();

    const circuitInputs: WithdrawCircuitInputs = {
      merkleRoot,
      nullifier0,
      nullifier1,
      changeCommitment,
      intentNullifier,
      withdrawRecipient: BigInt(withdrawRecipient),
      withdrawAmount,
      signatureData,
      txNonce: BigInt(txNonce),
      txMaxPriorityFee: parsed.maxPriorityFeePerGas ?? 0n,
      txMaxFee: parsed.maxFeePerGas ?? 0n,
      txGasLimit: parsed.gas ?? 0n,
      input0: {
        amount: note.amount,
        randomness: note.randomness,
        leafIndex: note.leafIndex,
        siblings: proof0.siblings,
      },
      input1: {
        amount: 0n,
        randomness: phantomRandomness,
        leafIndex: 0,
        siblings: Array(TREE_DEPTH).fill(0n),
      },
      changeAmount,
      changeRandomness,
      nullifierKey: session.keys.nullifierKey,
    };

    console.log('[Withdraw] Generating proof (single-note)...');
    const { proof } = await generateWithdrawProofWorker(circuitInputs);

    // Update status to submitting
    this.pendingTxs.set(virtualHash, { status: 'submitting', reservedNotes: [note] });

    // Encrypt change note
    const encryptedChange = changeAmount > 0n
      ? await encryptNoteData(session.keys.encryptionPubKey, {
          owner: changeOwner,
          amount: changeAmount,
          randomness: changeRandomness,
        })
      : '0x' as Hex;

    const l1Hash = await submitWithdraw(
      proof,
      merkleRoot,
      [nullifier0, nullifier1],
      changeCommitment,
      intentNullifier,
      withdrawRecipient,
      withdrawAmount,
      encryptedChange
    );
    const receipt = await waitForReceipt(l1Hash);

    // Check if L1 tx succeeded before updating local state
    if (receipt.status !== 'success') {
      throw new Error(`L1 transaction reverted: ${l1Hash}`);
    }

    // Mark note spent IMMEDIATELY after L1 success, before parsing
    // This prevents note corruption if parsing fails (note is spent on L1 regardless)
    session.noteStore.markSpent(note.commitment);

    // Contract always inserts changeCommitment (since it's always non-zero hash)
    const leafIndex = parseWithdrawLeafIndex(receipt);

    console.log(`[L1] Withdraw confirmed: ${l1Hash}`);

    // Mark L1 tx as confirmed immediately (so getTransactionReceipt works)
    this.txHashMapping.set(virtualHash, l1Hash);
    this.pendingTxs.set(virtualHash, { status: 'complete', l1Hash });

    // Update merkle tree locally (contract always inserts since commitment is non-zero hash)
    this.merkleTree.insert(changeCommitment);
    this.spentNullifiers.add(nullifier0);
    this.spentNullifiers.add(nullifier1);
    this.usedIntents.add(intentNullifier);

    // Only add note to store if there's actual change value
    if (changeAmount > 0n) {
      const changeNote = createNoteWithRandomness(changeAmount, changeOwner, changeRandomness, session.keys.nullifierKeyHash, leafIndex);
      session.noteStore.addNote(changeNote);
    }

    // Record transaction
    session.transactions.push({
      type: 'withdraw',
      virtualHash,
      l1Hash,
      amount: withdrawAmount,
      recipient: withdrawRecipient,
      timestamp: Date.now(),
    });

    console.log(`[Withdraw] Complete (single-note)! l1Hash=${l1Hash}`);
    return l1Hash;
  }

  // ==================== Receipt Methods ====================

  private async getTransactionReceipt(txHash: string): Promise<unknown> {
    const l1Hash = this.txHashMapping.get(txHash);
    if (!l1Hash) {
      return null;
    }

    try {
      const receipt = await l1Public.getTransactionReceipt({ hash: l1Hash as Hex });
      if (!receipt) return null;

      // Convert BigInts to hex strings for JSON serialization
      return {
        transactionHash: txHash,
        blockHash: receipt.blockHash,
        blockNumber: toHex(receipt.blockNumber),
        contractAddress: receipt.contractAddress,
        cumulativeGasUsed: toHex(receipt.cumulativeGasUsed),
        from: receipt.from,
        gasUsed: toHex(receipt.gasUsed),
        logs: receipt.logs.map(log => ({
          ...log,
          blockNumber: toHex(log.blockNumber),
          logIndex: toHex(log.logIndex),
          transactionIndex: toHex(log.transactionIndex),
        })),
        logsBloom: receipt.logsBloom,
        status: receipt.status === 'success' ? '0x1' : '0x0',
        to: receipt.to,
        transactionIndex: toHex(receipt.transactionIndex),
        type: toHex(receipt.type === 'eip1559' ? 2 : 0),
      };
    } catch {
      return null;
    }
  }

  private async getTransactionByHash(txHash: string): Promise<unknown> {
    const l1Hash = this.txHashMapping.get(txHash);
    if (l1Hash) {
      try {
        const tx = await l1Public.getTransaction({ hash: l1Hash as Hex });
        if (!tx) return null;

        // Convert BigInts to hex strings for JSON serialization
        return {
          hash: txHash,
          blockHash: tx.blockHash,
          blockNumber: tx.blockNumber ? toHex(tx.blockNumber) : null,
          from: tx.from,
          gas: toHex(tx.gas),
          gasPrice: tx.gasPrice ? toHex(tx.gasPrice) : '0x0',
          input: tx.input,
          nonce: toHex(tx.nonce),
          to: tx.to,
          transactionIndex: tx.transactionIndex !== null ? toHex(tx.transactionIndex) : null,
          value: toHex(tx.value),
          type: toHex(tx.type === 'eip1559' ? 2 : 0),
          chainId: tx.chainId ? toHex(tx.chainId) : null,
        };
      } catch {
        return null;
      }
    }

    // Return synthetic pending tx if in-flight (prevents MetaMask "dropped" status)
    const pending = this.pendingTxs.get(txHash);
    if (pending && (pending.status === 'proving' || pending.status === 'submitting')) {
      return {
        hash: txHash,
        blockHash: null,
        blockNumber: null,
        from: null,
        to: null,
        value: '0x0',
        nonce: '0x0',
        gas: '0x0',
        gasPrice: '0x0',
        input: '0x',
        transactionIndex: null,
        type: '0x2',
        chainId: toHex(VIRTUAL_CHAIN_ID),
      };
    }

    return null;
  }

  // ==================== Custom Methods ====================

  private async registerViewingKey(address: string, signature: string): Promise<boolean> {
    const normalizedAddress = address.toLowerCase();

    // Verify signature matches expected message
    const message = `Register viewing key for Facet Private\nAddress: ${address}`;

    const recoveredAddress = await recoverMessageAddress({
      message,
      signature: signature as Hex,
    });

    if (recoveredAddress.toLowerCase() !== normalizedAddress) {
      throw new Error(`Invalid signature. Expected address ${address}, got ${recoveredAddress}`);
    }

    // Derive keys from signature (deterministic)
    const viewingKeyHash = keccak256(signature as Hex);
    const nullifierKeySeed = keccak256(concat([signature as Hex, '0x01']));

    const viewingKey = hexToBytes(viewingKeyHash);
    const nullifierKey = BigInt(nullifierKeySeed) % FIELD_SIZE;
    // Compute nullifierKeyHash = poseidon(nullifierKey, DOMAIN) for registry storage
    const nullifierKeyHash = computeNullifierKeyHash(nullifierKey);

    // Derive encryption keypair (for ECIES)
    const { privateKey: encryptionPrivKey, publicKey: encryptionPubKey } = deriveEncryptionKeypair(signature as Hex);

    const sessionKeys: SessionKeys = {
      address: normalizedAddress,
      viewingKey,
      nullifierKey,
      nullifierKeyHash,
      encryptionPubKey,
      encryptionPrivKey, // Store private key for decryption
    };

    const noteStore = new NoteStore(sessionKeys);

    // Register encryption public key and nullifier key hash in Registry if not already registered
    const isRegistered = await isUserRegistered(normalizedAddress as Hex);
    if (!isRegistered) {
      console.log(`[RegisterViewingKey] Registering encryption key and nullifierKeyHash in Registry...`);
      const pkHex = pubKeyToHex(encryptionPubKey);
      const regHash = await registerEncryptionKey(normalizedAddress as Hex, pkHex, nullifierKeyHash);
      await waitForReceipt(regHash);
    }

    // Recover notes from chain events
    const userOwner = BigInt(normalizedAddress);
    let recoveredCount = 0;

    // 1. Scan deposit events and try to decrypt
    const { getDepositEvents, getTransferEvents, getWithdrawEvents } = await import('./sync.js');
    const deposits = await getDepositEvents();
    const recoveredTransactions: TransactionRecord[] = [];

    for (const dep of deposits) {
      if (dep.encryptedNote && dep.encryptedNote.length > 2) {
        // Try to decrypt with our private key
        const noteData = decryptNoteData(encryptionPrivKey, dep.encryptedNote);
        if (noteData && noteData.owner === userOwner) {
          // Verify commitment (uses our nullifierKeyHash)
          const expectedCommitment = computeCommitment(noteData.amount, noteData.owner, noteData.randomness, nullifierKeyHash);
          if (expectedCommitment === dep.commitment) {
            const nullifier = computeNullifier(dep.commitment, nullifierKey);
            if (!this.spentNullifiers.has(nullifier)) {
              const note = createNoteWithRandomness(noteData.amount, noteData.owner, noteData.randomness, nullifierKeyHash, dep.leafIndex);
              noteStore.addNote(note);
              recoveredCount++;
            }
            // Record deposit transaction (regardless of spent status)
            recoveredTransactions.push({
              type: 'deposit',
              virtualHash: dep.txHash,
              l1Hash: dep.txHash,
              amount: noteData.amount,
              timestamp: Number(dep.blockNumber),
            });
          }
        }
      }
    }

    // 2. Scan transfer events for received notes
    const transfers = await getTransferEvents();

    for (const xfer of transfers) {
      // Try to decrypt both notes first to detect self-sends
      const decryptedNotes: Array<{ index: number; amount: bigint; randomness: bigint; commitment: bigint; leafIndex: number }> = [];

      for (let i = 0; i < 2; i++) {
        const encNote = xfer.encryptedNotes[i];
        if (encNote && encNote.length > 2) {
          const noteData = decryptNoteData(encryptionPrivKey, encNote);
          if (noteData && noteData.owner === userOwner) {
            const expectedCommitment = computeCommitment(noteData.amount, noteData.owner, noteData.randomness, nullifierKeyHash);
            if (expectedCommitment === xfer.commitments[i]) {
              decryptedNotes.push({
                index: i,
                amount: noteData.amount,
                randomness: noteData.randomness,
                commitment: xfer.commitments[i],
                leafIndex: xfer.leafIndices[i],
              });
            }
          }
        }
      }

      // Add unspent notes to store
      for (const dn of decryptedNotes) {
        const nullifier = computeNullifier(dn.commitment, nullifierKey);
        if (!this.spentNullifiers.has(nullifier)) {
          const note = createNoteWithRandomness(dn.amount, userOwner, dn.randomness, nullifierKeyHash, dn.leafIndex);
          noteStore.addNote(note);
          recoveredCount++;
        }
      }

      // Record transaction
      if (decryptedNotes.length > 0) {
        const isSelfSend = decryptedNotes.length === 2;
        // For display: use sent amount (index 0) for self-send, otherwise use what we have
        const primaryNote = decryptedNotes.find(n => n.index === 0) || decryptedNotes[0];
        const isSent = !isSelfSend && decryptedNotes[0].index === 1;

        recoveredTransactions.push({
          type: isSelfSend ? 'transfer_self' : (isSent ? 'transfer_out' : 'transfer_in'),
          virtualHash: xfer.txHash,
          l1Hash: xfer.txHash,
          amount: primaryNote.amount,
          timestamp: Number(xfer.blockNumber),
        });
      }
    }

    // 3. Scan withdrawal events for change notes
    const withdrawals = await getWithdrawEvents();

    for (const w of withdrawals) {
      // Check if this withdrawal is ours (either by change note or recipient address)
      let isOurs = false;
      let withdrawAmount = w.amount;

      if (w.encryptedChange && w.encryptedChange.length > 2 && w.changeCommitment !== 0n) {
        const noteData = decryptNoteData(encryptionPrivKey, w.encryptedChange);
        if (noteData && noteData.owner === userOwner) {
          isOurs = true;
          const expectedCommitment = computeCommitment(noteData.amount, noteData.owner, noteData.randomness, nullifierKeyHash);
          if (expectedCommitment === w.changeCommitment) {
            const nullifier = computeNullifier(w.changeCommitment, nullifierKey);
            if (!this.spentNullifiers.has(nullifier)) {
              const note = createNoteWithRandomness(noteData.amount, noteData.owner, noteData.randomness, nullifierKeyHash, w.changeLeafIndex);
              noteStore.addNote(note);
              recoveredCount++;
            }
          }
        }
      }

      // Also check if recipient matches
      if (w.recipient.toLowerCase() === normalizedAddress) {
        isOurs = true;
      }

      if (isOurs) {
        recoveredTransactions.push({
          type: 'withdraw',
          virtualHash: w.txHash,
          l1Hash: w.txHash,
          amount: withdrawAmount,
          recipient: w.recipient,
          timestamp: Number(w.blockNumber),
        });
      }
    }

    // Sort transactions by timestamp (block number)
    recoveredTransactions.sort((a, b) => a.timestamp - b.timestamp);

    this.sessions.set(normalizedAddress, {
      address: normalizedAddress,
      keys: sessionKeys,
      noteStore,
      transactions: recoveredTransactions,
      txInFlight: false,
    });

    // Log starting nonce (computed from usedIntents)
    const startingNonce = this.recoverNonce(sessionKeys.nullifierKey);
    console.log(`[RegisterViewingKey] ${normalizedAddress}, recovered ${recoveredCount} notes, starting nonce ${startingNonce}`);
    return true;
  }

  // ==================== L1 Deposit Support ====================

  /**
   * Encrypt note data for a user (for L1 deposits)
   * Used by frontend to encrypt note data before submitting deposit tx
   */
  private async encryptNoteDataForUser(
    address: string,
    noteData: { owner: string; amount: string; randomness: string }
  ): Promise<Hex> {
    const normalizedAddress = address.toLowerCase();
    const session = this.sessions.get(normalizedAddress);
    if (!session) {
      throw new Error('Session not found. Register viewing key first.');
    }

    const owner = BigInt(noteData.owner);
    const amount = BigInt(noteData.amount);
    const randomness = BigInt(noteData.randomness);

    const encrypted = await encryptNoteData(session.keys.encryptionPubKey, {
      owner,
      amount,
      randomness,
    });

    return encrypted;
  }

  /**
   * Get user's transaction history
   */
  private getTransactions(address: string): unknown {
    const session = this.sessions.get(address.toLowerCase());
    if (!session) {
      return [];
    }
    const result = session.transactions.map((tx) => ({
      type: tx.type,
      virtualHash: tx.virtualHash,
      l1Hash: tx.l1Hash,
      amount: toHex(tx.amount),
      recipient: tx.recipient,
      timestamp: tx.timestamp,
    }));
    // Debug: log withdraw l1Hash values
    for (const tx of result) {
      if (tx.type === 'withdraw') {
        console.log(`[getTransactions] withdraw l1Hash=${tx.l1Hash}`);
      }
    }
    return result;
  }

  /**
   * Force refresh session state from chain
   */
  private async refreshSession(address: string): Promise<boolean> {
    const normalizedAddress = address.toLowerCase();
    const session = this.sessions.get(normalizedAddress);
    if (!session) {
      throw new Error('Session not found. Register viewing key first.');
    }

    console.log(`[Refresh] Syncing state for ${normalizedAddress}...`);

    // Sync global state from chain
    await syncFromChain(this.merkleTree, this.spentNullifiers, this.usedIntents);

    // Re-scan events for this user's notes
    const { getDepositEvents, getTransferEvents, getWithdrawEvents } = await import('./sync.js');
    const userOwner = BigInt(normalizedAddress);
    const encryptionPrivKey = session.keys.encryptionPrivKey;

    if (!encryptionPrivKey) {
      throw new Error('Encryption key not available');
    }

    // Clear and rebuild note store
    const newNoteStore = new NoteStore(session.keys);
    const newTransactions: TransactionRecord[] = [];

    // Scan deposits
    const deposits = await getDepositEvents();
    for (const dep of deposits) {
      if (dep.encryptedNote && dep.encryptedNote.length > 2) {
        const noteData = decryptNoteData(encryptionPrivKey, dep.encryptedNote);
        if (noteData && noteData.owner === userOwner) {
          const expectedCommitment = computeCommitment(noteData.amount, noteData.owner, noteData.randomness, session.keys.nullifierKeyHash);
          if (expectedCommitment === dep.commitment) {
            const nullifier = computeNullifier(dep.commitment, session.keys.nullifierKey);
            if (!this.spentNullifiers.has(nullifier)) {
              const note = createNoteWithRandomness(noteData.amount, noteData.owner, noteData.randomness, session.keys.nullifierKeyHash, dep.leafIndex);
              newNoteStore.addNote(note);
            }
            newTransactions.push({
              type: 'deposit',
              virtualHash: dep.txHash,
              l1Hash: dep.txHash,
              amount: noteData.amount,
              timestamp: Number(dep.blockNumber),
            });
          }
        }
      }
    }

    // Scan transfers
    const transfers = await getTransferEvents();
    for (const xfer of transfers) {
      // Try to decrypt both notes first to detect self-sends
      const decryptedNotes: Array<{ index: number; amount: bigint; randomness: bigint; commitment: bigint; leafIndex: number }> = [];

      for (let i = 0; i < 2; i++) {
        const encNote = xfer.encryptedNotes[i];
        if (encNote && encNote.length > 2) {
          const noteData = decryptNoteData(encryptionPrivKey, encNote);
          if (noteData && noteData.owner === userOwner) {
            const expectedCommitment = computeCommitment(noteData.amount, noteData.owner, noteData.randomness, session.keys.nullifierKeyHash);
            if (expectedCommitment === xfer.commitments[i]) {
              decryptedNotes.push({
                index: i,
                amount: noteData.amount,
                randomness: noteData.randomness,
                commitment: xfer.commitments[i],
                leafIndex: xfer.leafIndices[i],
              });
            }
          }
        }
      }

      // Add unspent notes to store
      for (const dn of decryptedNotes) {
        const nullifier = computeNullifier(dn.commitment, session.keys.nullifierKey);
        if (!this.spentNullifiers.has(nullifier)) {
          const note = createNoteWithRandomness(dn.amount, userOwner, dn.randomness, session.keys.nullifierKeyHash, dn.leafIndex);
          newNoteStore.addNote(note);
        }
      }

      // Record transaction
      if (decryptedNotes.length > 0) {
        const isSelfSend = decryptedNotes.length === 2;
        const primaryNote = decryptedNotes.find(n => n.index === 0) || decryptedNotes[0];
        const isSent = !isSelfSend && decryptedNotes[0].index === 1;

        newTransactions.push({
          type: isSelfSend ? 'transfer_self' : (isSent ? 'transfer_out' : 'transfer_in'),
          virtualHash: xfer.txHash,
          l1Hash: xfer.txHash,
          amount: primaryNote.amount,
          timestamp: Number(xfer.blockNumber),
        });
      }
    }

    // Scan withdrawals
    const withdrawals = await getWithdrawEvents();
    for (const w of withdrawals) {
      let isOurs = false;
      if (w.encryptedChange && w.encryptedChange.length > 2 && w.changeCommitment !== 0n) {
        const noteData = decryptNoteData(encryptionPrivKey, w.encryptedChange);
        if (noteData && noteData.owner === userOwner) {
          isOurs = true;
          const expectedCommitment = computeCommitment(noteData.amount, noteData.owner, noteData.randomness, session.keys.nullifierKeyHash);
          if (expectedCommitment === w.changeCommitment) {
            const nullifier = computeNullifier(w.changeCommitment, session.keys.nullifierKey);
            if (!this.spentNullifiers.has(nullifier)) {
              const note = createNoteWithRandomness(noteData.amount, noteData.owner, noteData.randomness, session.keys.nullifierKeyHash, w.changeLeafIndex);
              newNoteStore.addNote(note);
            }
          }
        }
      }
      if (w.recipient.toLowerCase() === normalizedAddress) {
        isOurs = true;
      }
      if (isOurs) {
        newTransactions.push({
          type: 'withdraw',
          virtualHash: w.txHash,
          l1Hash: w.txHash,
          amount: w.amount,
          recipient: w.recipient,
          timestamp: Number(w.blockNumber),
        });
      }
    }

    // Sort transactions and update session
    newTransactions.sort((a, b) => a.timestamp - b.timestamp);
    session.noteStore = newNoteStore;
    session.transactions = newTransactions;

    console.log(`[Refresh] Complete! ${newNoteStore.getAllNotes().length} notes, ${newTransactions.length} transactions`);
    return true;
  }

  /**
   * Get user's encryption public key (for deposits)
   */
  private async getEncryptionKey(address: string): Promise<Hex | null> {
    const normalizedAddress = address.toLowerCase();
    const session = this.sessions.get(normalizedAddress);
    if (session) {
      // Return from session if available
      return pubKeyToHex(session.keys.encryptionPubKey);
    }

    // Otherwise try to get from registry
    return getEncryptionKey(normalizedAddress as Hex);
  }

  /**
   * Get user's nullifier key hash (for deposits to others)
   */
  private async getNullifierKeyHashRpc(address: string): Promise<Hex> {
    const normalizedAddress = address.toLowerCase();
    const session = this.sessions.get(normalizedAddress);
    if (session) {
      // Return from session if available
      return toHex(session.keys.nullifierKeyHash);
    }

    // Otherwise get from registry
    const hash = await getRegistryNullifierKeyHash(normalizedAddress as Hex);
    return toHex(hash);
  }

  /**
   * Watch for a deposit transaction and sync notes
   * Called after user submits deposit tx on L1
   */
  private async watchForDeposit(address: string, txHash: string): Promise<boolean> {
    const normalizedAddress = address.toLowerCase();
    console.log(`[WatchForDeposit] ${normalizedAddress} watching for tx ${txHash}`);

    // Wait for receipt
    const receipt = await waitForReceipt(txHash as Hex);
    console.log(`[WatchForDeposit] Deposit confirmed in block ${receipt.blockNumber}`);

    // Sync merkle tree from chain to include new deposit
    await syncFromChain(this.merkleTree, this.spentNullifiers, this.usedIntents);

    // If user has a session, recover their notes
    const session = this.sessions.get(normalizedAddress);
    if (session && session.keys.encryptionPrivKey) {
      // Re-scan deposit events to pick up the new note
      const { getDepositEvents } = await import('./sync.js');
      const deposits = await getDepositEvents();
      const encryptionPrivKey = session.keys.encryptionPrivKey;
      const userOwner = BigInt(normalizedAddress);

      for (const dep of deposits) {
        if (dep.encryptedNote && dep.encryptedNote.length > 2) {
          const noteData = decryptNoteData(encryptionPrivKey, dep.encryptedNote);
          if (noteData && noteData.owner === userOwner) {
            const expectedCommitment = computeCommitment(noteData.amount, noteData.owner, noteData.randomness, session.keys.nullifierKeyHash);
            if (expectedCommitment === dep.commitment) {
              // Check if we already have this note
              const existingNotes = session.noteStore.getAllNotes();
              const alreadyHave = existingNotes.some(n => n.commitment === dep.commitment);
              if (!alreadyHave) {
                const nullifier = computeNullifier(dep.commitment, session.keys.nullifierKey);
                if (!this.spentNullifiers.has(nullifier)) {
                  const note = createNoteWithRandomness(noteData.amount, noteData.owner, noteData.randomness, session.keys.nullifierKeyHash, dep.leafIndex);
                  session.noteStore.addNote(note);
                  console.log(`[WatchForDeposit] Added note: ${noteData.amount} wei`);

                  // Record deposit transaction
                  session.transactions.push({
                    type: 'deposit',
                    virtualHash: txHash,
                    l1Hash: txHash,
                    amount: noteData.amount,
                    timestamp: Date.now(),
                  });
                }
              }
            }
          }
        }
      }
    }

    return true;
  }

  // ==================== Server Methods ====================

  async start(): Promise<void> {
    await this.initialize();
    await this.fastify.listen({ port: RPC_PORT, host: '0.0.0.0' });
    console.log(`[RpcAdapter] Listening on port ${RPC_PORT}`);
    console.log(`[RpcAdapter] Virtual Chain ID: ${VIRTUAL_CHAIN_ID}`);
    console.log(`[RpcAdapter] Privacy Pool: ${CONTRACTS.privacyPool}`);
    console.log(`[RpcAdapter] Relayer: ${getRelayerAddress()}`);
  }

  async stop(): Promise<void> {
    await this.fastify.close();
  }
}
