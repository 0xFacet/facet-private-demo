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
import { initPoseidon } from './crypto/poseidon.js';
import {
  computeCommitment,
  computeNullifier,
  computePhantomNullifier,
  computeNullifierKeyHash,
  computeIntentNullifier,
  deriveEncSeed,
  decryptSelfNote,
  tryDecryptNoteWithCommitmentAsync,
  encryptNoteEcdhAsync,
  encryptNoteSelfAsync,
  ciphertextHash10,
  ciphertextHash5,
  type Cipher5,
  type Point,
  type DecryptedNote,
  FIELD_SIZE as EMBEDDED_FIELD_SIZE,
} from './crypto/embedded-curve.js';
import {
  initGrumpkin,
  scalarMul as grumpkinScalarMul,
  fixedBaseMul as grumpkinFixedBaseMul,
  verifyGrumpkin,
} from './crypto/grumpkin.js';
import {
  l1Public,
  submitTransfer,
  submitWithdraw,
  waitForReceipt,
  getRelayerAddress,
  getEncryptionKey,
  getNullifierKeyHash as getRegistryNullifierKeyHash,
  isUserRegistered,
  getRegistryEntry,
  getRegistryRoot,
  parseTransferLeafIndices,
  parseWithdrawLeafIndex,
  registerUserOnL1,
} from './l1.js';
import { syncFromChain, needsRefresh } from './sync.js';
import { RegistryTree, type RegistryProof as RegistryTreeProof } from './registry-tree.js';
import { syncRegistryFromChain, registryNeedsRefresh } from './registry-sync.js';
import {
  generateTransferProofWorker,
  generateWithdrawProofWorker,
  extractSignatureFromTx,
  type TransferCircuitInputs,
  type WithdrawCircuitInputs,
} from './proof.js';

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
  private merkleTree!: MerkleTree;  // Initialized in initialize() after Poseidon
  private registryTree!: RegistryTree;  // Initialized in initialize() after Poseidon
  private spentNullifiers: Set<bigint> = new Set();
  private usedIntents: Set<bigint> = new Set();
  private txHashMapping: Map<string, string> = new Map(); // virtual -> L1
  private inFlightTx: Map<string, Promise<string>> = new Map(); // signed tx -> pending result
  private pendingTxs: Map<string, PendingTransaction> = new Map(); // virtualHash -> status
  private initialized = false;

  constructor() {
    // Trees are created in initialize() after Poseidon is initialized
    // (MerkleTree/RegistryTree constructors call poseidon2 to compute zeros)
  }

  /**
   * Initialize adapter - sync state from chain
   */
  async initialize(): Promise<void> {
    if (this.initialized) return;

    console.log('[RpcAdapter] Initializing...');

    // Initialize Poseidon hash function FIRST
    // (MerkleTree/RegistryTree constructors call poseidon2 to compute zeros)
    await initPoseidon();

    // Initialize Grumpkin curve operations (bb.js)
    console.log('[RpcAdapter] Initializing Grumpkin curve...');
    await initGrumpkin();
    const grumpkinOk = await verifyGrumpkin();
    if (!grumpkinOk) {
      throw new Error('Grumpkin curve verification failed - generator point mismatch');
    }
    console.log('[RpcAdapter] Grumpkin curve initialized');

    // Create trees now that Poseidon is initialized
    this.merkleTree = new MerkleTree();
    this.registryTree = new RegistryTree();

    // Sync state from chain (pool and registry in parallel)
    await Promise.all([
      syncFromChain(this.merkleTree, this.spentNullifiers, this.usedIntents),
      syncRegistryFromChain(this.registryTree),
    ]);

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
        return this.getEncryptionKeyRpc(params[0] as string);

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

      case 'privacy_getRegistrationData':
        return this.getRegistrationData(params[0] as string);

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

    // Check sender is registered on-chain (required for withdraw circuit)
    // Registration should happen automatically during session creation, but verify here
    const senderRegistered = await isUserRegistered(normalizedSender as Hex);
    if (!senderRegistered) {
      throw new Error(
        'Sender not registered on-chain. Please re-register your viewing key to trigger auto-registration.'
      );
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
      if (await registryNeedsRefresh(this.registryTree)) {
        console.log('[RPC] Registry refresh needed, syncing...');
        await syncRegistryFromChain(this.registryTree);
      }

      // Quick validation (sets txInFlight inside to prevent race)
      const validated = await this.validateTransaction(signedTx);

      // Reserve notes to prevent double-spend
      validated.session.noteStore.reserveNotes(validated.selectedNotes);

      // Mark as pending
      this.pendingTxs.set(virtualHash, { status: 'proving' });

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

    // Get recipient's registry proof from local tree
    const recipientProof = this.registryTree.generateProof(recipient);
    if (!recipientProof) {
      throw new Error(`Recipient ${recipient} is not registered. They must register first.`);
    }

    const totalInput = notes[0].amount + notes[1].amount;
    const change = totalInput - value;

    // Generate merkle proofs for input notes
    const proof0 = this.merkleTree.generateProof(notes[0].leafIndex);
    const proof1 = this.merkleTree.generateProof(notes[1].leafIndex);

    // Compute nullifiers (new format: hash(NULLIFIER_DOMAIN, nk, leaf_index, randomness))
    const nullifier0 = computeNullifier(session.keys.nullifierKey, notes[0].leafIndex, notes[0].randomness);
    const nullifier1 = computeNullifier(session.keys.nullifierKey, notes[1].leafIndex, notes[1].randomness);

    // Output 0: to recipient (uses recipient's nkHash from registry proof)
    const output0Owner = BigInt(recipient);
    const output0Randomness = BigInt(keccak256(concat([signedTx, '0x00']))) % FIELD_SIZE;
    const output0Commitment = computeCommitment(value, output0Owner, output0Randomness, recipientProof.nkHash);

    // Output 1: change back to sender
    const output1Owner = BigInt(senderAddress);
    const output1Randomness = BigInt(keccak256(concat([signedTx, '0x01']))) % FIELD_SIZE;
    const output1Commitment = computeCommitment(change, output1Owner, output1Randomness, session.keys.nullifierKeyHash);

    // Intent nullifier
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

    // Get roots for circuit
    const merkleRoot = this.merkleTree.getRoot();
    const registryRoot = this.registryTree.getRoot();

    // Compute encrypted notes matching circuit algorithm (MUST be before proof generation)
    // The circuit computes the same ciphertext and verifies ciphertextHash matches
    const encSeed = deriveEncSeed(session.keys.nullifierKey);
    const recipientPubkey: Point = { x: recipientProof.pubkeyX, y: recipientProof.pubkeyY };

    // Encrypt output 0: to recipient (ECDH encryption)
    const encryptedNote0: Cipher5 = await encryptNoteEcdhAsync(
      encSeed,
      recipientPubkey,
      value,
      output0Owner,
      output0Randomness,
      BigInt(txNonce),
      0n,  // outputIndex = 0
      grumpkinFixedBaseMul,
      grumpkinScalarMul
    );

    // Encrypt output 1: change to self (self-encryption)
    const encryptedNote1: Cipher5 = await encryptNoteSelfAsync(
      encSeed,
      change,
      output1Owner,
      output1Randomness,
      BigInt(txNonce),
      grumpkinFixedBaseMul
    );

    // Compute ciphertext hash (matching circuit and contract)
    const ciphertextHash = ciphertextHash10(encryptedNote0, encryptedNote1);

    // Build circuit inputs
    const circuitInputs: TransferCircuitInputs = {
      merkleRoot,
      nullifier0,
      nullifier1,
      outputCommitment0: output0Commitment,
      outputCommitment1: output1Commitment,
      intentNullifier,
      registryRoot,
      ciphertextHash, // Will be computed by circuit
      signatureData,
      txNonce: BigInt(txNonce),
      txMaxPriorityFee: parsed.maxPriorityFeePerGas ?? 0n,
      txMaxFee: parsed.maxFeePerGas ?? 0n,
      txGasLimit: parsed.gas ?? 0n,
      txTo: BigInt(recipient),
      txValue: value,
      input0: {
        amount: notes[0].amount,
        owner: notes[0].owner,
        randomness: notes[0].randomness,
        nullifierKeyHash: session.keys.nullifierKeyHash,
        leafIndex: notes[0].leafIndex,
        siblings: proof0.siblings,
      },
      input1: {
        amount: notes[1].amount,
        owner: notes[1].owner,
        randomness: notes[1].randomness,
        nullifierKeyHash: session.keys.nullifierKeyHash,
        leafIndex: notes[1].leafIndex,
        siblings: proof1.siblings,
      },
      output0Amount: value,
      output0Randomness,
      output1Amount: change,
      output1Randomness,
      nullifierKey: session.keys.nullifierKey,
      recipientProof: {
        pubkeyX: recipientProof.pubkeyX,
        pubkeyY: recipientProof.pubkeyY,
        nkHash: recipientProof.nkHash,
        leafIndex: recipientProof.leafIndex,
        siblings: recipientProof.siblings,
      },
    };

    console.log('[Transfer] Generating proof...');
    const { proof, publicInputs } = await generateTransferProofWorker(circuitInputs);

    // Update status to submitting
    this.pendingTxs.set(virtualHash, { status: 'submitting' });

    // Verify ciphertext hash matches what circuit computed (sanity check)
    const proofCiphertextHash = publicInputs[7];
    if (proofCiphertextHash !== ciphertextHash) {
      console.warn(`[Transfer] Ciphertext hash mismatch! Adapter: ${ciphertextHash}, Circuit: ${proofCiphertextHash}`);
      // This would indicate a bug in our encryption matching - log but continue for now
    }

    // Submit to L1 with encrypted notes computed above
    const l1Hash = await submitTransfer(
      proof,
      merkleRoot,
      registryRoot,
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
      const recipientNote = createNoteWithRandomness(value, output0Owner, output0Randomness, recipientProof.nkHash, leafIndex0);
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

    // Get recipient's registry proof from local tree
    const recipientProof = this.registryTree.generateProof(recipient);
    if (!recipientProof) {
      throw new Error(`Recipient ${recipient} is not registered. They must register first.`);
    }

    const change = note.amount - value;

    // Real note (input 0)
    const proof0 = this.merkleTree.generateProof(note.leafIndex);
    const nullifier0 = computeNullifier(session.keys.nullifierKey, note.leafIndex, note.randomness);

    // Phantom note (input 1) - zero amount, uses phantom nullifier domain
    // CRITICAL: Uses tx_nonce binding, not leaf_index/randomness (prevents nullifier poisoning)
    const nullifier1 = computePhantomNullifier(session.keys.nullifierKey, BigInt(txNonce));
    // Phantom randomness still needed for circuit input struct (value doesn't affect nullifier)
    const phantomRandomness = 0n;

    // Output 0: to recipient (uses recipient's nkHash from registry proof)
    const output0Owner = BigInt(recipient);
    const output0Randomness = BigInt(keccak256(concat([signedTx, '0x00']))) % FIELD_SIZE;
    const output0Commitment = computeCommitment(value, output0Owner, output0Randomness, recipientProof.nkHash);

    // Output 1: change back to sender
    const output1Owner = BigInt(senderAddress);
    const output1Randomness = BigInt(keccak256(concat([signedTx, '0x01']))) % FIELD_SIZE;
    const output1Commitment = computeCommitment(change, output1Owner, output1Randomness, session.keys.nullifierKeyHash);

    // Intent nullifier
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

    // Get roots for circuit
    const merkleRoot = this.merkleTree.getRoot();
    const registryRoot = this.registryTree.getRoot();

    // Compute encrypted notes matching circuit algorithm (MUST be before proof generation)
    // The circuit computes the same ciphertext and verifies ciphertextHash matches
    const encSeed = deriveEncSeed(session.keys.nullifierKey);
    const recipientPubkey: Point = { x: recipientProof.pubkeyX, y: recipientProof.pubkeyY };

    // Encrypt output 0: to recipient (ECDH encryption)
    const encryptedNote0: Cipher5 = await encryptNoteEcdhAsync(
      encSeed,
      recipientPubkey,
      value,
      output0Owner,
      output0Randomness,
      BigInt(txNonce),
      0n,  // outputIndex = 0
      grumpkinFixedBaseMul,
      grumpkinScalarMul
    );

    // Encrypt output 1: change to self (self-encryption)
    const encryptedNote1: Cipher5 = await encryptNoteSelfAsync(
      encSeed,
      change,
      output1Owner,
      output1Randomness,
      BigInt(txNonce),
      grumpkinFixedBaseMul
    );

    // Compute ciphertext hash (matching circuit and contract)
    const ciphertextHash = ciphertextHash10(encryptedNote0, encryptedNote1);

    // Build circuit inputs
    const circuitInputs: TransferCircuitInputs = {
      merkleRoot,
      nullifier0,
      nullifier1,
      outputCommitment0: output0Commitment,
      outputCommitment1: output1Commitment,
      intentNullifier,
      registryRoot,
      ciphertextHash,
      signatureData,
      txNonce: BigInt(txNonce),
      txMaxPriorityFee: parsed.maxPriorityFeePerGas ?? 0n,
      txMaxFee: parsed.maxFeePerGas ?? 0n,
      txGasLimit: parsed.gas ?? 0n,
      txTo: BigInt(recipient),
      txValue: value,
      input0: {
        amount: note.amount,
        owner: note.owner,
        randomness: note.randomness,
        nullifierKeyHash: session.keys.nullifierKeyHash,
        leafIndex: note.leafIndex,
        siblings: proof0.siblings,
      },
      input1: {
        amount: 0n,
        owner: BigInt(senderAddress),
        randomness: phantomRandomness,
        nullifierKeyHash: session.keys.nullifierKeyHash,
        leafIndex: 0,
        siblings: Array(TREE_DEPTH).fill(0n),
      },
      output0Amount: value,
      output0Randomness,
      output1Amount: change,
      output1Randomness,
      nullifierKey: session.keys.nullifierKey,
      recipientProof: {
        pubkeyX: recipientProof.pubkeyX,
        pubkeyY: recipientProof.pubkeyY,
        nkHash: recipientProof.nkHash,
        leafIndex: recipientProof.leafIndex,
        siblings: recipientProof.siblings,
      },
    };

    console.log('[Transfer] Generating proof (single-note)...');
    const { proof, publicInputs } = await generateTransferProofWorker(circuitInputs);

    // Update status to submitting
    this.pendingTxs.set(virtualHash, { status: 'submitting' });

    // Submit to L1
    const l1Hash = await submitTransfer(
      proof,
      merkleRoot,
      registryRoot,
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
      const recipientNote = createNoteWithRandomness(value, output0Owner, output0Randomness, recipientProof.nkHash, leafIndex0);
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

    // Get sender's registry proof from local tree
    const senderProof = this.registryTree.generateProof(senderAddress);
    if (!senderProof) {
      throw new Error(`Sender ${senderAddress} is not registered. Must register first.`);
    }

    // Merkle proofs for both notes
    const proof0 = this.merkleTree.generateProof(note0.leafIndex);
    const proof1 = this.merkleTree.generateProof(note1.leafIndex);

    // Nullifiers (new format: hash(NULLIFIER_DOMAIN, nk, leaf_index, randomness))
    const nullifier0 = computeNullifier(session.keys.nullifierKey, note0.leafIndex, note0.randomness);
    const nullifier1 = computeNullifier(session.keys.nullifierKey, note1.leafIndex, note1.randomness);

    // Change commitment
    const changeOwner = BigInt(senderAddress);
    const changeRandomness = BigInt(keccak256(concat([signedTx, '0x02']))) % FIELD_SIZE;
    const changeCommitment = computeCommitment(changeAmount, changeOwner, changeRandomness, session.keys.nullifierKeyHash);

    // Intent nullifier
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

    // Get roots for circuit
    const merkleRoot = this.merkleTree.getRoot();
    const registryRoot = this.registryTree.getRoot();

    // Compute encrypted change note matching circuit algorithm (MUST be before proof generation)
    const encSeed = deriveEncSeed(session.keys.nullifierKey);

    // Encrypt change note to self (self-encryption, no ECDH)
    const encryptedChange: Cipher5 = await encryptNoteSelfAsync(
      encSeed,
      changeAmount,
      changeOwner,
      changeRandomness,
      BigInt(txNonce),
      grumpkinFixedBaseMul
    );

    // Compute ciphertext hash (matching circuit and contract)
    const ciphertextHash = ciphertextHash5(encryptedChange);

    const circuitInputs: WithdrawCircuitInputs = {
      merkleRoot,
      nullifier0,
      nullifier1,
      changeCommitment,
      intentNullifier,
      withdrawRecipient: BigInt(withdrawRecipient),
      withdrawAmount,
      registryRoot,
      ciphertextHash,
      signatureData,
      txNonce: BigInt(txNonce),
      txMaxPriorityFee: parsed.maxPriorityFeePerGas ?? 0n,
      txMaxFee: parsed.maxFeePerGas ?? 0n,
      txGasLimit: parsed.gas ?? 0n,
      input0: {
        amount: note0.amount,
        owner: note0.owner,
        randomness: note0.randomness,
        nullifierKeyHash: session.keys.nullifierKeyHash,
        leafIndex: note0.leafIndex,
        siblings: proof0.siblings,
      },
      input1: {
        amount: note1.amount,
        owner: note1.owner,
        randomness: note1.randomness,
        nullifierKeyHash: session.keys.nullifierKeyHash,
        leafIndex: note1.leafIndex,
        siblings: proof1.siblings,
      },
      changeRandomness,
      nullifierKey: session.keys.nullifierKey,
      senderProof: {
        pubkeyX: senderProof.pubkeyX,
        pubkeyY: senderProof.pubkeyY,
        nkHash: senderProof.nkHash,
        leafIndex: senderProof.leafIndex,
        siblings: senderProof.siblings,
      },
    };

    console.log('[Withdraw] Generating proof...');
    const { proof, publicInputs } = await generateWithdrawProofWorker(circuitInputs);

    // Update status to submitting
    this.pendingTxs.set(virtualHash, { status: 'submitting' });

    // Verify ciphertext hash matches what circuit computed (sanity check)
    const proofCiphertextHash = publicInputs[8]; // Last element for withdraw
    if (proofCiphertextHash !== ciphertextHash) {
      console.warn(`[Withdraw] Ciphertext hash mismatch! Adapter: ${ciphertextHash}, Circuit: ${proofCiphertextHash}`);
    }

    // Submit to L1 with encrypted change note computed above
    const l1Hash = await submitWithdraw(
      proof,
      merkleRoot,
      registryRoot,
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

    // Get sender's registry proof from local tree
    const senderProof = this.registryTree.generateProof(senderAddress);
    if (!senderProof) {
      throw new Error(`Sender ${senderAddress} is not registered. Must register first.`);
    }

    // Real note (input 0)
    const proof0 = this.merkleTree.generateProof(note.leafIndex);
    const nullifier0 = computeNullifier(session.keys.nullifierKey, note.leafIndex, note.randomness);

    // Phantom note (input 1) - zero amount, uses phantom nullifier domain
    // CRITICAL: Uses tx_nonce binding, not leaf_index/randomness (prevents nullifier poisoning)
    const nullifier1 = computePhantomNullifier(session.keys.nullifierKey, BigInt(txNonce));
    // Phantom randomness still needed for circuit input struct (value doesn't affect nullifier)
    const phantomRandomness = 0n;

    // Change commitment
    const changeOwner = BigInt(senderAddress);
    const changeRandomness = BigInt(keccak256(concat([signedTx, '0x02']))) % FIELD_SIZE;
    const changeCommitment = computeCommitment(changeAmount, changeOwner, changeRandomness, session.keys.nullifierKeyHash);

    // Intent nullifier
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

    // Get roots for circuit
    const merkleRoot = this.merkleTree.getRoot();
    const registryRoot = this.registryTree.getRoot();

    // Compute encrypted change note matching circuit algorithm (MUST be before proof generation)
    const encSeed = deriveEncSeed(session.keys.nullifierKey);

    // Encrypt change note to self (self-encryption, no ECDH)
    const encryptedChange: Cipher5 = await encryptNoteSelfAsync(
      encSeed,
      changeAmount,
      changeOwner,
      changeRandomness,
      BigInt(txNonce),
      grumpkinFixedBaseMul
    );

    // Compute ciphertext hash (matching circuit and contract)
    const ciphertextHash = ciphertextHash5(encryptedChange);

    const circuitInputs: WithdrawCircuitInputs = {
      merkleRoot,
      nullifier0,
      nullifier1,
      changeCommitment,
      intentNullifier,
      withdrawRecipient: BigInt(withdrawRecipient),
      withdrawAmount,
      registryRoot,
      ciphertextHash,
      signatureData,
      txNonce: BigInt(txNonce),
      txMaxPriorityFee: parsed.maxPriorityFeePerGas ?? 0n,
      txMaxFee: parsed.maxFeePerGas ?? 0n,
      txGasLimit: parsed.gas ?? 0n,
      input0: {
        amount: note.amount,
        owner: note.owner,
        randomness: note.randomness,
        nullifierKeyHash: session.keys.nullifierKeyHash,
        leafIndex: note.leafIndex,
        siblings: proof0.siblings,
      },
      input1: {
        amount: 0n,
        owner: BigInt(senderAddress),
        randomness: phantomRandomness,
        nullifierKeyHash: session.keys.nullifierKeyHash,
        leafIndex: 0,
        siblings: Array(TREE_DEPTH).fill(0n),
      },
      changeRandomness,
      nullifierKey: session.keys.nullifierKey,
      senderProof: {
        pubkeyX: senderProof.pubkeyX,
        pubkeyY: senderProof.pubkeyY,
        nkHash: senderProof.nkHash,
        leafIndex: senderProof.leafIndex,
        siblings: senderProof.siblings,
      },
    };

    console.log('[Withdraw] Generating proof (single-note)...');
    const { proof, publicInputs } = await generateWithdrawProofWorker(circuitInputs);

    // Update status to submitting
    this.pendingTxs.set(virtualHash, { status: 'submitting' });

    // encryptedChange already computed above with encryptNoteSelfAsync - matches circuit

    const l1Hash = await submitWithdraw(
      proof,
      merkleRoot,
      registryRoot,
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

  private async registerViewingKey(address: string, signature: string): Promise<{
    success: boolean;
    registered: boolean;
    registrationNeeded: boolean;
  }> {
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

    // Note: Encryption keys are now derived from nullifierKey in-circuit
    // encSeed = deriveEncSeed(nullifierKey)
    // encPrivKey = ensureNonzero(encSeed)

    const sessionKeys: SessionKeys = {
      address: normalizedAddress,
      viewingKey,
      nullifierKey,
      nullifierKeyHash,
    };

    const noteStore = new NoteStore(sessionKeys);

    // Check if user is registered in the on-chain registry
    // If not, auto-register them via relayer's registerFor() privilege
    let isRegistered = await isUserRegistered(normalizedAddress as Hex);
    if (!isRegistered) {
      console.log(`[RegisterViewingKey] User ${normalizedAddress} not registered - auto-registering via relayer...`);

      // Derive encryption public key from nullifier key (same as circuit)
      const encSeed = deriveEncSeed(nullifierKey);
      const encPrivKey = encSeed === 0n ? 1n : encSeed;
      const encPubKey = await grumpkinFixedBaseMul(encPrivKey);

      try {
        // Register on L1 via relayer
        const { leafIndex } = await registerUserOnL1(
          normalizedAddress as Hex,
          [encPubKey.x, encPubKey.y],
          nullifierKeyHash
        );

        // Update local registry tree to include the new registration
        this.registryTree.insertEntry(
          BigInt(normalizedAddress),
          encPubKey.x,
          encPubKey.y,
          nullifierKeyHash
        );

        console.log(`[RegisterViewingKey] Auto-registration complete, leafIndex=${leafIndex}`);
        isRegistered = true;
      } catch (err) {
        const errMsg = err instanceof Error ? err.message : String(err);
        console.error(`[RegisterViewingKey] Auto-registration failed: ${errMsg}`);
        // Continue with local session - user can still receive from deposits with plaintext
        // but transfers from others won't work until registered
      }
    }

    // Recover notes from chain events
    const userOwner = BigInt(normalizedAddress);
    let recoveredCount = 0;

    // 1. Scan deposit events and try to decrypt
    const { getDepositEvents, getTransferEvents, getWithdrawEvents } = await import('./sync.js');
    const deposits = await getDepositEvents();
    const recoveredTransactions: TransactionRecord[] = [];

    for (const dep of deposits) {
      // Deposit event has plaintext amount, owner, randomness - no decryption needed
      if (dep.owner === userOwner) {
        // Verify commitment using our nullifierKeyHash
        const expectedCommitment = computeCommitment(dep.amount, dep.owner, dep.randomness, nullifierKeyHash);
        if (expectedCommitment === dep.commitment) {
          const nullifier = computeNullifier(nullifierKey, dep.leafIndex, dep.randomness);
          if (!this.spentNullifiers.has(nullifier)) {
            const note = createNoteWithRandomness(dep.amount, dep.owner, dep.randomness, nullifierKeyHash, dep.leafIndex);
            noteStore.addNote(note);
            recoveredCount++;
          }
          // Record deposit transaction (regardless of spent status)
          recoveredTransactions.push({
            type: 'deposit',
            virtualHash: dep.txHash,
            l1Hash: dep.txHash,
            amount: dep.amount,
            timestamp: Number(dep.blockNumber),
          });
        }
      }
    }

    // 2. Scan transfer events for received notes
    const transfers = await getTransferEvents();

    for (const xfer of transfers) {
      // Try to decrypt both notes using new in-circuit encryption format
      // Note 0: ECDH encrypted to recipient
      // Note 1: Self-encrypted (sender's change)
      const decryptedNotes: Array<{ index: number; amount: bigint; randomness: bigint; commitment: bigint; leafIndex: number; isChange: boolean }> = [];

      for (let i = 0; i < 2; i++) {
        const encNote = xfer.encryptedNotes[i];
        // encNote is now Cipher5 (5 bigints), not bytes
        const cipher: Cipher5 = [encNote[0], encNote[1], encNote[2], encNote[3], encNote[4]];

        // Try both self-decryption and ECDH, with commitment verification
        const result = await tryDecryptNoteWithCommitmentAsync(
          cipher,
          nullifierKey,
          nullifierKeyHash,
          xfer.commitments[i],
          userOwner,
          grumpkinScalarMul
        );
        if (result) {
          decryptedNotes.push({
            index: i,
            amount: result.note.amount,
            randomness: result.note.randomness,
            commitment: xfer.commitments[i],
            leafIndex: xfer.leafIndices[i],
            isChange: result.isChange,
          });
        }
      }

      // Add unspent notes to store
      for (const dn of decryptedNotes) {
        const nullifier = computeNullifier(nullifierKey, dn.leafIndex, dn.randomness);
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
    const encSeed = deriveEncSeed(nullifierKey);

    for (const w of withdrawals) {
      // Check if this withdrawal is ours (either by change note or recipient address)
      let isOurs = false;
      let withdrawAmount = w.amount;

      // encryptedChange is now Cipher5 (5 bigints), not bytes
      if (w.changeCommitment !== 0n) {
        const cipher: Cipher5 = [w.encryptedChange[0], w.encryptedChange[1], w.encryptedChange[2], w.encryptedChange[3], w.encryptedChange[4]];
        // Change notes are self-encrypted (no ECDH)
        const noteData = decryptSelfNote(cipher, encSeed);
        if (noteData && noteData.owner === userOwner) {
          isOurs = true;
          const expectedCommitment = computeCommitment(noteData.amount, noteData.owner, noteData.randomness, nullifierKeyHash);
          if (expectedCommitment === w.changeCommitment) {
            const nullifier = computeNullifier(nullifierKey, w.changeLeafIndex, noteData.randomness);
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
    console.log(`[RegisterViewingKey] ${normalizedAddress}, recovered ${recoveredCount} notes, starting nonce ${startingNonce}, registered: ${isRegistered}`);

    return {
      success: true,
      registered: isRegistered,
      registrationNeeded: !isRegistered,
    };
  }

  // ==================== L1 Deposit Support ====================

  /**
   * Encrypt note data for a user (deprecated)
   *
   * With in-circuit encryption, deposits no longer need ECIES encryption.
   * The plaintext (amount, owner, randomness) is included in the Deposit event.
   * This method is kept for API compatibility but returns empty bytes.
   */
  private async encryptNoteDataForUser(
    _address: string,
    _noteData: { owner: string; amount: string; randomness: string }
  ): Promise<Hex> {
    // Deposits now have plaintext in the event - encryption not needed
    // Return empty bytes for backwards compatibility
    return '0x' as Hex;
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
    const { nullifierKey, nullifierKeyHash } = session.keys;
    const encSeed = deriveEncSeed(nullifierKey);

    // Clear and rebuild note store
    const newNoteStore = new NoteStore(session.keys);
    const newTransactions: TransactionRecord[] = [];

    // Scan deposits - plaintext in event, no decryption needed
    const deposits = await getDepositEvents();
    for (const dep of deposits) {
      if (dep.owner === userOwner) {
        const expectedCommitment = computeCommitment(dep.amount, dep.owner, dep.randomness, nullifierKeyHash);
        if (expectedCommitment === dep.commitment) {
          const nullifier = computeNullifier(nullifierKey, dep.leafIndex, dep.randomness);
          if (!this.spentNullifiers.has(nullifier)) {
            const note = createNoteWithRandomness(dep.amount, dep.owner, dep.randomness, nullifierKeyHash, dep.leafIndex);
            newNoteStore.addNote(note);
          }
          newTransactions.push({
            type: 'deposit',
            virtualHash: dep.txHash,
            l1Hash: dep.txHash,
            amount: dep.amount,
            timestamp: Number(dep.blockNumber),
          });
        }
      }
    }

    // Scan transfers - use new in-circuit encryption format
    const transfers = await getTransferEvents();
    for (const xfer of transfers) {
      // Try to decrypt both notes using new encryption format
      const decryptedNotes: Array<{ index: number; amount: bigint; randomness: bigint; commitment: bigint; leafIndex: number; isChange: boolean }> = [];

      for (let i = 0; i < 2; i++) {
        const encNote = xfer.encryptedNotes[i];
        const cipher: Cipher5 = [encNote[0], encNote[1], encNote[2], encNote[3], encNote[4]];

        // Try both self-decryption and ECDH, with commitment verification
        const result = await tryDecryptNoteWithCommitmentAsync(
          cipher,
          nullifierKey,
          nullifierKeyHash,
          xfer.commitments[i],
          userOwner,
          grumpkinScalarMul
        );
        if (result) {
          decryptedNotes.push({
            index: i,
            amount: result.note.amount,
            randomness: result.note.randomness,
            commitment: xfer.commitments[i],
            leafIndex: xfer.leafIndices[i],
            isChange: result.isChange,
          });
        }
      }

      // Add unspent notes to store
      for (const dn of decryptedNotes) {
        const nullifier = computeNullifier(nullifierKey, dn.leafIndex, dn.randomness);
        if (!this.spentNullifiers.has(nullifier)) {
          const note = createNoteWithRandomness(dn.amount, userOwner, dn.randomness, nullifierKeyHash, dn.leafIndex);
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

    // Scan withdrawals - change notes are self-encrypted
    const withdrawals = await getWithdrawEvents();
    for (const w of withdrawals) {
      let isOurs = false;
      if (w.changeCommitment !== 0n) {
        const cipher: Cipher5 = [w.encryptedChange[0], w.encryptedChange[1], w.encryptedChange[2], w.encryptedChange[3], w.encryptedChange[4]];
        const noteData = decryptSelfNote(cipher, encSeed);
        if (noteData && noteData.owner === userOwner) {
          isOurs = true;
          const expectedCommitment = computeCommitment(noteData.amount, noteData.owner, noteData.randomness, nullifierKeyHash);
          if (expectedCommitment === w.changeCommitment) {
            const nullifier = computeNullifier(nullifierKey, w.changeLeafIndex, noteData.randomness);
            if (!this.spentNullifiers.has(nullifier)) {
              const note = createNoteWithRandomness(noteData.amount, noteData.owner, noteData.randomness, nullifierKeyHash, w.changeLeafIndex);
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
  private async getEncryptionKeyRpc(address: string): Promise<Hex | null> {
    const normalizedAddress = address.toLowerCase();

    // Check session first - derive Grumpkin pubkey from nullifierKey
    const session = this.sessions.get(normalizedAddress);
    if (session) {
      // Derive encryption public key from nullifier key (matches circuit derivation)
      const encSeed = deriveEncSeed(session.keys.nullifierKey);
      const encPrivKey = encSeed === 0n ? 1n : encSeed;
      const encPubKey = await grumpkinFixedBaseMul(encPrivKey);
      const xHex = encPubKey.x.toString(16).padStart(64, '0');
      const yHex = encPubKey.y.toString(16).padStart(64, '0');
      return `0x${xHex}${yHex}` as Hex;
    }

    // Get Grumpkin key from registry
    const grumpkinKey = await getEncryptionKey(normalizedAddress as Hex);
    if (!grumpkinKey) {
      return null;
    }
    // Return Grumpkin key as concatenated hex (x || y)
    const xHex = grumpkinKey[0].toString(16).padStart(64, '0');
    const yHex = grumpkinKey[1].toString(16).padStart(64, '0');
    return `0x${xHex}${yHex}` as Hex;
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
   * Get registration data for user to submit L1 registration tx
   * Returns the encPublicKey and nullifierKeyHash needed for RecipientRegistry.register()
   */
  private async getRegistrationData(address: string): Promise<{
    encPublicKey: [Hex, Hex];
    nullifierKeyHash: Hex;
    registered: boolean;
    registryAddress: Hex;
  } | null> {
    const normalizedAddress = address.toLowerCase();
    const session = this.sessions.get(normalizedAddress);

    if (!session) {
      console.log(`[GetRegistrationData] No session for ${normalizedAddress}`);
      return null;
    }

    // Derive encryption public key from nullifier key (same as circuit)
    const encSeed = deriveEncSeed(session.keys.nullifierKey);
    const encPrivKey = encSeed === 0n ? 1n : encSeed;
    const encPubKey = await grumpkinFixedBaseMul(encPrivKey);

    // Check if already registered on-chain
    const registered = await isUserRegistered(normalizedAddress as Hex);

    // Format for contract call: uint256[2]
    const xHex = toHex(encPubKey.x);
    const yHex = toHex(encPubKey.y);

    return {
      encPublicKey: [xHex, yHex],
      nullifierKeyHash: toHex(session.keys.nullifierKeyHash),
      registered,
      registryAddress: CONTRACTS.registry as Hex,
    };
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
    if (session) {
      // Re-scan deposit events to pick up the new note
      // Deposits have plaintext in the event - no decryption needed
      const { getDepositEvents } = await import('./sync.js');
      const deposits = await getDepositEvents();
      const userOwner = BigInt(normalizedAddress);
      const { nullifierKey, nullifierKeyHash } = session.keys;

      for (const dep of deposits) {
        if (dep.owner === userOwner) {
          const expectedCommitment = computeCommitment(dep.amount, dep.owner, dep.randomness, nullifierKeyHash);
          if (expectedCommitment === dep.commitment) {
            // Check if we already have this note
            const existingNotes = session.noteStore.getAllNotes();
            const alreadyHave = existingNotes.some(n => n.commitment === dep.commitment);
            if (!alreadyHave) {
              const nullifier = computeNullifier(nullifierKey, dep.leafIndex, dep.randomness);
              if (!this.spentNullifiers.has(nullifier)) {
                const note = createNoteWithRandomness(dep.amount, dep.owner, dep.randomness, nullifierKeyHash, dep.leafIndex);
                session.noteStore.addNote(note);
                console.log(`[WatchForDeposit] Added note: ${dep.amount} wei`);

                // Record deposit transaction
                session.transactions.push({
                  type: 'deposit',
                  virtualHash: txHash,
                  l1Hash: txHash,
                  amount: dep.amount,
                  timestamp: Date.now(),
                });
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
