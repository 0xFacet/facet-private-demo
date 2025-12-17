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
} from './config.js';
import { NoteStore, SessionKeys, createNoteWithRandomness, type Note } from './notes.js';
import { MerkleTree } from './merkle.js';
import { initPoseidon, computeCommitment, computeNullifier, computeIntentNullifier, computeWithdrawIntentNullifier } from './crypto/poseidon.js';
import {
  l1Public,
  submitDeposit,
  submitTransfer,
  submitWithdraw,
  waitForReceipt,
  getRelayerAddress,
} from './l1.js';
import { syncFromChain, needsRefresh } from './sync.js';
import {
  generateTransferProof,
  generateWithdrawProof,
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
 * User session state
 */
interface UserSession {
  address: string;
  keys: SessionKeys;
  noteStore: NoteStore;
  virtualNonce: bigint;
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

      // Gas estimation - return 1 to match circuit expectations
      // The relayer pays actual L1 fees
      case 'eth_estimateGas':
        return '0x1';

      // Fee methods - return 1 to match circuit expectations
      // Using 1 instead of 0 for simpler RLP encoding in circuits
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

      default:
        throw new Error(`Method ${method} not supported`);
    }
  }

  // ==================== Account Methods ====================

  private getAccounts(): string[] {
    return Array.from(this.sessions.keys());
  }

  private getBalance(address: string): string {
    const session = this.sessions.get(address.toLowerCase());
    if (!session) {
      return '0x100000000000000000';
    }
    const shieldedBalance = session.noteStore.getBalance();
    // Return shielded balance + 100 ETH buffer for MetaMask gas calculations
    // The relayer pays actual L1 fees, so this is just to satisfy MetaMask
    const displayBalance = shieldedBalance + 100n * 10n ** 18n;
    return toHex(displayBalance);
  }

  private getShieldedBalance(address: string): string {
    const session = this.sessions.get(address.toLowerCase());
    if (!session) {
      return '0x0';
    }
    // Return actual shielded balance (no buffer)
    return toHex(session.noteStore.getBalance());
  }

  private getTransactionCount(address: string): string {
    const session = this.sessions.get(address.toLowerCase());
    if (!session) {
      return '0x0';
    }
    return toHex(session.virtualNonce);
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
    }));
  }

  // ==================== Transaction Methods ====================

  private async sendRawTransaction(signedTx: string): Promise<string> {
    // Check if chain needs refresh before processing
    if (await needsRefresh(this.merkleTree)) {
      console.log('[RPC] State refresh needed, syncing...');
      await syncFromChain(this.merkleTree, this.spentNullifiers, this.usedIntents);
    }

    // Parse the signed transaction
    const parsed = parseTransaction(signedTx as Hex);

    // Validate chain ID
    if (BigInt(parsed.chainId || 0) !== VIRTUAL_CHAIN_ID) {
      throw new Error(`Invalid chain ID. Expected ${VIRTUAL_CHAIN_ID}, got ${parsed.chainId}`);
    }

    // Recover sender from signature using proper EIP-1559 serialization
    if (!parsed.r || !parsed.s || parsed.yParity === undefined) {
      throw new Error('Missing signature components');
    }

    // Reconstruct the unsigned transaction for hash computation
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

    // Recover the public key from the signature (needed for circuit)
    const recoveredPubKey = await recoverPublicKey({
      hash: unsignedHash,
      signature: {
        r: parsed.r,
        s: parsed.s,
        yParity: parsed.yParity,
      },
    });

    const senderAddress = await recoverAddress({
      hash: unsignedHash,
      signature: {
        r: parsed.r,
        s: parsed.s,
        yParity: parsed.yParity,
      },
    });

    const normalizedSender = senderAddress.toLowerCase();
    const session = this.sessions.get(normalizedSender);
    if (!session) {
      throw new Error('Session not found. Register viewing key first.');
    }

    // Sync nonce - accept whatever MetaMask sends (session resets on adapter restart)
    const txNonce = parsed.nonce ?? 0;
    if (BigInt(txNonce) !== session.virtualNonce) {
      console.log(`[Nonce] Syncing nonce from ${session.virtualNonce} to ${txNonce}`);
      session.virtualNonce = BigInt(txNonce);
    }

    // Route based on destination
    const to = parsed.to?.toLowerCase();
    const poolAddress = CONTRACTS.privacyPool.toLowerCase();

    if (to === poolAddress) {
      // Deposit to privacy pool
      return this.executeDeposit(parsed, session, senderAddress as Hex, signedTx as Hex);
    } else if (to === WITHDRAW_SENTINEL.toLowerCase()) {
      // Withdrawal
      return this.executeWithdraw(parsed, session, senderAddress as Hex, signedTx as Hex, recoveredPubKey);
    } else {
      // Private transfer
      return this.executeTransfer(parsed, session, senderAddress as Hex, signedTx as Hex, recoveredPubKey);
    }
  }

  // ==================== Deposit ====================

  private async executeDeposit(
    parsed: ReturnType<typeof parseTransaction>,
    session: UserSession,
    senderAddress: Hex,
    signedTx: Hex
  ): Promise<string> {
    const amount = parsed.value || 0n;
    if (amount === 0n) {
      throw new Error('Deposit amount must be > 0');
    }

    console.log(`[Deposit] ${senderAddress} depositing ${amount} wei (split into 2 notes)`);

    // Split deposit into 2 notes so user can immediately transfer/withdraw
    // (circuit requires 2 input notes)
    const amount1 = amount / 2n;
    const amount2 = amount - amount1; // Handles odd amounts

    const owner = BigInt(senderAddress);

    // Generate random values for both notes
    const randomBytes1 = crypto.getRandomValues(new Uint8Array(32));
    const randomness1 = BigInt('0x' + Array.from(randomBytes1).map(b => b.toString(16).padStart(2, '0')).join('')) % FIELD_SIZE;

    const randomBytes2 = crypto.getRandomValues(new Uint8Array(32));
    const randomness2 = BigInt('0x' + Array.from(randomBytes2).map(b => b.toString(16).padStart(2, '0')).join('')) % FIELD_SIZE;

    const commitment1 = computeCommitment(amount1, owner, randomness1);
    const commitment2 = computeCommitment(amount2, owner, randomness2);

    // Submit deposits sequentially (concurrent causes nonce conflicts on relayer)
    console.log(`[Deposit] Submitting 2 L1 deposits: ${amount1} + ${amount2} wei`);

    const l1Hash1 = await submitDeposit(commitment1, amount1);
    await waitForReceipt(l1Hash1);
    const leafIndex1 = this.merkleTree.insert(commitment1);
    const note1 = createNoteWithRandomness(amount1, owner, randomness1, leafIndex1);
    session.noteStore.addNote(note1);

    const l1Hash2 = await submitDeposit(commitment2, amount2);
    await waitForReceipt(l1Hash2);
    const leafIndex2 = this.merkleTree.insert(commitment2);
    const note2 = createNoteWithRandomness(amount2, owner, randomness2, leafIndex2);
    session.noteStore.addNote(note2);

    // Increment nonce
    session.virtualNonce += 1n;

    // Map virtual hash to first L1 hash (for receipt lookup)
    const virtualHash = keccak256(signedTx);
    this.txHashMapping.set(virtualHash, l1Hash1);

    console.log(`[Deposit] Complete! leafIndices=${leafIndex1},${leafIndex2}`);
    return virtualHash;
  }

  // ==================== Transfer ====================

  private async executeTransfer(
    parsed: ReturnType<typeof parseTransaction>,
    session: UserSession,
    senderAddress: Hex,
    signedTx: Hex,
    recoveredPubKey: Hex
  ): Promise<string> {
    const value = parsed.value || 0n;
    const recipient = parsed.to as Hex;

    if (!recipient) {
      throw new Error('Transfer must have a recipient');
    }

    console.log(`[Transfer] ${senderAddress} -> ${recipient}, value=${value}`);

    // Circuit requires exactly 2 notes with valid merkle proofs
    const selectedNotes = session.noteStore.selectNotesForSpend(value);
    if (!selectedNotes) {
      const unspent = session.noteStore.getUnspentNotes();
      if (unspent.length < 2) {
        throw new Error(`Need at least 2 deposits before transferring. You have ${unspent.length} note(s).`);
      }
      const total = unspent.reduce((sum, n) => sum + n.amount, 0n);
      throw new Error(`Insufficient balance. Have ${total}, need ${value}`);
    }

    return this.executeTransferTwoNotes(parsed, session, senderAddress, signedTx, selectedNotes, recoveredPubKey);
  }

  private async executeTransferTwoNotes(
    parsed: ReturnType<typeof parseTransaction>,
    session: UserSession,
    senderAddress: Hex,
    signedTx: Hex,
    notes: Note[],
    recoveredPubKey: Hex
  ): Promise<string> {
    const value = parsed.value || 0n;
    const recipient = parsed.to as Hex;
    const txNonce = parsed.nonce ?? 0;

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
    const output0Commitment = computeCommitment(value, output0Owner, output0Randomness);

    // Output 1: change back to sender
    const output1Owner = BigInt(senderAddress);
    const output1Randomness = BigInt(keccak256(concat([signedTx, '0x01']))) % FIELD_SIZE;
    const output1Commitment = computeCommitment(change, output1Owner, output1Randomness);

    // Intent nullifier = poseidon(signer, chainId, nonce, to, value)
    const intentNullifier = computeIntentNullifier(
      BigInt(senderAddress),
      VIRTUAL_CHAIN_ID,
      BigInt(txNonce),
      BigInt(recipient),
      value
    );

    // Extract signature data using recovered public key
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
    };

    console.log('[Transfer] Generating proof...');
    const { proof } = await generateTransferProof(circuitInputs);

    // Submit to L1
    const l1Hash = await submitTransfer(
      proof,
      merkleRoot,
      [nullifier0, nullifier1],
      [output0Commitment, output1Commitment],
      intentNullifier
    );
    await waitForReceipt(l1Hash);

    // Update local state
    session.noteStore.markSpent(notes[0].commitment);
    session.noteStore.markSpent(notes[1].commitment);
    this.spentNullifiers.add(nullifier0);
    this.spentNullifiers.add(nullifier1);
    this.usedIntents.add(intentNullifier);

    // Insert output commitments
    const leafIndex0 = this.merkleTree.insert(output0Commitment);
    const leafIndex1 = this.merkleTree.insert(output1Commitment);

    // Add change note back to sender's store
    if (change > 0n) {
      const changeNote = createNoteWithRandomness(change, output1Owner, output1Randomness, leafIndex1);
      session.noteStore.addNote(changeNote);
    }

    session.virtualNonce += 1n;

    const virtualHash = keccak256(signedTx);
    this.txHashMapping.set(virtualHash, l1Hash);

    console.log(`[Transfer] Complete! l1Hash=${l1Hash}`);
    return virtualHash;
  }

  // ==================== Withdraw ====================

  private async executeWithdraw(
    parsed: ReturnType<typeof parseTransaction>,
    session: UserSession,
    senderAddress: Hex,
    signedTx: Hex,
    recoveredPubKey: Hex
  ): Promise<string> {
    // For withdrawals, the value field is the withdraw amount
    // and the data field contains the recipient address
    const withdrawAmount = parsed.value || 0n;
    // Recipient is encoded in data field or defaults to sender
    let withdrawRecipient: Hex;
    if (parsed.data && parsed.data.length >= 42) {
      withdrawRecipient = ('0x' + parsed.data.slice(2, 42)) as Hex;
    } else {
      withdrawRecipient = senderAddress;
    }

    console.log(`[Withdraw] ${senderAddress} withdrawing ${withdrawAmount} to ${withdrawRecipient}`);

    // Circuit requires exactly 2 notes with valid merkle proofs
    const selectedNotes = session.noteStore.selectNotesForSpend(withdrawAmount);
    if (!selectedNotes) {
      const unspent = session.noteStore.getUnspentNotes();
      if (unspent.length < 2) {
        throw new Error(`Need at least 2 deposits before withdrawing. You have ${unspent.length} note(s).`);
      }
      const total = unspent.reduce((sum, n) => sum + n.amount, 0n);
      throw new Error(`Insufficient balance. Have ${total}, need ${withdrawAmount}`);
    }

    const [note0, note1] = selectedNotes;
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
    const changeCommitment =
      changeAmount > 0n ? computeCommitment(changeAmount, changeOwner, changeRandomness) : 0n;

    // Intent nullifier = poseidon(signer, chainId, nonce, WITHDRAW_SENTINEL, value)
    const intentNullifier = computeWithdrawIntentNullifier(
      BigInt(senderAddress),
      VIRTUAL_CHAIN_ID,
      BigInt(txNonce),
      withdrawAmount
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
    const { proof } = await generateWithdrawProof(circuitInputs);

    const l1Hash = await submitWithdraw(
      proof,
      merkleRoot,
      [nullifier0, nullifier1],
      changeCommitment,
      intentNullifier,
      withdrawRecipient,
      withdrawAmount
    );
    await waitForReceipt(l1Hash);

    // Update state - mark both notes as spent
    session.noteStore.markSpent(note0.commitment);
    session.noteStore.markSpent(note1.commitment);
    this.spentNullifiers.add(nullifier0);
    this.spentNullifiers.add(nullifier1);
    this.usedIntents.add(intentNullifier);

    if (changeCommitment !== 0n) {
      const leafIndex = this.merkleTree.insert(changeCommitment);
      const changeNote = createNoteWithRandomness(changeAmount, changeOwner, changeRandomness, leafIndex);
      session.noteStore.addNote(changeNote);
    }

    session.virtualNonce += 1n;

    const virtualHash = keccak256(signedTx);
    this.txHashMapping.set(virtualHash, l1Hash);

    console.log(`[Withdraw] Complete! l1Hash=${l1Hash}`);
    return virtualHash;
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
    if (!l1Hash) {
      return null;
    }

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

    const signatureBytes = hexToBytes(signature as Hex);

    // Derive keys from signature (deterministic)
    const viewingKeyHash = keccak256(signature as Hex);
    const nullifierKeyHash = keccak256(concat([signature as Hex, '0x01']));

    const viewingKey = hexToBytes(viewingKeyHash);
    const nullifierKey = BigInt(nullifierKeyHash) % FIELD_SIZE;

    // Encryption public key (placeholder for demo)
    const encryptionPubKey = signatureBytes.slice(0, 65);

    const sessionKeys: SessionKeys = {
      address: normalizedAddress,
      viewingKey,
      nullifierKey,
      encryptionPubKey,
    };

    const noteStore = new NoteStore(sessionKeys);

    this.sessions.set(normalizedAddress, {
      address: normalizedAddress,
      keys: sessionKeys,
      noteStore,
      virtualNonce: 0n,
    });

    console.log(`[RegisterViewingKey] ${normalizedAddress}, nullifierKey=${nullifierKey.toString(16).slice(0, 16)}...`);
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
