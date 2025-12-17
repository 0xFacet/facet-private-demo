// JSON-RPC server for MetaMask compatibility
// Handles virtual chain requests and routes them appropriately

import Fastify from 'fastify';
import { createPublicClient, createWalletClient, http, parseTransaction, toHex, hexToBytes, keccak256, recoverAddress } from 'viem';
import { sepolia } from 'viem/chains';
import { privateKeyToAccount } from 'viem/accounts';
import {
  VIRTUAL_CHAIN_ID,
  L1_RPC_URL,
  RPC_PORT,
  WITHDRAW_SENTINEL,
  FIELD_SIZE,
} from './config.js';

// Fixed gas parameters - MUST match circuit constants
// Circuit computes EIP-1559 signing hash with these exact values
// If transaction uses different params, signature verification will fail
const FIXED_MAX_PRIORITY_FEE = 1000000000n;  // 1 gwei
const FIXED_MAX_FEE = 30000000000n;           // 30 gwei
const FIXED_GAS_LIMIT = 21000n;               // simple transfer
import { NoteStore, SessionKeys } from './notes.js';
import { MerkleTree } from './merkle.js';

interface JsonRpcRequest {
  jsonrpc: string;
  id: number | string;
  method: string;
  params?: unknown[];
}

interface JsonRpcResponse {
  jsonrpc: string;
  id: number | string;
  result?: unknown;
  error?: { code: number; message: string };
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
export class RpcAdapter {
  private fastify = Fastify({ logger: true });
  private sessions: Map<string, UserSession> = new Map();
  private merkleTree: MerkleTree;
  private l1Client;
  private txHashMapping: Map<string, string> = new Map(); // virtual -> L1

  constructor() {
    this.merkleTree = new MerkleTree();
    this.l1Client = createPublicClient({
      chain: sepolia,
      transport: http(L1_RPC_URL),
    });

    this.setupRoutes();
  }

  private setupRoutes() {
    this.fastify.post('/', async (request, reply) => {
      const body = request.body as JsonRpcRequest;

      try {
        const result = await this.handleRequest(body.method, body.params || []);
        return {
          jsonrpc: '2.0',
          id: body.id,
          result,
        };
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Unknown error';
        return {
          jsonrpc: '2.0',
          id: body.id,
          error: { code: -32603, message },
        };
      }
    });
  }

  /**
   * Handle JSON-RPC request
   */
  // IMPORTANT: MetaMask's "Send" flow calls more methods than just sendRawTransaction.
  // Minimum required for MetaMask compatibility:
  //   - eth_chainId, net_version (chain identification)
  //   - eth_accounts, eth_requestAccounts (account discovery)
  //   - eth_getBalance (balance display)
  //   - eth_getTransactionCount (nonce for signing)
  //   - eth_estimateGas (gas estimation before send)
  //   - eth_gasPrice, eth_maxPriorityFeePerGas, eth_feeHistory (fee calculation)
  //   - eth_sendRawTransaction (tx submission)
  //   - eth_getTransactionReceipt, eth_getTransactionByHash (tx status polling)
  //   - eth_blockNumber, eth_getBlockByNumber (block context)
  //   - eth_call (for contract reads, e.g., registry.isRegistered)
  //   - eth_getCode (MetaMask checks if recipient is contract)

  private async handleRequest(method: string, params: unknown[]): Promise<unknown> {
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

      // Gas estimation - return fixed value (must match circuit)
      case 'eth_estimateGas':
        return '0x5208'; // 21000 for simple transfer

      // Fee methods - return FIXED values to match circuit expectations
      // CRITICAL: Circuit computes signing hash with these exact gas params
      // If MetaMask uses different values, signature verification will fail
      case 'eth_gasPrice':
        return '0x6fc23ac00'; // 30 gwei (maxFeePerGas)

      case 'eth_maxPriorityFeePerGas':
        return '0x3b9aca00'; // 1 gwei

      case 'eth_feeHistory':
        // Return fixed fee history that will make MetaMask use our fixed values
        return {
          oldestBlock: '0x1',
          baseFeePerGas: ['0x6fc23ac00', '0x6fc23ac00'], // 30 gwei base fee
          gasUsedRatio: [0.5],
          reward: [['0x3b9aca00']], // 1 gwei priority fee
        };

      // Transaction submission - intercept and process
      case 'eth_sendRawTransaction':
        return this.sendRawTransaction(params[0] as string);

      // Transaction status - use hash mapping
      case 'eth_getTransactionReceipt':
        return this.getTransactionReceipt(params[0] as string);

      case 'eth_getTransactionByHash':
        return this.getTransactionByHash(params[0] as string);

      // Block methods - proxy to L1
      case 'eth_blockNumber':
      case 'eth_getBlockByNumber':
      case 'eth_getBlockByHash':
        return this.l1Client.request({ method: method as any, params: params as any });

      // Contract methods - proxy to L1
      case 'eth_call':
      case 'eth_getCode':
        return this.l1Client.request({ method: method as any, params: params as any });

      // Custom methods
      case 'privacy_registerViewingKey':
        return this.registerViewingKey(params[0] as string, params[1] as string);

      case 'privacy_getShieldedBalance':
        return this.getBalance(params[0] as string);

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
      return '0x0';
    }
    const balance = session.noteStore.getBalance();
    return toHex(balance);
  }

  private getTransactionCount(address: string): string {
    const session = this.sessions.get(address.toLowerCase());
    if (!session) {
      return '0x0';
    }
    return toHex(session.virtualNonce);
  }

  // ==================== Transaction Methods ====================

  private async sendRawTransaction(signedTx: string): Promise<string> {
    // Parse the signed transaction
    const parsed = parseTransaction(signedTx as `0x${string}`);

    // Validate chain ID
    if (BigInt(parsed.chainId || 0) !== VIRTUAL_CHAIN_ID) {
      throw new Error(`Invalid chain ID. Expected ${VIRTUAL_CHAIN_ID}, got ${parsed.chainId}`);
    }

    // Recover sender from signature
    // For EIP-1559, we need r, s, and yParity
    if (!parsed.r || !parsed.s || parsed.yParity === undefined) {
      throw new Error('Missing signature components');
    }

    // Compute the signing hash and recover address
    // This is simplified - in production, properly serialize and hash
    const senderAddress = await recoverAddress({
      hash: keccak256(signedTx as `0x${string}`), // Simplified - should be unsigned tx hash
      signature: {
        r: parsed.r,
        s: parsed.s,
        yParity: parsed.yParity,
      },
    }).catch(() => null);

    if (!senderAddress) {
      throw new Error('Could not recover sender address');
    }

    const normalizedSender = senderAddress.toLowerCase();
    const session = this.sessions.get(normalizedSender);
    if (!session) {
      throw new Error('Session not found. Register viewing key first.');
    }

    // Validate nonce
    const txNonce = parsed.nonce ?? 0;
    if (BigInt(txNonce) !== session.virtualNonce) {
      throw new Error(`Invalid nonce. Expected ${session.virtualNonce}, got ${txNonce}`);
    }

    // Determine if this is a withdrawal (to sentinel) or transfer
    const isWithdrawal = parsed.to?.toLowerCase() === WITHDRAW_SENTINEL.toLowerCase();

    // Validate value is within field
    const value = parsed.value || 0n;
    if (value >= FIELD_SIZE) {
      throw new Error('Value exceeds field size');
    }

    // Validate gas parameters match circuit expectations
    // CRITICAL: Circuit computes signing hash with fixed gas params
    if (parsed.type === 'eip1559') {
      const maxPriorityFee = parsed.maxPriorityFeePerGas || 0n;
      const maxFee = parsed.maxFeePerGas || 0n;
      const gasLimit = parsed.gas || 0n;

      if (maxPriorityFee !== FIXED_MAX_PRIORITY_FEE) {
        throw new Error(`Invalid maxPriorityFeePerGas. Expected ${FIXED_MAX_PRIORITY_FEE}, got ${maxPriorityFee}`);
      }
      if (maxFee !== FIXED_MAX_FEE) {
        throw new Error(`Invalid maxFeePerGas. Expected ${FIXED_MAX_FEE}, got ${maxFee}`);
      }
      if (gasLimit !== FIXED_GAS_LIMIT) {
        throw new Error(`Invalid gas limit. Expected ${FIXED_GAS_LIMIT}, got ${gasLimit}`);
      }
    }

    // For now, return a mock transaction hash
    // In production, this would:
    // 1. Select input notes
    // 2. Generate ZK proof
    // 3. Submit to L1
    // 4. Map virtual tx hash to L1 tx hash

    const virtualTxHash = `0x${Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString('hex')}`;

    // Increment virtual nonce
    session.virtualNonce += 1n;

    console.log(`[${isWithdrawal ? 'WITHDRAW' : 'TRANSFER'}] ${senderAddress} -> ${parsed.to}, value: ${value}`);

    // Store mapping (in production, would map to actual L1 tx hash)
    this.txHashMapping.set(virtualTxHash, virtualTxHash);

    return virtualTxHash;
  }

  private async getTransactionReceipt(txHash: string): Promise<unknown> {
    const l1Hash = this.txHashMapping.get(txHash);
    if (!l1Hash) {
      return null;
    }

    // Return a mock receipt for now
    // In production, would query L1 for actual receipt
    return {
      transactionHash: txHash,
      blockNumber: '0x1',
      blockHash: '0x' + '0'.repeat(64),
      from: '0x' + '0'.repeat(40),
      to: '0x' + '0'.repeat(40),
      status: '0x1', // Success
      gasUsed: '0x5208',
      logs: [],
    };
  }

  private async getTransactionByHash(txHash: string): Promise<unknown> {
    const l1Hash = this.txHashMapping.get(txHash);
    if (!l1Hash) {
      return null;
    }

    // Return mock transaction
    return {
      hash: txHash,
      blockNumber: '0x1',
      from: '0x' + '0'.repeat(40),
      to: '0x' + '0'.repeat(40),
      value: '0x0',
      gas: '0x5208',
      gasPrice: '0x3b9aca00',
    };
  }

  // ==================== Custom Methods ====================

  private registerViewingKey(address: string, signature: string): boolean {
    const normalizedAddress = address.toLowerCase();

    // Derive keys from signature (simplified for demo)
    // In production, would properly derive viewing key and nullifier key
    const signatureBytes = hexToBytes(signature as `0x${string}`);
    const viewingKey = signatureBytes.slice(0, 32);
    const nullifierKey = BigInt('0x' + Buffer.from(signatureBytes.slice(32, 64)).toString('hex'));

    const sessionKeys: SessionKeys = {
      address: normalizedAddress,
      viewingKey,
      nullifierKey,
      encryptionPubKey: viewingKey, // Simplified
    };

    const noteStore = new NoteStore(sessionKeys);

    this.sessions.set(normalizedAddress, {
      address: normalizedAddress,
      keys: sessionKeys,
      noteStore,
      virtualNonce: 0n,
    });

    console.log(`Registered viewing key for ${normalizedAddress}`);
    return true;
  }

  // ==================== Server Methods ====================

  async start(): Promise<void> {
    await this.fastify.listen({ port: RPC_PORT, host: '0.0.0.0' });
    console.log(`RPC Adapter listening on port ${RPC_PORT}`);
    console.log(`Virtual Chain ID: ${VIRTUAL_CHAIN_ID}`);
  }

  async stop(): Promise<void> {
    await this.fastify.close();
  }
}
