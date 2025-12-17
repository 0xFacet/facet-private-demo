/**
 * Generate EIP-1559 transaction signing fixtures for cross-language validation
 *
 * These fixtures contain:
 * - Raw signed transactions (as would come from MetaMask)
 * - Decoded transaction fields
 * - Recovered public key and address
 * - Transaction hash (for circuit verification)
 *
 * All transactions use the virtual chain ID 13371337
 */

import {
  createWalletClient,
  http,
  parseEther,
  keccak256,
  hexToBytes,
  bytesToHex,
  serializeTransaction,
  parseTransaction,
  recoverPublicKey,
  recoverAddress,
  toHex,
  defineChain
} from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { writeFileSync } from 'fs';

// Virtual chain (not valid on any real network)
const virtualChain = defineChain({
  id: 13371337,
  name: 'Facet Private',
  nativeCurrency: { name: 'Ether', symbol: 'ETH', decimals: 18 },
  rpcUrls: { default: { http: ['http://localhost:8545'] } }
});

// Test accounts (Foundry/Hardhat defaults)
const TEST_ACCOUNTS = [
  {
    name: "account_0",
    privateKey: "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
    address: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
  },
  {
    name: "account_1",
    privateKey: "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
    address: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
  }
];

async function signAndSerialize(account, tx) {
  // Serialize unsigned transaction
  const serializedUnsigned = serializeTransaction({
    chainId: virtualChain.id,
    ...tx,
    type: 'eip1559'
  });

  // The unsigned tx hash is what gets signed
  const unsignedHash = keccak256(serializedUnsigned);

  // Sign the transaction
  const signedSerialized = await account.signTransaction({
    chainId: virtualChain.id,
    ...tx,
    type: 'eip1559'
  });

  // Parse to get signature components
  const parsed = parseTransaction(signedSerialized);

  // Recover public key from signature
  const recoveredPubKey = await recoverPublicKey({
    hash: unsignedHash,
    signature: {
      r: parsed.r,
      s: parsed.s,
      yParity: parsed.yParity
    }
  });

  // Public key is 0x04 + x + y (uncompressed)
  const pubKeyBytes = hexToBytes(recoveredPubKey);
  const pubKeyX = pubKeyBytes.slice(1, 33);
  const pubKeyY = pubKeyBytes.slice(33, 65);

  // Signature r and s
  const rBytes = hexToBytes(parsed.r);
  const sBytes = hexToBytes(parsed.s);

  return {
    unsignedHash,
    signedSerialized,
    parsed,
    signature: {
      r: parsed.r,
      s: parsed.s,
      yParity: parsed.yParity
    },
    publicKey: {
      x: '0x' + bytesToHex(pubKeyX),
      y: '0x' + bytesToHex(pubKeyY),
      uncompressed: recoveredPubKey
    },
    circuit_inputs: {
      message_hash: Array.from(hexToBytes(unsignedHash)),
      pubkey_x: Array.from(pubKeyX),
      pubkey_y: Array.from(pubKeyY),
      signature_r: Array.from(rBytes),
      signature_s: Array.from(sBytes)
    }
  };
}

async function main() {
  const fixtures = {
    description: "EIP-1559 transaction signing fixtures for virtual chain 13371337",
    virtual_chain_id: virtualChain.id.toString(),
    generated_at: new Date().toISOString(),
    transactions: []
  };

  const account0 = privateKeyToAccount(TEST_ACCOUNTS[0].privateKey);

  // Test case 1: Simple ETH transfer from account_0 to account_1
  const tx1 = {
    nonce: 0,
    maxPriorityFeePerGas: 1000000000n, // 1 gwei
    maxFeePerGas: 30000000000n, // 30 gwei
    gas: 21000n,
    to: TEST_ACCOUNTS[1].address,
    value: parseEther("1"), // 1 ETH
  };

  const signed1 = await signAndSerialize(account0, tx1);

  fixtures.transactions.push({
    name: "simple_transfer_1_eth",
    description: "Transfer 1 ETH from account_0 to account_1, nonce 0",
    signer: {
      address: TEST_ACCOUNTS[0].address,
      privateKey: TEST_ACCOUNTS[0].privateKey
    },
    transaction: {
      chainId: virtualChain.id.toString(),
      nonce: tx1.nonce.toString(),
      maxPriorityFeePerGas: tx1.maxPriorityFeePerGas.toString(),
      maxFeePerGas: tx1.maxFeePerGas.toString(),
      gas: tx1.gas.toString(),
      to: tx1.to,
      value: tx1.value.toString(),
    },
    unsigned_hash: signed1.unsignedHash,
    signed_raw: signed1.signedSerialized,
    signature: signed1.signature,
    recovered_pubkey: signed1.publicKey,
    circuit_inputs: {
      ...signed1.circuit_inputs,
      to_bytes: Array.from(hexToBytes(tx1.to)),
      value_bytes: Array.from(hexToBytes(toHex(tx1.value, { size: 32 })))
    }
  });

  // Test case 2: Withdrawal (send to sentinel address 0x1)
  const tx2 = {
    nonce: 1,
    maxPriorityFeePerGas: 1000000000n,
    maxFeePerGas: 30000000000n,
    gas: 21000n,
    to: "0x0000000000000000000000000000000000000001", // Sentinel
    value: parseEther("0.5"), // 0.5 ETH withdrawal
  };

  const signed2 = await signAndSerialize(account0, tx2);

  fixtures.transactions.push({
    name: "withdrawal_to_sentinel",
    description: "Withdrawal: send 0.5 ETH to sentinel address 0x1, nonce 1",
    signer: {
      address: TEST_ACCOUNTS[0].address,
      privateKey: TEST_ACCOUNTS[0].privateKey
    },
    transaction: {
      chainId: virtualChain.id.toString(),
      nonce: tx2.nonce.toString(),
      maxPriorityFeePerGas: tx2.maxPriorityFeePerGas.toString(),
      maxFeePerGas: tx2.maxFeePerGas.toString(),
      gas: tx2.gas.toString(),
      to: tx2.to,
      value: tx2.value.toString(),
    },
    unsigned_hash: signed2.unsignedHash,
    signed_raw: signed2.signedSerialized,
    signature: signed2.signature,
    recovered_pubkey: signed2.publicKey,
    circuit_inputs: {
      ...signed2.circuit_inputs,
      to_bytes: Array.from(hexToBytes(tx2.to)),
      value_bytes: Array.from(hexToBytes(toHex(tx2.value, { size: 32 })))
    }
  });

  // Test case 3: Large value transfer
  const tx3 = {
    nonce: 5,
    maxPriorityFeePerGas: 2000000000n, // 2 gwei
    maxFeePerGas: 50000000000n, // 50 gwei
    gas: 21000n,
    to: TEST_ACCOUNTS[1].address,
    value: parseEther("100"), // 100 ETH
  };

  const signed3 = await signAndSerialize(account0, tx3);

  fixtures.transactions.push({
    name: "large_transfer_100_eth",
    description: "Transfer 100 ETH with nonce 5",
    signer: {
      address: TEST_ACCOUNTS[0].address,
      privateKey: TEST_ACCOUNTS[0].privateKey
    },
    transaction: {
      chainId: virtualChain.id.toString(),
      nonce: tx3.nonce.toString(),
      maxPriorityFeePerGas: tx3.maxPriorityFeePerGas.toString(),
      maxFeePerGas: tx3.maxFeePerGas.toString(),
      gas: tx3.gas.toString(),
      to: tx3.to,
      value: tx3.value.toString(),
    },
    unsigned_hash: signed3.unsignedHash,
    signed_raw: signed3.signedSerialized,
    signature: signed3.signature,
    recovered_pubkey: signed3.publicKey,
    circuit_inputs: {
      ...signed3.circuit_inputs,
      to_bytes: Array.from(hexToBytes(tx3.to)),
      value_bytes: Array.from(hexToBytes(toHex(tx3.value, { size: 32 })))
    }
  });

  // Write fixtures
  const outputPath = 'eip1559-signed-txs.json';
  writeFileSync(outputPath, JSON.stringify(fixtures, null, 2));
  console.log(`Written to ${outputPath}`);

  // Print summary
  console.log('\n=== EIP-1559 Signing Fixtures ===');
  console.log(`Virtual Chain ID: ${virtualChain.id}`);
  console.log(`Transactions: ${fixtures.transactions.length}`);

  for (const tx of fixtures.transactions) {
    console.log(`\n[${tx.name}]`);
    console.log(`  Signer: ${tx.signer.address}`);
    console.log(`  To: ${tx.transaction.to}`);
    console.log(`  Value: ${tx.transaction.value} wei`);
    console.log(`  Nonce: ${tx.transaction.nonce}`);
    console.log(`  Unsigned hash: ${tx.unsigned_hash}`);
    console.log(`  Signed tx: ${tx.signed_raw.slice(0, 50)}...`);
  }
}

main().catch(console.error);
