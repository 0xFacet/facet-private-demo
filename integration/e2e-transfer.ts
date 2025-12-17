/**
 * End-to-End Transfer + Withdraw Test
 *
 * Tests the complete flow:
 * 1. Deploy contracts to local anvil
 * 2. Deposit ETH to create notes
 * 3. Sign a transfer transaction
 * 4. Generate transfer ZK proof
 * 5. Submit to PrivacyPool contract
 * 6. Verify transfer state updates
 * 7. Recipient signs withdrawal transaction
 * 8. Generate withdraw ZK proof
 * 9. Submit withdrawal to PrivacyPool
 * 10. Verify withdrawal state updates
 *
 * Run: npx tsx e2e-transfer.ts
 * Requires: anvil running on localhost:8545
 */

import {
  parseEther,
  keccak256,
  serializeTransaction,
  recoverPublicKey,
  Hex,
  hexToBytes,
  bytesToHex,
  defineChain,
  toHex,
  formatEther,
} from 'viem';
import { privateKeyToAccount } from 'viem/accounts';

import { initPoseidon, computeCommitment, computeNullifier, computeIntentNullifier, computeWithdrawIntentNullifier } from './helpers/poseidon.js';
import { MerkleTree } from './helpers/merkle.js';
import { deployContracts, getContracts, DeployedContracts } from './helpers/deploy.js';
import {
  generateTransferProof,
  generateWithdrawProof,
  extractSignatureFromTx,
  TransferCircuitInputs,
  WithdrawCircuitInputs,
} from './helpers/proof.js';
import {
  VIRTUAL_CHAIN_ID,
  TEST_PRIVATE_KEY,
  TEST_PRIVATE_KEY_1,
  TEST_ACCOUNT_1_ADDRESS,
  FIXED_MAX_PRIORITY_FEE,
  FIXED_MAX_FEE,
  FIXED_GAS_LIMIT,
  WITHDRAW_SENTINEL,
} from './helpers/config.js';

// Virtual chain for signing (not a real network)
const virtualChain = defineChain({
  id: Number(VIRTUAL_CHAIN_ID),
  name: 'Facet Private',
  nativeCurrency: { name: 'Ether', symbol: 'ETH', decimals: 18 },
  rpcUrls: { default: { http: ['http://localhost:8545'] } },
});

interface Note {
  amount: bigint;
  owner: bigint;
  randomness: bigint;
  commitment: bigint;
  leafIndex: number;
}

/**
 * Generate random bigint for note randomness
 */
function randomBigInt(): bigint {
  const bytes = new Uint8Array(31); // Keep under field size
  crypto.getRandomValues(bytes);
  return BigInt('0x' + bytesToHex(bytes).slice(2));
}

async function main() {
  console.log('='.repeat(60));
  console.log('Privacy Pool E2E Transfer Test');
  console.log('='.repeat(60));

  // Initialize Poseidon
  console.log('\n--- Initializing ---');
  await initPoseidon();
  console.log('Poseidon initialized');

  // Setup accounts
  const account = privateKeyToAccount(TEST_PRIVATE_KEY as Hex);
  const recipientAddress = TEST_ACCOUNT_1_ADDRESS;
  console.log(`Sender: ${account.address}`);
  console.log(`Recipient: ${recipientAddress}`);

  // Nullifier key (in production, derived from signature)
  const nullifierKey = randomBigInt();
  console.log(`Nullifier key: ${nullifierKey.toString(16).slice(0, 16)}...`);

  // Deploy contracts
  console.log('\n--- Deploying Contracts ---');
  const addresses = await deployContracts();
  const { publicClient, walletClient, privacyPool } = getContracts(addresses);

  // Create local merkle tree (mirrors on-chain)
  const merkleTree = new MerkleTree();

  // ==================== DEPOSIT PHASE ====================
  console.log('\n--- Depositing ETH ---');

  const notes: Note[] = [];
  const depositAmount = parseEther('1');

  // Deposit 2 notes (circuit requires 2 inputs)
  for (let i = 0; i < 2; i++) {
    const randomness = randomBigInt();
    const owner = BigInt(account.address);
    const commitment = computeCommitment(depositAmount, owner, randomness);

    console.log(`Depositing note ${i}: ${depositAmount} wei`);

    // Call deposit on contract
    const depositHash = await privacyPool.write.deposit(
      [commitment, '0x'], // commitment, empty encrypted note
      { value: depositAmount }
    );
    const receipt = await publicClient.waitForTransactionReceipt({ hash: depositHash });
    console.log(`  Deposit tx: ${depositHash.slice(0, 20)}...`);

    // Get leaf index from event
    const depositLog = receipt.logs[0];
    const leafIndex = merkleTree.insert(commitment);

    notes.push({
      amount: depositAmount,
      owner,
      randomness,
      commitment,
      leafIndex,
    });

    console.log(`  Leaf index: ${leafIndex}, Commitment: ${commitment.toString(16).slice(0, 16)}...`);
  }

  // Verify merkle root matches contract
  const contractRoot = await privacyPool.read.getLastRoot();
  const localRoot = merkleTree.getRoot();
  console.log(`\nContract root: ${contractRoot.toString(16).slice(0, 16)}...`);
  console.log(`Local root:    ${localRoot.toString(16).slice(0, 16)}...`);

  if (contractRoot !== localRoot) {
    throw new Error('Merkle root mismatch!');
  }
  console.log('✓ Merkle roots match');

  // ==================== SIGN TRANSACTION ====================
  console.log('\n--- Signing Transfer Transaction ---');

  const transferAmount = parseEther('0.5');
  const txNonce = 0n;
  const txTo = BigInt(recipientAddress);
  const txValue = transferAmount;

  // Build EIP-1559 transaction
  const tx = {
    chainId: Number(VIRTUAL_CHAIN_ID),
    nonce: Number(txNonce),
    maxPriorityFeePerGas: FIXED_MAX_PRIORITY_FEE,
    maxFeePerGas: FIXED_MAX_FEE,
    gas: FIXED_GAS_LIMIT,
    to: recipientAddress as Hex,
    value: txValue,
    type: 'eip1559' as const,
  };

  // Serialize unsigned for signing
  const serializedUnsigned = serializeTransaction(tx);
  const unsignedHash = keccak256(serializedUnsigned);
  console.log(`Unsigned tx hash: ${unsignedHash.slice(0, 20)}...`);

  // Sign the transaction
  const signedTx = await account.signTransaction(tx);
  console.log(`Signed tx: ${signedTx.slice(0, 30)}...`);

  // Recover public key from signature
  // Parse signature from signed tx (simplified - in production use parseTransaction)
  const { r, s, yParity } = await (async () => {
    // For viem, we need to parse the signed transaction
    const { parseTransaction } = await import('viem');
    const parsed = parseTransaction(signedTx as Hex);
    return {
      r: parsed.r!,
      s: parsed.s!,
      yParity: parsed.yParity!,
    };
  })();

  const recoveredPubKey = await recoverPublicKey({
    hash: unsignedHash,
    signature: { r, s, yParity },
  });
  console.log(`Recovered pubkey: ${recoveredPubKey.slice(0, 30)}...`);

  // Extract signature data for circuit
  const signatureData = extractSignatureFromTx(r, s, recoveredPubKey);

  // ==================== BUILD CIRCUIT INPUTS ====================
  console.log('\n--- Building Circuit Inputs ---');

  // Generate merkle proofs for input notes
  const proof0 = merkleTree.generateProof(notes[0].leafIndex);
  const proof1 = merkleTree.generateProof(notes[1].leafIndex);

  // Compute nullifiers
  const nullifier0 = computeNullifier(notes[0].commitment, nullifierKey);
  const nullifier1 = computeNullifier(notes[1].commitment, nullifierKey);
  console.log(`Nullifier 0: ${nullifier0.toString(16).slice(0, 16)}...`);
  console.log(`Nullifier 1: ${nullifier1.toString(16).slice(0, 16)}...`);

  // Output notes
  // Output 0: transfer amount to recipient
  const output0Randomness = randomBigInt();
  const output0Owner = txTo;
  const output0Amount = transferAmount;
  const outputCommitment0 = computeCommitment(output0Amount, output0Owner, output0Randomness);

  // Output 1: change back to sender
  const output1Randomness = randomBigInt();
  const output1Amount = notes[0].amount + notes[1].amount - transferAmount;
  const outputCommitment1 = computeCommitment(output1Amount, notes[0].owner, output1Randomness);

  console.log(`Output 0: ${output0Amount} wei to recipient`);
  console.log(`Output 1: ${output1Amount} wei change to sender`);

  // Compute intent nullifier
  const signerAddress = BigInt(account.address);
  const intentNullifier = computeIntentNullifier(
    signerAddress,
    VIRTUAL_CHAIN_ID,
    txNonce,
    txTo,
    txValue
  );
  console.log(`Intent nullifier: ${intentNullifier.toString(16).slice(0, 16)}...`);

  // Build full circuit inputs
  const circuitInputs: TransferCircuitInputs = {
    // Public inputs
    merkleRoot: localRoot,
    nullifier0,
    nullifier1,
    outputCommitment0,
    outputCommitment1,
    intentNullifier,

    // Private inputs
    signatureData,
    txNonce,
    txTo,
    txValue,

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

    output0Amount,
    output0Owner,
    output0Randomness,

    output1Amount,
    output1Randomness,

    nullifierKey,
  };

  // ==================== GENERATE PROOF ====================
  console.log('\n--- Generating ZK Proof ---');
  console.log('This may take 30-60 seconds...');

  const startTime = Date.now();
  const { proof, publicInputs } = await generateTransferProof(circuitInputs);
  const proofTime = (Date.now() - startTime) / 1000;
  console.log(`Proof generated in ${proofTime.toFixed(1)}s`);
  console.log(`Proof size: ${proof.length} bytes`);

  // ==================== SUBMIT TO CONTRACT ====================
  console.log('\n--- Submitting to Privacy Pool ---');

  // Convert proof to hex
  const proofHex = bytesToHex(proof) as Hex;

  // Submit transfer
  const transferHash = await privacyPool.write.transfer([
    proofHex,
    localRoot,
    [nullifier0, nullifier1],
    [outputCommitment0, outputCommitment1],
    intentNullifier,
    ['0x', '0x'], // empty encrypted notes for testing
  ]);

  console.log(`Transfer tx: ${transferHash}`);

  const transferReceipt = await publicClient.waitForTransactionReceipt({ hash: transferHash });
  console.log(`Transfer status: ${transferReceipt.status === 'success' ? '✓ Success' : '✗ Failed'}`);

  if (transferReceipt.status !== 'success') {
    throw new Error('Transfer transaction failed!');
  }

  // ==================== VERIFY STATE ====================
  console.log('\n--- Verifying State Updates ---');

  // Check nullifiers are spent
  const nullifier0Spent = await privacyPool.read.nullifierSpent([nullifier0]);
  const nullifier1Spent = await privacyPool.read.nullifierSpent([nullifier1]);
  console.log(`Nullifier 0 spent: ${nullifier0Spent ? '✓' : '✗'}`);
  console.log(`Nullifier 1 spent: ${nullifier1Spent ? '✓' : '✗'}`);

  if (!nullifier0Spent || !nullifier1Spent) {
    throw new Error('Nullifiers not marked as spent!');
  }

  // Check intent used
  const intentUsed = await privacyPool.read.intentUsed([intentNullifier]);
  console.log(`Intent used: ${intentUsed ? '✓' : '✗'}`);

  if (!intentUsed) {
    throw new Error('Intent not marked as used!');
  }

  // Check leaf index increased (2 deposits + 2 transfer outputs = 4)
  const finalLeafIndex = await privacyPool.read.nextLeafIndex();
  console.log(`Next leaf index: ${finalLeafIndex} (expected 4)`);

  if (finalLeafIndex !== 4n) {
    throw new Error(`Expected next leaf index 4, got ${finalLeafIndex}`);
  }

  // Check new merkle root is valid
  const newRoot = await privacyPool.read.getLastRoot();
  const isValidRoot = await privacyPool.read.isKnownRoot([newRoot]);
  console.log(`New merkle root valid: ${isValidRoot ? '✓' : '✗'}`);

  // Update local merkle tree with transfer outputs
  merkleTree.insert(outputCommitment0); // index 2 - recipient's note
  merkleTree.insert(outputCommitment1); // index 3 - sender's change

  // Store recipient's note for withdrawal
  const recipientNote: Note = {
    amount: output0Amount,
    owner: output0Owner,
    randomness: output0Randomness,
    commitment: outputCommitment0,
    leafIndex: 2, // After 2 deposits
  };

  console.log('\n' + '='.repeat(60));
  console.log('✓ Transfer Phase Complete');
  console.log('='.repeat(60));

  // ==================== WITHDRAWAL PHASE ====================
  console.log('\n' + '='.repeat(60));
  console.log('Starting Withdrawal Phase');
  console.log('='.repeat(60));

  // Setup recipient account
  const recipientAccount = privateKeyToAccount(TEST_PRIVATE_KEY_1 as Hex);
  console.log(`\nRecipient withdrawing: ${recipientAccount.address}`);

  // Recipient's nullifier key (different from sender's)
  const recipientNullifierKey = randomBigInt();

  // Get recipient's ETH balance before withdrawal
  const balanceBefore = await publicClient.getBalance({ address: recipientAccount.address });
  console.log(`Recipient ETH balance before: ${formatEther(balanceBefore)} ETH`);

  // ==================== SIGN WITHDRAWAL TX ====================
  console.log('\n--- Signing Withdrawal Transaction ---');

  // Withdraw the full recipient note amount (dust note will be added as second input)
  // Total withdrawal = recipient note + dust note = 0.5 ETH + 1 wei
  const withdrawAmount = recipientNote.amount + 1n; // Full note + dust
  const withdrawNonce = 0n; // Recipient's first tx on virtual chain

  // For withdrawal, sign tx to SENTINEL address (0x1)
  const withdrawTx = {
    chainId: Number(VIRTUAL_CHAIN_ID),
    nonce: Number(withdrawNonce),
    maxPriorityFeePerGas: FIXED_MAX_PRIORITY_FEE,
    maxFeePerGas: FIXED_MAX_FEE,
    gas: FIXED_GAS_LIMIT,
    to: WITHDRAW_SENTINEL as Hex,
    value: withdrawAmount,
    type: 'eip1559' as const,
  };

  const withdrawSerializedUnsigned = serializeTransaction(withdrawTx);
  const withdrawUnsignedHash = keccak256(withdrawSerializedUnsigned);
  console.log(`Unsigned withdraw tx hash: ${withdrawUnsignedHash.slice(0, 20)}...`);

  const signedWithdrawTx = await recipientAccount.signTransaction(withdrawTx);
  console.log(`Signed withdraw tx: ${signedWithdrawTx.slice(0, 30)}...`);

  // Parse signature
  const { r: wR, s: wS, yParity: wYParity } = await (async () => {
    const { parseTransaction } = await import('viem');
    const parsed = parseTransaction(signedWithdrawTx as Hex);
    return { r: parsed.r!, s: parsed.s!, yParity: parsed.yParity! };
  })();

  const withdrawPubKey = await recoverPublicKey({
    hash: withdrawUnsignedHash,
    signature: { r: wR, s: wS, yParity: wYParity },
  });
  console.log(`Recovered pubkey: ${withdrawPubKey.slice(0, 30)}...`);

  const withdrawSignatureData = extractSignatureFromTx(wR, wS, withdrawPubKey);

  // ==================== BUILD WITHDRAW INPUTS ====================
  console.log('\n--- Building Withdraw Circuit Inputs ---');

  // Get current merkle root from contract
  const withdrawMerkleRoot = await privacyPool.read.getLastRoot();

  // For withdrawal with single note, we need a second input
  // The contract requires msg.value > 0, so we deposit a dust note (1 wei) for the recipient
  const dustNoteRandomness = randomBigInt();
  const dustNoteAmount = 1n; // 1 wei - minimum allowed
  const dustNoteOwner = BigInt(recipientAccount.address);
  const dustNoteCommitment = computeCommitment(dustNoteAmount, dustNoteOwner, dustNoteRandomness);

  console.log('Depositing dust note (1 wei) for second input...');
  const dustDepositHash = await privacyPool.write.deposit(
    [dustNoteCommitment, '0x'],
    { value: dustNoteAmount }
  );
  await publicClient.waitForTransactionReceipt({ hash: dustDepositHash });
  const dustLeafIndex = merkleTree.insert(dustNoteCommitment);
  console.log(`Dust note at leaf index: ${dustLeafIndex}`);

  // Now get the updated merkle root
  const updatedWithdrawRoot = await privacyPool.read.getLastRoot();
  const localWithdrawRoot = merkleTree.getRoot();

  if (updatedWithdrawRoot !== localWithdrawRoot) {
    throw new Error('Merkle root mismatch after zero deposit!');
  }

  // Generate merkle proofs
  const recipientNoteProof = merkleTree.generateProof(recipientNote.leafIndex);
  const dustNoteProof = merkleTree.generateProof(dustLeafIndex);

  // Compute nullifiers
  const withdrawNullifier0 = computeNullifier(recipientNote.commitment, recipientNullifierKey);
  const withdrawNullifier1 = computeNullifier(dustNoteCommitment, recipientNullifierKey);
  console.log(`Nullifier 0: ${withdrawNullifier0.toString(16).slice(0, 16)}...`);
  console.log(`Nullifier 1: ${withdrawNullifier1.toString(16).slice(0, 16)}...`);

  // Change note (zero change since withdrawing full amount + dust)
  // Total input = 0.5 ETH + 1 wei, withdraw = 0.5 ETH + 1 wei, change = 0
  const changeAmount = 0n;
  const changeRandomness = randomBigInt();
  const changeCommitment = computeCommitment(changeAmount, dustNoteOwner, changeRandomness);

  // Compute withdraw intent nullifier
  const withdrawIntentNullifier = computeWithdrawIntentNullifier(
    BigInt(recipientAccount.address),
    VIRTUAL_CHAIN_ID,
    withdrawNonce,
    withdrawAmount
  );
  console.log(`Withdraw intent nullifier: ${withdrawIntentNullifier.toString(16).slice(0, 16)}...`);

  // Build withdraw circuit inputs
  const withdrawInputs: WithdrawCircuitInputs = {
    merkleRoot: localWithdrawRoot,
    nullifier0: withdrawNullifier0,
    nullifier1: withdrawNullifier1,
    changeCommitment,
    intentNullifier: withdrawIntentNullifier,
    withdrawRecipient: BigInt(recipientAccount.address),
    withdrawAmount,

    signatureData: withdrawSignatureData,
    txNonce: withdrawNonce,

    input0: {
      amount: recipientNote.amount,
      randomness: recipientNote.randomness,
      leafIndex: recipientNote.leafIndex,
      siblings: recipientNoteProof.siblings,
    },
    input1: {
      amount: dustNoteAmount,
      randomness: dustNoteRandomness,
      leafIndex: dustLeafIndex,
      siblings: dustNoteProof.siblings,
    },

    changeAmount,
    changeRandomness,
    nullifierKey: recipientNullifierKey,
  };

  // ==================== GENERATE WITHDRAW PROOF ====================
  console.log('\n--- Generating Withdraw ZK Proof ---');
  console.log('This may take 30-60 seconds...');

  const withdrawStartTime = Date.now();
  const { proof: withdrawProof } = await generateWithdrawProof(withdrawInputs);
  const withdrawProofTime = (Date.now() - withdrawStartTime) / 1000;
  console.log(`Withdraw proof generated in ${withdrawProofTime.toFixed(1)}s`);
  console.log(`Proof size: ${withdrawProof.length} bytes`);

  // ==================== SUBMIT WITHDRAWAL ====================
  console.log('\n--- Submitting Withdrawal to Privacy Pool ---');

  const withdrawProofHex = bytesToHex(withdrawProof) as Hex;

  const withdrawHash = await privacyPool.write.withdraw([
    withdrawProofHex,
    localWithdrawRoot,
    [withdrawNullifier0, withdrawNullifier1],
    changeCommitment,
    withdrawIntentNullifier,
    recipientAccount.address,
    withdrawAmount,
    '0x', // empty encrypted change
  ]);

  console.log(`Withdraw tx: ${withdrawHash}`);

  const withdrawReceipt = await publicClient.waitForTransactionReceipt({ hash: withdrawHash });
  console.log(`Withdraw status: ${withdrawReceipt.status === 'success' ? '✓ Success' : '✗ Failed'}`);

  if (withdrawReceipt.status !== 'success') {
    throw new Error('Withdrawal transaction failed!');
  }

  // ==================== VERIFY WITHDRAWAL STATE ====================
  console.log('\n--- Verifying Withdrawal State ---');

  // Check nullifiers spent
  const wNullifier0Spent = await privacyPool.read.nullifierSpent([withdrawNullifier0]);
  const wNullifier1Spent = await privacyPool.read.nullifierSpent([withdrawNullifier1]);
  console.log(`Withdraw nullifier 0 spent: ${wNullifier0Spent ? '✓' : '✗'}`);
  console.log(`Withdraw nullifier 1 spent: ${wNullifier1Spent ? '✓' : '✗'}`);

  if (!wNullifier0Spent || !wNullifier1Spent) {
    throw new Error('Withdraw nullifiers not marked as spent!');
  }

  // Check intent used
  const withdrawIntentUsed = await privacyPool.read.intentUsed([withdrawIntentNullifier]);
  console.log(`Withdraw intent used: ${withdrawIntentUsed ? '✓' : '✗'}`);

  if (!withdrawIntentUsed) {
    throw new Error('Withdraw intent not marked as used!');
  }

  // Check recipient received ETH
  const balanceAfter = await publicClient.getBalance({ address: recipientAccount.address });
  const ethReceived = balanceAfter - balanceBefore;
  console.log(`Recipient ETH balance after: ${formatEther(balanceAfter)} ETH`);
  console.log(`ETH received (minus gas): ~${formatEther(ethReceived)} ETH`);

  // Balance should have increased by approximately the withdraw amount (minus gas for the withdraw tx)
  // Note: The recipient didn't pay for the withdraw tx in this test setup, pool sent ETH to them
  if (balanceAfter <= balanceBefore) {
    throw new Error('Recipient did not receive ETH!');
  }

  // ==================== SUCCESS ====================
  console.log('\n' + '='.repeat(60));
  console.log('✓ E2E Transfer + Withdraw Test PASSED!');
  console.log('='.repeat(60));
  console.log('\nSummary:');
  console.log(`  - Deposited: 2 x ${formatEther(depositAmount)} ETH`);
  console.log(`  - Transferred: ${formatEther(transferAmount)} ETH to recipient`);
  console.log(`  - Change: ${formatEther(output1Amount)} ETH back to sender`);
  console.log(`  - Transfer proof: ${proofTime.toFixed(1)}s`);
  console.log(`  - Withdrawn: ${formatEther(withdrawAmount)} ETH to recipient`);
  console.log(`  - Withdraw proof: ${withdrawProofTime.toFixed(1)}s`);
  console.log(`  - All state verifications passed`);
}

main().catch((error) => {
  console.error('\n✗ E2E Test FAILED:');
  console.error(error);
  process.exit(1);
});
