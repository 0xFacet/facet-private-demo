// SPDX-License-Identifier: MIT
// Privacy Pool Transfer Circuit - Secure Implementation
//
// SECURITY FIXES IMPLEMENTED:
// 1. Compute EIP-1559 signing hash in-circuit (binds signature to tx fields)
// 2. tx_to, tx_value, tx_nonce are private inputs (privacy)
// 3. Remove redundant owner witnesses (use signer_address directly)
// 4. Use u128 for amounts (prevents Field overflow)
// 5. Use Poseidon hash (matches Solidity contracts)

use poseidon::poseidon::bn254::hash_2;
use poseidon::poseidon::bn254::hash_3;
use poseidon::poseidon::bn254::hash_5;
use keccak256::keccak256;

// ========================== CONSTANTS ==========================

// Tree depth must match contract
global TREE_DEPTH: u32 = 20;

// Virtual chain ID for replay protection (matches contract)
global VIRTUAL_CHAIN_ID: Field = 13371337;

// Fixed gas params for EIP-1559 tx (must match adapter)
global CHAIN_ID: u64 = 13371337;
global MAX_PRIORITY_FEE_PER_GAS: u64 = 1000000000; // 1 gwei
global MAX_FEE_PER_GAS: u64 = 30000000000; // 30 gwei
global GAS_LIMIT: u64 = 21000; // simple transfer

// Maximum RLP encoded length for EIP-1559 tx with our fixed params
// chainId (5) + nonce (9) + maxPriorityFee (9) + maxFee (9) + gasLimit (5) + to (21) + value (9) + data (1) + accessList (1) + list overhead (3) = ~72
global MAX_RLP_LEN: u32 = 128;

// ========================== MAIN CIRCUIT ==========================

fn main(
    // ===== Public Inputs (6 total) =====
    merkle_root: pub Field,
    nullifier_0: pub Field,
    nullifier_1: pub Field,
    output_commitment_0: pub Field,
    output_commitment_1: pub Field,
    intent_nullifier: pub Field,

    // ===== Private Inputs =====
    // ECDSA signature components
    pub_key_x: [u8; 32],
    pub_key_y: [u8; 32],
    signature: [u8; 64],

    // Transaction fields (PRIVATE - not revealed on-chain)
    tx_nonce: u64,
    tx_to: Field,      // 20-byte recipient address as Field
    tx_value: u128,    // wei amount

    // Input note 0
    input_0_amount: u128,
    input_0_randomness: Field,
    input_0_leaf_index: u32,
    input_0_siblings: [Field; TREE_DEPTH],

    // Input note 1
    input_1_amount: u128,
    input_1_randomness: Field,
    input_1_leaf_index: u32,
    input_1_siblings: [Field; TREE_DEPTH],

    // Output note 0 (to recipient)
    output_0_amount: u128,
    output_0_owner: Field,     // recipient address
    output_0_randomness: Field,

    // Output note 1 (change back to sender)
    output_1_amount: u128,
    output_1_randomness: Field,

    // Secret key for nullifier derivation
    nullifier_key: Field,
) {
    // ========================== 1. COMPUTE SIGNING HASH ==========================
    // CRITICAL: This binds the ECDSA signature to the actual transaction fields
    // Without this, a malicious prover could substitute any valid signature

    let signing_hash = compute_eip1559_signing_hash(tx_nonce, tx_to, tx_value);

    // ========================== 2. VERIFY ECDSA SIGNATURE ==========================
    // Signature must be over the EIP-1559 signing hash we just computed

    // Verify signature using Noir's stdlib
    let sig_valid = std::ecdsa_secp256k1::verify_signature(
        pub_key_x,
        pub_key_y,
        signature,
        signing_hash
    );
    assert(sig_valid, "Invalid ECDSA signature");

    // ========================== 3. DERIVE SIGNER ADDRESS ==========================
    // signer_address = keccak256(pubkey)[12:32] as Field

    let signer_address = derive_eth_address(pub_key_x, pub_key_y);

    // ========================== 4. VERIFY INPUT NOTE 0 ==========================
    // Commitment = poseidon(amount, owner, randomness)
    // Owner MUST be signer (no separate witness - eliminates redundancy bug)

    let commitment_0 = hash_3([input_0_amount as Field, signer_address, input_0_randomness]);
    let root_0 = compute_merkle_root(commitment_0, input_0_leaf_index, input_0_siblings);
    assert(root_0 == merkle_root, "Input 0 merkle proof invalid");

    // ========================== 5. VERIFY INPUT NOTE 1 ==========================

    let commitment_1 = hash_3([input_1_amount as Field, signer_address, input_1_randomness]);
    let root_1 = compute_merkle_root(commitment_1, input_1_leaf_index, input_1_siblings);
    assert(root_1 == merkle_root, "Input 1 merkle proof invalid");

    // ========================== 6. VERIFY NULLIFIERS ==========================
    // nullifier = poseidon(commitment, nullifier_key)
    // Using nullifier_key ensures only the note owner can compute the nullifier

    let computed_nullifier_0 = hash_2([commitment_0, nullifier_key]);
    let computed_nullifier_1 = hash_2([commitment_1, nullifier_key]);
    assert(nullifier_0 == computed_nullifier_0, "Nullifier 0 mismatch");
    assert(nullifier_1 == computed_nullifier_1, "Nullifier 1 mismatch");

    // ========================== 7. VERIFY OUTPUT COMMITMENTS ==========================
    // Output 0: to recipient
    // Output 1: change back to sender

    let computed_output_0 = hash_3([output_0_amount as Field, output_0_owner, output_0_randomness]);
    let computed_output_1 = hash_3([output_1_amount as Field, signer_address, output_1_randomness]);
    assert(output_commitment_0 == computed_output_0, "Output commitment 0 mismatch");
    assert(output_commitment_1 == computed_output_1, "Output commitment 1 mismatch");

    // ========================== 8. VALUE CONSERVATION ==========================
    // Using u128 prevents Field overflow attacks

    let total_in = input_0_amount + input_1_amount;
    let total_out = output_0_amount + output_1_amount;
    assert(total_in == total_out, "Value not conserved");

    // ========================== 9. TX FIELD BINDING ==========================
    // Link the private tx fields to the commitments
    // This proves the signed tx matches what we're proving

    assert(output_0_owner == tx_to, "Recipient doesn't match tx.to");
    assert(output_0_amount == tx_value, "Amount doesn't match tx.value");

    // ========================== 10. INTENT NULLIFIER ==========================
    // Replay protection: hash(signer, chainId, nonce, to, value)
    // Prevents same intent from being used twice

    let computed_intent = hash_5([
        signer_address,
        VIRTUAL_CHAIN_ID,
        tx_nonce as Field,
        tx_to,
        tx_value as Field
    ]);
    assert(intent_nullifier == computed_intent, "Intent nullifier mismatch");
}

// ========================== HELPER FUNCTIONS ==========================

/// Compute EIP-1559 signing hash with fixed gas parameters
/// signing_hash = keccak256(0x02 || rlp([chainId, nonce, maxPriorityFee, maxFee, gas, to, value, "", []]))
///
/// IMPORTANT: All RLP encoding is inlined here to avoid Noir's pass-by-value semantics
/// which would cause buffer modifications to be lost when using helper functions.
fn compute_eip1559_signing_hash(nonce: u64, to: Field, value: u128) -> [u8; 32] {
    // Validate 'to' address doesn't have high bits set (security fix for Field truncation)
    let to_bytes: [u8; 32] = to.to_be_bytes();
    for i in 0..12 {
        assert(to_bytes[i] == 0, "tx_to has invalid high bits");
    }

    // RLP encode the transaction - all encoding inlined to avoid copy-by-value bug
    let mut rlp_buffer: [u8; MAX_RLP_LEN] = [0; MAX_RLP_LEN];
    let mut pos: u32 = 0;

    // Reserve 1 byte for list prefix (short list format since list_len < 56)
    pos = 1;

    // 1. chainId = 13371337 (0xCC07C9) - 3 bytes, needs prefix 0x83
    let chain_bytes = u64_to_be_bytes(CHAIN_ID);
    // chainId = 13371337 = 0x00CC07C9, starts at byte 5 (index 4), length 3
    rlp_buffer[pos] = 0x83; // 0x80 + 3
    rlp_buffer[pos + 1] = chain_bytes[5];
    rlp_buffer[pos + 2] = chain_bytes[6];
    rlp_buffer[pos + 3] = chain_bytes[7];
    pos += 4;

    // 2. nonce (variable length)
    if nonce == 0 {
        rlp_buffer[pos] = 0x80;
        pos += 1;
    } else if nonce < 128 {
        rlp_buffer[pos] = nonce as u8;
        pos += 1;
    } else {
        let nonce_bytes = u64_to_be_bytes(nonce);
        let mut nonce_start: u32 = 8;
        for i in 0..8 {
            if (nonce_bytes[i] != 0) & (nonce_start == 8) {
                nonce_start = i as u32;
            }
        }
        let nonce_len = 8 - nonce_start;
        rlp_buffer[pos] = (0x80 + nonce_len) as u8;
        pos += 1;
        for i in 0..8 {
            if i >= nonce_start {
                rlp_buffer[pos] = nonce_bytes[i];
                pos += 1;
            }
        }
    }

    // 3. maxPriorityFeePerGas = 1 gwei (0x3B9ACA00) - 4 bytes, needs prefix 0x84
    let priority_bytes = u64_to_be_bytes(MAX_PRIORITY_FEE_PER_GAS);
    // 1 gwei = 0x3B9ACA00, starts at byte 4, length 4
    rlp_buffer[pos] = 0x84; // 0x80 + 4
    rlp_buffer[pos + 1] = priority_bytes[4];
    rlp_buffer[pos + 2] = priority_bytes[5];
    rlp_buffer[pos + 3] = priority_bytes[6];
    rlp_buffer[pos + 4] = priority_bytes[7];
    pos += 5;

    // 4. maxFeePerGas = 30 gwei (0x06FC23AC00) - 5 bytes, needs prefix 0x85
    let fee_bytes = u64_to_be_bytes(MAX_FEE_PER_GAS);
    // 30 gwei = 0x06FC23AC00, starts at byte 3, length 5
    rlp_buffer[pos] = 0x85; // 0x80 + 5
    rlp_buffer[pos + 1] = fee_bytes[3];
    rlp_buffer[pos + 2] = fee_bytes[4];
    rlp_buffer[pos + 3] = fee_bytes[5];
    rlp_buffer[pos + 4] = fee_bytes[6];
    rlp_buffer[pos + 5] = fee_bytes[7];
    pos += 6;

    // 5. gasLimit = 21000 (0x5208) - 2 bytes, needs prefix 0x82
    let gas_bytes = u64_to_be_bytes(GAS_LIMIT);
    // 21000 = 0x5208, starts at byte 6, length 2
    rlp_buffer[pos] = 0x82; // 0x80 + 2
    rlp_buffer[pos + 1] = gas_bytes[6];
    rlp_buffer[pos + 2] = gas_bytes[7];
    pos += 3;

    // 6. to = 20-byte address, prefix 0x94
    rlp_buffer[pos] = 0x94; // 0x80 + 20
    pos += 1;
    for i in 0..20 {
        rlp_buffer[pos + i] = to_bytes[12 + i];
    }
    pos += 20;

    // 7. value (variable length)
    if value == 0 {
        rlp_buffer[pos] = 0x80;
        pos += 1;
    } else if value < 128 {
        rlp_buffer[pos] = value as u8;
        pos += 1;
    } else {
        let value_bytes = u128_to_be_bytes(value);
        let mut value_start: u32 = 16;
        for i in 0..16 {
            if (value_bytes[i] != 0) & (value_start == 16) {
                value_start = i as u32;
            }
        }
        let value_len = 16 - value_start;
        rlp_buffer[pos] = (0x80 + value_len) as u8;
        pos += 1;
        for i in 0..16 {
            if i >= value_start {
                rlp_buffer[pos] = value_bytes[i];
                pos += 1;
            }
        }
    }

    // 8. data = empty (0x80)
    rlp_buffer[pos] = 0x80;
    pos += 1;

    // 9. accessList = empty (0xc0)
    rlp_buffer[pos] = 0xc0;
    pos += 1;

    // Calculate list length and set prefix
    // list_len = pos - 1 (since we started at index 1)
    let list_len = pos - 1;

    // For our tx sizes, list_len will always be < 56 (minimum ~43, max ~60 with large nonce/value)
    // Use short list format: single byte prefix 0xc0 + len
    assert(list_len < 56, "RLP list too long for short format");
    rlp_buffer[0] = (0xc0 + list_len) as u8;

    // Build final buffer: 0x02 type byte + RLP encoded list
    let mut to_hash: [u8; MAX_RLP_LEN] = [0; MAX_RLP_LEN];
    to_hash[0] = 0x02; // EIP-1559 type byte
    for i in 0..MAX_RLP_LEN - 1 {
        to_hash[i + 1] = rlp_buffer[i];
    }

    // Hash: keccak256(0x02 || rlp_list)
    // Total length = 1 (type byte) + pos (RLP list including prefix)
    keccak256(to_hash, (pos + 1) as u32)
}

/// Convert u64 to big-endian bytes
fn u64_to_be_bytes(value: u64) -> [u8; 8] {
    let mut bytes: [u8; 8] = [0; 8];
    bytes[0] = ((value >> 56) & 0xff) as u8;
    bytes[1] = ((value >> 48) & 0xff) as u8;
    bytes[2] = ((value >> 40) & 0xff) as u8;
    bytes[3] = ((value >> 32) & 0xff) as u8;
    bytes[4] = ((value >> 24) & 0xff) as u8;
    bytes[5] = ((value >> 16) & 0xff) as u8;
    bytes[6] = ((value >> 8) & 0xff) as u8;
    bytes[7] = (value & 0xff) as u8;
    bytes
}

/// Convert u128 to big-endian bytes
fn u128_to_be_bytes(value: u128) -> [u8; 16] {
    let mut bytes: [u8; 16] = [0; 16];
    bytes[0] = ((value >> 120) & 0xff) as u8;
    bytes[1] = ((value >> 112) & 0xff) as u8;
    bytes[2] = ((value >> 104) & 0xff) as u8;
    bytes[3] = ((value >> 96) & 0xff) as u8;
    bytes[4] = ((value >> 88) & 0xff) as u8;
    bytes[5] = ((value >> 80) & 0xff) as u8;
    bytes[6] = ((value >> 72) & 0xff) as u8;
    bytes[7] = ((value >> 64) & 0xff) as u8;
    bytes[8] = ((value >> 56) & 0xff) as u8;
    bytes[9] = ((value >> 48) & 0xff) as u8;
    bytes[10] = ((value >> 40) & 0xff) as u8;
    bytes[11] = ((value >> 32) & 0xff) as u8;
    bytes[12] = ((value >> 24) & 0xff) as u8;
    bytes[13] = ((value >> 16) & 0xff) as u8;
    bytes[14] = ((value >> 8) & 0xff) as u8;
    bytes[15] = (value & 0xff) as u8;
    bytes
}

/// Derive Ethereum address from public key
/// address = keccak256(pubkey_x || pubkey_y)[12:32]
fn derive_eth_address(pub_key_x: [u8; 32], pub_key_y: [u8; 32]) -> Field {
    // Concatenate x and y coordinates
    let mut pubkey: [u8; 64] = [0; 64];
    for i in 0..32 {
        pubkey[i] = pub_key_x[i];
        pubkey[32 + i] = pub_key_y[i];
    }

    // Hash with keccak256
    let hash = keccak256(pubkey, 64);

    // Take last 20 bytes as address
    let mut addr_bytes: [u8; 20] = [0; 20];
    for i in 0..20 {
        addr_bytes[i] = hash[12 + i];
    }

    // Convert to Field
    let mut result: Field = 0;
    for i in 0..20 {
        result = result * 256 + addr_bytes[i] as Field;
    }
    result
}

/// Compute Merkle root from leaf and path
fn compute_merkle_root(
    leaf: Field,
    leaf_index: u32,
    siblings: [Field; TREE_DEPTH]
) -> Field {
    let mut current = leaf;
    let mut index = leaf_index;

    for i in 0..TREE_DEPTH {
        let sibling = siblings[i];

        // If index is even, current is left child; otherwise right child
        if index % 2 == 0 {
            current = hash_2([current, sibling]);
        } else {
            current = hash_2([sibling, current]);
        }

        index = index / 2;
    }

    current
}

// ========================== TESTS ==========================

#[test]
fn test_signing_hash_matches_viem_simple_transfer() {
    // From fixtures/eip1559-signed-txs.json "simple_transfer_1_eth"
    // Transfer 1 ETH from account_0 to account_1, nonce 0
    let nonce: u64 = 0;
    let to: Field = 0x70997970C51812dc3A010C7d01b50e0d17dc79C8;
    let value: u128 = 1000000000000000000; // 1 ETH in wei

    let hash = compute_eip1559_signing_hash(nonce, to, value);

    // Expected unsigned_hash from viem: 0x89ee7397becb63652bfaa3bd4b2fa067fc9758ec4b681504a6ef8d95828e2084
    let expected: [u8; 32] = [
        137, 238, 115, 151, 190, 203, 99, 101,
        43, 250, 163, 189, 75, 47, 160, 103,
        252, 151, 88, 236, 75, 104, 21, 4,
        166, 239, 141, 149, 130, 142, 32, 132
    ];

    assert(hash == expected, "Signing hash does not match viem fixture");
}
