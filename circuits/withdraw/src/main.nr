// SPDX-License-Identifier: MIT
// Privacy Pool Withdraw Circuit - Secure Implementation
//
// SECURITY FIXES IMPLEMENTED:
// 1. Compute EIP-1559 signing hash in-circuit (binds signature to tx fields)
// 2. tx_nonce is private, but recipient/amount are public (required for withdrawal)
// 3. Remove redundant owner witnesses (use signer_address directly)
// 4. Use u128 for amounts (prevents Field overflow)
// 5. Use Poseidon hash (matches Solidity contracts)

use poseidon::poseidon::bn254::hash_2;
use poseidon::poseidon::bn254::hash_4;
use poseidon::poseidon::bn254::hash_5;
use keccak256::keccak256;

// ========================== CONSTANTS ==========================

// Tree depth must match contract
global TREE_DEPTH: u32 = 20;

// Virtual chain ID for replay protection (matches contract)
global VIRTUAL_CHAIN_ID: Field = 13371337;

// Chain ID for EIP-1559 tx
global CHAIN_ID: u64 = 13371337;

// Maximum RLP encoded length for EIP-1559 tx with our fixed params
global MAX_RLP_LEN: u32 = 128;

// Sentinel address for withdrawals - user signs tx to this address to trigger withdrawal
global WITHDRAW_SENTINEL: Field = 1;

// Domain separator for nullifier key hash computation
global NULLIFIER_KEY_DOMAIN: Field = 1;

// ========================== MAIN CIRCUIT ==========================

fn main(
    // ===== Public Inputs (7 total) =====
    merkle_root: pub Field,
    nullifier_0: pub Field,
    nullifier_1: pub Field,
    change_commitment: pub Field,      // Change note stays in pool
    intent_nullifier: pub Field,
    withdraw_recipient: pub Field,      // L1 address receiving funds (PUBLIC - contract needs this)
    withdraw_amount: pub Field,         // Amount leaving the pool (PUBLIC - contract needs this)

    // ===== Private Inputs =====
    // ECDSA signature components
    pub_key_x: [u8; 32],
    pub_key_y: [u8; 32],
    signature: [u8; 64],

    // Transaction fields (PRIVATE)
    tx_nonce: u64,
    tx_max_priority_fee: u64,
    tx_max_fee: u64,
    tx_gas_limit: u64,

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

    // Change note (stays in pool, goes back to sender)
    change_amount: u128,
    change_randomness: Field,

    // Nullifier key (private - used to compute nullifiers)
    nullifier_key: Field,
) {
    // ========================== 0. VALIDATE PUBLIC INPUT BOUNDS ==========================
    // withdraw_amount is a pub Field but used as u128 in value checks.
    // Validate it fits in u128 to prevent silent truncation attacks.
    let withdraw_amount_u128 = withdraw_amount as u128;
    assert(withdraw_amount_u128 as Field == withdraw_amount, "withdraw_amount exceeds u128");

    // ========================== 1. COMPUTE SIGNING HASH ==========================
    // CRITICAL: This binds the ECDSA signature to the actual transaction fields
    // For withdrawals, user signs tx to SENTINEL address (0x1), not the actual recipient
    // This matches the UX where sending to sentinel triggers a withdrawal

    let signing_hash = compute_eip1559_signing_hash(tx_nonce, WITHDRAW_SENTINEL, withdraw_amount_u128, tx_max_priority_fee, tx_max_fee, tx_gas_limit);

    // ========================== 2. VERIFY ECDSA SIGNATURE ==========================
    // Signature must be over the EIP-1559 signing hash we just computed

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

    // Withdrawals can only go to the signer's own address (security constraint)
    assert(withdraw_recipient == signer_address, "Can only withdraw to self");

    // ========================== 3.5. COMPUTE SIGNER'S NULLIFIER KEY HASH ==========================
    // This binds the nullifier key to the commitments, preventing double-spend attacks
    let signer_nk_hash = hash_2([nullifier_key, NULLIFIER_KEY_DOMAIN]);

    // ========================== 4. VERIFY INPUT NOTE 0 ==========================
    // Commitment = poseidon(amount, owner, randomness, nullifierKeyHash)
    // Owner MUST be signer (no separate witness - eliminates redundancy bug)

    let commitment_0 = hash_4([input_0_amount as Field, signer_address, input_0_randomness, signer_nk_hash]);
    let root_0 = compute_merkle_root(commitment_0, input_0_leaf_index, input_0_siblings);
    assert(root_0 == merkle_root, "Input 0 merkle proof invalid");

    // ========================== 5. VERIFY INPUT NOTE 1 ==========================
    // Phantom zero-input: When input_1_amount == 0, skip merkle verification.
    // This allows single-note transactions without requiring a "dust note" deposit.
    //
    // NOTE: Phantom inputs allow arbitrary nullifier_1 values, causing potential
    // nullifier set bloat. Production systems should use a sentinel (nullifier_1=0)
    // pattern. Acceptable for demo since it doesn't enable value theft.

    let commitment_1 = hash_4([input_1_amount as Field, signer_address, input_1_randomness, signer_nk_hash]);

    // Only verify merkle proof for non-phantom inputs
    if input_1_amount != 0 {
        let root_1 = compute_merkle_root(commitment_1, input_1_leaf_index, input_1_siblings);
        assert(root_1 == merkle_root, "Input 1 merkle proof invalid");

        // CRITICAL: Prevent using the same note twice (inflation attack)
        // Only checked when input_1 is non-phantom
        assert(input_0_leaf_index != input_1_leaf_index, "Duplicate input note");
    }

    // ========================== 6. VERIFY NULLIFIERS ==========================
    // nullifier = poseidon(commitment, nullifier_key)
    // nullifier_key is bound to the commitment via signer_nk_hash, making nullifiers deterministic per note

    let computed_nullifier_0 = hash_2([commitment_0, nullifier_key]);
    let computed_nullifier_1 = hash_2([commitment_1, nullifier_key]);
    assert(nullifier_0 == computed_nullifier_0, "Nullifier 0 mismatch");
    assert(nullifier_1 == computed_nullifier_1, "Nullifier 1 mismatch");

    // ========================== 7. VERIFY CHANGE COMMITMENT ==========================
    // Change goes back to signer (includes signer's nullifierKeyHash for spending)

    let computed_change = hash_4([change_amount as Field, signer_address, change_randomness, signer_nk_hash]);
    assert(change_commitment == computed_change, "Change commitment mismatch");

    // ========================== 8. VALUE CONSERVATION ==========================
    // Using u128 prevents Field overflow attacks
    // inputs = change + withdraw_amount

    let total_in = input_0_amount + input_1_amount;
    let total_out = change_amount + withdraw_amount_u128;
    assert(total_in == total_out, "Value not conserved");

    // ========================== 9. INTENT NULLIFIER ==========================
    // Replay protection: hash(signer, chainId, nonce, to, value)
    // Uses WITHDRAW_SENTINEL as 'to' to match what was actually signed
    // (withdraw_recipient == signer is enforced separately above)

    let computed_intent = hash_5([
        signer_address,
        VIRTUAL_CHAIN_ID,
        tx_nonce as Field,
        WITHDRAW_SENTINEL,
        withdraw_amount
    ]);
    assert(intent_nullifier == computed_intent, "Intent nullifier mismatch");
}

// ========================== HELPER FUNCTIONS ==========================

/// Compute EIP-1559 signing hash with gas parameters
/// signing_hash = keccak256(0x02 || rlp([chainId, nonce, maxPriorityFee, maxFee, gas, to, value, "", []]))
///
/// IMPORTANT: All RLP encoding is inlined here to avoid Noir's pass-by-value semantics
/// which would cause buffer modifications to be lost when using helper functions.
fn compute_eip1559_signing_hash(nonce: u64, to: Field, value: u128, max_priority_fee: u64, max_fee: u64, gas_limit: u64) -> [u8; 32] {
    // Validate 'to' address doesn't have high bits set (security fix for Field truncation)
    // Note: For withdrawals, 'to' is WITHDRAW_SENTINEL (1) which has no high bits
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

    // 3. maxPriorityFeePerGas (variable length)
    pos = encode_u64_rlp(&mut rlp_buffer, pos, max_priority_fee);

    // 4. maxFeePerGas (variable length)
    pos = encode_u64_rlp(&mut rlp_buffer, pos, max_fee);

    // 5. gasLimit (variable length)
    pos = encode_u64_rlp(&mut rlp_buffer, pos, gas_limit);

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

/// RLP encode a u64 value into the buffer at position pos, returns new position
/// Note: Takes mutable reference to avoid Noir's pass-by-value copy issue
fn encode_u64_rlp(buffer: &mut [u8; MAX_RLP_LEN], pos: u32, value: u64) -> u32 {
    let mut new_pos = pos;
    if value == 0 {
        buffer[new_pos] = 0x80;
        new_pos += 1;
    } else if value < 128 {
        buffer[new_pos] = value as u8;
        new_pos += 1;
    } else {
        let bytes = u64_to_be_bytes(value);
        // Find first non-zero byte
        let mut start: u32 = 8;
        for i in 0..8 {
            if (bytes[i] != 0) & (start == 8) {
                start = i as u32;
            }
        }
        let len = 8 - start;
        buffer[new_pos] = (0x80 + len) as u8;
        new_pos += 1;
        for i in 0..8 {
            if i >= start {
                buffer[new_pos] = bytes[i];
                new_pos += 1;
            }
        }
    }
    new_pos
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
fn test_signing_hash_matches_viem_withdrawal() {
    // From fixtures/eip1559-signed-txs.json "withdrawal_to_sentinel"
    // Withdrawal: send 0.5 ETH to sentinel address 0x1, nonce 1
    let nonce: u64 = 1;
    let to: Field = WITHDRAW_SENTINEL; // 0x0000000000000000000000000000000000000001
    let value: u128 = 500000000000000000; // 0.5 ETH in wei
    // Gas params from fixture
    let max_priority_fee: u64 = 1000000000;  // 1 gwei
    let max_fee: u64 = 30000000000;          // 30 gwei
    let gas_limit: u64 = 21000;

    let hash = compute_eip1559_signing_hash(nonce, to, value, max_priority_fee, max_fee, gas_limit);

    // Expected unsigned_hash from viem: 0x71f39ba3735b50936b9104f3daad67708ac6be21afd870d16cb81142bde86e58
    let expected: [u8; 32] = [
        113, 243, 155, 163, 115, 91, 80, 147,
        107, 145, 4, 243, 218, 173, 103, 112,
        138, 198, 190, 33, 175, 216, 112, 209,
        108, 184, 17, 66, 189, 232, 110, 88
    ];

    assert(hash == expected, "Signing hash does not match viem fixture");
}

