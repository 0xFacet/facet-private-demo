// SPDX-License-Identifier: MIT
// Privacy Pool Transfer Circuit - Production Implementation
//
// SECURITY FEATURES:
// 1. In-circuit encryption prevents adapter from corrupting ciphertext
// 2. Private registry membership proof binds tx_to -> pubkey -> nkHash
// 3. Ciphertext hash as public output - contract verifies match
// 4. u32 leaf indices prevent aliasing attacks
// 5. Value conservation in Field (not u128) prevents wrap
// 6. Domain separators prevent cross-protocol collisions

use std::embedded_curve_ops::EmbeddedCurvePoint;
use keccak256::keccak256;
use common::constants::{
    TREE_DEPTH, REGISTRY_DEPTH, VIRTUAL_CHAIN_ID, CHAIN_ID, MAX_RLP_LEN,
    NULLIFIER_KEY_DOMAIN, NULLIFIER_DOMAIN, INTENT_DOMAIN, PHANTOM_NULLIFIER_DOMAIN
};
use common::hashes::{hash_2, hash_4};
use common::scalar::{assert_is_address, assert_is_u128};
use common::merkle::verify_merkle_membership;
use common::registry::verify_registry_membership;
use common::encryption::{derive_enc_seed, encrypt_note_ecdh, encrypt_note_self, ciphertext_hash};

// ========================== MAIN CIRCUIT ==========================

fn main(
    // ===== PUBLIC INPUTS (8 total) =====
    merkle_root: pub Field,
    nullifier_0: pub Field,
    nullifier_1: pub Field,
    output_commitment_0: pub Field,
    output_commitment_1: pub Field,
    intent_nullifier: pub Field,
    registry_root: pub Field,
    ciphertext_hash_pub: pub Field,

    // ===== PRIVATE INPUTS =====
    // ECDSA signature components
    pub_key_x: [u8; 32],
    pub_key_y: [u8; 32],
    signature: [u8; 64],

    // Transaction fields (PRIVATE - not revealed on-chain)
    tx_nonce: u64,
    tx_to: Field,      // 20-byte recipient address as Field
    tx_value: u128,    // wei amount
    tx_max_priority_fee: u64,
    tx_max_fee: u64,
    tx_gas_limit: u64,

    // Input note 0 (index is u32!)
    input_0_amount: u128,
    input_0_randomness: Field,
    input_0_leaf_index: u32,  // NOT Field!
    input_0_siblings: [Field; TREE_DEPTH],

    // Input note 1 (index is u32!)
    input_1_amount: u128,
    input_1_randomness: Field,
    input_1_leaf_index: u32,  // NOT Field!
    input_1_siblings: [Field; TREE_DEPTH],

    // Output note randomness
    output_0_randomness: Field,
    output_1_randomness: Field,

    // Keys
    nullifier_key: Field,

    // Registry membership proof (index is u32!)
    recipient_pubkey_x: Field,
    recipient_pubkey_y: Field,
    recipient_nk_hash: Field,
    recipient_leaf_index: u32,  // NOT Field!
    recipient_siblings: [Field; REGISTRY_DEPTH]
) {
    // ========================== 1. DEFENSE-IN-DEPTH CHECKS ==========================
    assert_is_address(tx_to);  // 160-bit range check
    assert(recipient_nk_hash != 0, "recipient nkHash cannot be zero");

    // ========================== 2. COMPUTE SIGNING HASH ==========================
    let signing_hash = compute_eip1559_signing_hash(
        tx_nonce, tx_to, tx_value,
        tx_max_priority_fee, tx_max_fee, tx_gas_limit
    );

    // ========================== 3. VERIFY ECDSA SIGNATURE ==========================
    let sig_valid = std::ecdsa_secp256k1::verify_signature(
        pub_key_x,
        pub_key_y,
        signature,
        signing_hash
    );
    assert(sig_valid, "Invalid ECDSA signature");

    // ========================== 4. DERIVE SIGNER IDENTITY ==========================
    let signer_address = derive_eth_address(pub_key_x, pub_key_y);
    let signer_nk_hash = hash_2([nullifier_key, NULLIFIER_KEY_DOMAIN]);

    // ========================== 5. VERIFY INPUT NOTE 0 ==========================
    let commitment_0 = hash_4([input_0_amount as Field, signer_address, input_0_randomness, signer_nk_hash]);
    verify_merkle_membership(merkle_root, commitment_0, input_0_leaf_index, input_0_siblings);

    // Nullifier with domain separator
    let input_0_idx_field: Field = input_0_leaf_index as Field;
    let computed_nullifier_0 = hash_4([NULLIFIER_DOMAIN, nullifier_key, input_0_idx_field, input_0_randomness]);
    assert(nullifier_0 == computed_nullifier_0, "Nullifier 0 mismatch");

    // ========================== 6. VERIFY INPUT NOTE 1 ==========================
    // Phantom zero-input: skip merkle verification when amount == 0
    // SECURITY: When phantom, use tx-bound nullifier to prevent poisoning attack
    if input_1_amount != 0 {
        let commitment_1 = hash_4([input_1_amount as Field, signer_address, input_1_randomness, signer_nk_hash]);
        verify_merkle_membership(merkle_root, commitment_1, input_1_leaf_index, input_1_siblings);
        assert(input_0_leaf_index != input_1_leaf_index, "Duplicate input note");

        // Real note: nullifier from leaf index and randomness
        let input_1_idx_field: Field = input_1_leaf_index as Field;
        let computed_nullifier_1 = hash_4([NULLIFIER_DOMAIN, nullifier_key, input_1_idx_field, input_1_randomness]);
        assert(nullifier_1 == computed_nullifier_1, "Nullifier 1 mismatch");
    } else {
        // Phantom note: nullifier bound to tx_nonce, cannot collide with real notes
        // This prevents adapter from poisoning real notes by choosing arbitrary (leaf_index, randomness)
        let phantom_nullifier = hash_4([PHANTOM_NULLIFIER_DOMAIN, nullifier_key, tx_nonce as Field, 0]);
        assert(nullifier_1 == phantom_nullifier, "Phantom nullifier mismatch");
    }

    // ========================== 7. VERIFY RECIPIENT REGISTRY MEMBERSHIP ==========================
    verify_registry_membership(
        registry_root,
        tx_to,
        recipient_pubkey_x,
        recipient_pubkey_y,
        recipient_nk_hash,
        recipient_leaf_index,
        recipient_siblings
    );

    // ========================== 8. VALUE CONSERVATION ==========================
    // Sum inputs in Field to avoid u128 wrap-around
    let in_sum: Field = (input_0_amount as Field) + (input_1_amount as Field);

    // Compute change amount (output_1 goes to sender as change)
    let output_1_amount_field = in_sum - (tx_value as Field);

    // CRITICAL: Assert change is non-negative (prevents field underflow attack)
    // Without this, attacker could set tx_value > in_sum and wrap to huge positive
    assert_is_u128(output_1_amount_field);

    // Conservation check: in_sum == tx_value + change
    let out_sum: Field = (tx_value as Field) + output_1_amount_field;
    assert(in_sum == out_sum, "Value not conserved");

    // ========================== 9. VERIFY OUTPUT COMMITMENTS ==========================
    let computed_output_0 = hash_4([tx_value as Field, tx_to, output_0_randomness, recipient_nk_hash]);
    assert(output_commitment_0 == computed_output_0, "Output 0 commitment mismatch");

    let computed_output_1 = hash_4([output_1_amount_field, signer_address, output_1_randomness, signer_nk_hash]);
    assert(output_commitment_1 == computed_output_1, "Output 1 commitment mismatch");

    // ========================== 10. IN-CIRCUIT ENCRYPTION ==========================
    let enc_seed = derive_enc_seed(nullifier_key);

    // Recipient note (ECDH encryption)
    let recipient_pubkey = EmbeddedCurvePoint {
        x: recipient_pubkey_x,
        y: recipient_pubkey_y,
        is_infinite: false
    };
    let encrypted_0 = encrypt_note_ecdh(
        enc_seed,
        recipient_pubkey,
        tx_value as Field,
        tx_to,
        output_0_randomness,
        tx_nonce as Field,
        0
    );

    // Change note (self-encryption, no ECDH)
    let encrypted_1 = encrypt_note_self(
        enc_seed,
        output_1_amount_field,
        signer_address,
        output_1_randomness,
        tx_nonce as Field
    );

    // ========================== 11. VERIFY CIPHERTEXT HASH ==========================
    let computed_ct_hash = ciphertext_hash(encrypted_0, encrypted_1);
    assert(ciphertext_hash_pub == computed_ct_hash, "Ciphertext hash mismatch");

    // ========================== 12. INTENT NULLIFIER ==========================
    let computed_intent = hash_4([INTENT_DOMAIN, nullifier_key, VIRTUAL_CHAIN_ID, tx_nonce as Field]);
    assert(intent_nullifier == computed_intent, "Intent nullifier mismatch");
}

// ========================== HELPER FUNCTIONS ==========================

/// Compute EIP-1559 signing hash
fn compute_eip1559_signing_hash(
    nonce: u64,
    to: Field,
    value: u128,
    max_priority_fee: u64,
    max_fee: u64,
    gas_limit: u64
) -> [u8; 32] {
    // Validate 'to' address doesn't have high bits set
    let to_bytes: [u8; 32] = to.to_be_bytes();
    for i in 0..12 {
        assert(to_bytes[i] == 0, "tx_to has invalid high bits");
    }

    let mut rlp_buffer: [u8; MAX_RLP_LEN] = [0; MAX_RLP_LEN];
    let mut pos: u32 = 0;

    // Reserve 1 byte for list prefix
    pos = 1;

    // 1. chainId = 13371337 (0xCC07C9) - 3 bytes
    let chain_bytes = u64_to_be_bytes(CHAIN_ID);
    rlp_buffer[pos] = 0x83;
    rlp_buffer[pos + 1] = chain_bytes[5];
    rlp_buffer[pos + 2] = chain_bytes[6];
    rlp_buffer[pos + 3] = chain_bytes[7];
    pos += 4;

    // 2. nonce
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

    // 3. maxPriorityFeePerGas
    pos = encode_u64_rlp(&mut rlp_buffer, pos, max_priority_fee);

    // 4. maxFeePerGas
    pos = encode_u64_rlp(&mut rlp_buffer, pos, max_fee);

    // 5. gasLimit
    pos = encode_u64_rlp(&mut rlp_buffer, pos, gas_limit);

    // 6. to = 20-byte address
    rlp_buffer[pos] = 0x94;
    pos += 1;
    for i in 0..20 {
        rlp_buffer[pos + i] = to_bytes[12 + i];
    }
    pos += 20;

    // 7. value
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

    // 8. data = empty
    rlp_buffer[pos] = 0x80;
    pos += 1;

    // 9. accessList = empty
    rlp_buffer[pos] = 0xc0;
    pos += 1;

    // Set list prefix
    let list_len = pos - 1;
    assert(list_len < 56, "RLP list too long");
    rlp_buffer[0] = (0xc0 + list_len) as u8;

    // Build final buffer: 0x02 type byte + RLP
    let mut to_hash: [u8; MAX_RLP_LEN] = [0; MAX_RLP_LEN];
    to_hash[0] = 0x02;
    for i in 0..MAX_RLP_LEN - 1 {
        to_hash[i + 1] = rlp_buffer[i];
    }

    keccak256(to_hash, (pos + 1) as u32)
}

fn encode_u64_rlp(buffer: &mut [u8; MAX_RLP_LEN], pos: u32, value: u64) -> u32 {
    let mut new_pos = pos;
    if value == 0 {
        buffer[new_pos] = 0x80;
        new_pos += 1;
    } else if value < 128 {
        buffer[new_pos] = value as u8;
        new_pos += 1;
    } else {
        let value_bytes = u64_to_be_bytes(value);
        let mut value_start: u32 = 8;
        for i in 0..8 {
            if (value_bytes[i] != 0) & (value_start == 8) {
                value_start = i as u32;
            }
        }
        let value_len = 8 - value_start;
        buffer[new_pos] = (0x80 + value_len) as u8;
        new_pos += 1;
        for i in 0..8 {
            if i >= value_start {
                buffer[new_pos] = value_bytes[i];
                new_pos += 1;
            }
        }
    }
    new_pos
}

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

fn derive_eth_address(pub_key_x: [u8; 32], pub_key_y: [u8; 32]) -> Field {
    let mut pubkey: [u8; 64] = [0; 64];
    for i in 0..32 {
        pubkey[i] = pub_key_x[i];
        pubkey[32 + i] = pub_key_y[i];
    }

    let hash = keccak256(pubkey, 64);

    let mut addr_bytes: [u8; 20] = [0; 20];
    for i in 0..20 {
        addr_bytes[i] = hash[12 + i];
    }

    let mut result: Field = 0;
    for i in 0..20 {
        result = result * 256 + addr_bytes[i] as Field;
    }
    result
}

// ========================== TESTS ==========================

#[test]
fn test_signing_hash_matches_viem() {
    let nonce: u64 = 0;
    let to: Field = 0x70997970C51812dc3A010C7d01b50e0d17dc79C8;
    let value: u128 = 1000000000000000000;

    let hash = compute_eip1559_signing_hash(nonce, to, value, 1000000000, 30000000000, 21000);

    let expected: [u8; 32] = [
        137, 238, 115, 151, 190, 203, 99, 101,
        43, 250, 163, 189, 75, 47, 160, 103,
        252, 151, 88, 236, 75, 104, 21, 4,
        166, 239, 141, 149, 130, 142, 32, 132
    ];

    assert(hash == expected, "Signing hash mismatch");
}
