// SPDX-License-Identifier: MIT
// Privacy Pool Withdraw Circuit - Production Implementation
//
// SECURITY FEATURES:
// 1. In-circuit encryption for change note
// 2. Registry membership proof for sender (validates sender is registered)
// 3. Ciphertext hash as public output - contract verifies match
// 4. u32 leaf indices prevent aliasing attacks
// 5. Value conservation in Field prevents wrap
// 6. Domain separators prevent cross-protocol collisions

use keccak256::keccak256;
use common::constants::{
    TREE_DEPTH, REGISTRY_DEPTH, VIRTUAL_CHAIN_ID, CHAIN_ID, MAX_RLP_LEN,
    NULLIFIER_KEY_DOMAIN, NULLIFIER_DOMAIN, INTENT_DOMAIN, PHANTOM_NULLIFIER_DOMAIN
};
use common::hashes::{hash_2, hash_4};
use common::scalar::{assert_is_address, assert_is_u128};
use common::merkle::verify_merkle_membership;
use common::registry::verify_registry_membership;
use common::encryption::{derive_enc_seed, encrypt_note_self, ciphertext_hash_single};

// Sentinel address for withdrawals - user signs tx to this address to trigger withdrawal
global WITHDRAW_SENTINEL: Field = 1;

// ========================== MAIN CIRCUIT ==========================

fn main(
    // ===== PUBLIC INPUTS (9 total) =====
    merkle_root: pub Field,
    nullifier_0: pub Field,
    nullifier_1: pub Field,
    change_commitment: pub Field,
    intent_nullifier: pub Field,
    withdraw_recipient: pub Field,      // L1 address receiving funds (PUBLIC)
    withdraw_amount: pub Field,         // Amount leaving pool (PUBLIC)
    registry_root: pub Field,
    ciphertext_hash_pub: pub Field,

    // ===== PRIVATE INPUTS =====
    // ECDSA signature
    pub_key_x: [u8; 32],
    pub_key_y: [u8; 32],
    signature: [u8; 64],

    // Transaction fields (PRIVATE)
    tx_nonce: u64,
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

    // Change note
    change_randomness: Field,

    // Keys
    nullifier_key: Field,

    // Sender's registry membership proof (index is u32!)
    sender_pubkey_x: Field,
    sender_pubkey_y: Field,
    sender_leaf_index: u32,  // NOT Field!
    sender_siblings: [Field; REGISTRY_DEPTH]
) {
    // ========================== 1. DEFENSE-IN-DEPTH CHECKS ==========================
    assert_is_address(withdraw_recipient);

    // Validate withdraw_amount fits in u128
    let withdraw_amount_u128 = withdraw_amount as u128;
    assert(withdraw_amount_u128 as Field == withdraw_amount, "withdraw_amount exceeds u128");

    // ========================== 2. COMPUTE SIGNING HASH ==========================
    let signing_hash = compute_eip1559_signing_hash(
        tx_nonce, WITHDRAW_SENTINEL, withdraw_amount_u128,
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

    // Withdrawals can only go to signer's own address
    assert(withdraw_recipient == signer_address, "Can only withdraw to self");

    // ========================== 5. VERIFY SENDER REGISTRY MEMBERSHIP ==========================
    verify_registry_membership(
        registry_root,
        signer_address,
        sender_pubkey_x,
        sender_pubkey_y,
        signer_nk_hash,
        sender_leaf_index,
        sender_siblings
    );

    // ========================== 6. VERIFY INPUT NOTE 0 ==========================
    let commitment_0 = hash_4([input_0_amount as Field, signer_address, input_0_randomness, signer_nk_hash]);
    verify_merkle_membership(merkle_root, commitment_0, input_0_leaf_index, input_0_siblings);

    // Nullifier with domain separator
    let input_0_idx_field: Field = input_0_leaf_index as Field;
    let computed_nullifier_0 = hash_4([NULLIFIER_DOMAIN, nullifier_key, input_0_idx_field, input_0_randomness]);
    assert(nullifier_0 == computed_nullifier_0, "Nullifier 0 mismatch");

    // ========================== 7. VERIFY INPUT NOTE 1 ==========================
    // CRITICAL: Phantom inputs (amount=0) must use a different nullifier domain
    // to prevent adapter from poisoning real nullifiers
    if input_1_amount != 0 {
        // Real note: verify membership and compute nullifier from leaf index + randomness
        let commitment_1 = hash_4([input_1_amount as Field, signer_address, input_1_randomness, signer_nk_hash]);
        verify_merkle_membership(merkle_root, commitment_1, input_1_leaf_index, input_1_siblings);
        assert(input_0_leaf_index != input_1_leaf_index, "Duplicate input note");

        let input_1_idx_field: Field = input_1_leaf_index as Field;
        let computed_nullifier_1 = hash_4([NULLIFIER_DOMAIN, nullifier_key, input_1_idx_field, input_1_randomness]);
        assert(nullifier_1 == computed_nullifier_1, "Nullifier 1 mismatch");
    } else {
        // Phantom note: nullifier bound to tx_nonce, cannot collide with real notes
        // Uses PHANTOM_NULLIFIER_DOMAIN instead of NULLIFIER_DOMAIN
        let phantom_nullifier = hash_4([PHANTOM_NULLIFIER_DOMAIN, nullifier_key, tx_nonce as Field, 0]);
        assert(nullifier_1 == phantom_nullifier, "Phantom nullifier mismatch");
    }

    // ========================== 8. VALUE CONSERVATION ==========================
    // Sum inputs in Field to avoid u128 wrap-around
    let in_sum: Field = (input_0_amount as Field) + (input_1_amount as Field);

    // Compute change amount
    let change_amount_field = in_sum - withdraw_amount;

    // CRITICAL: Assert change is non-negative (prevents field underflow attack)
    // Without this, attacker could set withdraw_amount > in_sum and wrap to huge positive
    assert_is_u128(change_amount_field);

    // Conservation check: in_sum == withdraw_amount + change
    assert(in_sum == withdraw_amount + change_amount_field, "Value not conserved");

    // ========================== 9. VERIFY CHANGE COMMITMENT ==========================
    let computed_change = hash_4([change_amount_field, signer_address, change_randomness, signer_nk_hash]);
    assert(change_commitment == computed_change, "Change commitment mismatch");

    // ========================== 10. IN-CIRCUIT ENCRYPTION ==========================
    let enc_seed = derive_enc_seed(nullifier_key);

    // Change note uses self-encryption (no ECDH)
    let encrypted_change = encrypt_note_self(
        enc_seed,
        change_amount_field,
        signer_address,
        change_randomness,
        tx_nonce as Field
    );

    // ========================== 11. VERIFY CIPHERTEXT HASH ==========================
    let computed_ct_hash = ciphertext_hash_single(encrypted_change);
    assert(ciphertext_hash_pub == computed_ct_hash, "Ciphertext hash mismatch");

    // ========================== 12. INTENT NULLIFIER ==========================
    let computed_intent = hash_4([INTENT_DOMAIN, nullifier_key, VIRTUAL_CHAIN_ID, tx_nonce as Field]);
    assert(intent_nullifier == computed_intent, "Intent nullifier mismatch");
}

// ========================== HELPER FUNCTIONS ==========================

fn compute_eip1559_signing_hash(
    nonce: u64,
    to: Field,
    value: u128,
    max_priority_fee: u64,
    max_fee: u64,
    gas_limit: u64
) -> [u8; 32] {
    let to_bytes: [u8; 32] = to.to_be_bytes();
    for i in 0..12 {
        assert(to_bytes[i] == 0, "tx_to has invalid high bits");
    }

    let mut rlp_buffer: [u8; MAX_RLP_LEN] = [0; MAX_RLP_LEN];
    let mut pos: u32 = 1;

    // chainId
    let chain_bytes = u64_to_be_bytes(CHAIN_ID);
    rlp_buffer[pos] = 0x83;
    rlp_buffer[pos + 1] = chain_bytes[5];
    rlp_buffer[pos + 2] = chain_bytes[6];
    rlp_buffer[pos + 3] = chain_bytes[7];
    pos += 4;

    // nonce
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

    pos = encode_u64_rlp(&mut rlp_buffer, pos, max_priority_fee);
    pos = encode_u64_rlp(&mut rlp_buffer, pos, max_fee);
    pos = encode_u64_rlp(&mut rlp_buffer, pos, gas_limit);

    rlp_buffer[pos] = 0x94;
    pos += 1;
    for i in 0..20 {
        rlp_buffer[pos + i] = to_bytes[12 + i];
    }
    pos += 20;

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

    rlp_buffer[pos] = 0x80;
    pos += 1;
    rlp_buffer[pos] = 0xc0;
    pos += 1;

    let list_len = pos - 1;
    assert(list_len < 56, "RLP list too long");
    rlp_buffer[0] = (0xc0 + list_len) as u8;

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
fn test_signing_hash_matches_viem_withdrawal() {
    let nonce: u64 = 1;
    let to: Field = WITHDRAW_SENTINEL;
    let value: u128 = 500000000000000000;
    let max_priority_fee: u64 = 1000000000;
    let max_fee: u64 = 30000000000;
    let gas_limit: u64 = 21000;

    let hash = compute_eip1559_signing_hash(nonce, to, value, max_priority_fee, max_fee, gas_limit);

    let expected: [u8; 32] = [
        113, 243, 155, 163, 115, 91, 80, 147,
        107, 145, 4, 243, 218, 173, 103, 112,
        138, 198, 190, 33, 175, 216, 112, 209,
        108, 184, 17, 66, 189, 232, 110, 88
    ];

    assert(hash == expected, "Signing hash mismatch");
}
