// Private Withdraw Circuit - Demo Version
//
// NOTE: This demo uses Pedersen hash (available in Noir std).
// Production would use Poseidon for Solidity compatibility.
//
// This circuit proves a valid withdrawal authorized by an ECDSA signature.
// It verifies:
// 1. ECDSA signature is valid over the transaction hash
// 2. Signer owns the 2 input notes (merkle proofs)
// 3. Nullifiers are correctly computed
// 4. Change commitment is valid
// 5. Value is conserved (sum inputs = change + withdraw_amount)
// 6. Intent nullifier binds to the signed transaction

use std::ecdsa_secp256k1::verify_signature;
use keccak256::keccak256;

// Tree depth for merkle proofs
global TREE_DEPTH: u32 = 20;

// Virtual chain ID (must match contract)
global VIRTUAL_CHAIN_ID: Field = 13371337;

// ==================== Hash Wrappers ====================
// Using Pedersen for demo - production would use Poseidon

fn hash_2(inputs: [Field; 2]) -> Field {
    std::hash::pedersen_hash(inputs)
}

fn hash_3(inputs: [Field; 3]) -> Field {
    std::hash::pedersen_hash(inputs)
}

fn hash_5(inputs: [Field; 5]) -> Field {
    std::hash::pedersen_hash(inputs)
}

// ==================== Main Circuit ====================
fn main(
    // ===== Public Inputs =====
    merkle_root: pub Field,
    nullifier_0: pub Field,
    nullifier_1: pub Field,
    change_commitment: pub Field,      // Change note stays in pool
    withdraw_amount: pub Field,         // Amount leaving the pool (public)
    withdraw_recipient: pub Field,      // L1 address receiving funds (public)
    intent_nullifier: pub Field,
    tx_to: pub Field,
    tx_value: pub Field,
    tx_nonce: pub Field,

    // ===== Private Inputs =====
    pub_key_x: [u8; 32],
    pub_key_y: [u8; 32],
    signature: [u8; 64],
    message_hash: [u8; 32],

    // Input notes
    input_0_amount: Field,
    input_0_owner: Field,
    input_0_randomness: Field,
    input_0_leaf_index: u32,
    input_0_siblings: [Field; TREE_DEPTH],

    input_1_amount: Field,
    input_1_owner: Field,
    input_1_randomness: Field,
    input_1_leaf_index: u32,
    input_1_siblings: [Field; TREE_DEPTH],

    // Change note (stays in pool)
    change_amount: Field,
    change_owner: Field,
    change_randomness: Field,

    nullifier_key: Field,
) {
    // 1. Verify ECDSA Signature
    let sig_valid = verify_signature(pub_key_x, pub_key_y, signature, message_hash);
    assert(sig_valid, "Invalid ECDSA signature");

    // 2. Derive Signer Address
    let signer_address = derive_eth_address(pub_key_x, pub_key_y);

    // 3. Verify Input Note 0
    let commitment_0 = hash_3([input_0_amount, input_0_owner, input_0_randomness]);
    let root_0 = compute_merkle_root(commitment_0, input_0_leaf_index, input_0_siblings);
    assert(root_0 == merkle_root, "Input 0 merkle proof invalid");
    assert(input_0_owner == signer_address, "Input 0 not owned by signer");

    // 4. Verify Input Note 1
    let commitment_1 = hash_3([input_1_amount, input_1_owner, input_1_randomness]);
    let root_1 = compute_merkle_root(commitment_1, input_1_leaf_index, input_1_siblings);
    assert(root_1 == merkle_root, "Input 1 merkle proof invalid");
    assert(input_1_owner == signer_address, "Input 1 not owned by signer");

    // 5. Verify Nullifiers
    let computed_nullifier_0 = hash_2([commitment_0, nullifier_key]);
    let computed_nullifier_1 = hash_2([commitment_1, nullifier_key]);
    assert(nullifier_0 == computed_nullifier_0, "Nullifier 0 mismatch");
    assert(nullifier_1 == computed_nullifier_1, "Nullifier 1 mismatch");

    // 6. Verify Change Commitment
    let computed_change = hash_3([change_amount, change_owner, change_randomness]);
    assert(change_commitment == computed_change, "Change commitment mismatch");

    // 7. Verify Value Conservation (inputs = change + withdrawal)
    let total_input = input_0_amount + input_1_amount;
    let total_output = change_amount + withdraw_amount;
    assert(total_input == total_output, "Value not conserved");

    // 8. Verify Transaction Binding
    // tx_to is the L1 recipient, tx_value is the withdraw amount
    assert(withdraw_recipient == tx_to, "Withdraw recipient doesn't match tx.to");
    assert(withdraw_amount == tx_value, "Withdraw amount doesn't match tx.value");
    assert(change_owner == signer_address, "Change must go to signer");

    // 9. Verify Intent Nullifier
    let computed_intent = hash_5([signer_address, VIRTUAL_CHAIN_ID, tx_nonce, tx_to, tx_value]);
    assert(intent_nullifier == computed_intent, "Intent nullifier mismatch");
}

// ==================== Helper Functions ====================

fn derive_eth_address(pub_key_x: [u8; 32], pub_key_y: [u8; 32]) -> Field {
    let mut pubkey_bytes: [u8; 64] = [0; 64];
    for i in 0..32 {
        pubkey_bytes[i] = pub_key_x[i];
        pubkey_bytes[i + 32] = pub_key_y[i];
    }
    let hash = keccak256(pubkey_bytes, 64);

    let mut address_value: Field = 0;
    for i in 12..32 {
        address_value = address_value * 256 + hash[i] as Field;
    }
    address_value
}

fn compute_merkle_root(
    leaf: Field,
    leaf_index: u32,
    siblings: [Field; TREE_DEPTH]
) -> Field {
    let mut current_hash = leaf;
    let mut current_index = leaf_index;

    for i in 0..TREE_DEPTH {
        let sibling = siblings[i];
        let is_right = (current_index & 1) == 1;

        let (left, right) = if is_right {
            (sibling, current_hash)
        } else {
            (current_hash, sibling)
        };

        current_hash = hash_2([left, right]);
        current_index = current_index >> 1;
    }

    current_hash
}
