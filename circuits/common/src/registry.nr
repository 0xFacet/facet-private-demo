// Registry membership verification
//
// Verifies that a recipient is registered in the RecipientRegistry Merkle tree.
// This binds the transaction's tx_to address to a specific public key and nkHash,
// enabling private recipient membership proofs.

use crate::constants::{REGISTRY_DEPTH, REG_LEAF_DOMAIN};
use crate::hashes::hash_2;
use crate::merkle::compute_merkle_root;

/// Compute registry leaf with domain separator (matches Solidity)
/// leaf = hash(hash(hash(domain, address), hash(pkX, pkY)), nkHash)
pub fn compute_registry_leaf(
    address: Field,
    pubkey_x: Field,
    pubkey_y: Field,
    nk_hash: Field
) -> Field {
    // Binary tree hash matching Solidity RecipientRegistry.register():
    // uint256 h1 = PoseidonT3.hash([REG_LEAF_DOMAIN, uint256(uint160(msg.sender))]);
    // uint256 h2 = PoseidonT3.hash([encPublicKey[0], encPublicKey[1]]);
    // uint256 h3 = PoseidonT3.hash([h1, h2]);
    // uint256 leaf = PoseidonT3.hash([h3, nullifierKeyHash]);
    let h1 = hash_2([REG_LEAF_DOMAIN, address]);
    let h2 = hash_2([pubkey_x, pubkey_y]);
    let h3 = hash_2([h1, h2]);
    hash_2([h3, nk_hash])
}

/// Verify registry membership - proves recipient is registered
///
/// # Arguments
/// * `registry_root` - The Merkle root of the registry tree
/// * `recipient_address` - The tx_to address being proven
/// * `recipient_pubkey_x` - X coordinate of recipient's Grumpkin encryption key
/// * `recipient_pubkey_y` - Y coordinate of recipient's Grumpkin encryption key
/// * `recipient_nk_hash` - Hash of recipient's nullifier key
/// * `leaf_index` - Index of recipient's leaf in registry tree (u32!)
/// * `siblings` - Merkle proof siblings
pub fn verify_registry_membership(
    registry_root: Field,
    recipient_address: Field,
    recipient_pubkey_x: Field,
    recipient_pubkey_y: Field,
    recipient_nk_hash: Field,
    leaf_index: u32,  // u32 not Field!
    siblings: [Field; REGISTRY_DEPTH]
) {
    // Compute leaf
    let leaf = compute_registry_leaf(
        recipient_address,
        recipient_pubkey_x,
        recipient_pubkey_y,
        recipient_nk_hash
    );

    // Verify Merkle proof (index already range-checked in compute_merkle_root)
    let computed_root = compute_merkle_root(leaf, leaf_index, siblings);
    assert(computed_root == registry_root, "Recipient not in registry");
}

#[test]
fn test_compute_registry_leaf() {
    // Test with sample values
    let address: Field = 0x70997970C51812dc3A010C7d01b50e0d17dc79C8;
    let pubkey_x: Field = 1; // Grumpkin generator x
    let pubkey_y: Field = 17631683881184975370165255887551781615748388533673675138860;
    let nk_hash: Field = 12345678901234567890;

    let leaf = compute_registry_leaf(address, pubkey_x, pubkey_y, nk_hash);

    // Verify structure: hash(hash(hash(domain, addr), hash(pkX, pkY)), nkHash)
    let h1 = hash_2([REG_LEAF_DOMAIN, address]);
    let h2 = hash_2([pubkey_x, pubkey_y]);
    let h3 = hash_2([h1, h2]);
    let expected = hash_2([h3, nk_hash]);

    assert(leaf == expected, "Leaf structure mismatch");
}

#[test]
fn test_verify_registry_membership_success() {
    // Create a simple test case with depth 3
    let address: Field = 12345;
    let pubkey_x: Field = 1;
    let pubkey_y: Field = 2;
    let nk_hash: Field = 3;

    let leaf = compute_registry_leaf(address, pubkey_x, pubkey_y, nk_hash);

    // Build siblings for index 0 in depth-20 tree (all zeros)
    let mut siblings: [Field; 20] = [0; 20];
    // zeros[0] = 0
    let mut zero: Field = 0;
    for i in 1..20 {
        zero = hash_2([zero, zero]);
        siblings[i] = zero;
    }
    // First sibling is 0
    siblings[0] = 0;

    // Compute the root
    let root = compute_merkle_root(leaf, 0, siblings);

    // This should not panic
    verify_registry_membership(root, address, pubkey_x, pubkey_y, nk_hash, 0, siblings);
}
