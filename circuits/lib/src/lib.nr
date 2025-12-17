// Merkle tree verification library
// Uses Poseidon hash for BN254 compatibility

use poseidon::poseidon::bn254::hash_2;
use poseidon::poseidon::bn254::hash_3;
use poseidon::poseidon::bn254::hash_5;

/// Verify a merkle proof for a leaf
/// Returns true if the proof is valid
pub fn verify_merkle_proof<let DEPTH: u32>(
    leaf: Field,
    leaf_index: u32,
    siblings: [Field; DEPTH],
    root: Field
) -> bool {
    let computed_root = compute_merkle_root(leaf, leaf_index, siblings);
    computed_root == root
}

/// Compute the merkle root from a leaf and its proof
pub fn compute_merkle_root<let DEPTH: u32>(
    leaf: Field,
    leaf_index: u32,
    siblings: [Field; DEPTH]
) -> Field {
    let mut current_hash = leaf;
    let mut current_index = leaf_index;

    for i in 0..DEPTH {
        let sibling = siblings[i];
        let is_right = (current_index & 1) == 1;

        // If current is right child, sibling is left
        // If current is left child, sibling is right
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

/// Compute a note commitment: poseidon(amount, owner, randomness)
pub fn compute_commitment(amount: Field, owner: Field, randomness: Field) -> Field {
    hash_3([amount, owner, randomness])
}

/// Compute a nullifier: poseidon(commitment, nullifier_key)
pub fn compute_nullifier(commitment: Field, nullifier_key: Field) -> Field {
    hash_2([commitment, nullifier_key])
}

/// Compute an intent nullifier: poseidon(signer, chain_id, nonce, to, value)
pub fn compute_intent_nullifier(
    signer: Field,
    chain_id: Field,
    nonce: Field,
    to: Field,
    value: Field
) -> Field {
    hash_5([signer, chain_id, nonce, to, value])
}

#[test]
fn test_merkle_single_leaf() {
    // Test with a simple case: single leaf at index 0
    // All siblings are zeros (empty tree positions)
    let zero = hash_2([0, 0]);
    let leaf: Field = 12345;

    // Build siblings array (all zeros at each level)
    let mut siblings: [Field; 3] = [0; 3];
    siblings[0] = zero;
    siblings[1] = hash_2([zero, zero]);
    siblings[2] = hash_2([siblings[1], siblings[1]]);

    let root = compute_merkle_root(leaf, 0, siblings);

    // Verify the proof validates
    assert(verify_merkle_proof(leaf, 0, siblings, root));
}
