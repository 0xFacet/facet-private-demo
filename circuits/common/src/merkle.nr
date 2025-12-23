// Merkle tree operations with range-checked indices
//
// CRITICAL: All leaf indices use u32, NOT Field, to prevent aliasing attacks.
// An aliased index (e.g., index + 2^TREE_DEPTH) would produce a valid proof
// for the same leaf, enabling double-spends.

use crate::hashes::hash_2;

/// Compute Merkle root with RANGE-CHECKED index
/// CRITICAL: index must be u32 to prevent aliasing attacks
pub fn compute_merkle_root<let DEPTH: u32>(
    leaf: Field,
    index: u32,  // NOT Field - prevents aliasing!
    siblings: [Field; DEPTH]
) -> Field {
    // Explicit range check (defense in depth)
    assert((index as u64) < ((1 as u64) << (DEPTH as u64)), "leaf index out of range");

    let mut current = leaf;
    let mut idx = index;

    for i in 0..DEPTH {
        let sibling = siblings[i];
        if (idx & 1) == 0 {
            current = hash_2([current, sibling]);
        } else {
            current = hash_2([sibling, current]);
        }
        idx >>= 1;
    }

    current
}

/// Verify membership in Merkle tree
pub fn verify_merkle_membership<let DEPTH: u32>(
    root: Field,
    leaf: Field,
    index: u32,
    siblings: [Field; DEPTH]
) {
    let computed_root = compute_merkle_root(leaf, index, siblings);
    assert(computed_root == root, "Merkle proof invalid");
}

#[test]
fn test_compute_merkle_root_single_leaf() {
    // Test with a simple case: single leaf at index 0 in depth-3 tree
    let leaf: Field = 12345;

    // All siblings are zeros (empty tree positions)
    // zeros[0] = 0 (NOT hash(0,0) - matches contract)
    let zero_0: Field = 0;
    let zero_1 = hash_2([zero_0, zero_0]);
    let zero_2 = hash_2([zero_1, zero_1]);

    let siblings: [Field; 3] = [zero_0, zero_1, zero_2];

    let root = compute_merkle_root(leaf, 0, siblings);

    // Compute expected: hash(hash(hash(leaf, 0), zero_1), zero_2)
    let h0 = hash_2([leaf, zero_0]);
    let h1 = hash_2([h0, zero_1]);
    let expected = hash_2([h1, zero_2]);

    assert(root == expected, "Root mismatch for single leaf");
}

#[test]
fn test_merkle_proof_right_path() {
    // Leaf at index 1 (right child at level 0)
    let leaf: Field = 99999;

    let zero_0: Field = 0;
    let zero_1 = hash_2([zero_0, zero_0]);
    let zero_2 = hash_2([zero_1, zero_1]);

    // For index 1: bit 0 = 1, so sibling 0 is on the left
    let siblings: [Field; 3] = [zero_0, zero_1, zero_2];

    let root = compute_merkle_root(leaf, 1, siblings);

    // Compute expected: hash(hash(hash(0, leaf), zero_1), zero_2)
    let h0 = hash_2([zero_0, leaf]); // sibling on left since we're right child
    let h1 = hash_2([h0, zero_1]);
    let expected = hash_2([h1, zero_2]);

    assert(root == expected, "Root mismatch for index 1");
}

#[test]
fn test_verify_merkle_membership() {
    let leaf: Field = 42;
    let zero_0: Field = 0;
    let zero_1 = hash_2([zero_0, zero_0]);
    let zero_2 = hash_2([zero_1, zero_1]);

    let siblings: [Field; 3] = [zero_0, zero_1, zero_2];
    let root = compute_merkle_root(leaf, 0, siblings);

    // This should not panic
    verify_merkle_membership(root, leaf, 0, siblings);
}

#[test(should_fail_with = "Merkle proof invalid")]
fn test_verify_merkle_membership_wrong_root() {
    let leaf: Field = 42;
    let siblings: [Field; 3] = [0, 0, 0];

    // Wrong root should fail
    let wrong_root: Field = 999;
    verify_merkle_membership(wrong_root, leaf, 0, siblings);
}
