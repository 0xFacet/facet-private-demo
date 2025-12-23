// Poseidon hashing functions using binary tree structure
//
// ALL hashing uses Poseidon (2-input) with binary tree structure.
// This ensures cross-language consistency with only one Poseidon instantiation.
//
// CRITICAL: Use poseidon::poseidon::bn254, NOT std::hash::poseidon2!
// Poseidon2 is a DIFFERENT algorithm with different round constants.
// poseidon-solidity uses original Poseidon - must match.

use poseidon::poseidon::bn254::hash_2 as poseidon_hash_2;

/// Hash 2 inputs using Poseidon
pub fn hash_2(inputs: [Field; 2]) -> Field {
    poseidon_hash_2(inputs)
}

/// Hash 3 inputs via binary tree: hash(hash(a,b), c)
pub fn hash_3(inputs: [Field; 3]) -> Field {
    let h_ab = hash_2([inputs[0], inputs[1]]);
    hash_2([h_ab, inputs[2]])
}

/// Hash 4 inputs via binary tree: hash(hash(a,b), hash(c,d))
pub fn hash_4(inputs: [Field; 4]) -> Field {
    let h_ab = hash_2([inputs[0], inputs[1]]);
    let h_cd = hash_2([inputs[2], inputs[3]]);
    hash_2([h_ab, h_cd])
}

/// Hash 5 inputs via binary tree: hash(hash(hash(a,b), hash(c,d)), e)
pub fn hash_5(inputs: [Field; 5]) -> Field {
    let h_01 = hash_2([inputs[0], inputs[1]]);
    let h_23 = hash_2([inputs[2], inputs[3]]);
    let h_0123 = hash_2([h_01, h_23]);
    hash_2([h_0123, inputs[4]])
}

/// Hash 7 inputs via binary tree
pub fn hash_7(inputs: [Field; 7]) -> Field {
    let h_01 = hash_2([inputs[0], inputs[1]]);
    let h_23 = hash_2([inputs[2], inputs[3]]);
    let h_45 = hash_2([inputs[4], inputs[5]]);
    let h_0123 = hash_2([h_01, h_23]);
    let h_456 = hash_2([h_45, inputs[6]]);
    hash_2([h_0123, h_456])
}

/// Hash 10 inputs (two 5-element notes) via binary tree
pub fn hash_10(inputs: [Field; 10]) -> Field {
    // Split into two 5-element groups
    let h0 = hash_5([inputs[0], inputs[1], inputs[2], inputs[3], inputs[4]]);
    let h1 = hash_5([inputs[5], inputs[6], inputs[7], inputs[8], inputs[9]]);
    hash_2([h0, h1])
}

#[test]
fn test_hash_2_deterministic() {
    let a: Field = 123;
    let b: Field = 456;
    let h1 = hash_2([a, b]);
    let h2 = hash_2([a, b]);
    assert(h1 == h2, "Hash should be deterministic");
}

#[test]
fn test_hash_4_binary_tree() {
    // Verify binary tree structure
    let a: Field = 1;
    let b: Field = 2;
    let c: Field = 3;
    let d: Field = 4;

    let result = hash_4([a, b, c, d]);

    // Should equal hash(hash(a,b), hash(c,d))
    let h_ab = hash_2([a, b]);
    let h_cd = hash_2([c, d]);
    let expected = hash_2([h_ab, h_cd]);

    assert(result == expected, "Binary tree structure mismatch");
}
