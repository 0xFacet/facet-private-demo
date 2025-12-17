use std::ecdsa_secp256k1::verify_signature;
use keccak256::keccak256;

// secp256k1 curve order n / 2 (for EIP-2 low-s check)
// n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
// n/2 = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0
global SECP256K1_HALF_N: [u8; 32] = [
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d,
    0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b, 0x20, 0xa0
];

// Check if s <= n/2 (EIP-2 low-s requirement)
// Prevents signature malleability: for any valid (r,s), (r, n-s) is also valid
// By requiring low-s, each message+signer has exactly one valid signature
fn is_low_s(s: [u8; 32]) -> bool {
    // Big-endian comparison: s <= SECP256K1_HALF_N
    let mut result = true;
    let mut decided = false;

    for i in 0..32 {
        if !decided {
            if s[i] < SECP256K1_HALF_N[i] {
                // s is definitively less
                decided = true;
                result = true;
            } else if s[i] > SECP256K1_HALF_N[i] {
                // s is definitively greater
                decided = true;
                result = false;
            }
            // if equal, continue to next byte
        }
    }
    result
}

// Derive Ethereum address from uncompressed public key
// address = keccak256(pub_key_x || pub_key_y)[12:32]
fn pubkey_to_address(pub_key_x: [u8; 32], pub_key_y: [u8; 32]) -> [u8; 20] {
    let mut pubkey_bytes: [u8; 64] = [0; 64];
    for i in 0..32 {
        pubkey_bytes[i] = pub_key_x[i];
        pubkey_bytes[i + 32] = pub_key_y[i];
    }
    let hash = keccak256(pubkey_bytes, 64);

    let mut address: [u8; 20] = [0; 20];
    for i in 0..20 {
        address[i] = hash[i + 12];
    }
    address
}

// Hash address to create a commitment (so we can link proofs without revealing address)
fn hash_address(address: [u8; 20]) -> [u8; 32] {
    let mut padded: [u8; 20] = [0; 20];
    for i in 0..20 {
        padded[i] = address[i];
    }
    keccak256(padded, 20)
}

fn main(
    // Private inputs
    pub_key_x: [u8; 32],
    pub_key_y: [u8; 32],
    signature: [u8; 64],  // r || s (each 32 bytes)

    // Public inputs
    message_hash: pub [u8; 32],       // The tx/message hash that was signed
    address_commitment: pub [u8; 32], // keccak256(raw 20-byte address, no padding)
) {
    // 1. Extract s from signature (bytes 32-63) and enforce EIP-2 low-s
    // This prevents signature malleability: ensures unique signature per message+signer
    let mut s: [u8; 32] = [0; 32];
    for i in 0..32 {
        s[i] = signature[i + 32];
    }
    assert(is_low_s(s), "Signature s value must be low (EIP-2)");

    // 2. Verify the ECDSA signature is valid for this message
    let valid = verify_signature(pub_key_x, pub_key_y, signature, message_hash);
    assert(valid, "Invalid ECDSA signature");

    // 3. Derive the Ethereum address from the public key
    let address = pubkey_to_address(pub_key_x, pub_key_y);

    // 4. Verify the address commitment matches
    let computed_commitment = hash_address(address);
    assert(computed_commitment == address_commitment, "Address commitment mismatch");
}
