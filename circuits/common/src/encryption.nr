// In-circuit encryption module for privacy pool
//
// Provides deterministic in-circuit encryption of notes to prevent
// malicious adapters from corrupting ciphertext or encrypting to wrong keys.
//
// Two encryption modes:
// 1. ECDH encryption - for recipient notes (ephemeral key derived from tx context)
// 2. Self encryption - for change notes (no ECDH, simpler)
//
// All encryption uses x-only KDF (ignores y coordinate) to be robust against
// y-sign mismatches between Noir and Solidity point representations.

use std::embedded_curve_ops::{
    EmbeddedCurvePoint,
    fixed_base_scalar_mul,
    multi_scalar_mul
};
use crate::constants::{
    ENC_KEY_DOMAIN, EPHEMERAL_DOMAIN, KEYSTREAM_DOMAIN, SHARED_DOMAIN,
    SELF_EPHEMERAL_DOMAIN, SELF_SECRET_DOMAIN
};
use crate::scalar::{field_to_scalar, ensure_nonzero};
use crate::hashes::{hash_2, hash_3, hash_5, hash_7};

/// Derive encryption seed from nullifier key
/// enc_seed = hash(nullifier_key, ENC_KEY_DOMAIN)
pub fn derive_enc_seed(nullifier_key: Field) -> Field {
    hash_2([nullifier_key, ENC_KEY_DOMAIN])
}

/// Derive encryption public key from nullifier key
/// enc_pubkey = G * enc_scalar where enc_scalar = scalar(enc_seed)
pub fn derive_enc_pubkey(nullifier_key: Field) -> EmbeddedCurvePoint {
    let enc_seed = derive_enc_seed(nullifier_key);
    let enc_scalar = field_to_scalar(ensure_nonzero(enc_seed));
    fixed_base_scalar_mul(enc_scalar)
}

/// Encrypt note to recipient using ECDH
///
/// # Algorithm
/// 1. Derive ephemeral scalar from: enc_seed, recipient pubkey, tx context
/// 2. Compute ephemeral public key: E = G * ephemeral_scalar
/// 3. ECDH: shared_point = ephemeral_scalar * recipient_pubkey
/// 4. x-only KDF: shared_secret = hash(shared_point.x, SHARED_DOMAIN)
/// 5. Derive keystream from shared_secret
/// 6. XOR encrypt plaintext with keystream
///
/// # Arguments
/// * `enc_seed` - Sender's encryption seed (derived from nullifier_key)
/// * `recipient_pubkey` - Recipient's Grumpkin public key
/// * `amount` - Note amount (plaintext)
/// * `owner` - Note owner address (plaintext)
/// * `randomness` - Note randomness (plaintext)
/// * `tx_nonce` - Transaction nonce (for ephemeral uniqueness)
/// * `output_index` - Output index (0 or 1, for ephemeral uniqueness)
///
/// # Returns
/// Ciphertext: [ephemeral_x, ephemeral_y, enc_amount, enc_owner, enc_randomness]
pub fn encrypt_note_ecdh(
    enc_seed: Field,
    recipient_pubkey: EmbeddedCurvePoint,
    amount: Field,
    owner: Field,
    randomness: Field,
    tx_nonce: Field,
    output_index: Field
) -> [Field; 5] {
    // 1. Derive ephemeral scalar (deterministic from tx context)
    let ephemeral_seed = hash_7([
        enc_seed,
        recipient_pubkey.x,
        recipient_pubkey.y,
        tx_nonce,
        output_index,
        randomness,
        EPHEMERAL_DOMAIN
    ]);
    let ephemeral_scalar = field_to_scalar(ensure_nonzero(ephemeral_seed));

    // 2. Compute ephemeral public key (fixed-base mul)
    let ephemeral_pubkey = fixed_base_scalar_mul(ephemeral_scalar);
    assert(!ephemeral_pubkey.is_infinite, "Ephemeral pubkey is infinity");

    // 3. ECDH: shared_point = ephemeral_scalar * recipient_pubkey
    let shared_point = multi_scalar_mul([recipient_pubkey], [ephemeral_scalar]);
    assert(!shared_point.is_infinite, "Shared point is infinity");

    // 4. x-only KDF (robust to y-sign mismatch)
    let shared_secret = hash_2([shared_point.x, SHARED_DOMAIN]);

    // 5. Derive keystream
    let key_0 = hash_3([shared_secret, 0, KEYSTREAM_DOMAIN]);
    let key_1 = hash_3([shared_secret, 1, KEYSTREAM_DOMAIN]);
    let key_2 = hash_3([shared_secret, 2, KEYSTREAM_DOMAIN]);

    // 6. Encrypt (additive "XOR" in field)
    [ephemeral_pubkey.x, ephemeral_pubkey.y, amount + key_0, owner + key_1, randomness + key_2]
}

/// Encrypt change note to self (no ECDH, still scannable)
///
/// CRITICAL: Does NOT include randomness in seed derivation (would be circular)
/// Decryptor reads ephemeral.x from ciphertext, recomputes secret
///
/// # Algorithm
/// 1. Derive self scalar from: enc_seed, tx_nonce
/// 2. Compute self ephemeral: S = G * self_scalar
/// 3. Derive self secret: hash(enc_seed, S.x, SELF_SECRET_DOMAIN)
/// 4. Derive keystream from self secret
/// 5. XOR encrypt plaintext with keystream
///
/// # Arguments
/// * `enc_seed` - Sender's encryption seed
/// * `amount` - Note amount
/// * `owner` - Note owner (sender's address)
/// * `randomness` - Note randomness
/// * `tx_nonce` - Transaction nonce
///
/// # Returns
/// Ciphertext: [self_ephemeral_x, self_ephemeral_y, enc_amount, enc_owner, enc_randomness]
pub fn encrypt_note_self(
    enc_seed: Field,
    amount: Field,
    owner: Field,
    randomness: Field,
    tx_nonce: Field
) -> [Field; 5] {
    // 1. Derive self scalar (NO randomness - would be circular!)
    let self_scalar_seed = hash_3([enc_seed, tx_nonce, SELF_EPHEMERAL_DOMAIN]);
    let self_scalar = field_to_scalar(ensure_nonzero(self_scalar_seed));

    // 2. Compute self ephemeral point (fixed-base mul only)
    let self_ephemeral = fixed_base_scalar_mul(self_scalar);
    assert(!self_ephemeral.is_infinite, "Self ephemeral is infinity");

    // 3. Derive secret from enc_seed + ephemeral.x (both known to decryptor)
    let self_secret = hash_3([enc_seed, self_ephemeral.x, SELF_SECRET_DOMAIN]);

    // 4. Derive keystream
    let key_0 = hash_3([self_secret, 0, KEYSTREAM_DOMAIN]);
    let key_1 = hash_3([self_secret, 1, KEYSTREAM_DOMAIN]);
    let key_2 = hash_3([self_secret, 2, KEYSTREAM_DOMAIN]);

    // 5. Encrypt (uniform format - starts with curve point)
    [self_ephemeral.x, self_ephemeral.y, amount + key_0, owner + key_1, randomness + key_2]
}

/// Compute ciphertext hash for two notes (binary tree)
/// Used to bind ciphertext to proof - contract verifies this hash
pub fn ciphertext_hash(enc0: [Field; 5], enc1: [Field; 5]) -> Field {
    let h0 = hash_5(enc0);
    let h1 = hash_5(enc1);
    hash_2([h0, h1])
}

/// Compute ciphertext hash for single note
/// Used for withdraw (only change note)
pub fn ciphertext_hash_single(enc: [Field; 5]) -> Field {
    hash_5(enc)
}

#[test]
fn test_derive_enc_seed() {
    let nk: Field = 12345;
    let seed1 = derive_enc_seed(nk);
    let seed2 = derive_enc_seed(nk);
    assert(seed1 == seed2, "Enc seed should be deterministic");
}

#[test]
fn test_derive_enc_pubkey_not_infinity() {
    let nk: Field = 12345;
    let pubkey = derive_enc_pubkey(nk);
    assert(!pubkey.is_infinite, "Enc pubkey should not be infinity");
}

#[test]
fn test_encrypt_note_ecdh_deterministic() {
    // Create a mock recipient pubkey using fixed_base_scalar_mul
    let recipient_scalar = field_to_scalar(67890);
    let recipient_pubkey = fixed_base_scalar_mul(recipient_scalar);

    let enc_seed: Field = 11111;
    let amount: Field = 1000000000000000000; // 1 ETH
    let owner: Field = 0x70997970C51812dc3A010C7d01b50e0d17dc79C8;
    let randomness: Field = 99999;
    let tx_nonce: Field = 5;
    let output_index: Field = 0;

    let cipher1 = encrypt_note_ecdh(enc_seed, recipient_pubkey, amount, owner, randomness, tx_nonce, output_index);
    let cipher2 = encrypt_note_ecdh(enc_seed, recipient_pubkey, amount, owner, randomness, tx_nonce, output_index);

    assert(cipher1 == cipher2, "ECDH encryption should be deterministic");
}

#[test]
fn test_encrypt_note_self_deterministic() {
    let enc_seed: Field = 11111;
    let amount: Field = 500000000000000000; // 0.5 ETH
    let owner: Field = 0x70997970C51812dc3A010C7d01b50e0d17dc79C8;
    let randomness: Field = 88888;
    let tx_nonce: Field = 5;

    let cipher1 = encrypt_note_self(enc_seed, amount, owner, randomness, tx_nonce);
    let cipher2 = encrypt_note_self(enc_seed, amount, owner, randomness, tx_nonce);

    assert(cipher1 == cipher2, "Self encryption should be deterministic");
}

#[test]
fn test_ciphertext_hash_deterministic() {
    let enc0: [Field; 5] = [1, 2, 3, 4, 5];
    let enc1: [Field; 5] = [6, 7, 8, 9, 10];

    let h1 = ciphertext_hash(enc0, enc1);
    let h2 = ciphertext_hash(enc0, enc1);

    assert(h1 == h2, "Ciphertext hash should be deterministic");
}
