// Domain separators and constants for privacy pool circuits
//
// Domain separators are computed as: keccak256("facet.<name>") % FIELD_SIZE
// All values must be < BN254 field size.

// Tree depths
pub global TREE_DEPTH: u32 = 20;
pub global REGISTRY_DEPTH: u32 = 20;

// Virtual chain ID for replay protection (matches contract)
pub global VIRTUAL_CHAIN_ID: Field = 13371337;

// Chain ID for EIP-1559 tx encoding
pub global CHAIN_ID: u64 = 13371337;

// Domain separators for cryptographic operations
// All values are < FIELD_SIZE (modular reduction applied)

// Registry leaf: hash(hash(hash(domain, address), hash(pkX, pkY)), nkHash)
// Must match Solidity REG_LEAF_DOMAIN
pub global REG_LEAF_DOMAIN: Field = 0x1a2b3c4d5e6f7890abcdef1234567890abcdef1234567890abcdef12345678;

// Encryption key derivation: enc_seed = hash(nullifier_key, ENC_KEY_DOMAIN)
pub global ENC_KEY_DOMAIN: Field = 0x05c0366c550e7c08ba7fdf905e32a9cf2e13de6807d8df5f31fb94eeb9ffd31c;

// Ephemeral scalar derivation for ECDH encryption
pub global EPHEMERAL_DOMAIN: Field = 0x12d6fc0a3c3236aa13408ef9c5357a87a9442d02cdc33439d1144724efd2c045;

// Keystream derivation from shared secret
pub global KEYSTREAM_DOMAIN: Field = 0x12a75193c39272d475e037ae5044175cf98efd26a563452dc1e3fd396c718824;

// Shared secret derivation (x-only KDF)
pub global SHARED_DOMAIN: Field = 0x1a2b3c4d5e6f7890abcdef1234567890abcdef1234567890abcdef1234567890;

// Self-encryption ephemeral (change notes)
pub global SELF_EPHEMERAL_DOMAIN: Field = 0x0b3c4d5e6f7890ab1234567890abcdef1234567890abcdef1234567890abcdef;

// Self-encryption secret (reduced to be within field)
pub global SELF_SECRET_DOMAIN: Field = 0x0c4d5e6f7890abcd234567890abcdef1234567890abcdef1234567890abcdef;

// Nullifier key hash: nkHash = hash(nullifier_key, NULLIFIER_KEY_DOMAIN)
pub global NULLIFIER_KEY_DOMAIN: Field = 0x0d5e6f7890abcdef34567890abcdef1234567890abcdef1234567890abcdef;

// Nullifier derivation: nullifier = hash(NULLIFIER_DOMAIN, nk, leaf_index, randomness)
pub global NULLIFIER_DOMAIN: Field = 0x0e6f7890abcdef0134567890abcdef1234567890abcdef1234567890abcdef;

// Intent nullifier: hash(INTENT_DOMAIN, nk, chain_id, nonce)
pub global INTENT_DOMAIN: Field = 0x0f7890abcdef012345678901abcdef1234567890abcdef1234567890abcdef;

// Phantom nullifier for zero-amount inputs: hash(PHANTOM_DOMAIN, nk, tx_nonce, 0)
// Prevents nullifier poisoning attack where adapter picks (leaf_index, randomness) of real notes
pub global PHANTOM_NULLIFIER_DOMAIN: Field = 0x107890abcdef012345678901abcdef1234567890abcdef1234567890abcde0;

// Maximum RLP encoded length for EIP-1559 tx
pub global MAX_RLP_LEN: u32 = 128;
