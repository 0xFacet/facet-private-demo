// Configuration constants for the Facet Private adapter
//
// Domain separators MUST match circuits/common/src/constants.nr

export const VIRTUAL_CHAIN_ID = 13371337n;

export const TREE_DEPTH = 20;
export const REGISTRY_DEPTH = 20;

// BN254 scalar field size
export const FIELD_SIZE = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

// Sentinel address for withdrawals
export const WITHDRAW_SENTINEL = '0x0000000000000000000000000000000000000001';

// Domain separators (must match circuits/common/src/constants.nr)
export const DOMAIN = {
  ENC_KEY: 0x05c0366c550e7c08ba7fdf905e32a9cf2e13de6807d8df5f31fb94eeb9ffd31cn,
  EPHEMERAL: 0x12d6fc0a3c3236aa13408ef9c5357a87a9442d02cdc33439d1144724efd2c045n,
  KEYSTREAM: 0x12a75193c39272d475e037ae5044175cf98efd26a563452dc1e3fd396c718824n,
  SHARED: 0x1a2b3c4d5e6f7890abcdef1234567890abcdef1234567890abcdef1234567890n,
  SELF_EPHEMERAL: 0x0b3c4d5e6f7890ab1234567890abcdef1234567890abcdef1234567890abcdefn,
  SELF_SECRET: 0x0c4d5e6f7890abcd234567890abcdef1234567890abcdef1234567890abcdefn,
  NULLIFIER_KEY: 0x0d5e6f7890abcdef34567890abcdef1234567890abcdef1234567890abcdefn,
  NULLIFIER: 0x0e6f7890abcdef0134567890abcdef1234567890abcdef1234567890abcdefn,
  INTENT: 0x0f7890abcdef012345678901abcdef1234567890abcdef1234567890abcdefn,
  REG_LEAF: 0x1a2b3c4d5e6f7890abcdef1234567890abcdef1234567890abcdef12345678n,
} as const;

// Contract addresses (to be filled after deployment)
export const CONTRACTS = {
  privacyPool: process.env.PRIVACY_POOL_ADDRESS || '0x0000000000000000000000000000000000000000',
  registry: process.env.REGISTRY_ADDRESS || '0x0000000000000000000000000000000000000000',
};

// RPC configuration
export const RPC_PORT = parseInt(process.env.PORT || process.env.RPC_PORT || '8546');
export const L1_RPC_URL = process.env.L1_RPC_URL || 'https://sepolia.infura.io/v3/YOUR_API_KEY';
