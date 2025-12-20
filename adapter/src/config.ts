// Configuration constants for the Facet Private adapter

export const VIRTUAL_CHAIN_ID = 13371337n;

export const TREE_DEPTH = 20;

// BN254 scalar field size
export const FIELD_SIZE = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

// Sentinel address for withdrawals
export const WITHDRAW_SENTINEL = '0x0000000000000000000000000000000000000001';

// Contract addresses (to be filled after deployment)
export const CONTRACTS = {
  privacyPool: process.env.PRIVACY_POOL_ADDRESS || '0x0000000000000000000000000000000000000000',
  registry: process.env.REGISTRY_ADDRESS || '0x0000000000000000000000000000000000000000',
};

// RPC configuration
export const RPC_PORT = parseInt(process.env.PORT || process.env.RPC_PORT || '8546');
export const L1_RPC_URL = process.env.L1_RPC_URL || 'https://sepolia.infura.io/v3/YOUR_API_KEY';
