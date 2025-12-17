// Configuration constants for integration tests

export const VIRTUAL_CHAIN_ID = 13371337n;
export const L1_CHAIN_ID = 31337n; // Anvil default

export const TREE_DEPTH = 20;
export const ROOT_HISTORY_SIZE = 500;

// BN254 scalar field size
export const FIELD_SIZE = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

// Sentinel address for withdrawals
export const WITHDRAW_SENTINEL = '0x0000000000000000000000000000000000000001';

// Fixed gas parameters (must match circuit constants)
// Using 1/1/1 for simpler RLP encoding (single byte 0x01)
export const FIXED_MAX_PRIORITY_FEE = 1n;
export const FIXED_MAX_FEE = 1n;
export const FIXED_GAS_LIMIT = 1n;

// Anvil default test accounts
export const TEST_PRIVATE_KEY = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80';
export const TEST_PRIVATE_KEY_1 = '0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d';
export const TEST_ACCOUNT_1_ADDRESS = '0x70997970C51812dc3A010C7d01b50e0d17dc79C8';

// RPC URL
export const ANVIL_RPC_URL = 'http://127.0.0.1:8545';
