// Facet Private Adapter
// JSON-RPC server that enables private transfers via MetaMask

import { initPoseidon } from './crypto/poseidon.js';
import { RpcAdapter } from './rpc.js';

async function main() {
  console.log('Initializing Facet Private Adapter...');

  // Initialize Poseidon hash function
  await initPoseidon();
  console.log('Poseidon initialized');

  // Start RPC server
  const adapter = new RpcAdapter();
  await adapter.start();

  // Handle shutdown
  process.on('SIGINT', async () => {
    console.log('\nShutting down...');
    await adapter.stop();
    process.exit(0);
  });
}

main().catch((error) => {
  console.error('Fatal error:', error);
  process.exit(1);
});
