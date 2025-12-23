#!/usr/bin/env npx tsx
/**
 * Generate Solidity verifier contracts via bb.js
 * Ensures consistency with proof generation (both use keccakZK mode)
 */

import { generateAllVerifiers } from './helpers/proof.js';

async function main() {
  console.log('Generating Solidity verifiers via bb.js...\n');
  await generateAllVerifiers();
  console.log('\nDone! Now run: cd ../contracts && forge build');
}

main().then(() => {
  // Force exit because bb.js worker threads don't cleanly shut down
  process.exit(0);
}).catch((err) => {
  console.error('Error:', err);
  process.exit(1);
});
