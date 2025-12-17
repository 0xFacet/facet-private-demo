// Generate ECDSA test fixture for Noir circuit
// Run: node generate-ecdsa-fixture.mjs

import { secp256k1 } from '@noble/curves/secp256k1.js';
import { keccak_256 } from '@noble/hashes/sha3.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { writeFileSync } from 'fs';

// Generate a random private key
const privateKey = secp256k1.utils.randomPrivateKey();
const publicKey = secp256k1.getPublicKey(privateKey, false); // uncompressed

// Create a message and hash it
const message = "Test message for ECDSA verification";
const messageHash = keccak_256(new TextEncoder().encode(message));

// Sign the message hash
const signature = secp256k1.sign(messageHash, privateKey);

// Extract r and s as 32-byte arrays
const r = signature.r.toString(16).padStart(64, '0');
const s = signature.s.toString(16).padStart(64, '0');
const sigBytes = hexToBytes(r + s);

// Public key: skip the 0x04 prefix, split into x and y
const pubkeyX = publicKey.slice(1, 33);
const pubkeyY = publicKey.slice(33, 65);

// Format for Noir (as arrays of decimal numbers)
const toNoirArray = (bytes) => Array.from(bytes);

const fixture = {
  message,
  message_hash: toNoirArray(messageHash),
  pubkey_x: toNoirArray(pubkeyX),
  pubkey_y: toNoirArray(pubkeyY),
  signature: toNoirArray(sigBytes),
  // Hex versions for debugging
  _hex: {
    privateKey: bytesToHex(privateKey),
    messageHash: bytesToHex(messageHash),
    pubkeyX: bytesToHex(pubkeyX),
    pubkeyY: bytesToHex(pubkeyY),
    signature: bytesToHex(sigBytes),
  }
};

// Write Prover.toml for Noir
const proverToml = `# Generated ECDSA test fixture
message_hash = [${fixture.message_hash.join(', ')}]
pubkey_x = [${fixture.pubkey_x.join(', ')}]
pubkey_y = [${fixture.pubkey_y.join(', ')}]
signature = [${fixture.signature.join(', ')}]
`;

writeFileSync('ecdsa-fixture.json', JSON.stringify(fixture, null, 2));
writeFileSync('../circuits/ecdsa_spike/Prover.toml', proverToml);

console.log('Generated ecdsa-fixture.json and Prover.toml');
console.log('\nMessage hash:', bytesToHex(messageHash));
console.log('Public key X:', bytesToHex(pubkeyX));
console.log('Public key Y:', bytesToHex(pubkeyY));
console.log('Signature:', bytesToHex(sigBytes));
