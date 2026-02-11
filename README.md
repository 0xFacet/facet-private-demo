# Facet Private Demo

A standalone demo of **Facet Private** — private payments on Ethereum, powered by MetaMask.

**[Try the live demo →](https://facet-private-demo.vercel.app/)**

## The Vision

**Facet Private** is a privacy layer for Ethereum where you use MetaMask normally, but your balances and transfers are private. No new wallet, no new keys.

### The Privacy Adapter

A Privacy Adapter sits between MetaMask and Ethereum:

```
MetaMask → Privacy Adapter → Ethereum (Sepolia)
```

Two jobs:
1. **Balances:** Decrypts your notes, reports them to MetaMask
2. **Transfers:** You sign a normal send tx → Adapter builds ZK proof → amounts and parties stay hidden

Anyone can run their own Adapter.

---

## What This Demo Covers

This demo proves the core innovation: **ECDSA signature verification inside ZK proofs**. Your MetaMask signature authorizes spends; the adapter cannot forge it.

| Feature | Status |
|---------|--------|
| Private EOA balances | ✅ |
| Private transfers | ✅ |
| Unlinkable spends | ✅ |
| Contract calls (unshield→execute→reshield) | ❌ Not in demo |

The demo uses a PrivacyPool contract on Sepolia. Think of it as a proof-of-concept for the hardest part: private transactions with a normal wallet UX.

## Privacy Model

| What | Visible on-chain? | Who can see it? |
|------|-------------------|-----------------|
| Deposit amount | Yes | Everyone |
| Deposit recipient | Yes | Everyone |
| Transfer amount | No | Only sender & recipient |
| Transfer parties | No | Only sender & recipient |
| Withdrawal amount | Yes | Everyone |
| **Deposit → Spend link** | **No** | **Nobody** |

The core privacy property: **observers cannot link your deposits to your transfers or withdrawals**. Even though deposits are public, the nullifier scheme makes spends unlinkable.

This is a deliberate tradeoff. Full deposit privacy would require users to generate ZK proofs, which we avoid to keep the UX simple.

## How It Works

### Architecture

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│    MetaMask     │────▶│ Privacy Adapter  │────▶│     Sepolia     │
│  (User Wallet)  │     │   (RPC Server)   │     │  (PrivacyPool)  │
└─────────────────┘     └─────────────────┘     └─────────────────┘
        │                       │                       │
   Signs private txs        Generates ZK           Verifies proofs,
   (chain 13371337)         proofs, submits        stores commitments
                            on-chain               in merkle tree
```

The demo uses two signing contexts: **Sepolia** for deposits, and a **private adapter network** (chain 13371337) for transfers and withdrawals. Final settlement is always on Sepolia.

1. **Deposit:** User sends ETH to the PrivacyPool contract on Sepolia. A "note" commitment is added to the merkle tree.

2. **Transfer:** User signs a transaction via the adapter network in MetaMask. The adapter generates a ZK proof that the signature authorizes the spend, and submits it on-chain.

3. **Withdraw:** Same as transfer, but user sends to the sentinel address `0x1`. ETH exits the pool to the user's wallet.

### Trust Model

| Component | Trusted for... | NOT trusted for... |
|-----------|----------------|-------------------|
| **Adapter** | Privacy (sees all your notes), Auto-registration | Spending (can't forge your signature) |
| **PrivacyPool Contract** | Proof verification | Nothing else — trustless |
| **MetaMask** | Key custody | N/A |

The adapter is like a privacy-preserving RPC node. It can see your balance, but every spend requires your MetaMask signature verified inside the ZK circuit.

### RecipientRegistry

The RecipientRegistry stores encryption public keys for each registered user, enabling:
- **Encrypted transfers**: Senders encrypt notes to recipients using their registered Grumpkin public key
- **Registry membership proofs**: The circuit verifies both sender (for withdraws) and recipient (for transfers) are registered

When you sign the "Register Viewing Key" message, the adapter derives your encryption keypair and automatically registers it on L1 via a trusted relayer. This happens transparently — you just wait a few seconds for the L1 transaction to confirm.

---

## User Guide

### Prerequisites

- MetaMask browser extension
- Some Sepolia ETH

### Getting Started

1. **Open the app** at `http://localhost:5173` (or deployed URL)

2. **Connect Wallet** — Click the button and approve in MetaMask

3. **Register Viewing Key** — Sign a message to derive your encryption keys. This is a one-time setup that registers you on-chain and lets the adapter decrypt notes sent to you. The adapter auto-registers you in the RecipientRegistry (takes a few seconds for the L1 tx to confirm).

4. **Shield** — Enter an amount and click "Shield". You'll sign a deposit transaction on Sepolia that adds shielded ETH to your private balance.

5. **Transfer** — Enter a recipient address and amount, click "Send". The recipient must also be registered. You'll sign a transaction via the adapter network; proof generation takes ~60 seconds.

6. **Unshield** — Enter an amount and click "Unshield". Your shielded ETH returns to your public wallet.

### Tips

- Proof generation takes ~60 seconds on typical hardware
- The adapter must be running for transfers/withdrawals to work
- If the adapter restarts, click "Refresh Page" to re-register your session

---

## Developer Setup

### Prerequisites

#### 1. Foundry (Forge)

```bash
curl -L https://foundry.paradigm.xyz | bash
foundryup
forge --version
```

#### 2. Noir (Nargo)

```bash
curl -L https://raw.githubusercontent.com/noir-lang/noirup/refs/heads/main/install | bash
noirup -v 1.0.0-beta.16
nargo --version
```

#### 3. Barretenberg (bb)

```bash
curl -L https://raw.githubusercontent.com/AztecProtocol/aztec-packages/refs/heads/master/barretenberg/bbup/install | bash
bbup --nightly
bb --version
```

#### 4. Node.js

```bash
nvm install 20
nvm use 20
node --version  # v20.x or later
```

### Installation

```bash
git clone https://github.com/0xFacet/facet-private-demo.git
cd facet-private-demo

# Install all dependencies
cd contracts && forge install && cd ..
cd adapter && npm install && cd ..
cd frontend && npm install && cd ..
cd integration && npm install && cd ..
```

### Running Locally

**Terminal 1 — Adapter:**
```bash
cd adapter
cp .env.example .env  # Edit with your config
npm run dev
```

**Terminal 2 — Frontend:**
```bash
cd frontend
npm run dev
```

Open `http://localhost:5173`

### Environment Variables

**Adapter (`adapter/.env`):**
```bash
PRIVACY_POOL_ADDRESS=0x...      # Deployed PrivacyPool address
REGISTRY_ADDRESS=0x...          # Deployed RecipientRegistry address
L1_RPC_URL=https://sepolia...   # Sepolia RPC endpoint
RELAYER_PRIVATE_KEY=0x...       # Key for submitting L1 txs
DEPLOY_BLOCK=12345678           # Block number of deployment (for faster sync)
```

**Frontend (`frontend/.env`):**
```bash
VITE_ADAPTER_URL=http://localhost:8546
VITE_PRIVACY_POOL_ADDRESS=0x...
```

---

## Development

### Rebuilding Circuits

After modifying circuit code:

```bash
./scripts/rebuild-circuits.sh
```

This compiles both circuits, regenerates Solidity verifiers, and rebuilds contracts.

### Manual Steps

**Compile circuits:**
```bash
cd circuits/transfer && nargo compile
cd ../withdraw && nargo compile
```

**Generate verifiers:**
```bash
cd integration && npx tsx generate-verifiers.ts
```

**Build contracts:**
```bash
cd contracts && forge build
```

### Running Tests

**Contract tests:**
```bash
cd contracts && forge test
```

**E2E tests (requires local anvil):**
```bash
# Terminal 1
anvil

# Terminal 2
cd integration && npx tsx e2e-transfer.ts
```

### Deployment

**Deploy to Sepolia:**
```bash
cd contracts
PRIVATE_KEY=0x... forge script script/Deploy.s.sol --broadcast --rpc-url https://sepolia...
```

Note the deployed addresses and update your `.env` files.

---

## Technical Deep Dive

### Note Structure

A note commitment is: `poseidon(amount, owner, randomness, nullifierKeyHash)`

- **amount** — ETH value in wei
- **owner** — Ethereum address as field element
- **randomness** — Random value for uniqueness
- **nullifierKeyHash** — Hash of owner's nullifier key, binding note to their spending authority

### Nullifier Scheme

When spending a note, the circuit computes: `nullifier = hash(NULLIFIER_DOMAIN, nullifierKey, leafIndex, randomness)`

The `nullifierKey` is derived from the user's signature during registration and never revealed on-chain. Only its hash (`nullifierKeyHash`) is stored in the registry and embedded in commitments. The nullifier binds to both the note's position (leafIndex) and its randomness, ensuring uniqueness.

This means:
- Only the note owner can compute the nullifier (they have the key)
- Observers see nullifiers but can't link them to deposits (they don't have the key)
- Double-spend is prevented (same note → same nullifier → rejected)

### Circuit Constraints

The transfer circuit proves:
1. Input notes exist in the pool merkle tree
2. Nullifiers are correctly computed from notes + nullifier key
3. ECDSA signature over the transaction is valid
4. Signer owns the input notes
5. Output commitments are correctly formed
6. Value is conserved (inputs = outputs)
7. Intent nullifier prevents replay
8. Recipient is registered in the RecipientRegistry (merkle membership proof)

The withdraw circuit additionally proves the sender is registered in the RecipientRegistry.

### Why "No User Proofs"?

Traditional privacy systems (Tornado Cash, Railgun) require users to generate ZK proofs client-side. This has UX costs:
- Slow (minutes on mobile)
- Requires WASM/native binaries
- Complex key management

Our approach: the adapter generates proofs server-side. Users just sign with MetaMask. The tradeoff is weaker deposit privacy, but the spend unlinkability — the core privacy property — is preserved.

---

## Project Structure

```
facet-private-demo/
├── circuits/
│   ├── transfer/        # Transfer circuit (Noir)
│   └── withdraw/        # Withdraw circuit (Noir)
├── contracts/
│   ├── src/             # Solidity contracts
│   ├── verifiers/       # Generated verifier contracts
│   └── script/          # Deployment scripts
├── adapter/             # Privacy RPC server
├── frontend/            # React UI
├── integration/         # E2E tests, verifier generation
└── scripts/             # Build scripts
```

---

## FAQ

**Q: Is this a production system?**
A: No. This is a demo that proves the core innovation works.

**Q: Can the adapter steal my funds?**
A: No. Every spend requires your ECDSA signature, verified inside the ZK circuit. The adapter can see your balance but cannot forge signatures. Even though the adapter auto-registers you, this only sets up your encryption key — it doesn't give anyone spending authority over your funds.

**Q: What if the adapter goes down?**
A: Your funds are safe in the on-chain contract. You'd need to run your own adapter (or wait for it to come back) to generate proofs for transfers/withdrawals.

**Q: Why are deposits public?**
A: To avoid requiring users to generate proofs. Full deposit privacy would need a deposit circuit, adding UX complexity. This is a deliberate tradeoff for better UX.

**Q: Can I run my own adapter?**
A: Yes! The adapter is open source. Point it at your own Sepolia RPC and you're independent.

**Q: How is this different from Tornado Cash?**
A: Tornado uses fixed denominations and requires client-side proofs. We support variable amounts with server-side proofs and a MetaMask-native UX.

---

## Acknowledgments

Architecture inspired by [Nullmask](https://nullmask.io/).

---

## License

MIT
