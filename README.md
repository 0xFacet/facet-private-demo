# Facet Private Demo

Private ETH transactions with ZK proofs on Ethereum Sepolia.

## Quick Start: Running the MetaMask Demo

### 1. Start the Adapter

```bash
cd adapter
npm install
npm run dev
```

The adapter listens on `http://localhost:8546`.

### 2. Start the Frontend

```bash
cd frontend
npm install
npm run dev
```

Open `http://localhost:5173` in your browser.

### 3. Connect MetaMask

1. Click "Connect Wallet" - the app will prompt you to add the network:
   - **Network Name**: Facet Private (Demo)
   - **RPC URL**: http://localhost:8546
   - **Chain ID**: 13371337
   - **Symbol**: ETH

2. Click "Register Viewing Key" and sign the message

### 4. Use the Demo

**Important**: The circuit requires 2 input notes. Make at least **2 deposits** before transferring.

1. **Deposit**: Enter amount (e.g., 0.01 ETH), click "Deposit to Pool"
2. **Deposit again**: Make a second deposit
3. **Transfer**: Enter recipient address and amount, click "Send Privately"
4. **Withdraw**: Enter amount, click "Withdraw to Wallet"

Proof generation takes ~30 seconds per operation.

### Running E2E Tests

```bash
# Terminal 1: Start anvil
anvil

# Terminal 2: Run tests
cd integration
npm install
npx tsx e2e-transfer.ts
```

---

## Prerequisites

### Required Tools

This project requires the following tools to be installed:

#### 1. Foundry (Forge)

Foundry is used for Solidity smart contract development and testing.

```bash
# Install foundryup
curl -L https://foundry.paradigm.xyz | bash

# Install foundry
foundryup
```

After installation, verify with:
```bash
forge --version
```

#### 2. Noir (Nargo)

Noir is the ZK circuit language used for the privacy proofs. Install version `1.0.0-beta.16` or compatible.

```bash
# Install noirup
curl -L https://raw.githubusercontent.com/noir-lang/noirup/refs/heads/main/install | bash

# Install nargo (specific version)
noirup -v 1.0.0-beta.16
```

After installation, verify with:
```bash
nargo --version
```

#### 3. Barretenberg (bb)

Barretenberg is the proving backend for Noir circuits. Use `bbup` to install it.

```bash
# Install bbup
curl -L https://raw.githubusercontent.com/AztecProtocol/aztec-packages/refs/heads/master/barretenberg/bbup/install | bash

# Install bb (use nightly for latest features, or a specific version)
bbup --nightly
```

After installation, verify with:
```bash
bb --version
```

> **Note**: The `bb` version should be compatible with your `nargo` version. For nargo `1.0.0-beta.x`, use the nightly build or check the [Noir documentation](https://noir-lang.org/docs/getting_started/quick_start) for version compatibility.

#### 4. Node.js

Node.js is required for the adapter and frontend components.

```bash
# Using nvm (recommended)
nvm install 20
nvm use 20

# Or download from https://nodejs.org/
```

After installation, verify with:
```bash
node --version  # Should be v20.x or later
```

### Project Setup

After installing the prerequisites:

```bash
# Clone the repository
git clone <repo-url>
cd facet-private-demo

# Install contract dependencies
cd contracts
forge install
cd ..

# Install fixture dependencies
cd fixtures
npm install
cd ..

# Install adapter dependencies
cd adapter
npm install
cd ..

# Install frontend dependencies
cd frontend
npm install
cd ..

# Install integration dependencies (for verifier generation)
cd integration
npm install
cd ..
```

---

## Development

### Rebuilding Circuits (Quick)

After modifying circuit code, run the rebuild script from the project root:

```bash
./scripts/rebuild-circuits.sh
```

This compiles both circuits, regenerates the Solidity verifiers, and rebuilds the contracts.

### Manual Steps

If you prefer to run steps individually:

#### Compiling Circuits

```bash
# Compile transfer circuit
cd circuits/transfer
nargo compile
# Generates: circuits/transfer/target/transfer.json

# Compile withdraw circuit
cd ../withdraw
nargo compile
# Generates: circuits/withdraw/target/withdraw.json
```

These JSON files contain the compiled circuit bytecode used by both the verifier generator and the adapter's proof generation.

#### Regenerating Verifier Contracts

After compiling circuits, regenerate the Solidity verifiers:

```bash
cd integration
npx tsx generate-verifiers.ts
```

This generates:
- `contracts/verifiers/TransferVerifier.sol`
- `contracts/verifiers/WithdrawVerifier.sol`

Then rebuild the contracts:

```bash
cd ../contracts
forge build
```

### Running Contract Tests

```bash
cd contracts
forge test
```

---

## Introduction: Why This Architecture Exists

### The Problem with Private Transactions Today

Every existing privacy solution on Ethereum—Tornado Cash, Railgun, Aztec—requires users to manage a separate set of cryptographic keys. You generate a "shielded wallet," back up a new seed phrase, and interact through custom interfaces. This isn't just inconvenient; it's a fundamental barrier to adoption. Users don't want another wallet. They want their existing wallet to just... work privately.

The mental model shift is significant: instead of "send 70 ETH to Bob," users have to think about "deposit to shielded pool, wait for anonymity set, generate proof with my shielded key, withdraw to fresh address." The privacy is real, but the UX is a research project.

### The Core Insight

What if we could keep the spending authority exactly where it already is—in the user's Ethereum private key, secured by MetaMask—and move only the *visibility* into a separate layer?

That's what this system does. When you click "Send" in MetaMask, you're signing a real Ethereum transaction. That signature is your authorization to spend. The ZK circuit verifies that signature *inside the proof*, which means:

1. **No new keys to manage.** Your ETH private key is your spending key.
2. **No new interfaces to learn.** MetaMask's Send flow is the UX.
3. **No trust in the adapter for spending.** The adapter can see your balance (it has your viewing key), but it literally cannot move your funds without your MetaMask signature.

The adapter is more like a privacy-preserving RPC node than a wallet. It watches the chain, decrypts your notes, and constructs proofs—but every spend requires you to sign with MetaMask.

### Why a Virtual Chain ID?

There's an obvious attack if we're not careful: if the user signs a transaction targeting Sepolia (chainId 11155111), that transaction is valid on Sepolia. A malicious actor could intercept it and broadcast it, draining the user's *public* ETH to whatever address was in the `to` field.

The fix is elegant: we present MetaMask with a fake chain ID (13371337) that doesn't correspond to any real network. The signed transaction is cryptographically valid, but useless on any actual blockchain. The adapter extracts the signature, verifies it inside the ZK circuit, and submits a *different* transaction (the proof) to Sepolia. The user's signature authorizes the private transfer; it never touches L1 directly.

### What This Proves

This demo is a standalone extraction of the private payments layer from a larger system—a privacy-oriented L2 rollup where all EOA balances are shielded by default. Building a full rollup is months of work. But the core innovation—ECDSA authorization inside ZK, preserving the MetaMask UX—can be demonstrated in a much smaller package.

If this works, we've proven:

1. **ECDSA-in-ZK is practical.** Yes, it's expensive (~400k constraints for secp256k1 + keccak), but modern provers handle it in reasonable time.

2. **The UX can be seamless.** Users add a custom RPC, sign one setup message, and then just... use MetaMask normally. Send works. Balances update. No PhD required.

3. **The trust model is sound.** The adapter is trusted with *privacy* (it sees everything), but not with *funds* (it can't forge your signature). This is a meaningful separation.

### Relationship to the Full Rollup Vision

In the complete system, this private payment mechanism would be one part of a larger privacy-preserving execution environment. The rollup would support general smart contract execution with shielded state, not just transfers. The "unshield → swap → reshield" flow would let users interact with DeFi without revealing their holdings.

But payments are the foundation. If we can't do private sends cleanly, nothing else matters. This demo isolates that foundation and proves it works.

### What the Developer Should Understand

As you implement this, keep in mind:

1. **The signed transaction is sacred.** Every constraint in the circuit exists to ensure that the user's MetaMask signature—and nothing else—authorizes the spend. The intent nullifier binds to (signer, chainId, nonce, to, value). The circuit verifies ECDSA. The adapter cannot substitute different parameters.

2. **The adapter is powerful but not dangerous.** It holds the viewing key, so it sees all notes and can compute nullifiers. But the spending authority is the ECDSA signature, which only MetaMask can produce. This is the whole point: separate visibility from control.

3. **The virtual chain ID is load-bearing.** If you accidentally use a real chain ID, signed transactions become weapons. The 13371337 ID isn't arbitrary—it's a security boundary.

4. **Two input notes is a simplification.** Real systems support variable input counts with padding. We're requiring exactly two notes to keep the circuit simple and avoid edge cases around "dummy notes." This means users need at least two deposits before they can transfer, which is fine for a demo.

5. **Events are your indexing strategy.** The `LeafInserted` event tells you where each commitment landed in the tree. Without it, you'd have to replay every transaction to reconstruct indices. Don't skip it.

### The Goal

When this is done, a user should be able to:

1. Add "Facet Private" as a network in MetaMask
2. Sign one message to derive their viewing key
3. Register their encryption pubkey (one-time, on Sepolia)
4. Deposit ETH through a simple web page
5. Send ETH to any registered recipient using MetaMask's normal Send flow
6. See their shielded balance update
7. Withdraw back to their EOA when needed

No new wallet. No seed phrases. No learning curve beyond "add network, sign message, deposit." That's the bar.
