# Privacy Pool Contracts

## Regenerating Verifier Contracts

When you modify the Noir circuits (`circuits/transfer/` or `circuits/withdraw/`), you must regenerate the Solidity verifier contracts. **This is critical** - the verifier must match the circuit exactly.

### Method: Use bb.js (Recommended)

The `bb` CLI can fail with assertion errors. Use bb.js programmatically instead:

```bash
cd integration
npm install
npx tsx generate-verifiers.ts
cd ../contracts
forge build
```

This script generates verifiers via bb.js with `{ keccakZK: true }` option, which ensures consistency with proof generation.

### Why keccakZK mode?

The `keccakZK` option enables both:
1. **Keccak hashing** - EVM has native `keccak256` opcode, making verification gas-efficient
2. **Zero-knowledge** - Proofs don't leak private inputs (recipient, amounts, etc.)

**WARNING**: Using `{ keccak: true }` instead of `{ keccakZK: true }` disables zero-knowledge! The proofs would still be valid but chain observers could extract private witness data. For a privacy pool, this defeats the entire purpose.

| Option | Hash | ZK | Use Case |
|--------|------|-----|----------|
| `keccak: true` | Keccak | No | Rollups (succinctness only) |
| `keccakZK: true` | Keccak | Yes | Privacy applications |

The verifier contracts must be generated with the same option used for proof generation. Mismatched options = verification fails on-chain.

### Version Compatibility

The following versions must be aligned:

| Component | Version | Notes |
|-----------|---------|-------|
| nargo | 1.0.0-beta.16 | Circuit compiler |
| @noir-lang/noir_js | 1.0.0-beta.16 | Must match nargo |
| @aztec/bb.js | 3.0.0-nightly.20251104 | Proving backend |

If you update nargo, you must also update the npm packages in `integration/package.json`.

### Testing

After regenerating verifiers:

```bash
# Start anvil (in a separate terminal)
anvil

# Run E2E test
cd integration
npx tsx e2e-transfer.ts
```

Note: The E2E test assumes anvil is already running on `localhost:8545`.

---

## Foundry

**Foundry is a blazing fast, portable and modular toolkit for Ethereum application development written in Rust.**

Foundry consists of:

- **Forge**: Ethereum testing framework (like Truffle, Hardhat and DappTools).
- **Cast**: Swiss army knife for interacting with EVM smart contracts, sending transactions and getting chain data.
- **Anvil**: Local Ethereum node, akin to Ganache, Hardhat Network.
- **Chisel**: Fast, utilitarian, and verbose solidity REPL.

## Documentation

https://book.getfoundry.sh/

## Usage

### Build

```shell
$ forge build
```

### Test

```shell
$ forge test
```

### Format

```shell
$ forge fmt
```

### Gas Snapshots

```shell
$ forge snapshot
```

### Anvil

```shell
$ anvil
```

### Deploy

```shell
$ forge script script/Counter.s.sol:CounterScript --rpc-url <your_rpc_url> --private-key <your_private_key>
```

### Cast

```shell
$ cast <subcommand>
```

### Help

```shell
$ forge --help
$ anvil --help
$ cast --help
```
