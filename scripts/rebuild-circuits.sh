#!/bin/bash
# Rebuild circuits and regenerate Solidity verifiers
# Run from project root: ./scripts/rebuild-circuits.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo "=== Compiling transfer circuit ==="
cd "$PROJECT_ROOT/circuits/transfer"
nargo compile

echo ""
echo "=== Compiling withdraw circuit ==="
cd "$PROJECT_ROOT/circuits/withdraw"
nargo compile

echo ""
echo "=== Generating Solidity verifiers ==="
cd "$PROJECT_ROOT/integration"
npx tsx generate-verifiers.ts

echo ""
echo "=== Building contracts ==="
cd "$PROJECT_ROOT/contracts"
forge build

echo ""
echo "=== Done! ==="
echo "Generated:"
echo "  - circuits/transfer/target/transfer.json"
echo "  - circuits/withdraw/target/withdraw.json"
echo "  - contracts/verifiers/TransferVerifier.sol"
echo "  - contracts/verifiers/WithdrawVerifier.sol"
