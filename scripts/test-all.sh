#!/bin/bash
# Run all tests: circuits, contracts, and e2e integration
# Run from project root: ./scripts/test-all.sh
#
# Options:
#   --skip-e2e    Skip the e2e integration test (requires anvil)
#   --e2e-only    Only run the e2e test (assumes anvil is running)
#   --rebuild     Rebuild circuits and regenerate Solidity verifiers before testing

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Parse arguments
SKIP_E2E=false
E2E_ONLY=false
REBUILD=false
for arg in "$@"; do
    case $arg in
        --skip-e2e)
            SKIP_E2E=true
            ;;
        --e2e-only)
            E2E_ONLY=true
            ;;
        --rebuild)
            REBUILD=true
            ;;
    esac
done

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

passed=0
failed=0

# Rebuild circuits and verifiers if requested
if [ "$REBUILD" = true ]; then
    echo ""
    echo "============================================================"
    echo -e "${YELLOW}Rebuilding circuits and verifiers...${NC}"
    echo "============================================================"
    "$SCRIPT_DIR/rebuild-circuits.sh"
    echo ""
fi

run_test() {
    local name="$1"
    local cmd="$2"

    echo ""
    echo "============================================================"
    echo -e "${YELLOW}Running: $name${NC}"
    echo "============================================================"

    if eval "$cmd"; then
        echo -e "${GREEN}✓ $name PASSED${NC}"
        ((passed++)) || true
    else
        echo -e "${RED}✗ $name FAILED${NC}"
        ((failed++)) || true
    fi
}

if [ "$E2E_ONLY" = false ]; then
    # 1. Compile and check transfer circuit
    run_test "Transfer circuit compilation" \
        "cd '$PROJECT_ROOT/circuits/transfer' && nargo compile"

    # 2. Compile and check withdraw circuit
    run_test "Withdraw circuit compilation" \
        "cd '$PROJECT_ROOT/circuits/withdraw' && nargo compile"

    # 3. Run Forge tests
    run_test "Solidity contract tests (forge)" \
        "cd '$PROJECT_ROOT/contracts' && forge test -vvv"
fi

# 4. Run E2E integration test (requires anvil)
if [ "$SKIP_E2E" = false ]; then
    echo ""
    echo "============================================================"
    echo -e "${YELLOW}Running: E2E integration test${NC}"
    echo "============================================================"
    echo "Note: This requires anvil to be running on localhost:8545"
    echo ""

    # Check if anvil is running
    if ! nc -z localhost 8545 2>/dev/null; then
        echo -e "${YELLOW}Starting anvil in background...${NC}"
        anvil --silent &
        ANVIL_PID=$!
        sleep 2
        STARTED_ANVIL=true
    else
        echo "anvil already running"
        STARTED_ANVIL=false
    fi

    # Run e2e test
    if cd "$PROJECT_ROOT/integration" && npx tsx e2e-transfer.ts; then
        echo -e "${GREEN}✓ E2E integration test PASSED${NC}"
        ((passed++)) || true
    else
        echo -e "${RED}✗ E2E integration test FAILED${NC}"
        ((failed++)) || true
    fi

    # Stop anvil if we started it
    if [ "$STARTED_ANVIL" = true ]; then
        echo "Stopping anvil..."
        kill $ANVIL_PID 2>/dev/null || true
    fi
fi

# Summary
echo ""
echo "============================================================"
echo "TEST SUMMARY"
echo "============================================================"
echo -e "${GREEN}Passed: $passed${NC}"
echo -e "${RED}Failed: $failed${NC}"

if [ $failed -gt 0 ]; then
    echo ""
    echo -e "${RED}Some tests failed!${NC}"
    exit 1
else
    echo ""
    echo -e "${GREEN}All tests passed!${NC}"
    exit 0
fi
