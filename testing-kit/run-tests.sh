#!/bin/bash
# SIOPV Testing Kit - CI Integration Script
# Usage: ./testing-kit/run-tests.sh [skill]
# Example: ./testing-kit/run-tests.sh comprehensive-test
#          ./testing-kit/run-tests.sh test-quick

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SIOPV_DIR="$(dirname "$SCRIPT_DIR")"
SKILL="${1:-comprehensive-test}"

echo "=== SIOPV Testing Kit ==="
echo "Project: $SIOPV_DIR"
echo "Skill: /$SKILL"
echo ""

# Step 1: Copy testing infrastructure
echo "[1/4] Copying testing infrastructure..."
cp -r "$SCRIPT_DIR/claude" "$SIOPV_DIR/.claude"
cp -r "$SCRIPT_DIR/fixtures" "$SIOPV_DIR/.claude/fixtures"

# Step 2: Run Claude with skill
echo "[2/4] Running /$SKILL..."
cd "$SIOPV_DIR"

# Check if running in CI (non-interactive)
if [ -n "$CI" ] || [ ! -t 0 ]; then
    echo "CI mode detected - running with --dangerously-skip-permissions"
    claude --dangerously-skip-permissions -p "/$SKILL"
else
    echo "Interactive mode - launching Claude session"
    claude -p "/$SKILL"
fi

# Step 3: Check results
echo "[3/4] Checking results..."
LATEST_RESULTS=$(ls -td "$SIOPV_DIR/claude-verification-reports"/*/ 2>/dev/null | head -1)

if [ -z "$LATEST_RESULTS" ]; then
    echo "ERROR: No test results found"
    rm -rf "$SIOPV_DIR/.claude"
    exit 1
fi

echo "Results saved to: $LATEST_RESULTS"

# Step 4: Cleanup
echo "[4/4] Cleaning up .claude/ folder..."
rm -rf "$SIOPV_DIR/.claude"

# Display summary
echo ""
echo "=== Test Complete ==="
if [ -f "$LATEST_RESULTS/00-COMPREHENSIVE-SUMMARY.md" ]; then
    echo ""
    head -50 "$LATEST_RESULTS/00-COMPREHENSIVE-SUMMARY.md"
fi

echo ""
echo "Full reports: $LATEST_RESULTS"
