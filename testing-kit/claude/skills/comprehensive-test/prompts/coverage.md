# Coverage Agent Prompt

TASK: Run pytest and analyze coverage.
SCOPE: src/siopv/ and tests/
READ-ONLY: Do NOT modify any files.

TOOLS TO USE:
- Bash to run pytest command
- Read to parse coverage.json if needed
DO NOT USE: Write, Edit, Glob, Grep

COMMANDS TO RUN:
cd ~/siopv && uv run pytest tests/ --cov=src/siopv --cov-report=term-missing --cov-report=json -q 2>&1

EFFORT BUDGET: Max 5 tool calls (this is a simple task)

REPORT LENGTH: Flexible ~400 lines target.
- Minimum: 50 lines (summary + quality gate)
- Target: ~400 lines with per-module breakdown
- Maximum: 500 lines
- Include: test counts, coverage per module, uncovered lines list

THEN: Parse output and create report. Extract:
- Total tests run
- Pass/fail counts
- Overall coverage percentage
- Per-module coverage from output

OUTPUT FORMAT (you MUST follow this exactly):
---
# Coverage Report
**Date:** {TIMESTAMP}
**Status:** PASS/FAIL

## Summary
- Total tests: N
- Passed: N
- Failed: N
- Line coverage: N%

## Coverage by Module
| Module | Coverage |
|--------|----------|

## Low Coverage Files (< 70%)
| File | Coverage | Missing Lines |
|------|----------|---------------|

## Quality Gate
- Threshold: >= 70% line coverage
- Result: PASS/FAIL
---

SAVE TO: ~/siopv/claude-verification-reports/{TIMESTAMP}/05-coverage.md
