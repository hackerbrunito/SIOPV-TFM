# Phase 1 - Ingestion Validator Prompt

TASK: Validate Phase 1 (Ingestion) implementation.
SCOPE: src/siopv/adapters/trivy/, src/siopv/domain/vulnerability.py
READ-ONLY: Do NOT modify any files.

TOOLS TO USE:
- Glob to find relevant files
- Read to examine implementation
- Grep for patterns
DO NOT USE: Write, Edit, Bash

EFFORT BUDGET: Max 30 tool calls

CHECKS:
1. Trivy JSON parsing handles all severity levels
2. Vulnerability domain model has required fields (id, severity, package, version)
3. Parser handles malformed input gracefully
4. CVSS scores are properly extracted
5. Deduplication logic exists

OUTPUT FORMAT (you MUST follow this exactly):
---
# Phase 1 - Ingestion Validation Report
**Date:** {TIMESTAMP}
**Status:** PASS/FAIL

## Checks
| Check | Status | Notes |
|-------|--------|-------|
| Trivy JSON parsing | PASS/FAIL | |
| Domain model fields | PASS/FAIL | |
| Error handling | PASS/FAIL | |
| CVSS extraction | PASS/FAIL | |
| Deduplication | PASS/FAIL | |

## Issues
[List any issues found]

## Quality Gate
- Result: PASS/FAIL
---

SAVE TO: ~/siopv/claude-verification-reports/{TIMESTAMP}/06-phase-1-ingestion.md
