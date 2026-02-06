# Phase 3 - ML Classification Validator Prompt

TASK: Validate Phase 3 (ML Classification) implementation.
SCOPE: src/siopv/application/classification/, src/siopv/adapters/ml/
READ-ONLY: Do NOT modify any files.

TOOLS TO USE:
- Glob to find relevant files
- Read to examine implementation
- Grep for patterns
DO NOT USE: Write, Edit, Bash

EFFORT BUDGET: Max 30 tool calls

CHECKS:
1. Classification model loading/inference
2. Confidence scores returned
3. Multi-label support if applicable
4. Model versioning tracked
5. Fallback for model failures

OUTPUT FORMAT (you MUST follow this exactly):
---
# Phase 3 - ML Classification Validation Report
**Date:** {TIMESTAMP}
**Status:** PASS/FAIL

## Checks
| Check | Status | Notes |
|-------|--------|-------|
| Model loading | PASS/FAIL | |
| Confidence scores | PASS/FAIL | |
| Multi-label support | PASS/FAIL | |
| Model versioning | PASS/FAIL | |
| Failure fallback | PASS/FAIL | |

## Issues
[List any issues found]

## Quality Gate
- Result: PASS/FAIL
---

SAVE TO: ~/siopv/claude-verification-reports/{TIMESTAMP}/08-phase-3-ml.md
