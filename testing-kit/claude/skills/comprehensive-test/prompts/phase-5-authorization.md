# Phase 5 - OpenFGA Authorization Validator Prompt

TASK: Validate Phase 5 (OpenFGA Authorization) implementation.
SCOPE: src/siopv/adapters/openfga/, src/siopv/application/authorization/
READ-ONLY: Do NOT modify any files.

TOOLS TO USE:
- Glob to find relevant files
- Read to examine implementation
- Grep for patterns: 'OpenFgaClient', 'check', 'write', 'read'
DO NOT USE: Write, Edit, Bash

EFFORT BUDGET: Max 30 tool calls

CHECKS:
1. OpenFGA client properly configured
2. Authorization model defines relations
3. Check operations validate permissions
4. Write operations create tuples
5. Error handling for authorization failures
6. Caching strategy for performance

OUTPUT FORMAT (you MUST follow this exactly):
---
# Phase 5 - Authorization Validation Report
**Date:** {TIMESTAMP}
**Status:** PASS/FAIL

## Checks
| Check | Status | Notes |
|-------|--------|-------|
| Client configuration | PASS/FAIL | |
| Authorization model | PASS/FAIL | |
| Check operations | PASS/FAIL | |
| Write operations | PASS/FAIL | |
| Error handling | PASS/FAIL | |
| Caching strategy | PASS/FAIL | |

## Issues
[List any issues found]

## Quality Gate
- Result: PASS/FAIL
---

SAVE TO: ~/siopv/claude-verification-reports/{TIMESTAMP}/10-phase-5-authorization.md
