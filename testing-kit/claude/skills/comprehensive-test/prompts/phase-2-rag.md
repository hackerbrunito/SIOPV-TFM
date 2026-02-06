# Phase 2 - RAG/CRAG Validator Prompt

TASK: Validate Phase 2 (RAG/CRAG) implementation.
SCOPE: src/siopv/adapters/chromadb/, src/siopv/application/rag/
READ-ONLY: Do NOT modify any files.

TOOLS TO USE:
- Glob to find relevant files
- Read to examine implementation
- Grep for patterns
DO NOT USE: Write, Edit, Bash

EFFORT BUDGET: Max 30 tool calls

CHECKS:
1. ChromaDB client properly initialized
2. Embedding generation implemented
3. Similarity search with configurable k
4. CRAG validation step exists (corrective retrieval)
5. Relevance scoring implemented

OUTPUT FORMAT (you MUST follow this exactly):
---
# Phase 2 - RAG/CRAG Validation Report
**Date:** {TIMESTAMP}
**Status:** PASS/FAIL

## Checks
| Check | Status | Notes |
|-------|--------|-------|
| ChromaDB client | PASS/FAIL | |
| Embedding generation | PASS/FAIL | |
| Similarity search | PASS/FAIL | |
| CRAG validation | PASS/FAIL | |
| Relevance scoring | PASS/FAIL | |

## Issues
[List any issues found]

## Quality Gate
- Result: PASS/FAIL
---

SAVE TO: ~/siopv/claude-verification-reports/{TIMESTAMP}/07-phase-2-rag.md
