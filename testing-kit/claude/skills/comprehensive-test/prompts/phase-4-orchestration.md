# Phase 4 - LangGraph Orchestration Validator Prompt

TASK: Validate Phase 4 (LangGraph Orchestration) implementation.
SCOPE: src/siopv/application/orchestration/, src/siopv/adapters/langgraph/
READ-ONLY: Do NOT modify any files.

TOOLS TO USE:
- Glob to find relevant files
- Read to examine implementation
- Grep for patterns: 'StateGraph', 'add_node', 'add_edge', 'compile'
DO NOT USE: Write, Edit, Bash

EFFORT BUDGET: Max 30 tool calls

CHECKS:
1. StateGraph properly defined with typed state
2. Nodes registered with clear responsibilities
3. Edges define valid transitions
4. Conditional edges use proper logic
5. Graph compiles without errors
6. Checkpointing enabled for recovery

OUTPUT FORMAT (you MUST follow this exactly):
---
# Phase 4 - Orchestration Validation Report
**Date:** {TIMESTAMP}
**Status:** PASS/FAIL

## Checks
| Check | Status | Notes |
|-------|--------|-------|
| StateGraph definition | PASS/FAIL | |
| Node registration | PASS/FAIL | |
| Edge transitions | PASS/FAIL | |
| Conditional logic | PASS/FAIL | |
| Graph compilation | PASS/FAIL | |
| Checkpointing | PASS/FAIL | |

## Issues
[List any issues found]

## Quality Gate
- Result: PASS/FAIL
---

SAVE TO: ~/siopv/claude-verification-reports/{TIMESTAMP}/09-phase-4-orchestration.md
