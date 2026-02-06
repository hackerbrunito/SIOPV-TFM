# Hallucination Detection Agent Prompt

TASK: Verify API usage against official documentation.
SCOPE: All .py files in src/siopv/
READ-ONLY: Do NOT modify any files.

TOOLS TO USE:
- Glob('src/siopv/**/*.py') to find Python files
- Read to examine import statements and API calls
- mcp__context7__resolve-library-id to get library IDs
- mcp__context7__query-docs to verify API usage
DO NOT USE: Write, Edit, Bash

EFFORT BUDGET: Max 80 tool calls (Context7 queries are expensive)

REPORT LENGTH: Flexible ~400 lines target.
- Minimum: 50 lines (even if no issues found)
- Target: ~400 lines documenting verification process
- Maximum: 500 lines
- Include: which APIs checked, Context7 queries made, verification results

LIBRARIES TO CHECK (in order of priority):
1. pydantic (v2) - model definitions, validators
2. httpx - async client usage
3. langgraph - StateGraph, nodes, edges
4. chromadb - client, collections
5. openfga-sdk - check, write operations

PROCESS:
1. For each library, call resolve-library-id first
2. Then query-docs with specific usage questions
3. Compare code against documented patterns

IF CONTEXT7 UNAVAILABLE: Note in report, skip API verification, mark as PARTIAL.

OUTPUT FORMAT (you MUST follow this exactly):
---
# Hallucination Detection Report
**Date:** {TIMESTAMP}
**Status:** PASS/FAIL/PARTIAL

## Summary
- Libraries verified: N
- Issues found: N
- Context7 available: YES/NO

## Verification Process
[Document which libraries checked and queries made]

## Issues
| Library | File | Line | Issue | Correct Usage |
|---------|------|------|-------|---------------|

## Quality Gate
- Threshold: 0 hallucinated APIs
- Result: PASS/FAIL
---

SAVE TO: ~/siopv/claude-verification-reports/{TIMESTAMP}/03-hallucination.md
