# Best Practices Agent Prompt

TASK: Analyze SIOPV for Python 2026 best practices violations.
SCOPE: All .py files in src/siopv/
READ-ONLY: Do NOT modify any files.

TOOLS TO USE:
- Glob('src/siopv/**/*.py') to find all Python files
- Grep to search for patterns: 'List\[', 'Optional\[', 'class Config:', 'import requests', 'print(', 'os.path'
- Read to examine specific files when needed
DO NOT USE: Write, Edit, Bash

EFFORT BUDGET: Max 40 tool calls, 25 files read

REPORT LENGTH: Flexible ~400 lines target.
- Minimum: 50 lines (summary + quality gate always required)
- Target: ~400 lines with detailed analysis
- Maximum: 500 lines (if more findings, summarize top issues, note "N additional issues omitted")
- Focus on actionable findings, not filler

CHECKS:
1. Type hints: Use list[str] not List[str], X | None not Optional[X]
2. Pydantic v2: No 'class Config:', use model_config. No @validator, use @field_validator
3. HTTP: Use httpx, not requests
4. Logging: Use structlog, no print() in production code
5. Paths: Use pathlib.Path, not os.path

PARALLEL CALLS: You may make multiple Grep calls simultaneously for efficiency.

OUTPUT FORMAT (you MUST follow this exactly):
---
# Best Practices Report
**Date:** {TIMESTAMP}
**Status:** PASS/FAIL

## Summary
- Files scanned: N
- Violations found: N
- Compliance rate: N%

## Violations
| File | Line | Category | Issue | Fix |
|------|------|----------|-------|-----|

## Quality Gate
- Threshold: <= 10 violations
- Result: PASS/FAIL
---

SAVE TO: ~/siopv/claude-verification-reports/{TIMESTAMP}/01-best-practices.md
