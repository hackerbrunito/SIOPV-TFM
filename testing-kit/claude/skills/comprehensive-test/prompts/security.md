# Security Agent Prompt

TASK: Security audit of SIOPV codebase.
SCOPE: All .py files in src/siopv/
READ-ONLY: Do NOT modify any files.

TOOLS TO USE:
- Glob('src/siopv/**/*.py') to find all Python files
- Grep for patterns: 'subprocess', 'eval(', 'exec(', 'shell=True', 'password', 'secret', 'api_key', 'token', '.format(', 'f".*{.*}', 'open(.*,'
- Read to examine suspicious files in detail
DO NOT USE: Write, Edit, Bash

EFFORT BUDGET: Max 60 tool calls, 35 files read

REPORT LENGTH: Flexible ~400 lines target.
- Minimum: 50 lines (summary + quality gate always required)
- Target: ~400 lines with detailed analysis per severity
- Maximum: 500 lines (summarize if more, note omitted count)
- Include remediation guidance for each finding

REASONING: Before writing report, think step-by-step:
1. What injection vectors exist?
2. Are there hardcoded secrets?
3. How is user input validated?

CHECKS:
1. Injection: SQL, command, path traversal
2. Secrets: Hardcoded API keys, tokens, passwords
3. Input validation: Untrusted data handling
4. Error handling: No stack traces to users

SEVERITY LEVELS:
- CRITICAL: Immediate exploitation risk
- HIGH: Significant security risk
- MEDIUM: Should fix before production
- LOW: Informational

OUTPUT FORMAT (you MUST follow this exactly):
---
# Security Audit Report
**Date:** {TIMESTAMP}
**Status:** PASS/FAIL

## Summary
- Files scanned: N
- Critical: N | High: N | Medium: N | Low: N

## Findings
| Severity | File | Line | Issue | Remediation |
|----------|------|------|-------|-------------|

## Quality Gate
- Threshold: 0 CRITICAL, <= 3 HIGH
- Result: PASS/FAIL
---

SAVE TO: ~/siopv/claude-verification-reports/{TIMESTAMP}/02-security.md
