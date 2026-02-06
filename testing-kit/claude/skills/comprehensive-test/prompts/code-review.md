# Code Review Agent Prompt

TASK: Code quality review of SIOPV.
SCOPE: All .py files in src/siopv/
READ-ONLY: Do NOT modify any files.

TOOLS TO USE:
- Glob('src/siopv/**/*.py') to find Python files
- Read to examine code structure and quality
- Grep for patterns: 'except:', 'TODO', 'FIXME', 'pass$'
DO NOT USE: Write, Edit, Bash

EFFORT BUDGET: Max 50 tool calls, 30 files read

REPORT LENGTH: Flexible ~400 lines target.
- Minimum: 50 lines (scores + quality gate required)
- Target: ~400 lines with examples per category
- Maximum: 500 lines
- Include code snippets illustrating good/bad patterns

REASONING: Before scoring, think step-by-step:
1. Sample files from each layer (domain, application, adapters, infrastructure)
2. Evaluate each category with specific examples
3. Calculate weighted average for overall score

CHECKS:
1. Complexity: Functions > 10 cyclomatic complexity
2. Naming: Clear, descriptive names
3. DRY: Duplicate code patterns
4. Documentation: Docstrings on public APIs
5. Error handling: No bare except:

SCORING: 1-10 scale per category, average for overall.

OUTPUT FORMAT (you MUST follow this exactly):
---
# Code Review Report
**Date:** {TIMESTAMP}
**Status:** PASS/FAIL
**Overall Score:** N/10

## Scores
| Category | Score | Notes |
|----------|-------|-------|
| Complexity | N/10 | |
| Naming | N/10 | |
| DRY | N/10 | |
| Documentation | N/10 | |
| Error Handling | N/10 | |

## Issues
| File | Line | Category | Issue |
|------|------|----------|-------|

## Recommendations
[Top 3-5 actionable improvements]

## Quality Gate
- Threshold: >= 7/10
- Result: PASS/FAIL
---

SAVE TO: ~/siopv/claude-verification-reports/{TIMESTAMP}/04-code-review.md
