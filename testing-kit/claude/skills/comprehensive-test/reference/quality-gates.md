# Quality Gates Reference

Objective thresholds for PASS/FAIL determination.

## Coverage Gate

| Metric | Threshold | Gate |
|--------|-----------|------|
| Line coverage | >= 70% | FAIL if below |
| Branch coverage | >= 60% | WARN if below |

## Security Gate

| Severity | Threshold | Gate |
|----------|-----------|------|
| CRITICAL | 0 | FAIL if any |
| HIGH | <= 3 | FAIL if exceeded |
| MEDIUM | <= 10 | WARN if exceeded |
| LOW | No limit | Informational |

## Best Practices Gate

| Metric | Threshold | Gate |
|--------|-----------|------|
| Total violations | <= 10 | FAIL if exceeded |
| Type hint violations | <= 5 | WARN if exceeded |
| Pydantic v1 patterns | 0 | FAIL if any |

## Code Review Gate

| Metric | Threshold | Gate |
|--------|-----------|------|
| Overall score | >= 7/10 | FAIL if below |
| Any category | >= 5/10 | WARN if below |

## Hallucination Gate

| Metric | Threshold | Gate |
|--------|-----------|------|
| Hallucinated APIs | 0 | FAIL if any |
| Deprecated patterns | <= 3 | WARN if exceeded |

## Phase Validator Gates

Each phase validator passes if:
- All required components exist
- No critical implementation issues
- Error handling is present

## Overall Determination

**PASS**: All gates pass
**FAIL**: Any gate fails
**WARN**: No fails, but warnings present
**PARTIAL**: Some agents could not complete (e.g., Context7 unavailable)

## Customization

To adjust thresholds for your project:
1. Edit this file
2. Update corresponding agent prompts
3. Re-run `/comprehensive-test`
