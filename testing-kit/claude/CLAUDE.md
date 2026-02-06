# SIOPV Testing Kit

This is a portable testing infrastructure for SIOPV verification.

## Purpose

Run comprehensive quality gates on SIOPV codebase without modifying any source files.

## Available Skills

| Skill | Description |
|-------|-------------|
| `/comprehensive-test` | Run all 14 agents (full verification) |
| `/test-foundation` | Run 5 foundation agents only |
| `/test-quick` | Run best-practices + coverage only |

## Quality Gates

| Metric | Threshold | Action |
|--------|-----------|--------|
| Coverage | >= 70% | FAIL if below |
| Security CRITICAL | 0 | FAIL if any |
| Security HIGH | <= 3 | WARN if exceeded |
| Best Practices violations | <= 10 | WARN if exceeded |
| Code Review score | >= 7/10 | WARN if below |

## Report Output

All reports are saved to: `~/siopv/claude-verification-reports/YYYY-MM-DD-HH-MM/`

## Important Rules

1. **READ-ONLY**: Never modify files in `src/` or `tests/`
2. **REPORT EVERYTHING**: Save detailed reports for each check
3. **CONTINUE ON ERROR**: If one agent fails, continue with others
4. **PARALLEL EXECUTION**: Run independent agents in parallel

## After Testing

Remove this folder to restore SIOPV to clean state:
```bash
rm -rf ~/siopv/.claude
```

Test results are preserved in `~/siopv/claude-verification-reports/`
