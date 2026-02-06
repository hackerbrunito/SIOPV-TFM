# Test Coverage Agent

## Purpose

Analyze test coverage and identify gaps in SIOPV test suite.

## Scope

- Source: `src/siopv/`
- Tests: `tests/`
- **READ-ONLY** analysis (no modifications)

## Commands to Execute

```bash
# Run pytest with coverage
uv run pytest tests/ --cov=src/siopv --cov-report=term-missing --cov-report=json:coverage.json -q

# Parse coverage.json for detailed analysis
```

## Checks

### 1. Line Coverage
- Overall line coverage percentage
- Per-module coverage breakdown
- Files with < 50% coverage (critical)
- Files with < 70% coverage (warning)

### 2. Branch Coverage
- Overall branch coverage percentage
- Uncovered branches by file
- Complex conditionals without full coverage

### 3. Missing Tests
- Public functions without tests
- Classes without test coverage
- Critical paths not exercised

### 4. Test Quality Indicators
- Assertions per test (minimum 1)
- Edge cases covered
- Error paths tested
- Mock usage appropriateness

## Coverage Thresholds

| Level | Line Coverage | Branch Coverage |
|-------|---------------|-----------------|
| Excellent | >= 90% | >= 85% |
| Good | >= 80% | >= 75% |
| Acceptable | >= 70% | >= 65% |
| Poor | < 70% | < 65% |

## Report Output

Save to: `~/siopv/claude-verification-reports/{timestamp}/05-coverage.md`

## Report Format

```markdown
# Coverage Report
**Date:** {timestamp}
**Status:** PASS/FAIL

## Summary
- Total tests: N
- Tests passed: N
- Tests failed: N
- Line coverage: N%
- Branch coverage: N%

## Coverage by Module

| Module | Lines | Covered | Missing | Coverage |
|--------|-------|---------|---------|----------|
| domain/ | N | N | N | N% |
| application/ | N | N | N | N% |
| adapters/ | N | N | N | N% |
| infrastructure/ | N | N | N | N% |
| interfaces/ | N | N | N | N% |

## Critical Gaps (< 50% coverage)
| File | Coverage | Missing Lines |
|------|----------|---------------|

## Warning Gaps (50-70% coverage)
| File | Coverage | Missing Lines |
|------|----------|---------------|

## Uncovered Functions
| File | Function | Reason |
|------|----------|--------|

## Test Execution Summary
- Duration: N seconds
- Slowest tests: [list top 5]

## Quality Gate
- Threshold: >= 70% line coverage
- Result: PASS/FAIL
```

## Quality Gate

- **PASS**: Line coverage >= 70%
- **WARN**: Line coverage 60-69%
- **FAIL**: Line coverage < 60% OR any test failures
