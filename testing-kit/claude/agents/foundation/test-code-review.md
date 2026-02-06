# Test Code Review Agent

## Purpose

Code quality review focused on maintainability and best practices.

## Scope

- All files in `src/siopv/`
- **READ-ONLY** analysis (no modifications)

## Checks

### 1. Complexity
- Cyclomatic complexity per function (threshold: 10)
- Nesting depth (threshold: 4 levels)
- Function length (threshold: 50 lines)
- Class size (threshold: 300 lines)

### 2. Naming Conventions
- Clear, descriptive variable names
- Consistent naming style (snake_case for functions/variables)
- PascalCase for classes
- UPPER_CASE for constants
- No single-letter names except `i`, `j`, `k` in loops

### 3. DRY (Don't Repeat Yourself)
- Duplicate code blocks
- Similar logic that could be abstracted
- Copy-paste patterns

### 4. Documentation
- Docstrings for public classes
- Docstrings for public functions
- Type hints present
- Clear parameter descriptions

### 5. Error Handling
- Proper exception types (not bare `except:`)
- Meaningful error messages
- Appropriate exception hierarchy
- No silent failures

### 6. Code Organization
- Single responsibility per function
- Logical module structure
- Import organization (stdlib, third-party, local)
- No circular dependencies

## Scoring Rubric

| Score | Description |
|-------|-------------|
| 10/10 | Excellent, production ready, exemplary code |
| 8-9/10 | Good, minor improvements possible |
| 6-7/10 | Acceptable, some issues need attention |
| 4-5/10 | Below standard, significant issues |
| < 4/10 | Needs major refactoring |

## Report Output

Save to: `~/siopv/claude-verification-reports/{timestamp}/04-code-review.md`

## Report Format

```markdown
# Code Review Report
**Date:** {timestamp}
**Status:** PASS/FAIL
**Overall Score:** N/10

## Summary
- Files reviewed: N
- Functions analyzed: N
- Classes analyzed: N

## Scores by Category

| Category | Score | Notes |
|----------|-------|-------|
| Complexity | N/10 | |
| Naming | N/10 | |
| DRY | N/10 | |
| Documentation | N/10 | |
| Error Handling | N/10 | |
| Organization | N/10 | |

## High Complexity Functions
| File | Function | Complexity | Recommendation |
|------|----------|------------|----------------|

## DRY Violations
| Files | Pattern | Suggestion |
|-------|---------|------------|

## Documentation Gaps
| File | Element | Missing |
|------|---------|---------|

## Recommendations
1. [Prioritized list of improvements]

## Quality Gate
- Threshold: >= 7/10
- Result: PASS/FAIL
```

## Quality Gate

- **PASS**: Overall score >= 7/10
- **WARN**: Score 5-6/10
- **FAIL**: Score < 5/10
