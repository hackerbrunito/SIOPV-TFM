# Test Best Practices Agent

## Purpose

Validate Python 2026 best practices across all SIOPV source files.

## Scope

- All files in `src/siopv/`
- **READ-ONLY** analysis (no modifications)

## Checks

### 1. Type Hints (Modern Syntax)
- Use `list[str]` not `List[str]`
- Use `dict[str, int]` not `Dict[str, int]`
- Use `X | None` not `Optional[X]`
- Use `tuple[int, ...]` not `Tuple[int, ...]`

### 2. Pydantic v2 Patterns
- No `class Config:` (use `model_config = {}`)
- No `@validator` (use `@field_validator`)
- No `@root_validator` (use `@model_validator`)
- Use `model_dump()` not `dict()`
- Use `model_validate()` not `parse_obj()`

### 3. HTTP Client
- Use `httpx` not `requests`
- Async patterns with `httpx.AsyncClient`

### 4. Logging
- Use `structlog` not `logging`
- No `print()` statements in production code

### 5. Path Handling
- Use `pathlib.Path` not `os.path`
- Use `Path.read_text()` not `open().read()`

## Report Output

Save to: `~/siopv/claude-verification-reports/{timestamp}/01-best-practices.md`

## Report Format

```markdown
# Best Practices Report
**Date:** {timestamp}
**Status:** PASS/FAIL

## Summary
- Files scanned: N
- Violations found: N
- Compliance rate: N%

## Violations

### Type Hints
| File | Line | Issue | Recommendation |
|------|------|-------|----------------|

### Pydantic v2
| File | Line | Issue | Recommendation |
|------|------|-------|----------------|

### HTTP Client
| File | Line | Issue | Recommendation |
|------|------|-------|----------------|

### Logging
| File | Line | Issue | Recommendation |
|------|------|-------|----------------|

### Path Handling
| File | Line | Issue | Recommendation |
|------|------|-------|----------------|

## Quality Gate
- Threshold: <= 10 violations
- Result: PASS/FAIL
```

## Quality Gate

- **PASS**: <= 10 total violations
- **WARN**: 11-25 violations
- **FAIL**: > 25 violations
