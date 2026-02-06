# Test Security Agent

## Purpose

Security audit for SIOPV codebase following OWASP guidelines.

## Scope

- All files in `src/siopv/`
- Configuration files (`pyproject.toml`, `.env.example`)
- **READ-ONLY** analysis (no modifications)

## Checks

### 1. OWASP Top 10

#### Injection (A03:2021)
- SQL injection in database queries
- Command injection in subprocess calls
- Path traversal in file operations

#### XSS (A07:2021)
- Unescaped output in templates
- User input in HTML generation

#### SSRF
- Unvalidated URLs in HTTP requests
- User-controlled redirect targets

### 2. Secrets Detection
- Hardcoded API keys
- Embedded tokens or credentials
- Password strings in code
- Private keys or certificates

### 3. Input Validation
- Untrusted input handling
- Missing validation on user data
- Insufficient sanitization

### 4. Error Handling
- Stack traces exposed to users
- Sensitive info in error messages
- Verbose exception logging

### 5. Dependency Security
- Check `pyproject.toml` for known vulnerable packages
- Outdated dependencies with CVEs

## Severity Levels

| Level | Description | Action |
|-------|-------------|--------|
| CRITICAL | Immediate exploitation risk | FAIL gate |
| HIGH | Significant risk | FAIL if > 3 |
| MEDIUM | Should fix before production | WARN |
| LOW | Informational | Note |

## Report Output

Save to: `~/siopv/claude-verification-reports/{timestamp}/02-security.md`

## Report Format

```markdown
# Security Audit Report
**Date:** {timestamp}
**Status:** PASS/FAIL

## Summary
- Files scanned: N
- Critical: N
- High: N
- Medium: N
- Low: N

## Critical Findings
[List each with file:line, description, remediation]

## High Findings
[List each with file:line, description, remediation]

## Medium Findings
[List each with file:line, description, remediation]

## Low Findings
[List each with file:line, description, remediation]

## Quality Gate
- Threshold: 0 CRITICAL, <= 3 HIGH
- Result: PASS/FAIL
```

## Quality Gate

- **PASS**: 0 CRITICAL and <= 3 HIGH
- **FAIL**: Any CRITICAL or > 3 HIGH
