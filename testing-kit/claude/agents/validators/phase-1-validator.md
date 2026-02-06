# Phase 1 Validator - Ingestion

## Purpose

Validate Phase 1 (Ingestion and Preprocessing) implementation.

## Scope

- **READ-ONLY** analysis (no modifications)

## Files to Analyze

```
src/siopv/domain/entities/vulnerability_record.py
src/siopv/domain/value_objects/cve_id.py
src/siopv/domain/value_objects/cvss_score.py
src/siopv/domain/value_objects/package_version.py
src/siopv/domain/value_objects/layer_info.py
src/siopv/adapters/parsers/trivy_parser.py
src/siopv/application/use_cases/ingest_trivy_report.py
```

## Checks

### 1. Domain Model
- [ ] VulnerabilityRecord entity exists
- [ ] Proper value objects (CVEId, CVSSScore, PackageVersion, LayerInfo)
- [ ] Immutable value objects (frozen=True or equivalent)
- [ ] Validation in value object constructors

### 2. Trivy Parser
- [ ] Handles Trivy JSON schema v2
- [ ] Parses `Results[].Vulnerabilities[]` structure
- [ ] Extracts all required fields (CVE ID, severity, package, version)
- [ ] Error handling for malformed JSON

### 3. Deduplication
- [ ] Map-reduce pattern for deduplication
- [ ] Key: (cve_id, package, version)
- [ ] Preserves highest severity on duplicates

### 4. Batch Processing
- [ ] `group_by_package()` function exists
- [ ] `sort_by_severity()` function exists
- [ ] IngestTrivyReportUseCase orchestrates flow

### 5. Hexagonal Compliance
- [ ] Domain layer has NO external dependencies
- [ ] No imports from adapters/infrastructure in domain
- [ ] Use cases depend on ports, not implementations

## Report Output

Save to: `~/siopv/claude-verification-reports/{timestamp}/06-phase-1-ingestion.md`

## Report Format

```markdown
# Phase 1 - Ingestion Validation Report
**Date:** {timestamp}
**Status:** PASS/FAIL

## Summary
- Files analyzed: N
- Checks passed: N/N
- Issues found: N

## Domain Model
| Check | Status | Notes |
|-------|--------|-------|
| VulnerabilityRecord entity | PASS/FAIL | |
| CVEId value object | PASS/FAIL | |
| CVSSScore value object | PASS/FAIL | |
| PackageVersion value object | PASS/FAIL | |
| LayerInfo value object | PASS/FAIL | |
| Immutability | PASS/FAIL | |

## Trivy Parser
| Check | Status | Notes |
|-------|--------|-------|
| Schema v2 support | PASS/FAIL | |
| Vulnerability extraction | PASS/FAIL | |
| Error handling | PASS/FAIL | |

## Deduplication
| Check | Status | Notes |
|-------|--------|-------|
| Map-reduce pattern | PASS/FAIL | |
| Correct key tuple | PASS/FAIL | |
| Severity preservation | PASS/FAIL | |

## Batch Processing
| Check | Status | Notes |
|-------|--------|-------|
| group_by_package | PASS/FAIL | |
| sort_by_severity | PASS/FAIL | |
| Use case orchestration | PASS/FAIL | |

## Hexagonal Compliance
| Check | Status | Notes |
|-------|--------|-------|
| Domain isolation | PASS/FAIL | |
| Port dependencies | PASS/FAIL | |

## Issues
[List any issues found]

## Quality Gate
- Threshold: All critical checks pass
- Result: PASS/FAIL
```

## Quality Gate

- **PASS**: All checks pass
- **FAIL**: Any critical check fails
