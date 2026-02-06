# SIOPV Testing Kit

Portable verification infrastructure for standalone quality gates and comprehensive testing.

## Quick Start

```bash
# 1. Copy testing infrastructure to SIOPV
cp -r ~/siopv/testing-kit/claude ~/siopv/.claude
cp -r ~/siopv/testing-kit/fixtures ~/siopv/.claude/fixtures

# 2. Start Claude session in SIOPV
cd ~/siopv
claude

# 3. Run comprehensive test
/comprehensive-test

# 4. After tests complete, clean up (results preserved in claude-verification-reports/)
rm -rf ~/siopv/.claude
```

## Available Skills

| Skill | Description | Duration |
|-------|-------------|----------|
| `/comprehensive-test` | Full 14-agent verification | ~15-20 min |
| `/test-foundation` | 5 foundation agents only | ~5-8 min |
| `/test-quick` | Best-practices + coverage only | ~2-3 min |

## What Gets Tested

### Foundation Agents (5)
- **Best Practices**: Python 2026 standards (type hints, Pydantic v2, httpx, structlog, pathlib)
- **Security**: OWASP Top 10, secrets detection, input validation
- **Hallucination**: API verification against Context7 documentation
- **Code Review**: Complexity, naming, DRY, documentation
- **Coverage**: Line/branch coverage analysis

### Phase Validators (8)
| Phase | Name | Status |
|-------|------|--------|
| 1 | Ingestion | Active |
| 2 | RAG/CRAG | Active |
| 3 | ML Classification | Active |
| 4 | LangGraph Orchestration | Active |
| 5 | OpenFGA Authorization | Active |
| 6 | DLP (Presidio) | Stub |
| 7 | Human-in-the-Loop | Stub |
| 8 | Output/Audit | Stub |

### Report Generator (1)
- **Comprehensive Summary**: Consolidates all reports with pass/fail status

## Quality Gates

| Metric | Threshold | Gate |
|--------|-----------|------|
| Coverage | >= 70% | FAIL if below |
| Security Critical | 0 | FAIL if any |
| Security High | <= 3 | WARN if exceeded |
| Best Practices | <= 10 violations | WARN if exceeded |
| Code Review | >= 7/10 | WARN if below |

## Report Location

Reports are saved to: `~/siopv/claude-verification-reports/YYYY-MM-DD-HH-MM/`

This folder:
- Is clearly named to distinguish from pytest/other test outputs
- Persists after `.claude/` is removed
- Contains a `MANIFEST.md` explaining the report origin

## CI Integration

```bash
# One-liner for CI pipelines
./testing-kit/run-tests.sh
```

## Workflow Diagram

```
testing-kit/claude/ ──copy──> .claude/
        │
        ▼
   /comprehensive-test
        │
        ├── Foundation Agents (parallel)
        │   ├── best-practices
        │   ├── security
        │   ├── hallucination
        │   ├── code-review
        │   └── coverage
        │
        ├── Phase Validators (parallel)
        │   └── phase-1 through phase-8
        │
        └── Comprehensive Report
                │
                ▼
        claude-verification-reports/YYYY-MM-DD-HH-MM/
                │
                ▼
          rm -rf .claude/
```

## Files Created

After running `/comprehensive-test`:

```
claude-verification-reports/2026-02-06-14-30/
├── MANIFEST.md                  # Explains report origin
├── 00-COMPREHENSIVE-SUMMARY.md
├── 01-best-practices.md
├── 02-security.md
├── 03-hallucination.md
├── 04-code-review.md
├── 05-coverage.md
├── 06-phase-1-ingestion.md
├── 07-phase-2-rag.md
├── 08-phase-3-ml.md
├── 09-phase-4-orchestration.md
├── 10-phase-5-authorization.md
├── 11-phase-6-dlp.md
├── 12-phase-7-hitl.md
└── 13-phase-8-output.md
```
