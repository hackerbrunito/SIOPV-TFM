# Test Hallucination Agent

## Purpose

Verify code syntax against official documentation using Context7 MCP.

## Scope

- All files in `src/siopv/`
- **READ-ONLY** analysis (no modifications)

## Libraries to Verify

| Library | Version | Focus Areas |
|---------|---------|-------------|
| Pydantic | v2.x | Model definitions, validators, serialization |
| httpx | 0.27+ | Client instantiation, async patterns |
| structlog | 24.x | Logger configuration, processors |
| LangGraph | 0.2+ | StateGraph, nodes, edges, checkpointing |
| ChromaDB | 0.5+ | Client, collections, queries |
| XGBoost | 2.x | Classifier API, training, prediction |
| SHAP | 0.45+ | Explainer types, value extraction |
| LIME | 0.2+ | LimeTabularExplainer usage |
| OpenFGA SDK | 0.6+ | Client, check, write operations |
| Presidio | 2.2+ | Analyzer, Anonymizer patterns |

## Checks

### 1. API Signatures
- Function/method calls match library documentation
- Correct number and types of arguments
- Valid return type expectations

### 2. Deprecated Patterns
- Usage of deprecated APIs
- Old parameter names
- Legacy import paths

### 3. Parameter Names
- Keyword arguments are spelled correctly
- No invented parameters

### 4. Import Paths
- Valid module paths
- Correct class/function locations

## Verification Process

For each library:
1. Query Context7 MCP with `resolve-library-id`
2. Query documentation with `query-docs`
3. Compare code usage against official docs
4. Report discrepancies

## Context7 Fallback

If Context7 MCP is unavailable:
1. Log warning in report
2. Skip API verification
3. Continue with static analysis (import paths, obvious errors)
4. Mark report as "PARTIAL - Context7 unavailable"

## Report Output

Save to: `~/siopv/claude-verification-reports/{timestamp}/03-hallucination.md`

## Report Format

```markdown
# Hallucination Detection Report
**Date:** {timestamp}
**Status:** PASS/FAIL/PARTIAL

## Summary
- Libraries verified: N
- Files scanned: N
- Issues found: N

## Context7 Status
- Available: YES/NO
- Libraries queried: [list]

## Issues Found

### Pydantic
| File | Line | Issue | Correct Usage |
|------|------|-------|---------------|

### LangGraph
| File | Line | Issue | Correct Usage |
|------|------|-------|---------------|

[... other libraries ...]

## Quality Gate
- Threshold: 0 hallucinated APIs
- Result: PASS/FAIL
```

## Quality Gate

- **PASS**: 0 hallucinated API calls
- **WARN**: 1-3 minor discrepancies
- **FAIL**: > 3 issues or any critical API mismatch
