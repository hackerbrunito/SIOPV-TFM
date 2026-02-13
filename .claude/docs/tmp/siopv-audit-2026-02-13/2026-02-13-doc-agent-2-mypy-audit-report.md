# DOC-AGENT-2: Mypy Audit Comparison Report — Extraction Report

**Document Analyzed:** `~/siopv/.claude/docs/mypy-audit-comparison-report.md`
**Report Date:** February 13, 2026
**Original Document Date:** February 11, 2026
**Agent:** DOC-AGENT-2

---

## 1. EXECUTIVE SUMMARY

This is a **technical audit report** (not an implementation record) documenting 17 mypy type-checking errors and 65 `type: ignore` comments across 76 Python source files in the SIOPV project.

**Scope:**
- mypy 1.19.1 (strict mode)
- Python 3.12
- Pydantic 2.12.5
- LangGraph 1.0.7

**Key Metrics:**
- **Total mypy errors:** 17
- **Total `type: ignore` comments:** 65 (14 stale, 28 acceptable, 23 problematic)
- **Estimated total effort:** ~150+ minutes for complete remediation

---

## 2. DATES & TIMESTAMPS

| Date | Context |
|------|---------|
| **2026-02-11** | Original audit report creation date |
| **2026-02-13** | This extraction report creation date |

**Note:** No execution timestamps or completion dates were found in the document. This is a planning/analysis document, not an implementation log.

---

## 3. PLANNED ITEMS (4 Tiers)

### Tier 1: Quick Wins (5 min, zero risk)
1. Remove 7 stale `@retry` decorator `type: ignore[misc]` comments
2. Remove 2 stale `type: ignore[no-any-return]` comments (graph.py:313, xgboost_classifier.py:589)
3. Narrow 4 `@computed_field` comments from `[misc]` to `[prop-decorator]` (or remove if unnecessary)

**Expected Result:** 13 of 17 mypy errors fixed

### Tier 2: Standard Fixes (15 min, low risk)
4. Annotate `config` as `RunnableConfig` in graph.py:426 (fixes error E1)
5. Use `cast(PipelineState, result)` in graph.py:449 (fixes error C2)
6. Review remaining `type: ignore[no-any-return]` comments

**Expected Result:** 16 of 17 mypy errors fixed

### Tier 3: LangGraph Generic Fix (30 min, medium risk)
7. Fix `CompiledStateGraph` generic parameters with full 4-parameter form
8. Update all method signatures using `cast()` at compile boundary

**Expected Result:** 17 of 17 mypy errors fixed (100% remediation)

### Tier 4: Type System Improvements (60+ min, refactoring)
9. Fix 10 `[attr-defined]` errors on `classification.risk_score`
10. Fix 6 `[arg-type]` errors on optional port parameters
11. Fix 4 `[return-value]` errors in node functions
12. Reduce Chroma `type: ignore` count with wrapper functions
13. Replace blanket `ignore_missing_imports` with per-module `[mypy-*]` sections

---

## 4. COMPLETED ITEMS

**NONE.** This is an audit/planning document. No implementation work is recorded as completed.

The document identifies what NEEDS to be done, not what HAS been done.

---

## 5. PENDING ITEMS

**ALL 17 mypy errors are pending fixes**, organized into the 4 tiers above.

Additionally:
- 14 stale `type: ignore` comments require removal
- 23 problematic `type: ignore` comments require proper fixes
- 28 acceptable `type: ignore` comments should be reviewed for potential improvement

---

## 6. MYPY ERRORS BREAKDOWN (17 Total)

### Category A: Stale `@retry` Decorator Ignores (7 errors)

**Error Type:** `[unused-ignore]`
**Status:** PENDING (Tier 1 fix)
**Effort:** ~2 minutes (mechanical deletion)

| # | File | Line | Current Comment | Fix |
|---|------|------|-----------------|-----|
| 1 | `adapters/external_apis/tavily_client.py` | 132 | `# type: ignore[misc]` | Remove |
| 2 | `adapters/external_apis/nvd_client.py` | 126 | `# type: ignore[misc]` | Remove |
| 3 | `adapters/external_apis/github_advisory_client.py` | 204 | `# type: ignore[misc]` | Remove |
| 4 | `adapters/external_apis/epss_client.py` | 111 | `# type: ignore[misc]` | Remove |
| 5 | `adapters/external_apis/epss_client.py` | 205 | `# type: ignore[misc]` | Remove |
| 6 | `adapters/authorization/openfga_adapter.py` | 267 | `# type: ignore[misc]` | Remove |
| 7 | `adapters/ml/xgboost_classifier.py` | 589 | `# type: ignore[no-any-return]` | Remove |

**Root Cause:** Tenacity 9.1.2 updated stubs; mypy no longer errors on `@retry` decorators.

---

### Category B: Stale `@computed_field` Ignores (4 errors)

**Error Type:** `[unused-ignore]` (should use narrower `[prop-decorator]`)
**Status:** PENDING (Tier 1 fix)
**Effort:** ~3 minutes (string replacement or removal)

| # | File | Line | Property | Current | Fix |
|---|------|------|----------|---------|-----|
| 1 | `domain/authorization/entities.py` | 434 | `audit_log_entry` | `# type: ignore[misc]` | `# type: ignore[prop-decorator]` or remove |
| 2 | `domain/authorization/entities.py` | 515 | `all_allowed` | `# type: ignore[misc]` | `# type: ignore[prop-decorator]` or remove |
| 3 | `domain/authorization/entities.py` | 521 | `any_denied` | `# type: ignore[misc]` | `# type: ignore[prop-decorator]` or remove |
| 4 | `domain/entities/ml_feature_vector.py` | 112 | `feature_names` | `# type: ignore[misc]` | `# type: ignore[prop-decorator]` or remove |

**Root Cause:** mypy 1.7+ uses specific `[prop-decorator]` error code instead of generic `[misc]`.

---

### Category C: Stale Ignores in graph.py (2 errors, 3 issues)

**File:** `application/orchestration/graph.py`
**Status:** PENDING (Tier 1 and Tier 2 fixes)

| Line | Error Type | Issue | Fix | Tier |
|------|------------|-------|-----|------|
| 313 | `[unused-ignore]` | Stale `[no-any-return]` on `visualize()` | Remove comment | 1 |
| 449 | `[unused-ignore]` | Stale `[no-any-return]` on `run_pipeline()` | Remove comment | 1 |
| 449 | `[return-value]` | Wrong ignore code, actual error exposed | `cast(PipelineState, result)` | 2 |

**Issue at Line 449:** TWO errors on same line:
1. The `[no-any-return]` ignore is unused (stale)
2. Removing it exposes a `[return-value]` error

**Recommended Fix:** Use `cast(PipelineState, result)` instead of type ignore.

---

### Category D: LangGraph Generic Type Mismatches (2 errors)

**File:** `application/orchestration/graph.py`
**Status:** PENDING (Tier 3 fix - complex)
**Effort:** ~30 minutes

| Line | Error Type | Issue | Severity |
|------|------------|-------|----------|
| 287 | `[assignment]` | `CompiledStateGraph` generic parameter mismatch | MEDIUM |
| 294 | `[return-value]` | Return type Optional vs non-Optional mismatch | MEDIUM |

**Root Cause:** LangGraph's `StateGraph.compile()` returns `CompiledStateGraph[StateT, ContextT, InputT, OutputT]` (4 type params), but the class uses simplified `CompiledStateGraph[PipelineState]` (1 param). Mypy cannot resolve the generic mapping.

**Recommended Fix:**
1. Use full 4-parameter type annotation: `CompiledStateGraph[PipelineState, None, PipelineState, PipelineState]`
2. Use `cast()` at compile boundary
3. Consider creating a type alias for cleaner code

---

### Category E: RunnableConfig Type Mismatch (1 error)

**File:** `application/orchestration/graph.py`
**Line:** 437
**Error Type:** `[arg-type]`
**Status:** PENDING (Tier 2 fix)
**Effort:** ~5 minutes

**Issue:** Plain dict literal `{"configurable": {"thread_id": "..."}}` passed to `invoke()` which expects `RunnableConfig` TypedDict.

**Recommended Fix:**
```python
from langchain_core.runnables import RunnableConfig

config: RunnableConfig = {"configurable": {"thread_id": initial_state["thread_id"]}}
result = graph.invoke(initial_state, config)
```

---

## 7. TYPE IGNORE COMMENTS ANALYSIS (65 Total)

### Summary by Status

| Status | Count | Action Required |
|--------|-------|-----------------|
| **Stale/Unused** | 14 | REMOVE immediately |
| **Acceptable** | 28 | KEEP (justified by 3rd-party type gaps) |
| **Problematic** | 23 | FIX with proper type narrowing |

### Breakdown by Error Code

| Error Code | Total Count | Stale | Acceptable | Problematic |
|-----------|-------------|-------|------------|-------------|
| `[misc]` | 12 | 11 | 1 | 0 |
| `[no-any-return]` | 3 | 3 | 0 | 0 |
| `[arg-type]` | 18 | 0 | 12 | 6 |
| `[attr-defined]` | 10 | 0 | 6 | 4 |
| `[return-value]` | 6 | 0 | 3 | 3 |
| `[list-item]` | 2 | 0 | 2 | 0 |
| `[return]` | 1 | 0 | 1 | 0 |

### Acceptable Type Ignores (28 comments - KEEP)

**Justification:** These suppress errors caused by incomplete 3rd-party library type stubs.

#### 1. Chroma Adapter (13 comments)
**Files:** `adapters/storage/chroma_adapter.py`
**Reason:** Chromadb's API returns loosely-typed dicts; type stubs are incomplete.

#### 2. LangGraph State Access (15 comments)
**Files:** `orchestration/enrich_node.py`, `classify_node.py`, `edges.py`, `escalate_node.py`
**Reason:** LangGraph TypedDict state values are accessed as union types; runtime values are concrete types.

**Pattern:**
```python
# Acceptable — state["vulnerabilities"] is list[VulnerabilityRecord] at runtime
vulnerabilities=vulnerabilities,  # type: ignore[arg-type]
```

---

### Problematic Type Ignores (23 comments - SHOULD FIX)

#### Problem 1: `[attr-defined]` on Classification Results (10 comments)

**Files:** `orchestration/utils.py` (6), `orchestration/edges.py` (4)

**Pattern:**
```python
if classification.risk_score is None:  # type: ignore[attr-defined]
ml_score = classification.risk_score.risk_probability  # type: ignore[attr-defined]
```

**Root Cause:** `classification` is typed as something that doesn't have `risk_score` attribute, suggesting union type issue.

**Recommended Fix:** Add proper type narrowing with `isinstance` or `assert`, or fix `ClassificationResult` type definition.

---

#### Problem 2: `[arg-type]` on Optional Port Parameters (6 comments)

**Files:** `enrich_node.py` (5), `classify_node.py` (1)

**Pattern:**
```python
nvd_client=nvd_client,  # type: ignore[arg-type]
```

**Root Cause:** State contains `SomePort | None` but function expects `SomePort` (required).

**Recommended Fix:**
```python
if nvd_client is None:
    raise ValueError("nvd_client is required")
```

---

#### Problem 3: `[return-value]` Mismatches (3 comments)

**Files:** `classify_node.py`, `enrich_node.py`

**Pattern:**
```python
return classifications, llm_confidence  # type: ignore[return-value]
```

**Root Cause:** Function returns tuple but annotation expects different type, or state update dict is missing keys.

**Recommended Fix:** Correct return type annotation to match actual return value.

---

## 8. FILES AUDITED (Compliance Status)

### Files with Errors (17 errors across 8 unique files)

| File | Errors | Category | Compliance |
|------|--------|----------|------------|
| `domain/authorization/entities.py` | 2 | B (stale ignores) | ⚠️ MINOR ISSUES |
| `domain/entities/ml_feature_vector.py` | 1 | B (stale ignores) | ⚠️ MINOR ISSUES |
| `adapters/external_apis/tavily_client.py` | 1 | A (stale ignores) | ⚠️ MINOR ISSUES |
| `adapters/external_apis/nvd_client.py` | 1 | A (stale ignores) | ⚠️ MINOR ISSUES |
| `adapters/external_apis/github_advisory_client.py` | 1 | A (stale ignores) | ⚠️ MINOR ISSUES |
| `adapters/external_apis/epss_client.py` | 2 | A (stale ignores) | ⚠️ MINOR ISSUES |
| `adapters/authorization/openfga_adapter.py` | 1 | A (stale ignores) | ⚠️ MINOR ISSUES |
| `adapters/ml/xgboost_classifier.py` | 1 | A (stale ignores) | ⚠️ MINOR ISSUES |
| `application/orchestration/graph.py` | 7 | C, D, E (mixed complexity) | ❌ MAJOR ISSUES |

**Most Critical File:** `application/orchestration/graph.py` (7 errors including complex LangGraph generic issues)

---

### Files with Problematic Type Ignores (23 issues)

| File | Issues | Type |
|------|--------|------|
| `orchestration/utils.py` | 6 | `[attr-defined]` on classification.risk_score |
| `orchestration/edges.py` | 4 | `[attr-defined]` on classification.risk_score |
| `orchestration/enrich_node.py` | 5 | `[arg-type]` on optional ports |
| `orchestration/classify_node.py` | 1 | `[arg-type]` on optional ports |
| `orchestration/classify_node.py` | Multiple | `[return-value]` mismatches |
| `orchestration/enrich_node.py` | Multiple | `[return-value]` mismatches |

---

### Files with Acceptable Type Ignores (28 issues)

| File | Issues | Justification |
|------|--------|---------------|
| `adapters/storage/chroma_adapter.py` | 13 | Incomplete Chromadb type stubs |
| `orchestration/enrich_node.py` | 10 | LangGraph state union types |
| `orchestration/classify_node.py` | ~5 | LangGraph state union types |

**Total Scope:** 76 source files analyzed (only subset shown above have issues)

---

## 9. BLOCKERS & ISSUES

### Technical Blockers

| Issue | Impact | Severity | Tier |
|-------|--------|----------|------|
| **LangGraph generic type complexity** | Cannot properly type `CompiledStateGraph` without 4-param form | MEDIUM | 3 |
| **3rd-party library type stubs** | Chromadb and LangGraph have incomplete type coverage | LOW | 4 (optional) |
| **Union type handling in state** | LangGraph state access returns union types requiring type narrowing | MEDIUM | 4 |

### Process Blockers

**NONE IDENTIFIED.** All fixes are technical, no approval or dependency blockers noted.

---

## 10. GAP ANALYSIS (Current vs Best Practices)

| Area | Current State | Best Practice | Gap Severity |
|------|--------------|---------------|--------------|
| Type ignore granularity | Uses broad `[misc]` in 15 places | Always use narrowest error code | MEDIUM |
| Stale ignores | 14 stale comments present | `warn_unused_ignores = true` catches these | LOW (easy fix) |
| LangGraph generics | `CompiledStateGraph[PipelineState]` (1 param) | Full 4-param `[S, C, I, O]` or use `cast` | MEDIUM |
| RunnableConfig typing | Plain dict literal | Annotate as `RunnableConfig` TypedDict | LOW |
| `attr-defined` suppression | 10 comments on `classification.risk_score` | Proper type narrowing with `isinstance`/`assert` | MEDIUM |
| 3rd-party library typing | `ignore_missing_imports = true` blanket | Per-module overrides in `[mypy-module]` | LOW priority |
| Return type accuracy | 6 `[return-value]` ignores | Correct function signatures | MEDIUM |

---

## 11. KEY FINDINGS

1. **Quick Win Opportunity:** 76% of mypy errors (13 of 17) can be fixed in ~5 minutes with mechanical deletion/replacement.

2. **Low Overall Risk:** Most errors are stale type ignores from library upgrades (Tenacity, Pydantic, mypy itself).

3. **LangGraph Type System Friction:** The 2 remaining complex errors stem from LangGraph's 4-parameter generic type system not fully resolving in mypy. This is a known limitation.

4. **Acceptable Technical Debt:** 28 of 65 type ignores (43%) are justified due to incomplete 3rd-party type stubs (Chromadb, LangGraph).

5. **Type Safety Improvements Needed:** 23 of 65 type ignores (35%) indicate actual type safety gaps that should be fixed with proper narrowing, not suppression.

6. **Strict Mode Compliance:** Project uses `warn_unused_ignores = true` which is best practice — this audit was triggered by that setting catching stale ignores.

---

## 12. RECOMMENDED PRIORITY ORDER

1. **Tier 1 (5 min):** Remove stale ignores → 13/17 errors fixed
2. **Tier 2 (15 min):** Standard type fixes → 16/17 errors fixed
3. **Tier 3 (30 min):** LangGraph generics → 17/17 errors fixed (100%)
4. **Tier 4 (60+ min):** Refactor problematic type ignores → Improved type safety

**Total Effort for 100% Mypy Compliance:** ~50 minutes
**Total Effort for Full Type Safety:** ~110+ minutes

---

## 13. DELIVERABLE SUMMARY

**This report provides:**
- ✅ Complete extraction of planned items (4 tiers)
- ✅ Identification of completed items (NONE - audit only)
- ✅ Identification of pending items (ALL 17 errors)
- ✅ All timestamps and dates (Feb 11, 2026)
- ✅ Complete mypy error catalog with file paths, line numbers, and fix strategies
- ✅ File-by-file compliance status
- ✅ Blocker identification (technical only, no process blockers)

**Document Status:** PLANNING/AUDIT (not implementation record)

---

**Report Generated By:** DOC-AGENT-2
**Date:** 2026-02-13
**Source Document:** `~/siopv/.claude/docs/mypy-audit-comparison-report.md`
