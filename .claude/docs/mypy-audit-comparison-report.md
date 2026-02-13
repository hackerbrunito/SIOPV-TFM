# SIOPV Python Type Audit — Comparison Report

**Date:** 2026-02-11
**Scope:** 17 mypy errors + 65 `type: ignore` comments across 76 source files
**mypy:** 1.19.1 (strict mode) | **Python:** 3.12 | **Pydantic:** 2.12.5 | **LangGraph:** 1.0.7

---

## Executive Summary

| Category | Count | Effort |
|----------|-------|--------|
| Quick wins (remove stale `type: ignore`) | 11 | ~5 min |
| Standard fixes (narrow `type: ignore` code) | 4 | ~10 min |
| Complex fixes (LangGraph generic types) | 2 | ~30 min |
| **Total mypy errors** | **17** | **~45 min** |
| Acceptable `type: ignore` comments | 42 | — |
| Problematic `type: ignore` comments | 23 | ~60 min |

---

## Part 1: The 17 Mypy Errors — Detailed Analysis

### Category A: Stale `type: ignore[misc]` on `@retry` decorator (7 errors)

These all follow the same pattern: a `# type: ignore[misc]` was placed on the tenacity `@retry()` decorator, but mypy no longer emits an error there (likely due to updated tenacity stubs in v9.1.2).

**Affected files:**
1. `src/siopv/adapters/external_apis/tavily_client.py:132`
2. `src/siopv/adapters/external_apis/nvd_client.py:126`
3. `src/siopv/adapters/external_apis/github_advisory_client.py:204`
4. `src/siopv/adapters/external_apis/epss_client.py:111`
5. `src/siopv/adapters/external_apis/epss_client.py:205`
6. `src/siopv/adapters/authorization/openfga_adapter.py:267`
7. `src/siopv/adapters/ml/xgboost_classifier.py:589` (same pattern: stale `# type: ignore[no-any-return]`)

**Error type:** `[unused-ignore]`

**Best practice:** When `warn_unused_ignores = true` is set in mypy config (which it is in this project), stale ignores become errors. This is correct behavior — stale ignores indicate the underlying issue was resolved and the suppression is no longer needed.

**Before (all 7 files):**
```python
@retry(
    retry=retry_if_exception_type((httpx.TimeoutException, httpx.HTTPStatusError)),
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=2, max=10),
    reraise=True,
)  # type: ignore[misc]
async def _execute_search(self, ...) -> ...:
```

**After:**
```python
@retry(
    retry=retry_if_exception_type((httpx.TimeoutException, httpx.HTTPStatusError)),
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=2, max=10),
    reraise=True,
)
async def _execute_search(self, ...) -> ...:
```

**Fix:** Simply remove `# type: ignore[misc]` (or `# type: ignore[no-any-return]` for xgboost_classifier) from all 7 locations.

**Priority:** Quick win — mechanical deletion, zero risk.

---

### Category B: Stale `type: ignore[misc]` → narrower `[prop-decorator]` on `@computed_field` (4 errors)

**Affected files:**
1. `src/siopv/domain/authorization/entities.py:434` — `audit_log_entry`
2. `src/siopv/domain/authorization/entities.py:515` — `all_allowed`
3. `src/siopv/domain/authorization/entities.py:521` — `any_denied`
4. `src/siopv/domain/entities/ml_feature_vector.py:112` — `feature_names`

**Error type:** `[unused-ignore]` with message: *use narrower `[prop-decorator]` instead of `[misc]` code*

**Root cause:** Pydantic's `@computed_field` combined with `@property` triggers a mypy `[prop-decorator]` error because mypy sees the decorator transforming a property into something else. In older mypy, this was `[misc]`; since mypy 1.7+ it has its own error code `[prop-decorator]`.

**Best practice:** Use the narrowest possible error code in `type: ignore` comments (PEP 484 / mypy docs). This prevents accidentally suppressing unrelated errors.

**Before:**
```python
@computed_field  # type: ignore[misc]
@property
def audit_log_entry(self) -> dict[str, Any]:
    ...
```

**After (Option A — narrow the code):**
```python
@computed_field  # type: ignore[prop-decorator]
@property
def audit_log_entry(self) -> dict[str, Any]:
    ...
```

**After (Option B — remove if mypy no longer errors):**
First test if removing the `type: ignore` entirely still passes. If Pydantic 2.12+ and mypy 1.19+ have resolved this interaction, remove it completely. If not, use Option A.

**Fix:** Change `[misc]` to `[prop-decorator]` in all 4 locations. If the `[prop-decorator]` error is also gone, remove the comment entirely.

**Priority:** Quick win — simple string replacement.

---

### Category C: Stale `type: ignore` on `graph.py` (2 errors)

**File:** `src/siopv/application/orchestration/graph.py`

#### Error C1: Line 313 — `visualize()` method
```
error: Unused "type: ignore" comment  [unused-ignore]
```

**Before:**
```python
def visualize(self) -> str:
    compiled = self.get_compiled()
    return compiled.get_graph().draw_mermaid()  # type: ignore[no-any-return]
```

**After:**
```python
def visualize(self) -> str:
    compiled = self.get_compiled()
    return compiled.get_graph().draw_mermaid()
```

**Fix:** Remove `# type: ignore[no-any-return]` — mypy now knows the return type.

#### Error C2: Line 449 — `run_pipeline()` function (TWO errors on same line)
```
error: Unused "type: ignore" comment  [unused-ignore]
error: Incompatible return value type (got "dict[str, Any] | Any", expected "PipelineState")  [return-value]
note: Error code "return-value" not covered by "type: ignore" comment
```

**Root cause:** The `type: ignore[no-any-return]` suppresses `[no-any-return]` but the actual error is `[return-value]`. Since `[no-any-return]` is no longer emitted, the ignore is unused AND the `[return-value]` error is exposed.

**Before:**
```python
def run_pipeline(...) -> PipelineState:
    ...
    result = graph.invoke(initial_state, config)
    ...
    return result  # type: ignore[no-any-return]
```

**After (Option A — cast):**
```python
from typing import cast

def run_pipeline(...) -> PipelineState:
    ...
    result = graph.invoke(initial_state, config)
    ...
    return cast(PipelineState, result)
```

**After (Option B — narrow type: ignore):**
```python
def run_pipeline(...) -> PipelineState:
    ...
    result = graph.invoke(initial_state, config)
    ...
    return result  # type: ignore[return-value]
```

**Recommendation:** Option A (`cast`) is preferred. The `invoke()` method returns `dict[str, Any] | Any`, but at runtime it is always a `PipelineState` TypedDict. Using `cast` documents the developer's intent clearly.

**Priority:** Standard fix.

---

### Category D: LangGraph Generic Type Mismatch (2 errors)

**File:** `src/siopv/application/orchestration/graph.py`

#### Error D1: Line 287 — assignment type mismatch
```
error: Incompatible types in assignment (expression has type
"CompiledStateGraph[PipelineState, None, StateT, StateT]",
variable has type "CompiledStateGraph[PipelineState, None, PipelineState, PipelineState] | None")
[assignment]
```

**Root cause:** `self._compiled` is typed as `CompiledStateGraph[PipelineState] | None` (line 138) which mypy infers as `CompiledStateGraph[PipelineState, None, PipelineState, PipelineState] | None`. But `StateGraph.compile()` returns `CompiledStateGraph[StateT, ContextT, InputT, OutputT]` where `InputT` and `OutputT` are generic `StateT` from the `StateGraph` class definition, which mypy can't fully resolve to `PipelineState`.

#### Error D2: Line 294 — return type mismatch
```
error: Incompatible return value type (got
"CompiledStateGraph[PipelineState, None, PipelineState, PipelineState] | None",
expected "CompiledStateGraph[PipelineState, None, PipelineState, PipelineState]")
[return-value]
```

**Root cause:** The `compile()` method assigns to `self._compiled` and returns it, but the method signature promises a non-optional return. Because `self._compiled` is `... | None` and the assignment + return is not recognized as narrowing, mypy complains.

**Before:**
```python
class PipelineGraphBuilder:
    def __init__(self, ...) -> None:
        ...
        self._compiled: CompiledStateGraph[PipelineState] | None = None

    def compile(self, *, with_checkpointer: bool = True) -> CompiledStateGraph[PipelineState]:
        if self._graph is None:
            self.build()
        if self._graph is None:
            msg = "Failed to build graph"
            raise RuntimeError(msg)

        checkpointer = self._create_checkpointer() if with_checkpointer else None
        self._compiled = self._graph.compile(checkpointer=checkpointer)
        ...
        return self._compiled
```

**After:**
```python
class PipelineGraphBuilder:
    def __init__(self, ...) -> None:
        ...
        self._compiled: CompiledStateGraph[PipelineState, None, PipelineState, PipelineState] | None = None

    def compile(self, *, with_checkpointer: bool = True) -> CompiledStateGraph[PipelineState, None, PipelineState, PipelineState]:
        if self._graph is None:
            self.build()
        if self._graph is None:
            msg = "Failed to build graph"
            raise RuntimeError(msg)

        checkpointer = self._create_checkpointer() if with_checkpointer else None
        compiled = self._graph.compile(checkpointer=checkpointer)
        self._compiled = compiled  # type: ignore[assignment]
        ...
        return self._compiled  # type: ignore[return-value]
```

**Better approach — use a type alias and `cast`:**
```python
from typing import TypeAlias, cast

# At module level
CompiledPipeline: TypeAlias = CompiledStateGraph  # Don't parameterize — LangGraph generics are fragile

class PipelineGraphBuilder:
    def __init__(self, ...) -> None:
        ...
        self._compiled: CompiledStateGraph[PipelineState, None, PipelineState, PipelineState] | None = None

    def compile(self, ...) -> CompiledStateGraph[PipelineState, None, PipelineState, PipelineState]:
        ...
        compiled = self._graph.compile(checkpointer=checkpointer)
        self._compiled = cast(
            CompiledStateGraph[PipelineState, None, PipelineState, PipelineState],
            compiled,
        )
        return self._compiled
```

**Recommendation:** Use `cast()` at the compile assignment. LangGraph's generic types are complex (4 type params) and not fully resolvable by mypy when mixing `StateGraph[PipelineState]` (1 param) with `CompiledStateGraph[S, C, I, O]` (4 params). This is a known friction point with LangGraph's type system.

**Priority:** Complex fix — requires understanding LangGraph generics.

---

### Category E: `invoke()` config type mismatch (1 error)

**File:** `src/siopv/application/orchestration/graph.py:437`

```
error: Argument 2 to "invoke" of "Pregel" has incompatible type
"dict[str, dict[str, str]]"; expected "RunnableConfig | None"  [arg-type]
```

**Root cause:** The `config` variable is `{"configurable": {"thread_id": "..."}}` which is a `dict[str, dict[str, str]]`. But `invoke()` expects `RunnableConfig | None`. `RunnableConfig` is a TypedDict with optional keys including `configurable: dict[str, Any]`. A plain dict literal is not compatible with a TypedDict.

**Before:**
```python
config = {"configurable": {"thread_id": initial_state["thread_id"]}}
result = graph.invoke(initial_state, config)
```

**After (Option A — annotate as RunnableConfig):**
```python
from langchain_core.runnables import RunnableConfig

config: RunnableConfig = {"configurable": {"thread_id": initial_state["thread_id"]}}
result = graph.invoke(initial_state, config)
```

**After (Option B — cast inline):**
```python
from typing import cast
from langchain_core.runnables import RunnableConfig

config = {"configurable": {"thread_id": initial_state["thread_id"]}}
result = graph.invoke(initial_state, cast(RunnableConfig, config))
```

**Recommendation:** Option A — directly annotate `config` as `RunnableConfig`. This is the cleanest and most idiomatic approach. It provides documentation value and mypy will validate that the dict literal has valid keys.

**Priority:** Standard fix.

---

## Part 2: Analysis of 65 `type: ignore` Comments

### Summary by Error Code

| Error Code | Count | Assessment |
|-----------|-------|------------|
| `[misc]` (stale) | 11 | **Remove** — all are stale/unused |
| `[no-any-return]` (stale) | 3 | **Remove** — stale |
| `[arg-type]` | 18 | **Review** — 12 acceptable, 6 problematic |
| `[attr-defined]` | 10 | **Review** — 6 acceptable, 4 problematic |
| `[return-value]` | 6 | **Review** — 3 acceptable, 3 problematic |
| `[list-item]` | 2 | **Review** — acceptable (Chroma dict typing) |
| `[misc]` (active) | 1 | **Acceptable** — `enrich_context.py:276` async coroutine |
| `[return]` | 1 | **Acceptable** — circuit breaker wrapper |

### Detailed Assessment

#### A. Stale/Unused — REMOVE (14 comments)

These are the same 11 comments covered in Part 1 mypy errors, plus 3 additional `[no-any-return]` that are now unnecessary:

- All `@retry` decorator `# type: ignore[misc]` (7)
- All `@computed_field` `# type: ignore[misc]` (4) → narrow to `[prop-decorator]`
- `graph.py:313` `# type: ignore[no-any-return]` (1)
- `graph.py:449` `# type: ignore[no-any-return]` (1) → change to `[return-value]` or use `cast`
- `xgboost_classifier.py:589` `# type: ignore[no-any-return]` (1)

#### B. Acceptable — KEEP (28 comments)

These fall into patterns where `type: ignore` is justified:

**1. Chroma adapter dictionary access (`chroma_adapter.py` — 13 comments)**
Chromadb's API returns loosely-typed dicts. The `type: ignore[arg-type]`, `[list-item]`, `[attr-defined]`, `[return-value]` comments are justified because Chroma's type stubs are incomplete.

```python
# Acceptable — Chroma API returns Optional[...] but we've validated
self._collection = client.get_or_create_collection(...)  # type: ignore[attr-defined]
metadata["full_data"]  # type: ignore[arg-type]  — metadata is dict[str, str|int|float|bool]
```

**2. Orchestration node `arg-type` on TypedDict state values (`enrich_node.py`, `classify_node.py`, `edges.py`, `escalate_node.py` — 15 comments)**
These suppress `[arg-type]` errors when passing TypedDict values to functions expecting specific domain types. LangGraph's state access returns union types (`VulnerabilityRecord | ...`) while functions expect concrete types.

```python
# Acceptable — state["vulnerabilities"] is list[VulnerabilityRecord] at runtime
vulnerabilities=vulnerabilities,  # type: ignore[arg-type]
```

#### C. Problematic — SHOULD FIX (23 comments)

**1. `[attr-defined]` on orchestration utils/edges (10 comments)**

Files: `orchestration/utils.py` (6), `orchestration/edges.py` (6)

```python
if classification.risk_score is None:  # type: ignore[attr-defined]
    ...
ml_score = classification.risk_score.risk_probability  # type: ignore[attr-defined]
```

**Problem:** These indicate that `classification` is typed as something that doesn't have `risk_score` attribute. This suggests `ClassificationResult` may be a union type or the state access returns an incorrect type.

**Fix:** Check the `ClassificationResult` type. If `risk_score` is an optional attribute, add a proper `assert` or `isinstance` check instead of suppressing with `type: ignore`.

**2. `[arg-type]` on state-to-function boundaries (6 comments)**

Files: `enrich_node.py` (5), `classify_node.py` (1)

```python
nvd_client=nvd_client,  # type: ignore[arg-type]
```

**Problem:** These suppress mismatches between `SomePort | None` (from optional state) and `SomePort` (required parameter). The `None` case should be handled explicitly.

**Fix:** Add explicit `None` checks before calling:
```python
if nvd_client is None:
    raise ValueError("nvd_client is required")
```

**3. `[return-value]` in classify_node/enrich_node (4 comments)**

```python
return classifications, llm_confidence  # type: ignore[return-value]
```

**Problem:** Return type doesn't match function signature. This usually means the function returns a tuple but is annotated to return something else, or the state update dict is missing keys.

**Fix:** Correct the return type annotation to match actual return value.

---

## Part 3: Gap Analysis

### Current vs Best Practices

| Area | Current State | Best Practice | Gap |
|------|--------------|---------------|-----|
| `type: ignore` granularity | Uses broad `[misc]` in 15 places | Always use narrowest error code | Medium |
| Stale ignores | 14 stale comments | `warn_unused_ignores = true` catches these | Low (just delete) |
| LangGraph generics | `CompiledStateGraph[PipelineState]` (1 param) | Full 4-param `[S, C, I, O]` or use `cast` | Medium |
| RunnableConfig typing | Plain dict literal | Annotate as `RunnableConfig` TypedDict | Low |
| `attr-defined` suppression | 10 comments on `classification.risk_score` | Proper type narrowing with `isinstance`/`assert` | Medium |
| 3rd-party library typing | `ignore_missing_imports = true` blanket | Use per-module overrides in `[mypy-module]` | Low priority |
| Return type accuracy | 6 `[return-value]` ignores | Correct function signatures | Medium |

---

## Part 4: Prioritized Recommendations

### Tier 1 — Quick Wins (5 min, zero risk)

1. **Remove 7 stale `@retry` `type: ignore[misc]`** — Tenacity 9.1.2 stubs are clean
2. **Remove 2 stale `type: ignore[no-any-return]`** in `graph.py:313` and `xgboost_classifier.py:589`
3. **Narrow 4 `@computed_field` from `[misc]` to `[prop-decorator]`** — or remove if no longer needed

**Result:** 13 of 17 mypy errors fixed.

### Tier 2 — Standard Fixes (15 min, low risk)

4. **Annotate `config` as `RunnableConfig`** in `graph.py:426` — fixes error E1
5. **Use `cast(PipelineState, result)`** in `graph.py:449` — fixes error C2
6. **Review and potentially remove** the remaining `type: ignore[no-any-return]` comments that haven't triggered unused-ignore yet

**Result:** 16 of 17 mypy errors fixed.

### Tier 3 — LangGraph Generic Fix (30 min, medium risk)

7. **Fix `CompiledStateGraph` generic parameters** in `graph.py` — use full 4-parameter form and `cast()` at compile boundary. Fixes errors D1 and D2.
8. **Update all method signatures** that reference `CompiledStateGraph[PipelineState]` to use full form or a type alias.

**Result:** 17 of 17 mypy errors fixed. Zero remaining.

### Tier 4 — Type System Improvements (60+ min, refactoring)

9. **Fix 10 `[attr-defined]` on `classification.risk_score`** — Add proper type narrowing or fix the `ClassificationResult` union type.
10. **Fix 6 `[arg-type]` on optional port parameters** — Add explicit `None` guards.
11. **Fix 4 `[return-value]` in node functions** — Correct return type annotations.
12. **Reduce Chroma `type: ignore` count** — Consider wrapper functions with proper typing.
13. **Replace blanket `ignore_missing_imports`** with per-module `[mypy-*]` sections for better coverage.

---

## Appendix: Complete Error Index

| # | File | Line | Error Code | Category | Fix |
|---|------|------|------------|----------|-----|
| 1 | `domain/authorization/entities.py` | 434 | `[unused-ignore]` | B | `[misc]` → `[prop-decorator]` |
| 2 | `domain/authorization/entities.py` | 515 | `[unused-ignore]` | B | `[misc]` → `[prop-decorator]` |
| 3 | `domain/authorization/entities.py` | 521 | `[unused-ignore]` | B | `[misc]` → `[prop-decorator]` |
| 4 | `domain/entities/ml_feature_vector.py` | 112 | `[unused-ignore]` | B | `[misc]` → `[prop-decorator]` |
| 5 | `adapters/external_apis/tavily_client.py` | 132 | `[unused-ignore]` | A | Remove comment |
| 6 | `adapters/external_apis/nvd_client.py` | 126 | `[unused-ignore]` | A | Remove comment |
| 7 | `adapters/external_apis/github_advisory_client.py` | 204 | `[unused-ignore]` | A | Remove comment |
| 8 | `adapters/external_apis/epss_client.py` | 111 | `[unused-ignore]` | A | Remove comment |
| 9 | `adapters/external_apis/epss_client.py` | 205 | `[unused-ignore]` | A | Remove comment |
| 10 | `adapters/authorization/openfga_adapter.py` | 267 | `[unused-ignore]` | A | Remove comment |
| 11 | `adapters/ml/xgboost_classifier.py` | 589 | `[unused-ignore]` | A | Remove comment |
| 12 | `application/orchestration/graph.py` | 287 | `[assignment]` | D | `cast()` at compile |
| 13 | `application/orchestration/graph.py` | 294 | `[return-value]` | D | `cast()` + full generics |
| 14 | `application/orchestration/graph.py` | 313 | `[unused-ignore]` | C | Remove comment |
| 15 | `application/orchestration/graph.py` | 437 | `[arg-type]` | E | Annotate as `RunnableConfig` |
| 16 | `application/orchestration/graph.py` | 449 | `[unused-ignore]` | C | Remove + fix `[return-value]` |
| 17 | `application/orchestration/graph.py` | 449 | `[return-value]` | C | `cast(PipelineState, result)` |
