# Python Type Checking Best Practices - Research Document (2026)

> Research for SIOPV mypy/typing audit. Compiled from official docs, PEPs, and modern typing guides.

---

## Table of Contents

1. [PEP Summary Reference](#1-pep-summary-reference)
2. [Best Practices for `type: ignore` Comments](#2-best-practices-for-type-ignore-comments)
3. [Async Typing Patterns](#3-async-typing-patterns)
4. [Generic Type Handling](#4-generic-type-handling)
5. [TypedDict vs Pydantic Models](#5-typeddict-vs-pydantic-models)
6. [LangChain/LangGraph Typing Patterns](#6-langchainlanggraph-typing-patterns)
7. [Mypy Configuration Best Practices](#7-mypy-configuration-best-practices)
8. [Complete Mypy Error Code Reference](#8-complete-mypy-error-code-reference)
9. [SIOPV-Specific Observations](#9-siopv-specific-observations)

---

## 1. PEP Summary Reference

### PEP 484 - Type Hints (Python 3.5+)
The foundational PEP. Introduced `typing` module, `TypeVar`, `Generic`, `Callable`, `Optional`, `Union`.

```python
from typing import Optional, Union

def greet(name: str, greeting: Optional[str] = None) -> str:
    return f"{greeting or 'Hello'}, {name}"
```

### PEP 526 - Variable Annotations (Python 3.6+)
Syntax for annotating variables outside function signatures. Introduced `ClassVar`.

```python
from typing import ClassVar

class Config:
    max_retries: ClassVar[int] = 3       # Class variable
    timeout: float                        # Instance variable
```

### PEP 544 - Protocols / Structural Subtyping (Python 3.8+)
Static duck-typing. Classes don't need to inherit from a base - they just need to match the structure.

```python
from typing import Protocol, runtime_checkable

@runtime_checkable
class Enrichable(Protocol):
    """Any object with a cve_id and severity."""
    @property
    def cve_id(self) -> str: ...
    @property
    def severity(self) -> str: ...
```

**SIOPV relevance:** Could replace some ABC-based ports with Protocol classes for looser coupling.

### PEP 585 - Generics in Standard Collections (Python 3.9+)
Use `list[str]` instead of `typing.List[str]`. Use `dict[str, Any]` instead of `typing.Dict[str, Any]`.

```python
# Modern (PEP 585) - preferred
def process(items: list[str]) -> dict[str, int]: ...

# Legacy (pre-3.9) - avoid
from typing import List, Dict
def process(items: List[str]) -> Dict[str, int]: ...
```

**SIOPV status:** Already using PEP 585 style with `from __future__ import annotations`.

### PEP 586 - Literal Types (Python 3.8+)
Restrict values to specific literals.

```python
from typing import Literal

RiskLevel = Literal["critical", "high", "medium", "low", "info"]

def classify(severity: RiskLevel) -> float: ...
```

**SIOPV relevance:** Could use for node names, routing decisions, severity levels.

### PEP 612 - ParamSpec (Python 3.10+)
Preserves callable signatures through decorators. Critical for typing higher-order functions.

```python
from typing import Callable, ParamSpec, TypeVar

P = ParamSpec('P')
T = TypeVar('T')

def retry(func: Callable[P, T]) -> Callable[P, T]:
    def wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
        return func(*args, **kwargs)
    return wrapper
```

**SIOPV relevance:** Already used in `circuit_breaker.py` for the `with_circuit_breaker` decorator.

---

## 2. Best Practices for `type: ignore` Comments

### Golden Rules

1. **ALWAYS use specific error codes:** `# type: ignore[attr-defined]` not bare `# type: ignore`
2. **Combine multiple codes when needed:** `# type: ignore[arg-type, return-value]`
3. **Add a brief comment explaining WHY:** `# type: ignore[attr-defined]  # chromadb API returns untyped`
4. **Enable strict enforcement in mypy config**

### Recommended Mypy Configuration

```toml
[tool.mypy]
strict = true
warn_unused_ignores = true            # Flag stale ignores
enable_error_code = ["ignore-without-code"]  # Require error codes
show_error_codes = true               # Show codes in output
```

### When `type: ignore` is Acceptable

| Scenario | Example | Error Code |
|---|---|---|
| Untyped third-party library | `client.method()` | `[attr-defined]` |
| Pydantic `@computed_field` | `@computed_field` | `[misc]` |
| Dynamic return from framework | `return result` | `[no-any-return]` |
| Intentional type narrowing | `assert isinstance(x, str)` | `[union-attr]` |

### When `type: ignore` Should Be Avoided

- **Masking real bugs:** If `[arg-type]` fires, the argument type is probably wrong
- **Cascading ignores:** 5+ ignores in a function = redesign needed
- **Same ignore pattern repeated:** Extract a typed wrapper instead

### Reducing Ignores - Strategies

```python
# BAD: Multiple ignores hiding a design issue
def process(data: dict[str, Any]) -> Result:
    name = data["name"]           # type: ignore[index]
    score = data["score"]         # type: ignore[index]
    return Result(name, score)    # type: ignore[arg-type]

# GOOD: Use TypedDict or Pydantic to type the dict
class InputData(TypedDict):
    name: str
    score: float

def process(data: InputData) -> Result:
    return Result(data["name"], data["score"])  # No ignores needed
```

---

## 3. Async Typing Patterns

### Basic Async Function Typing

```python
import asyncio
from collections.abc import AsyncGenerator, AsyncIterator, Awaitable, Coroutine

# Async function - return type is the UNWRAPPED type
async def fetch_data(url: str) -> dict[str, Any]:
    ...  # mypy knows this returns Coroutine[Any, Any, dict[str, Any]]

# Async generator
async def stream_results() -> AsyncGenerator[str, None]:
    yield "result"

# Async iterator
async def iterate() -> AsyncIterator[int]:
    yield 1
```

### Async Context Managers

```python
from contextlib import asynccontextmanager
from collections.abc import AsyncGenerator

@asynccontextmanager
async def managed_resource() -> AsyncGenerator[Resource, None]:
    resource = await Resource.create()
    try:
        yield resource
    finally:
        await resource.close()
```

### Typing Async Callbacks and Handlers

```python
from typing import Callable, Awaitable

# Function that takes an async callback
async def with_retry(
    func: Callable[[], Awaitable[T]],
    max_retries: int = 3,
) -> T:
    for attempt in range(max_retries):
        try:
            return await func()
        except Exception:
            if attempt == max_retries - 1:
                raise
    raise RuntimeError("Unreachable")
```

### ParamSpec with Async Decorators

```python
from typing import ParamSpec, TypeVar, Callable
from collections.abc import Coroutine
from functools import wraps

P = ParamSpec('P')
T = TypeVar('T')

def async_retry(
    func: Callable[P, Coroutine[Any, Any, T]]
) -> Callable[P, Coroutine[Any, Any, T]]:
    @wraps(func)
    async def wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
        return await func(*args, **kwargs)
    return wrapper
```

**SIOPV relevance:** The `circuit_breaker.py` uses this pattern. Line 205 has `# type: ignore[return]` which may be avoidable with proper overload typing.

---

## 4. Generic Type Handling

### Modern Python 3.12+ Syntax (Future Reference)

```python
# Python 3.12+ (new syntax)
def first[T](items: list[T]) -> T:
    return items[0]

class Stack[T]:
    def __init__(self) -> None:
        self.items: list[T] = []
```

### Current Best Practice (Python 3.11, SIOPV target)

```python
from typing import TypeVar, Generic

T = TypeVar('T')

class Repository(Generic[T]):
    def get(self, id: str) -> T | None: ...
    def save(self, entity: T) -> None: ...
```

### Bounded TypeVars

```python
from typing import TypeVar
from pydantic import BaseModel

ModelT = TypeVar('ModelT', bound=BaseModel)

def validate_and_save(model: ModelT) -> ModelT:
    """Works with any Pydantic model subclass."""
    model.model_validate(model.model_dump())
    return model
```

### Variance

```python
from typing import TypeVar, Generic

T_co = TypeVar('T_co', covariant=True)      # Read-only containers
T_contra = TypeVar('T_contra', contravariant=True)  # Write-only/consumers

class Reader(Generic[T_co]):
    def read(self) -> T_co: ...

class Writer(Generic[T_contra]):
    def write(self, value: T_contra) -> None: ...
```

### Self Type (Python 3.11+)

```python
from typing import Self

class Builder:
    def with_option(self, name: str) -> Self:
        # Returns the same subclass type
        return self
```

**SIOPV relevance:** `PipelineGraphBuilder.build()` returns `PipelineGraphBuilder` - could use `Self` for proper method chaining with subclasses.

---

## 5. TypedDict vs Pydantic Models

### Decision Matrix

| Criterion | TypedDict | Pydantic BaseModel |
|---|---|---|
| **Runtime validation** | None | Full |
| **Performance overhead** | Zero | Moderate |
| **IDE autocomplete** | Yes | Yes |
| **Default values** | `total=False` only | Full support |
| **Nested validation** | No | Yes |
| **Serialization** | Manual | Built-in |
| **LangGraph state** | Required | Not supported |
| **API boundaries** | Avoid | Preferred |

### Recommended Architecture Pattern

```
External Input (JSON, API)
    --> Pydantic Model (validate at boundary)
        --> TypedDict (internal state, LangGraph)
            --> Pydantic Model (validate at output boundary)
                --> External Output (API response, report)
```

### SIOPV Current Pattern (Correct)

```python
# Internal state: TypedDict (correct for LangGraph)
class PipelineState(TypedDict, total=False):
    vulnerabilities: list[VulnerabilityRecord]
    enrichments: dict[str, EnrichmentData]
    ...

# Domain entities: Pydantic (correct for validation)
class VulnerabilityRecord(BaseModel):
    cve_id: CVEIdentifier
    severity: str
    ...

# Value objects: Pydantic (correct for immutability + validation)
class EnrichmentData(BaseModel):
    nvd: NVDData | None
    epss: EPSSData | None
    ...
```

**SIOPV assessment:** The project follows the recommended hybrid pattern correctly.

---

## 6. LangChain/LangGraph Typing Patterns

### StateGraph Generic Parameters

`StateGraph` is generic on the state type. Current LangGraph typing is limited:

```python
from langgraph.graph import StateGraph
from langgraph.graph.state import CompiledStateGraph

# Correct usage
graph: StateGraph[PipelineState] = StateGraph(PipelineState)
compiled: CompiledStateGraph[PipelineState] = graph.compile()
```

**Known issue (GitHub #5000):** `StateGraph` and `CompiledStateGraph` type safety is incomplete. The type parameters `StateT`, `InputT`, `OutputT`, `ContextT` are not fully enforced. This means:
- Node function signatures aren't validated against the state type
- `invoke()` return type isn't properly narrowed
- `Command` and `Send` accept arbitrary state shapes

**Workaround:** Use `# type: ignore[no-any-return]` on `invoke()` results and explicit type annotations.

### RunnableConfig Pattern

```python
from langchain_core.runnables import RunnableConfig

# In tool definitions - config is injected by name+type, not position
@tool
async def my_tool(query: str, config: RunnableConfig) -> str:
    thread_id = config["configurable"]["thread_id"]
    return f"Result for {query}"

# In node functions
def my_node(state: PipelineState, config: RunnableConfig) -> dict:
    ...
```

### Common LangGraph Type Ignore Patterns

```python
# Pattern 1: invoke() returns Any due to incomplete generics
result = graph.invoke(state, config)  # type: ignore[no-any-return]

# Pattern 2: get_graph().draw_mermaid() return type
mermaid = compiled.get_graph().draw_mermaid()  # type: ignore[no-any-return]

# Pattern 3: Node lambdas with injected dependencies
graph.add_node("enrich", lambda state: enrich_node(state, client=self._client))
# Lambda type is inferred but may not match expected node signature
```

**These ignores are ACCEPTABLE** because they stem from LangGraph's incomplete type stubs, not from SIOPV code errors.

---

## 7. Mypy Configuration Best Practices

### Recommended `pyproject.toml` for SIOPV

```toml
[tool.mypy]
python_version = "3.11"
strict = true
warn_return_any = true
warn_unused_ignores = true
disallow_untyped_defs = true
# Consider adding:
enable_error_code = ["ignore-without-code"]  # Enforce specific error codes
show_error_codes = true                       # Always show error codes in output

# Per-module overrides for poorly-typed third-party libraries
[[tool.mypy.overrides]]
module = [
    "chromadb.*",
    "xgboost.*",
    "shap.*",
    "lime.*",
    "openfga_sdk.*",
]
ignore_missing_imports = true
# Consider: disallow_untyped_defs = false  # for test modules
```

### Current SIOPV Config Assessment

```toml
# Current (good baseline)
[tool.mypy]
python_version = "3.11"
strict = true
warn_return_any = true
warn_unused_ignores = true
disallow_untyped_defs = true
ignore_missing_imports = true   # <-- BROAD: consider per-module overrides
```

**Recommendation:** Replace blanket `ignore_missing_imports = true` with per-module overrides. This way, imports from well-typed packages (like `pydantic`, `httpx`) will be properly checked.

---

## 8. Complete Mypy Error Code Reference

### Default Error Codes (Most Relevant to SIOPV)

| Code | Description | SIOPV Count |
|---|---|---|
| `attr-defined` | Attribute not found on type | 14 |
| `arg-type` | Argument type incompatible | 13 |
| `return-value` | Return type incompatible | 5 |
| `misc` | Miscellaneous (Pydantic computed_field, etc.) | 8 |
| `no-any-return` | Returning Any from typed function | 4 |
| `list-item` | List item type mismatch | 2 |
| `return` | Missing return in non-None function | 1 |
| `override` | Method override violates LSP | 0 |
| `union-attr` | Attribute on union type | 0 |
| `call-overload` | No matching overload | 0 |
| `assignment` | Incompatible assignment | 0 |
| `operator` | Invalid operand types | 0 |
| `index` | Invalid index type | 0 |

### Full Error Code Catalog

- **`attr-defined`** - Attribute/method not found on type
- **`union-attr`** - Attribute access on union type (not all variants have it)
- **`name-defined`** - Name not defined in scope
- **`used-before-def`** - Variable used before definition
- **`call-arg`** - Wrong number/names of arguments
- **`arg-type`** - Argument type mismatch
- **`call-overload`** - No matching overload variant
- **`valid-type`** - Invalid type annotation
- **`var-annotated`** - Type cannot be inferred, needs annotation
- **`override`** - Method override violates Liskov Substitution Principle
- **`return`** - Missing return statement
- **`return-value`** - Return value type mismatch
- **`assignment`** - Incompatible types in assignment
- **`method-assign`** - Method monkey-patching (subcode of assignment)
- **`type-var`** - Type variable value out of bounds/constraints
- **`operator`** - Invalid operand types for operator
- **`index`** - Invalid index type
- **`list-item`** - List item doesn't match list type
- **`dict-item`** - Dict key/value type mismatch
- **`typeddict-item`** - TypedDict value type mismatch
- **`typeddict-unknown-key`** - Unknown key in TypedDict
- **`import`** - Import error
- **`import-not-found`** - Module not found
- **`import-untyped`** - Module lacks type stubs (PEP 561)
- **`no-redef`** - Name redefined
- **`func-returns-value`** - Using None-returning function as value
- **`abstract`** - Instantiating abstract class
- **`misc`** - Catch-all for miscellaneous errors

---

## 9. SIOPV-Specific Observations

### Current `type: ignore` Usage Summary

**Total `type: ignore` comments: ~65** across the source tree.

#### Breakdown by Pattern

1. **`[attr-defined]` (14 occurrences)** - Mostly in `edges.py`, `utils.py`, `classify_node.py`
   - Pattern: `classification.risk_score.risk_probability  # type: ignore[attr-defined]`
   - **Root cause:** `ClassificationResult` type may not expose `risk_score` properly
   - **Fix strategy:** Verify `ClassificationResult` type definition; may need union narrowing or Protocol

2. **`[arg-type]` (13 occurrences)** - Mostly in `enrich_node.py`, `classify_node.py`, `edges.py`
   - Pattern: Passing `Optional[X]` where `X` is expected
   - **Fix strategy:** Add None-checks before passing, or adjust port signatures to accept Optional

3. **`[misc]` (8 occurrences)** - Pydantic `@computed_field` and external API patterns
   - Pattern: `@computed_field  # type: ignore[misc]`
   - **Status:** Known Pydantic-mypy incompatibility. These are **acceptable** ignores.

4. **`[no-any-return]` (4 occurrences)** - LangGraph/structlog returns
   - Pattern: `return result  # type: ignore[no-any-return]`
   - **Status:** Caused by untyped framework returns. **Acceptable** with comment.

5. **`[return-value]` (5 occurrences)** - Node return types
   - Pattern: `return enrichments  # type: ignore[return-value]`
   - **Fix strategy:** Ensure node functions return `dict[str, Any]` as LangGraph expects

6. **`[list-item]` (2 occurrences)** - ChromaDB adapter
   - Pattern: Passing typed lists where chromadb expects untyped
   - **Status:** Third-party library issue. **Acceptable**.

### Priority Recommendations

1. **HIGH:** Fix `[arg-type]` ignores in orchestration nodes (13 occurrences) - These likely mask Optional/None handling bugs
2. **HIGH:** Fix `[attr-defined]` ignores in edges/utils (14 occurrences) - May indicate missing type narrowing
3. **MEDIUM:** Add `enable_error_code = ["ignore-without-code"]` to mypy config
4. **MEDIUM:** Replace blanket `ignore_missing_imports` with per-module overrides
5. **LOW:** Document acceptable ignores (`[misc]` for Pydantic, `[no-any-return]` for LangGraph)

---

## References

- [Python typing module documentation](https://docs.python.org/3/library/typing.html)
- [Mypy documentation - Error codes](https://mypy.readthedocs.io/en/stable/error_codes.html)
- [Mypy documentation - Common issues](https://mypy.readthedocs.io/en/stable/common_issues.html)
- [PEP 484 - Type Hints](https://peps.python.org/pep-0484/)
- [PEP 526 - Variable Annotations](https://peps.python.org/pep-0526/)
- [PEP 544 - Protocols](https://peps.python.org/pep-0544/)
- [PEP 585 - Generics in Standard Collections](https://peps.python.org/pep-0585/)
- [PEP 586 - Literal Types](https://peps.python.org/pep-0586/)
- [PEP 612 - ParamSpec](https://peps.python.org/pep-0612/)
- [Python Typing Survey 2025 - Meta Engineering](https://engineering.fb.com/2025/12/22/developer-tools/python-typing-survey-2025-code-quality-flexibility-typing-adoption/)
- [LangGraph StateGraph type safety issue #5000](https://github.com/langchain-ai/langgraph/issues/5000)
- [Type Safety in LangGraph: TypedDict vs Pydantic](https://shazaali.substack.com/p/type-safety-in-langgraph-when-to)
- [Adam Johnson - Managing type: ignore with Mypy](https://adamj.eu/tech/2021/05/25/python-type-hints-specific-type-ignore/)
- [Generics - typing documentation](https://typing.python.org/en/latest/reference/generics.html)
- [RunnableConfig - LangChain documentation](https://python.langchain.com/api_reference/core/runnables/langchain_core.runnables.config.RunnableConfig.html)
- [Modern Python 3.12+ Features](https://dasroot.net/posts/2026/01/modern-python-312-features-type-hints-generics-performance/)
- [Mypy type hints cheat sheet](https://mypy.readthedocs.io/en/stable/cheat_sheet_py3.html)
