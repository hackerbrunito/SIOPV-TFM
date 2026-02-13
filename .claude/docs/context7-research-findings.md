# Context7 Research Findings: LangGraph & MyPy Typing Patterns

> Research completed 2026-02-11 via web documentation queries
> (Context7 MCP tools were not available; used official documentation sources instead)

---

## 1. LangGraph (>=0.2.0) Typing Patterns

### 1.1 StateGraph Generic Type Parameters

`StateGraph` is generic with four type parameters:

```python
class StateGraph(Generic[StateT, ContextT, InputT, OutputT])
```

| Parameter | Description |
|-----------|-------------|
| `StateT`  | The state schema class (typically `TypedDict`) |
| `ContextT`| Runtime context schema (immutable data: `user_id`, `db_conn`) |
| `InputT`  | Input schema for graph invocation |
| `OutputT` | Output schema for graph execution results |

**Constructor signature:**
```python
StateGraph(
    state_schema: type[StateT],
    context_schema: type[ContextT] | None = None,
    input_schema: type[InputT] | None = None,
    output_schema: type[OutputT] | None = None,
)
```

**Source:** [LangGraph Graphs Reference](https://reference.langchain.com/python/langgraph/graphs/)

### 1.2 CompiledStateGraph Type Annotations

The `compile()` method returns:

```python
CompiledStateGraph[StateT, ContextT, InputT, OutputT]
```

- Inherits from `Pregel`
- Implements the `Runnable` interface
- Supports: `invoke()`, `stream()`, `ainvoke()`, `astream()`
- All execution methods accept `RunnableConfig` for parameterization

**Current limitation (Issue #5000):** As of June 2025, there's an active proposal to make `StateGraph` and `CompiledStateGraph` fully type-safe with compile-time validation of node signatures and input/output types.

**Source:** [GitHub Issue #5000](https://github.com/langchain-ai/langgraph/issues/5000)

### 1.3 RunnableConfig Usage

Node functions can accept `RunnableConfig` as an optional parameter:

```python
from langchain_core.runnables import RunnableConfig

def my_node(state: State, config: RunnableConfig) -> dict:
    thread_id = config["configurable"]["thread_id"]
    step = config["metadata"]["langgraph_step"]
    return {"key": "value"}
```

Alternatively, with Runtime context:

```python
from langgraph.types import Runtime

def my_node(state: State, runtime: Runtime[ContextSchema]) -> dict:
    ctx = runtime.context  # typed as ContextSchema
    return {"key": "value"}
```

**Both `config` and `runtime` are optional parameters** - nodes may implement any subset of `(state, config, runtime)`.

**Source:** [LangGraph Graph API](https://docs.langchain.com/oss/python/langgraph/graph-api)

### 1.4 Type Annotations in Nodes

#### State definition with TypedDict + Annotated reducers:

```python
from typing import Annotated
from typing_extensions import TypedDict
from langgraph.graph.message import add_messages
import operator

class AgentState(TypedDict):
    messages: Annotated[list, add_messages]     # append reducer
    subjects: list[str]                          # replace (no reducer)
    jokes: Annotated[list[str], operator.add]   # concatenation reducer
```

#### Node return patterns:

```python
# 1. Simple dict (partial state update)
def node(state: State) -> dict:
    return {"messages": [new_msg]}

# 2. Command object (state update + routing)
from langgraph.types import Command
def node(state: State) -> Command:
    return Command(update={"key": "val"}, goto="next_node")

# 3. Send object (dynamic edges)
from langgraph.types import Send
def route(state: State) -> list[Send]:
    return [Send("process", {"item": x}) for x in state["items"]]
```

**Best practice:** Use TypedDict inside the LangGraph state machine (lightweight, no runtime overhead), and Pydantic at the boundaries (inputs/outputs, integrations, user-facing data) for validation.

**Source:** [LangGraph Types Reference](https://reference.langchain.com/python/langgraph/types/)

---

## 2. MyPy (>=1.9.0) Best Practices

### 2.1 Strict Mode Settings

**Current SIOPV configuration** (from `pyproject.toml`):

```toml
[tool.mypy]
python_version = "3.11"
strict = true
warn_return_any = true
warn_unused_ignores = true
disallow_untyped_defs = true
ignore_missing_imports = true
```

**Analysis:** The current config is solid but has some redundancy and one notable trade-off:

| Setting | Status | Note |
|---------|--------|------|
| `strict = true` | Good | Already enables `disallow_untyped_defs`, `warn_return_any` |
| `warn_return_any = true` | Redundant | Already included in `strict = true` |
| `warn_unused_ignores = true` | Redundant | Already included in `strict = true` |
| `disallow_untyped_defs = true` | Redundant | Already included in `strict = true` |
| `ignore_missing_imports = true` | Trade-off | Convenient but hides missing stubs |

**Recommendation:** Since `strict = true` already enables `warn_return_any`, `warn_unused_ignores`, and `disallow_untyped_defs`, these explicit settings are redundant. They don't cause harm but add noise. The explicit settings do serve as documentation of intent.

**Source:** [MyPy Strict Configuration Guide](https://hrekov.com/blog/mypy-configuration-for-strict-typing)

### 2.2 Handling Unused `type: ignore` Comments

Two key error codes for managing ignores:

#### `unused-ignore` (enabled by `warn_unused_ignores = true`)
- Reports errors when `# type: ignore` is present but no error would occur
- Detects obsolete ignores as code evolves
- Activated by `--enable-error-code unused-ignore` or `--warn-unused-ignores`

#### `ignore-without-code` (opt-in)
- Warns when `# type: ignore` lacks specific error codes
- **Best practice:** Always use specific codes: `# type: ignore[assignment]` instead of blanket `# type: ignore`
- Activated by `--enable-error-code ignore-without-code`

**Recommendation for SIOPV:** Consider enabling `ignore-without-code` to enforce specific error codes on all type ignores:

```toml
[tool.mypy]
enable_error_code = ["ignore-without-code"]
```

**Source:** [MyPy Error Codes for Optional Checks](https://mypy.readthedocs.io/en/stable/error_code_list2.html)

### 2.3 Third-Party Library Stubs

**Current approach:** `ignore_missing_imports = true` (global)

**Better approach:** Per-module overrides for untyped libraries:

```toml
[tool.mypy]
strict = true
# Remove global ignore_missing_imports

# Per-library overrides for untyped packages
[[tool.mypy.overrides]]
module = [
    "chromadb.*",
    "presidio_analyzer.*",
    "presidio_anonymizer.*",
    "openfga_sdk.*",
    "fpdf2.*",
    "shap.*",
    "lime.*",
    "imbalanced_learn.*",
]
ignore_missing_imports = true
```

**Benefits:**
- New dependencies get type-checked by default
- Only known-untyped libraries are exempted
- Prevents silently accepting `Any` from new imports

**Available type stubs for SIOPV dependencies:**
- `types-requests` (if using requests)
- `sqlalchemy` has built-in stubs (PEP 561 compliant)
- `pydantic` has built-in stubs
- `httpx` has built-in stubs
- `structlog` has built-in stubs

**Source:** [Professional-grade MyPy Configuration (Wolt)](https://careers.wolt.com/en/blog/tech/professional-grade-mypy-configuration)

---

## 3. Key Recommendations for SIOPV Audit

### LangGraph Typing:
1. **Use `TypedDict` for state schemas** with `Annotated` reducers
2. **Type node functions explicitly**: `def node(state: State, config: RunnableConfig) -> dict:`
3. **Use `CompiledStateGraph` type** when storing compiled graph references (but note the generic parameters may not be fully enforced yet per Issue #5000)
4. **Prefer partial dict returns** over full state replacement in nodes

### MyPy Configuration:
1. **Remove redundant settings** that `strict = true` already enables (or keep as documentation)
2. **Switch from global `ignore_missing_imports`** to per-module overrides
3. **Enable `ignore-without-code`** error code for stricter `type: ignore` hygiene
4. **Always use specific error codes** in `# type: ignore[error-code]` comments
5. **Regularly clean up stale ignores** using `warn_unused_ignores`

---

## Sources

- [LangGraph Graphs Reference](https://reference.langchain.com/python/langgraph/graphs/)
- [LangGraph Types Reference](https://reference.langchain.com/python/langgraph/types/)
- [LangGraph Graph API](https://docs.langchain.com/oss/python/langgraph/graph-api)
- [GitHub Issue #5000: Make StateGraph/CompiledStateGraph more type safe](https://github.com/langchain-ai/langgraph/issues/5000)
- [MyPy Strict Configuration Guide](https://hrekov.com/blog/mypy-configuration-for-strict-typing)
- [Professional-grade MyPy Configuration (Wolt)](https://careers.wolt.com/en/blog/tech/professional-grade-mypy-configuration)
- [MyPy Error Codes for Optional Checks](https://mypy.readthedocs.io/en/stable/error_code_list2.html)
- [Type Safety in LangGraph: TypedDict vs Pydantic](https://shazaali.substack.com/p/type-safety-in-langgraph-when-to)
