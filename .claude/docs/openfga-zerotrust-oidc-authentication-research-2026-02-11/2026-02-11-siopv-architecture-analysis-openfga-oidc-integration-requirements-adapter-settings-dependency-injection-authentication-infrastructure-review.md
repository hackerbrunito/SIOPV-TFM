# SIOPV Architecture Analysis: OpenFGA OIDC Integration Requirements

**Date:** 2026-02-11
**Agent:** siopv-architecture-analyzer
**Task:** #4 — Analyze SIOPV project architecture for OIDC integration requirements

---

## 1. Executive Summary

The SIOPV project has a mature, well-structured OpenFGA authorization layer following hexagonal architecture (ports & adapters). The current implementation uses **unauthenticated** connections to OpenFGA (only `api_url` and `store_id`). Adding OIDC client credentials authentication requires changes across **3 layers**: settings, adapter initialization, and dependency injection. The changes are localized and non-breaking due to the clean separation of concerns.

---

## 2. Current OpenFGA Adapter Implementation

### 2.1 Source Location

- **Adapter:** `src/siopv/adapters/authorization/openfga_adapter.py` (1173 lines)
- **Ports:** `src/siopv/application/ports/authorization.py` (556 lines)
- **DI:** `src/siopv/infrastructure/di/authorization.py` (211 lines)
- **Domain entities:** `src/siopv/domain/authorization/entities.py` (558 lines)
- **Value objects:** `src/siopv/domain/authorization/value_objects.py` (387 lines)
- **Exceptions:** `src/siopv/domain/authorization/exceptions.py` (293 lines)
- **Use cases:** `src/siopv/application/use_cases/authorization.py` (853 lines)
- **LangGraph node:** `src/siopv/application/orchestration/nodes/authorization_node.py` (393 lines)
- **Tests:** `tests/unit/adapters/authorization/test_openfga_adapter.py` (1604 lines)
- **DI tests:** `tests/unit/infrastructure/di/test_authorization_di.py` (369 lines)
- **SDK version:** `openfga-sdk>=0.6.0` (in pyproject.toml)

### 2.2 Architecture Pattern

The project follows **hexagonal architecture** with clean separation:

```
Domain Layer (entities, value objects, exceptions)
  └── No external dependencies
Application Layer (ports, use cases, orchestration)
  └── Defines Protocol-based port interfaces
Infrastructure Layer (DI, config, resilience)
  └── Wires adapters to ports
Adapter Layer (OpenFGAAdapter)
  └── Implements all 3 port interfaces
```

### 2.3 Port Interfaces (Protocol-based)

Three `@runtime_checkable` Protocol classes in `application/ports/authorization.py`:

1. **`AuthorizationPort`** — Permission checks: `check()`, `batch_check()`, `check_relation()`, `list_user_relations()`
2. **`AuthorizationStorePort`** — Tuple management: `write_tuple()`, `write_tuples()`, `delete_tuple()`, `delete_tuples()`, `read_tuples()`, `read_tuples_for_resource()`, `read_tuples_for_user()`, `tuple_exists()`
3. **`AuthorizationModelPort`** — Model management: `get_model_id()`, `validate_model()`, `health_check()`

All three are implemented by the single `OpenFGAAdapter` class.

### 2.4 Current `ClientConfiguration` Setup (No Auth)

In `openfga_adapter.py:159-164`:

```python
configuration = ClientConfiguration(
    api_url=self._api_url,
    store_id=self._store_id,
)
self._owned_client = OpenFgaClient(configuration)
```

**This is the primary change point.** The `ClientConfiguration` object accepts OIDC credentials but currently none are passed.

### 2.5 Resilience Features Already in Place

- **Circuit breaker** via `CircuitBreaker` from `siopv.infrastructure.resilience`
- **Retry with exponential backoff** via `tenacity` (3 attempts, 1-10s wait)
- **Error mapping** to domain exceptions (FgaValidationException → AuthorizationModelError, CircuitBreakerError → AuthorizationCheckError)
- **Structured logging** via `structlog`
- **Audit trails** with PII pseudonymization (SHA-256)

---

## 3. Settings Configuration (`settings.py`)

### 3.1 Current OpenFGA Settings

File: `src/siopv/infrastructure/config/settings.py:64-66`

```python
# === OpenFGA ===
openfga_api_url: str | None = None
openfga_store_id: str | None = None
```

### 3.2 Settings Framework

- Uses **Pydantic Settings v2** (`pydantic_settings.BaseSettings`)
- Environment prefix: `SIOPV_` (all env vars prefixed)
- Loads from `.env` file
- Supports `SecretStr` for sensitive values (used for `anthropic_api_key`, `github_token`, `jira_api_token`, `model_signing_key`)
- Both `.env` and `.env.example` files exist in the repo root (`.env` is gitignored)
- `.env.example` already includes basic OpenFGA configuration (`SIOPV_OPENFGA_API_URL`, `SIOPV_OPENFGA_STORE_ID`)

### 3.3 Required OIDC Settings to Add

The following settings need to be added to the `# === OpenFGA ===` section:

| Setting | Type | Env Variable | Purpose |
|---------|------|-------------|---------|
| `openfga_client_id` | `str \| None` | `SIOPV_OPENFGA_CLIENT_ID` | OIDC client identifier |
| `openfga_client_secret` | `SecretStr \| None` | `SIOPV_OPENFGA_CLIENT_SECRET` | OIDC client secret (sensitive) |
| `openfga_token_endpoint` | `str \| None` | `SIOPV_OPENFGA_TOKEN_ENDPOINT` | OIDC token issuer URL |
| `openfga_audience` | `str \| None` | `SIOPV_OPENFGA_AUDIENCE` | OIDC audience claim |
| `openfga_api_token` | `SecretStr \| None` | `SIOPV_OPENFGA_API_TOKEN` | Pre-shared key fallback |

**Note:** All should default to `None` to preserve backward compatibility with unauthenticated local development.

---

## 4. Dependency Injection Setup

### 4.1 Current DI Pattern

File: `src/siopv/infrastructure/di/authorization.py`

- **`create_authorization_adapter(settings)`** — Factory function creating `OpenFGAAdapter(settings)`
- **`get_authorization_port(settings)`** — `@lru_cache(maxsize=1)` singleton returning `AuthorizationPort`
- **`get_authorization_store_port(settings)`** — `@lru_cache(maxsize=1)` singleton returning `AuthorizationStorePort`
- **`get_authorization_model_port(settings)`** — `@lru_cache(maxsize=1)` singleton returning `AuthorizationModelPort`

All factory functions pass the `Settings` object directly to `OpenFGAAdapter.__init__()`.

### 4.2 DI Changes Required

**No changes needed in the DI layer.** The factory functions already pass the full `Settings` object to the adapter. Once settings are updated with OIDC fields, the adapter can read them directly. The DI module docs should be updated to reflect the new settings fields.

---

## 5. Adapter Initialization Changes Required

### 5.1 `__init__` Method Changes

File: `openfga_adapter.py:101-137`

Current:
```python
self._api_url = settings.openfga_api_url
self._store_id = settings.openfga_store_id
```

Needed additions:
```python
self._client_id = settings.openfga_client_id
self._client_secret = settings.openfga_client_secret
self._token_endpoint = settings.openfga_token_endpoint
self._audience = settings.openfga_audience
self._api_token = settings.openfga_api_token
```

### 5.2 `initialize` Method Changes

File: `openfga_adapter.py:139-171`

This is the **critical change point**. Current `ClientConfiguration` must be enhanced:

```python
# Current (unauthenticated)
configuration = ClientConfiguration(
    api_url=self._api_url,
    store_id=self._store_id,
)

# Proposed (with OIDC support)
credentials = self._build_credentials()
configuration = ClientConfiguration(
    api_url=self._api_url,
    store_id=self._store_id,
    credentials=credentials,  # NEW: OIDC or pre-shared key
)
```

### 5.3 New Private Method: `_build_credentials`

A new method should determine the authentication mode:

1. **OIDC client credentials** — When `client_id`, `client_secret`, and `token_endpoint` are all set
2. **Pre-shared API token** — When `api_token` is set (simpler, for dev/staging)
3. **No authentication** — When none are set (local development with Docker)

The OpenFGA SDK `ClientConfiguration` accepts a `credentials` parameter of type `Credentials` which supports:
- `CredentialConfiguration(method="client_credentials", config=ClientCredentialConfiguration(...))`
- `CredentialConfiguration(method="api_token", config=ApiTokenConfiguration(...))`

---

## 6. Existing Authentication/Identity Infrastructure

### 6.1 No Existing OIDC/Identity Provider

The SIOPV project has **no existing OIDC provider, OAuth integration, or identity management** beyond the OpenFGA authorization layer. Key observations:

- **No JWT/token validation middleware** exists
- **No user authentication layer** — the `user_id` comes from pipeline state, not from an auth token
- **No identity provider configuration** anywhere in the codebase
- The `authorization_node.py` receives `user_id` from `PipelineState` (set externally)

### 6.2 Secret Management Pattern

The project uses `pydantic.SecretStr` for sensitive values. The OIDC client secret should follow this pattern.

### 6.3 External API Authentication Patterns

The project already authenticates with external services:
- **Anthropic API:** `anthropic_api_key: SecretStr` (required)
- **GitHub GraphQL:** `github_token: SecretStr | None` (optional)
- **Jira:** `jira_api_token: SecretStr | None` (optional)
- **NVD API:** `nvd_api_key: SecretStr | None` (optional)
- **Tavily:** `tavily_api_key: SecretStr | None` (optional)

Pattern: All optional external credentials are `SecretStr | None` with `None` default.

---

## 7. Test Infrastructure Impact

### 7.1 Existing Test Pattern

Tests use `MagicMock` for settings and `AsyncMock` for the OpenFGA client:

```python
@pytest.fixture
def mock_settings() -> MagicMock:
    settings = MagicMock()
    settings.openfga_api_url = "http://localhost:8080"
    settings.openfga_store_id = "test-store-id"
    settings.circuit_breaker_failure_threshold = 5
    settings.circuit_breaker_recovery_timeout = 60
    return settings
```

### 7.2 Required Test Updates

1. **`mock_settings` fixtures** must add OIDC fields (defaulting to `None`)
2. **New tests** for `_build_credentials()` method covering all 3 auth modes
3. **New tests** for `initialize()` with OIDC configuration
4. **SecretStr mocking** — `settings.openfga_client_secret.get_secret_value()` pattern

---

## 8. Files Requiring Changes (Ordered by Dependency)

| Priority | File | Change Type | Scope |
|----------|------|-------------|-------|
| 1 | `src/siopv/infrastructure/config/settings.py` | Add OIDC fields | ~10 lines |
| 2 | `src/siopv/adapters/authorization/openfga_adapter.py` | Modify `__init__`, `initialize`, add `_build_credentials` | ~40 lines |
| 3 | `tests/unit/adapters/authorization/test_openfga_adapter.py` | Update fixtures, add credential tests | ~60 lines |
| 4 | `tests/unit/infrastructure/di/test_authorization_di.py` | Update mock_settings fixtures | ~10 lines |

### Files NOT Requiring Changes

- `application/ports/authorization.py` — Port interfaces unchanged
- `domain/authorization/*` — Domain layer unaffected
- `infrastructure/di/authorization.py` — Already passes full Settings
- `application/use_cases/authorization.py` — Uses ports, not adapter directly
- `application/orchestration/nodes/authorization_node.py` — Uses port interface

---

## 9. Key Design Decisions for Implementation

### 9.1 Authentication Priority

When multiple credentials are configured:
1. **OIDC client credentials** takes priority (production)
2. **Pre-shared API token** as fallback (staging)
3. **No auth** when nothing configured (local dev)

### 9.2 SecretStr Handling

The `openfga_client_secret` must use `SecretStr` and call `.get_secret_value()` only when building the `CredentialConfiguration`. Never log or expose the secret value.

### 9.3 Backward Compatibility

All new settings default to `None`, preserving the existing unauthenticated flow. No breaking changes for existing deployments.

### 9.4 Logging

Log the authentication method being used (OIDC, API token, or none) during initialization, but never log credentials.

---

## 10. SDK Compatibility Notes

- **openfga-sdk>=0.6.0** is already specified in `pyproject.toml`
- SDK 0.6.x+ supports `ClientConfiguration(credentials=...)` with `CredentialConfiguration`
- The `Credentials` class supports `method="client_credentials"` for OIDC
- `ClientCredentialConfiguration` accepts: `client_id`, `client_secret`, `api_issuer` (token endpoint), `api_audience`
