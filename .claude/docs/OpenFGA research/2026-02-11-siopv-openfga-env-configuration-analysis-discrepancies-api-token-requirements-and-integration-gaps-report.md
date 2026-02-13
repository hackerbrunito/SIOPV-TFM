# SIOPV OpenFGA .env Configuration Analysis: Discrepancies, API Token Requirements, and Integration Gaps

**Date:** 2026-02-11
**Analyst:** siopv-analyzer (OpenFGA Research Team)
**Project:** SIOPV (~/siopv/)
**Scope:** OpenFGA configuration, .env setup, API token requirements, integration discrepancies

---

## 1. Executive Summary

The SIOPV project has a well-architected OpenFGA integration at the code level (Phase 5 complete), but the **runtime configuration is incomplete**. Critical gaps include: no `.env` or `.env.example` file exists, no API token/credential support for OpenFGA, no authorization model definition file, and no Docker Compose for running the OpenFGA server. The adapter works with mocked clients in tests but cannot connect to a real OpenFGA instance without additional configuration.

---

## 2. Current .env Configuration Status

### 2.1 Missing .env and .env.example Files

- **No `.env` file** exists in the project root
- **No `.env.example` file** exists, despite being referenced in:
  - `README.md` line 12: `cp .env.example .env`
  - `docs/PHASE-0-REPORT-EN.md` line 135: listed as a created configuration file
  - `docs/PHASE-0-REPORT-EN.md` line 290: `cp .env.example .env`

The Phase 0 report states `.env.example` was created as part of the initial setup, but it no longer exists in the filesystem. It may have been accidentally deleted or never committed to git.

### 2.2 OpenFGA Settings in `settings.py`

**File:** `src/siopv/infrastructure/config/settings.py` (lines 64-66)

The Settings class uses Pydantic Settings with `SIOPV_` prefix and defines only **2 OpenFGA fields**:

```python
# === OpenFGA ===
openfga_api_url: str | None = None
openfga_store_id: str | None = None
```

**Corresponding env vars:**
- `SIOPV_OPENFGA_API_URL` (e.g., `http://localhost:8080`)
- `SIOPV_OPENFGA_STORE_ID` (e.g., `01HXYZ...`)

Both are **optional** with `None` defaults, meaning the application can start without any OpenFGA configuration, but the authorization adapter will raise `StoreNotFoundError` when `initialize()` is called.

---

## 3. API Token / Credential Analysis

### 3.1 No Authentication Configuration

**Critical finding:** The SIOPV project has **zero** authentication/credential support for OpenFGA.

- **Settings:** No `openfga_api_token`, `openfga_api_key`, or `openfga_credentials` field
- **Adapter:** `ClientConfiguration` is created with only `api_url` and `store_id`:
  ```python
  configuration = ClientConfiguration(
      api_url=self._api_url,
      store_id=self._store_id,
  )
  ```
- **No Bearer token, API key, or OAuth support** anywhere in the codebase

### 3.2 OpenFGA SDK Credential Support

The `openfga_sdk.ClientConfiguration` supports a `credentials` parameter for production deployments:

```python
# What the SDK supports (not used in SIOPV):
ClientConfiguration(
    api_url="https://openfga.example.com",
    store_id="...",
    credentials=ClientCredentials(
        method="api_token",
        config=CredentialConfiguration(api_token="your-token"),
    ),
)
```

Or for OIDC/OAuth2:
```python
ClientCredentials(
    method="client_credentials",
    config=CredentialConfiguration(
        client_id="...",
        client_secret="...",
        api_issuer="...",
        api_audience="...",
    ),
)
```

**Impact:** The current adapter can only connect to **unauthenticated local OpenFGA** instances (e.g., Docker dev server). Production deployments requiring authentication will fail.

### 3.3 Missing Authorization Model ID Setting

The adapter has an internal `_cached_model_id` that gets populated by calling `get_model_id()`, but there is no way to **pre-configure** a specific model ID from settings. This means:

- The adapter always uses the latest model in the store
- There is no way to pin to a specific model version for reproducibility
- No `SIOPV_OPENFGA_AUTHORIZATION_MODEL_ID` env var exists

---

## 4. Missing Infrastructure Components

### 4.1 No Docker Compose

No `docker-compose.yml` or `docker-compose.yaml` exists for running OpenFGA locally. A typical setup would include:

- OpenFGA server container
- PostgreSQL/MySQL for persistent storage (optional, defaults to in-memory)
- Network configuration

### 4.2 No Authorization Model File

No `.fga` model definition files exist in the project. The OpenFGA authorization model (defining types like `project`, `vulnerability`, `report`, `organization` and their relations) exists only conceptually in:

- Domain value objects (`value_objects.py`: `ResourceType`, `Relation` enums)
- Code comments and docstrings

There is no declarative model file that can be loaded into OpenFGA.

### 4.3 No Model Migration/Seeding Script

No script or command exists to:
- Create an OpenFGA store
- Write the authorization model
- Seed initial relationship tuples

---

## 5. Discrepancy Analysis

| Item | Expected | Actual | Severity |
|------|----------|--------|----------|
| `.env.example` | Exists (per README + Phase 0 report) | **Missing** | HIGH |
| `.env` | Created from .env.example | **Missing** | HIGH |
| OpenFGA API token support | Needed for production | **Not implemented** | MEDIUM |
| OpenFGA model ID in settings | Needed for model pinning | **Not implemented** | LOW |
| Docker Compose for OpenFGA | Needed for local dev | **Not implemented** | MEDIUM |
| `.fga` model definition | Needed for store setup | **Not implemented** | MEDIUM |
| Model seeding script | Needed for bootstrapping | **Not implemented** | LOW |

### 5.1 Code vs Config Gap

The codebase has a **complete** Phase 5 implementation:
- Domain layer: entities, value objects, exceptions (8 files)
- Application layer: ports (3 Protocol interfaces), use cases (3 classes)
- Adapter layer: OpenFGAAdapter (1173 lines, full SDK integration)
- Infrastructure: DI container, circuit breaker, retry logic
- Tests: 87+ authorization-specific tests (unit + integration)

But the **configuration and infrastructure** to actually run it is missing:
- No env file template
- No server setup
- No model definition
- No credential support

### 5.2 Test Coverage vs Runtime Gap

All tests use `MagicMock`/`AsyncMock` for the OpenFGA client. While this provides good unit/integration test coverage, there are **no tests that validate against a real OpenFGA server**, and the configuration needed to do so doesn't exist.

---

## 6. Recommended .env.example Configuration

Based on the analysis, a complete `.env.example` for OpenFGA should include:

```bash
# === OpenFGA (Phase 5: Authorization) ===
SIOPV_OPENFGA_API_URL=http://localhost:8080
SIOPV_OPENFGA_STORE_ID=
# SIOPV_OPENFGA_API_TOKEN=          # For authenticated deployments
# SIOPV_OPENFGA_AUTHORIZATION_MODEL_ID=  # Pin to specific model version
```

### Settings fields that should be added:

```python
# === OpenFGA ===
openfga_api_url: str | None = None
openfga_store_id: str | None = None
openfga_api_token: SecretStr | None = None           # NEW: API token for auth
openfga_authorization_model_id: str | None = None     # NEW: Pin model version
```

---

## 7. Summary of All OpenFGA-Related Files

| File | Purpose | Lines |
|------|---------|-------|
| `src/siopv/infrastructure/config/settings.py` | OpenFGA config (2 fields) | 89 |
| `src/siopv/adapters/authorization/openfga_adapter.py` | SDK adapter | 1173 |
| `src/siopv/application/ports/authorization.py` | Port interfaces | 556 |
| `src/siopv/application/use_cases/authorization.py` | Use cases | 853 |
| `src/siopv/application/orchestration/nodes/authorization_node.py` | LangGraph node | 393 |
| `src/siopv/domain/authorization/entities.py` | Domain entities | 558 |
| `src/siopv/domain/authorization/value_objects.py` | Value objects | 387 |
| `src/siopv/domain/authorization/exceptions.py` | Domain exceptions | 293 |
| `src/siopv/infrastructure/di/authorization.py` | DI container | 211 |
| `tests/unit/adapters/authorization/test_openfga_adapter.py` | Unit tests | - |
| `tests/unit/domain/authorization/test_entities.py` | Entity tests | - |
| `tests/unit/domain/authorization/test_value_objects.py` | VO tests | - |
| `tests/unit/domain/authorization/test_exceptions.py` | Exception tests | - |
| `tests/unit/application/test_authorization.py` | Use case tests | - |
| `tests/unit/infrastructure/di/test_authorization_di.py` | DI tests | - |
| `tests/integration/test_authorization_integration.py` | Integration tests | 971 |
| `tests/unit/infrastructure/test_settings.py` | Settings tests (OpenFGA section) | 482 |

---

## 8. Key Recommendations

1. **Create `.env.example`** with all required environment variables including OpenFGA section
2. **Add `openfga_api_token` to Settings** as `SecretStr | None` for authenticated deployments
3. **Add `openfga_authorization_model_id` to Settings** for model version pinning
4. **Update `OpenFGAAdapter.initialize()`** to pass credentials to `ClientConfiguration` when token is provided
5. **Create a `.fga` model definition** capturing the authorization model (types: project, vulnerability, report, organization; relations: owner, viewer, analyst, auditor, member, admin)
6. **Add Docker Compose** for local OpenFGA development server
7. **Create a bootstrap/seed script** to initialize store, write model, and create initial tuples
