# OpenFGA OIDC Authentication: Discrete Executable Actions

**Date:** 2026-02-11
**Source:** Implementation plan analysis + source code validation
**Scope:** SIOPV project (`~/siopv/`) — OpenFGA authentication ONLY

---

## Source Validation Summary

Before extracting actions, I validated the plan against actual source code:

| Plan Reference | File | Plan Line Refs | Actual State | Discrepancy? |
|---|---|---|---|---|
| settings.py OpenFGA fields | `src/siopv/infrastructure/config/settings.py:64-66` | Lines 64-66 | Lines 64-66: `openfga_api_url`, `openfga_store_id` ONLY | **No** — matches plan |
| `.env.example` | `.env.example` | Says "needs auth variables added" | **Already has auth vars at lines 37-51** (auth_method, api_token, client_id, client_secret, api_audience, api_token_issuer, authorization_model_id) | **YES — .env.example already updated** |
| Adapter `__init__` | `src/siopv/adapters/authorization/openfga_adapter.py:101-137` | Lines 101-137 | Lines 101-137: stores `_api_url`, `_store_id` only | **No** — matches plan |
| Adapter `initialize` | `openfga_adapter.py:159-164` | Lines 159-164 | Lines 159-164: basic `ClientConfiguration(api_url, store_id)` | **No** — matches plan |
| DI logging | `src/siopv/infrastructure/di/authorization.py:82-86` | Lines 82-86 | Lines 82-86: logs `api_url`, `store_id` only | **No** — matches plan |
| mock_settings fixture | `tests/unit/adapters/authorization/test_openfga_adapter.py:36-43` | Lines 36-43 | Lines 36-43: `openfga_api_url`, `openfga_store_id`, circuit_breaker fields ONLY | **No** — matches plan |
| Settings tests | `tests/unit/infrastructure/test_settings.py` | No OpenFGA auth tests | Lines 370-396: tests for `openfga_api_url`/`openfga_store_id` only | **No** — matches plan |
| `SecretStr` import | `settings.py:10` | Line 10 | `from pydantic import Field, SecretStr` — confirmed | **No** |
| `Literal` import | `settings.py:8` | Line 8 | `from typing import Literal` — confirmed | **No** |

### Critical Finding
**`.env.example` is ALREADY updated with all OpenFGA auth variables.** Step 1.2 from the plan should be marked as ALREADY COMPLETE. The actual gap is that `settings.py` lacks the corresponding Python fields for these env vars.

---

## Phase 1: Configuration Foundation

### Action 1.1: Add 7 new settings fields to `settings.py`

- **File:** `src/siopv/infrastructure/config/settings.py`
- **Type:** MODIFY existing file
- **Location:** After line 66 (after `openfga_store_id`)
- **What to add:** 7 new fields in the OpenFGA section

**Current code (lines 64-66):**
```python
# === OpenFGA ===
openfga_api_url: str | None = None
openfga_store_id: str | None = None
```

**Target code:**
```python
# === OpenFGA ===
openfga_api_url: str | None = None
openfga_store_id: str | None = None
openfga_api_token: SecretStr | None = None
openfga_authorization_model_id: str | None = None
# === OpenFGA OIDC (Phase 4) ===
openfga_auth_method: Literal["none", "api_token", "client_credentials"] = "none"
openfga_client_id: str | None = None
openfga_client_secret: SecretStr | None = None
openfga_api_audience: str | None = None
openfga_api_token_issuer: str | None = None
```

**Dependencies:** None (imports `SecretStr` and `Literal` already present)
**Risk:** LOW — all fields default to `None` or `"none"`, backward compatible
**Verification:** `pytest tests/unit/infrastructure/test_settings.py -v` (existing tests still pass)

---

### Action 1.2: Update `.env.example` — ALREADY DONE

- **File:** `.env.example`
- **Status:** **SKIP** — Already contains all OpenFGA auth variables at lines 33-51
- **No action required**

---

### Action 1.3: Add 3 new settings tests

- **File:** `tests/unit/infrastructure/test_settings.py`
- **Type:** MODIFY existing file (append after line 396)
- **What to add:** 3 test functions

**Test 1: `test_settings_openfga_auth_defaults`**
- Verifies all 7 new fields have correct defaults
- All `None` except `openfga_auth_method` which defaults to `"none"`

**Test 2: `test_settings_openfga_api_token_from_env`**
- Sets `SIOPV_OPENFGA_API_TOKEN=my-secret-token` and `SIOPV_OPENFGA_AUTH_METHOD=api_token`
- Verifies `SecretStr.get_secret_value()` returns correct value

**Test 3: `test_settings_openfga_oidc_from_env`**
- Sets all OIDC env vars (`CLIENT_ID`, `CLIENT_SECRET`, `API_AUDIENCE`, `API_TOKEN_ISSUER`)
- Verifies all fields load correctly

**Code snippets:** See implementation plan Steps 1.3 (lines 148-196)
**Dependencies:** Action 1.1 must be completed first
**Verification:** `pytest tests/unit/infrastructure/test_settings.py::test_settings_openfga_auth_defaults tests/unit/infrastructure/test_settings.py::test_settings_openfga_api_token_from_env tests/unit/infrastructure/test_settings.py::test_settings_openfga_oidc_from_env -v`

---

## Phase 2: Adapter Authentication Support

### Action 2.1: Update adapter `__init__` to store new settings

- **File:** `src/siopv/adapters/authorization/openfga_adapter.py`
- **Type:** MODIFY existing file
- **Location:** Lines 113-114 (after `self._store_id = ...`)
- **What to add:** 7 new instance variable assignments

**Current (lines 113-114):**
```python
self._api_url = settings.openfga_api_url
self._store_id = settings.openfga_store_id
```

**Target (insert after line 114):**
```python
self._api_url = settings.openfga_api_url
self._store_id = settings.openfga_store_id
self._authorization_model_id = settings.openfga_authorization_model_id
self._auth_method = settings.openfga_auth_method
self._api_token = settings.openfga_api_token
self._client_id = settings.openfga_client_id
self._client_secret = settings.openfga_client_secret
self._api_audience = settings.openfga_api_audience
self._api_token_issuer = settings.openfga_api_token_issuer
```

**Dependencies:** Action 1.1 (settings fields must exist)
**Risk:** LOW — only stores references, no behavior change
**Verification:** Existing tests must still pass (but mock_settings needs update first — see Action 2.4)

---

### Action 2.2: Add import for `Credentials` and `CredentialConfiguration`

- **File:** `src/siopv/adapters/authorization/openfga_adapter.py`
- **Type:** MODIFY existing file
- **Location:** After line 32 (after other `openfga_sdk` imports)
- **What to add:**

```python
from openfga_sdk.credentials import Credentials, CredentialConfiguration
```

**Dependencies:** `openfga-sdk` package already installed
**Risk:** LOW — import only, fails fast if SDK version incompatible

---

### Action 2.3: Update adapter `initialize()` to build credentials

- **File:** `src/siopv/adapters/authorization/openfga_adapter.py`
- **Type:** MODIFY existing file
- **Location:** Lines 159-164 (the `ClientConfiguration` creation block)
- **What to change:** Replace simple config with credential-aware config

**Current (lines 159-164):**
```python
configuration = ClientConfiguration(
    api_url=self._api_url,
    store_id=self._store_id,
)

self._owned_client = OpenFgaClient(configuration)
```

**Target:**
```python
config_kwargs: dict[str, Any] = {
    "api_url": self._api_url,
    "store_id": self._store_id,
}

if self._authorization_model_id:
    config_kwargs["authorization_model_id"] = self._authorization_model_id

if self._auth_method == "api_token" and self._api_token:
    config_kwargs["credentials"] = Credentials(
        method="api_token",
        configuration=CredentialConfiguration(
            api_token=self._api_token.get_secret_value(),
        ),
    )
elif self._auth_method == "client_credentials" and self._client_id and self._client_secret:
    config_kwargs["credentials"] = Credentials(
        method="client_credentials",
        configuration=CredentialConfiguration(
            client_id=self._client_id,
            client_secret=self._client_secret.get_secret_value(),
            api_audience=self._api_audience or "",
            api_token_issuer=self._api_token_issuer or "",
        ),
    )

configuration = ClientConfiguration(**config_kwargs)

self._owned_client = OpenFgaClient(configuration)
```

**Dependencies:** Actions 2.1 (instance vars) + 2.2 (import)
**Risk:** MEDIUM — core connection logic changed. Fallthrough to unauthenticated when `auth_method="none"`
**Verification:** Unit tests with mocked client + integration test with real server

---

### Action 2.4: Update DI container logging

- **File:** `src/siopv/infrastructure/di/authorization.py`
- **Type:** MODIFY existing file
- **Location:** Lines 82-86

**Current (lines 82-86):**
```python
logger.debug(
    "creating_authorization_adapter",
    api_url=settings.openfga_api_url,
    store_id=settings.openfga_store_id,
)
```

**Target:**
```python
logger.debug(
    "creating_authorization_adapter",
    api_url=settings.openfga_api_url,
    store_id=settings.openfga_store_id,
    auth_method=settings.openfga_auth_method,
    model_id=settings.openfga_authorization_model_id,
)
```

**Dependencies:** Action 1.1 (settings fields)
**Risk:** LOW — logging only
**Verification:** Visual inspection of structured logs

---

### Action 2.5: Update mock_settings fixture in adapter tests

- **File:** `tests/unit/adapters/authorization/test_openfga_adapter.py`
- **Type:** MODIFY existing file
- **Location:** Lines 36-43 (the `mock_settings` fixture)
- **What to change:** Add 7 new mock attributes

**Current (lines 36-43):**
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

**Target:**
```python
@pytest.fixture
def mock_settings() -> MagicMock:
    settings = MagicMock()
    settings.openfga_api_url = "http://localhost:8080"
    settings.openfga_store_id = "test-store-id"
    settings.openfga_api_token = None
    settings.openfga_authorization_model_id = None
    settings.openfga_auth_method = "none"
    settings.openfga_client_id = None
    settings.openfga_client_secret = None
    settings.openfga_api_audience = None
    settings.openfga_api_token_issuer = None
    settings.circuit_breaker_failure_threshold = 5
    settings.circuit_breaker_recovery_timeout = 60
    return settings
```

**Dependencies:** Must be done BEFORE or SIMULTANEOUSLY with Action 2.1 (adapter reads these in `__init__`)
**Risk:** LOW — updates mock to match new code
**Verification:** `pytest tests/unit/adapters/authorization/test_openfga_adapter.py -v`

---

### Action 2.6: Add 4 new adapter authentication tests

- **File:** `tests/unit/adapters/authorization/test_openfga_adapter.py`
- **Type:** MODIFY existing file (append new test class)
- **What to add:** `TestOpenFGAAdapterAuthentication` class with 4 tests

**Tests:**
1. `test_initialize_with_api_token` — adapter stores `api_token` auth config
2. `test_initialize_with_client_credentials` — adapter stores OIDC config
3. `test_initialize_with_model_id` — adapter stores pinned model ID
4. `test_initialize_no_auth_backward_compatible` — default `"none"` works

**Code snippets:** See implementation plan Step 2.4 (lines 351-392)
**Dependencies:** Actions 2.1-2.5 must be completed
**Verification:** `pytest tests/unit/adapters/authorization/test_openfga_adapter.py::TestOpenFGAAdapterAuthentication -v`

---

## Phase 3: Infrastructure Setup

### Action 3.1: Create `docker-compose.yml`

- **File:** `docker-compose.yml` (project root — NEW FILE)
- **Type:** CREATE new file
- **Contents:** 3 services: `openfga-postgres`, `openfga-migrate`, `openfga`
- **Key config:**
  - PostgreSQL 16-alpine backend
  - OpenFGA with `OPENFGA_AUTHN_METHOD=preshared` and key `dev-key-siopv-local-1`
  - Playground enabled at port 3000
  - Healthcheck via `/healthz`
  - Named volume `openfga_data` for postgres persistence

**Code snippet:** See implementation plan Step 3.1 (lines 406-456)
**Dependencies:** Docker installed
**Risk:** LOW — additive, no existing code changed
**Verification:** `docker compose config` (validates YAML), then `docker compose up -d` + healthcheck

---

### Action 3.2: Create `openfga/model.fga`

- **File:** `openfga/model.fga` (NEW FILE in new directory)
- **Type:** CREATE new directory + file
- **Contents:** Authorization model with 5 types: `user`, `organization`, `project`, `vulnerability`, `report`
- **Based on:** `src/siopv/domain/authorization/value_objects.py` — `ResourceType` (project, vulnerability, report, organization) and `Relation` (owner, viewer, analyst, auditor, member, admin)

**Code snippet:** See implementation plan Step 3.2 (lines 466-498)
**Dependencies:** None
**Risk:** LOW — standalone file
**Verification:** FGA CLI validation (if installed): `fga model validate --file openfga/model.fga`

---

### Action 3.3: Create `scripts/setup-openfga.sh`

- **File:** `scripts/setup-openfga.sh` (NEW FILE)
- **Type:** CREATE new file (executable)
- **Purpose:** Bootstrap script that:
  1. Waits for OpenFGA health
  2. Creates a store named "siopv"
  3. Writes the authorization model
  4. Outputs store_id and model_id for `.env`

**Code snippet:** See implementation plan Step 3.3 (lines 504-643)
**Dependencies:** Actions 3.1 (docker-compose running), 3.2 (model definition)
**Risk:** LOW — dev tooling only
**Verification:** `chmod +x scripts/setup-openfga.sh && bash -n scripts/setup-openfga.sh` (syntax check)

---

### Action 3.4: Create integration tests

- **File:** `tests/integration/test_openfga_real_server.py` (NEW FILE)
- **Type:** CREATE new file
- **Contents:** 2 test classes with `@pytest.mark.real_openfga` marker, skipped when env vars not set
- **Tests:**
  - `test_health_check` — verifies connection + health endpoint
  - `test_get_model_id` — verifies model retrieval

**Code snippet:** See implementation plan Step 3.4 (lines 650-721)
**Dependencies:** All Phase 1 + Phase 2 actions (adapter must support auth)
**Risk:** LOW — tests are skipped by default
**Verification:** `pytest tests/integration/test_openfga_real_server.py -v` (should skip with "not configured" message)

---

## Phase 4: OIDC Migration

### Action 4.1: OIDC Provider Setup (INFRASTRUCTURE — no code changes)

- **Type:** INFRASTRUCTURE task (not code)
- **Steps:**
  1. Deploy Keycloak (self-hosted, recommended) or configure Auth0/Cognito
  2. Create OAuth2 client with `client_credentials` grant type
  3. Configure client audience to match OpenFGA
  4. Note: `client_id`, `client_secret`, `token_endpoint`, `issuer`

**Dependencies:** None (infrastructure task)
**Risk:** MEDIUM — external system dependency

---

### Action 4.2: Update Docker Compose for OIDC (optional dev Keycloak)

- **File:** `docker-compose.yml`
- **Type:** MODIFY existing file
- **What to add:** Keycloak service + change OpenFGA env to OIDC mode

**Keycloak service:**
```yaml
keycloak:
  image: quay.io/keycloak/keycloak:latest
  command: start-dev
  environment:
    - KEYCLOAK_ADMIN=admin
    - KEYCLOAK_ADMIN_PASSWORD=admin
  ports:
    - "8180:8080"
```

**OpenFGA env change (when using OIDC):**
```yaml
- OPENFGA_AUTHN_METHOD=oidc
- OPENFGA_AUTHN_OIDC_ISSUER=https://keycloak.example.com/realms/siopv
- OPENFGA_AUTHN_OIDC_AUDIENCE=openfga-api
```

**Dependencies:** Action 3.1 (docker-compose exists), Action 4.1 (OIDC provider decided)
**Risk:** MEDIUM — must NOT break pre-shared key flow
**Verification:** `docker compose config`

---

### Action 4.3: Add token refresh validation test

- **File:** `tests/unit/adapters/authorization/test_openfga_adapter.py`
- **Type:** MODIFY existing file (append test)
- **What to add:** `test_client_credentials_token_refresh` — validates SDK receives correct OIDC config

**Code snippet:** See implementation plan Step 4.3 (lines 780-793)
**Dependencies:** Actions 2.1-2.5
**Risk:** LOW — unit test only
**Verification:** `pytest tests/unit/adapters/authorization/test_openfga_adapter.py::test_client_credentials_token_refresh -v`

---

## Phase 5: Production Hardening

### Action 5.1: Add TLS configuration to Docker Compose (production profile)

- **File:** `docker-compose.yml`
- **Type:** MODIFY existing file
- **What to add:** Production environment variables for TLS, metrics, tracing

```yaml
environment:
  - OPENFGA_HTTP_TLS_ENABLED=true
  - OPENFGA_HTTP_TLS_CERT=/certs/server.crt
  - OPENFGA_HTTP_TLS_KEY=/certs/server.key
  - OPENFGA_PLAYGROUND_ENABLED=false
  - OPENFGA_METRICS_ENABLED=true
  - OPENFGA_TRACE_ENABLED=true
  - OPENFGA_TRACE_SAMPLE_RATIO=0.3
```

**Dependencies:** Action 3.1
**Risk:** LOW — config only
**Verification:** `docker compose config`

---

### Action 5.2: Add Pydantic `model_validator` for auth config consistency

- **File:** `src/siopv/infrastructure/config/settings.py`
- **Type:** MODIFY existing file
- **Location:** Inside `Settings` class, after all field definitions (after line 66 + new fields)
- **What to add:** `@model_validator(mode="after")` that warns on inconsistent auth config

**New import needed:** `from pydantic import model_validator` (add to existing pydantic import line 10)
**What to validate:**
1. `auth_method="api_token"` but `api_token` is None → warning
2. `auth_method="client_credentials"` but `client_id`/`client_secret`/`api_token_issuer` missing → warning

**Code snippet:** See implementation plan Step 5.2 (lines 822-849)
**Dependencies:** Action 1.1 (fields must exist)
**Risk:** LOW — uses `warnings.warn`, not exceptions (non-breaking)
**Verification:** `pytest tests/unit/infrastructure/test_settings.py -v` + add test for warning behavior

---

### Action 5.3: Security hardening checklist (DOCUMENTATION — no code)

- **Type:** DOCUMENTATION
- **What:** 10-item production readiness checklist
- **Items:** Authentication, TLS, playground disabled, model pinning, network isolation, JSON logging, metrics, no PII in tuples, key rotation, concurrency limits

**Dependencies:** All phases
**Risk:** NONE — documentation only

---

## Complete Dependency Graph

```
Action 1.1 (settings fields)
  ├──► Action 1.3 (settings tests) — depends on 1.1
  ├──► Action 2.1 (adapter __init__) — depends on 1.1
  ├──► Action 2.4 (DI logging) — depends on 1.1
  └──► Action 5.2 (validator) — depends on 1.1

Action 2.1 (adapter __init__)
  └──► depends on: 1.1, 2.5 (mock update must happen simultaneously)

Action 2.2 (import Credentials)
  └──► Action 2.3 (initialize with creds) — depends on 2.2

Action 2.3 (initialize with creds)
  └──► depends on: 2.1, 2.2

Action 2.5 (mock_settings update)
  └──► MUST happen before or with 2.1 (tests break otherwise)

Action 2.6 (auth tests)
  └──► depends on: 2.1, 2.2, 2.3, 2.5

Action 3.1 (docker-compose) — independent of Phase 1-2 code
Action 3.2 (model.fga) — independent
Action 3.3 (bootstrap script) — depends on 3.1, 3.2
Action 3.4 (integration tests) — depends on 3.3 + Phase 2

Action 4.2 (Keycloak compose) — depends on 3.1
Action 4.3 (token refresh test) — depends on 2.1-2.5

Action 5.1 (TLS config) — depends on 3.1
Action 5.2 (validator) — depends on 1.1
```

---

## Execution Order (Recommended)

### PR 1: Phase 1 + Phase 2 (config + adapter auth)

**Order of operations:**
1. Action 1.1 — Add settings fields
2. Action 2.5 — Update mock_settings fixture (BEFORE adapter changes)
3. Action 1.3 — Add settings tests
4. Action 2.1 — Update adapter `__init__`
5. Action 2.2 — Add Credentials import
6. Action 2.3 — Update adapter `initialize()`
7. Action 2.4 — Update DI logging
8. Action 2.6 — Add adapter auth tests

**Verification after PR 1:**
```bash
pytest tests/unit/infrastructure/test_settings.py -v
pytest tests/unit/adapters/authorization/test_openfga_adapter.py -v
pytest tests/ -v --ignore=tests/integration/
```

### PR 2: Phase 3 (infrastructure)

**Order of operations:**
1. Action 3.1 — Create docker-compose.yml
2. Action 3.2 — Create openfga/model.fga
3. Action 3.3 — Create scripts/setup-openfga.sh
4. Action 3.4 — Create integration tests

**Verification after PR 2:**
```bash
docker compose config
bash -n scripts/setup-openfga.sh
pytest tests/integration/test_openfga_real_server.py -v  # (skips without server)
```

### PR 3: Phase 4 (OIDC)

1. Action 4.1 — OIDC provider setup (infrastructure)
2. Action 4.2 — Keycloak to docker-compose
3. Action 4.3 — Token refresh test

### PR 4: Phase 5 (hardening)

1. Action 5.1 — TLS configuration
2. Action 5.2 — Environment validation (model_validator)
3. Action 5.3 — Security checklist

---

## Files Changed Summary

### Files MODIFIED (6 files)

| # | File | Actions | Phase |
|---|------|---------|-------|
| 1 | `src/siopv/infrastructure/config/settings.py` | 1.1, 5.2 | 1, 5 |
| 2 | `src/siopv/adapters/authorization/openfga_adapter.py` | 2.1, 2.2, 2.3 | 2 |
| 3 | `src/siopv/infrastructure/di/authorization.py` | 2.4 | 2 |
| 4 | `tests/unit/infrastructure/test_settings.py` | 1.3 | 1 |
| 5 | `tests/unit/adapters/authorization/test_openfga_adapter.py` | 2.5, 2.6, 4.3 | 2, 4 |
| 6 | `docker-compose.yml` | 4.2, 5.1 | 4, 5 |

### Files CREATED (4 files)

| # | File | Action | Phase |
|---|------|--------|-------|
| 1 | `docker-compose.yml` | 3.1 | 3 |
| 2 | `openfga/model.fga` | 3.2 | 3 |
| 3 | `scripts/setup-openfga.sh` | 3.3 | 3 |
| 4 | `tests/integration/test_openfga_real_server.py` | 3.4 | 3 |

### Files ALREADY DONE (1 file)

| # | File | Action | Status |
|---|------|--------|--------|
| 1 | `.env.example` | 1.2 | **ALREADY COMPLETE** — has all OpenFGA auth vars |

### Files NOT CHANGED (confirmed safe)

| File | Reason |
|------|--------|
| `src/siopv/application/ports/authorization.py` | Port interfaces unchanged |
| `src/siopv/application/use_cases/authorization.py` | Use cases unchanged |
| `src/siopv/domain/authorization/*` | Domain layer untouched |
| `tests/integration/test_authorization_integration.py` | Uses mocks (unaffected) |

---

## Total Action Count

| Phase | Actions | Code Actions | Infra/Doc Actions |
|-------|---------|-------------|-------------------|
| Phase 1 | 3 (1.1, 1.2-SKIP, 1.3) | 2 | 0 |
| Phase 2 | 6 (2.1-2.6) | 6 | 0 |
| Phase 3 | 4 (3.1-3.4) | 1 (tests) | 3 (infra) |
| Phase 4 | 3 (4.1-4.3) | 1 (test) | 2 (infra) |
| Phase 5 | 3 (5.1-5.3) | 1 (validator) | 2 (config/doc) |
| **Total** | **19** | **11** | **7** (+1 skip) |
