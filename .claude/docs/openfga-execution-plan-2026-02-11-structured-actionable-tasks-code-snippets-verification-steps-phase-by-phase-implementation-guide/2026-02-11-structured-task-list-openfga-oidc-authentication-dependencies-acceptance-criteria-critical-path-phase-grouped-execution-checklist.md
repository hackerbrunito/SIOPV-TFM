# Structured Task List: OpenFGA OIDC Authentication Implementation

**Date:** 2026-02-11
**Project:** SIOPV (`~/siopv/`)
**Source:** Implementation Plan + Codebase Analysis
**Format:** Execution checklist with task IDs, dependencies, acceptance criteria

---

## Legend

- **Status:** `[ ]` pending, `[x]` done
- **Dep:** Task IDs that must complete first
- **CP:** Critical path task (yes/no)
- **File (M):** Modified file | **File (C):** Created file

---

## Phase 1: Configuration Foundation

### TASK-001: Add authentication settings fields to Settings class

- **File (M):** `src/siopv/infrastructure/config/settings.py` (lines 64-66)
- **Dep:** none
- **CP:** yes
- **Action:** Add 7 new fields after existing `openfga_store_id`:
  - `openfga_api_token: SecretStr | None = None`
  - `openfga_authorization_model_id: str | None = None`
  - `openfga_auth_method: Literal["none", "api_token", "client_credentials"] = "none"`
  - `openfga_client_id: str | None = None`
  - `openfga_client_secret: SecretStr | None = None`
  - `openfga_api_audience: str | None = None`
  - `openfga_api_token_issuer: str | None = None`
- **Notes:** `SecretStr` already imported (line 10). `Literal` already imported (line 8). All fields `None`-defaulted = backward compatible.
- **Acceptance Criteria:**
  - [ ] 7 new fields exist in `Settings` class under `# === OpenFGA ===` section
  - [ ] `openfga_auth_method` defaults to `"none"`
  - [ ] `openfga_api_token` and `openfga_client_secret` use `SecretStr`
  - [ ] Existing tests pass without modification (`pytest tests/unit/infrastructure/test_settings.py`)
  - [ ] No new imports needed

---

### TASK-002: Update .env.example with authentication variables

- **File (M):** `.env.example`
- **Dep:** none (can run parallel with TASK-001)
- **CP:** no
- **Action:** `.env.example` already contains OpenFGA auth fields (lines 33-51). **Verify** the current file matches the plan. If it does, this task is a no-op.
- **Current state analysis:** `.env.example` already has:
  - `SIOPV_OPENFGA_AUTHORIZATION_MODEL_ID=` (line 38)
  - `SIOPV_OPENFGA_AUTH_METHOD=none` (line 42)
  - `SIOPV_OPENFGA_API_TOKEN=` (line 45)
  - `SIOPV_OPENFGA_CLIENT_ID=` (line 48)
  - `SIOPV_OPENFGA_CLIENT_SECRET=` (line 49)
  - `SIOPV_OPENFGA_API_AUDIENCE=` (line 50)
  - `SIOPV_OPENFGA_API_TOKEN_ISSUER=` (line 51)
- **Acceptance Criteria:**
  - [ ] All 7 auth-related env vars present in `.env.example`
  - [ ] Comments explain `auth_method` options: `"none"`, `"api_token"`, `"client_credentials"`
  - [ ] OIDC fields grouped and commented as optional

---

### TASK-003: Add settings unit tests for new OpenFGA auth fields

- **File (M):** `tests/unit/infrastructure/test_settings.py`
- **Dep:** TASK-001
- **CP:** yes
- **Action:** Add 3 new test functions after existing `test_settings_openfga_configured` (line 396):
  1. `test_settings_openfga_auth_defaults()` — verify all 7 new fields have correct defaults
  2. `test_settings_openfga_api_token_from_env()` — load api_token + auth_method from env
  3. `test_settings_openfga_oidc_from_env()` — load all OIDC fields from env
- **Pattern:** Follow existing test style with `patch.dict(os.environ, {...}, clear=True)`
- **Acceptance Criteria:**
  - [ ] 3 new test functions added
  - [ ] Tests verify `SecretStr.get_secret_value()` for token/secret fields
  - [ ] Tests verify `openfga_auth_method` accepts `"none"`, `"api_token"`, `"client_credentials"`
  - [ ] `pytest tests/unit/infrastructure/test_settings.py -v` passes (all tests green)

---

## Phase 2: Adapter Authentication Support

### TASK-004: Store new auth settings in adapter `__init__`

- **File (M):** `src/siopv/adapters/authorization/openfga_adapter.py` (lines 101-137)
- **Dep:** TASK-001
- **CP:** yes
- **Action:** Add 7 new instance variables after `self._store_id` (line 114):
  - `self._authorization_model_id = settings.openfga_authorization_model_id`
  - `self._auth_method = settings.openfga_auth_method`
  - `self._api_token = settings.openfga_api_token`
  - `self._client_id = settings.openfga_client_id`
  - `self._client_secret = settings.openfga_client_secret`
  - `self._api_audience = settings.openfga_api_audience`
  - `self._api_token_issuer = settings.openfga_api_token_issuer`
- **Acceptance Criteria:**
  - [ ] 7 new `self._*` attributes set in `__init__`
  - [ ] Existing constructor signature unchanged (backward compatible)
  - [ ] No new imports needed for this step

---

### TASK-005: Add credentials import to adapter

- **File (M):** `src/siopv/adapters/authorization/openfga_adapter.py` (imports section)
- **Dep:** TASK-004
- **CP:** yes
- **Action:** Add import at top of file:
  ```python
  from openfga_sdk.credentials import Credentials, CredentialConfiguration
  ```
- **Acceptance Criteria:**
  - [ ] Import exists and does not break existing imports
  - [ ] `python -c "from openfga_sdk.credentials import Credentials, CredentialConfiguration"` succeeds

---

### TASK-006: Update adapter `initialize()` to build credentials

- **File (M):** `src/siopv/adapters/authorization/openfga_adapter.py` (lines 159-164)
- **Dep:** TASK-004, TASK-005
- **CP:** yes
- **Action:** Replace the `ClientConfiguration(...)` block with credential-aware builder:
  1. Build `config_kwargs` dict with `api_url` and `store_id`
  2. Optionally add `authorization_model_id` if set
  3. If `auth_method == "api_token"` and `api_token` set: add `Credentials(method="api_token", ...)`
  4. If `auth_method == "client_credentials"` and `client_id`+`client_secret` set: add `Credentials(method="client_credentials", ...)`
  5. Pass `**config_kwargs` to `ClientConfiguration`
- **Key detail:** Use `self._api_token.get_secret_value()` and `self._client_secret.get_secret_value()` to extract actual values from `SecretStr`
- **Acceptance Criteria:**
  - [ ] `auth_method="none"` produces same `ClientConfiguration` as current code (backward compatible)
  - [ ] `auth_method="api_token"` creates `Credentials(method="api_token", ...)`
  - [ ] `auth_method="client_credentials"` creates `Credentials(method="client_credentials", ...)`
  - [ ] `authorization_model_id` included in config when set
  - [ ] No `SecretStr` objects leaked into `ClientConfiguration` (only `.get_secret_value()`)

---

### TASK-007: Update DI container logging

- **File (M):** `src/siopv/infrastructure/di/authorization.py` (lines 82-86)
- **Dep:** TASK-001
- **CP:** no
- **Action:** Add 2 fields to `logger.debug("creating_authorization_adapter", ...)`:
  - `auth_method=settings.openfga_auth_method`
  - `model_id=settings.openfga_authorization_model_id`
- **Acceptance Criteria:**
  - [ ] Log output includes `auth_method` and `model_id` fields
  - [ ] No secrets logged (only auth_method string and model_id)

---

### TASK-008: Update adapter test fixtures for new fields

- **File (M):** `tests/unit/adapters/authorization/test_openfga_adapter.py` (lines 36-43)
- **Dep:** TASK-004
- **CP:** yes
- **Action:** Update `mock_settings` fixture to include all 7 new fields with `None`/`"none"` defaults:
  ```python
  settings.openfga_api_token = None
  settings.openfga_authorization_model_id = None
  settings.openfga_auth_method = "none"
  settings.openfga_client_id = None
  settings.openfga_client_secret = None
  settings.openfga_api_audience = None
  settings.openfga_api_token_issuer = None
  ```
- **Acceptance Criteria:**
  - [ ] All existing 87+ tests still pass after fixture update
  - [ ] `pytest tests/unit/adapters/authorization/test_openfga_adapter.py -v` all green

---

### TASK-009: Add adapter authentication unit tests

- **File (M):** `tests/unit/adapters/authorization/test_openfga_adapter.py`
- **Dep:** TASK-008
- **CP:** yes
- **Action:** Add new test class `TestOpenFGAAdapterAuthentication` with 4 tests:
  1. `test_initialize_with_api_token` — verify `_auth_method` and `_api_token` set
  2. `test_initialize_with_client_credentials` — verify OIDC fields set
  3. `test_initialize_with_model_id` — verify `_authorization_model_id` set
  4. `test_initialize_no_auth_backward_compatible` — verify `_auth_method == "none"`
- **Acceptance Criteria:**
  - [ ] 4 new test methods in `TestOpenFGAAdapterAuthentication`
  - [ ] Tests use `MagicMock()` for `SecretStr` fields with `.get_secret_value.return_value`
  - [ ] `pytest tests/unit/adapters/authorization/test_openfga_adapter.py -v` all green

---

### TASK-010: Run full unit test suite for Phase 1+2 validation

- **File:** n/a (verification task)
- **Dep:** TASK-003, TASK-006, TASK-007, TASK-009
- **CP:** yes (gate for Phase 3)
- **Action:** Run complete test suite to verify backward compatibility:
  ```bash
  pytest tests/unit/ -v --tb=short
  ```
- **Acceptance Criteria:**
  - [ ] All existing tests pass (zero regressions)
  - [ ] All new tests pass
  - [ ] No new warnings related to OpenFGA fields

---

## Phase 3: Infrastructure Setup

### TASK-011: Create Docker Compose for OpenFGA + PostgreSQL

- **File (C):** `docker-compose.yml` (project root)
- **Dep:** TASK-010 (Phase 1+2 validated)
- **CP:** yes
- **Action:** Create `docker-compose.yml` with 3 services:
  1. `openfga-postgres` — PostgreSQL 16-alpine with healthcheck
  2. `openfga-migrate` — OpenFGA migration (depends on postgres healthy)
  3. `openfga` — OpenFGA server with pre-shared key auth, playground, healthcheck
- **Key config:**
  - `OPENFGA_AUTHN_METHOD=preshared`
  - `OPENFGA_AUTHN_PRESHARED_KEYS=dev-key-siopv-local-1`
  - Ports: 8080 (HTTP), 8081 (gRPC), 3000 (playground)
  - Volume: `openfga_data` for postgres persistence
- **Acceptance Criteria:**
  - [ ] `docker compose config` validates without errors
  - [ ] `docker compose up -d` starts all 3 services
  - [ ] `curl http://localhost:8080/healthz` returns 200 within 30s
  - [ ] `curl -H "Authorization: Bearer dev-key-siopv-local-1" http://localhost:8080/stores` returns 200

---

### TASK-012: Create authorization model file (model.fga)

- **File (C):** `openfga/model.fga`
- **Dep:** none (can start anytime, but best after TASK-011)
- **CP:** yes
- **Action:** Create `.fga` model matching domain value objects (`ResourceType`, `Relation`):
  - Types: `user`, `organization`, `project`, `vulnerability`, `report`
  - Relations per type matching `value_objects.py` enums
  - Hierarchical: org admin → project owner, org member → project viewer
- **Acceptance Criteria:**
  - [ ] Model file parses without errors (validate with `fga model validate` if FGA CLI available)
  - [ ] All `ResourceType` enum values have a corresponding `type` definition
  - [ ] All `Relation` enum values appear in appropriate type definitions
  - [ ] Inheritance chains work: org admin → project owner → vulnerability owner

---

### TASK-013: Create bootstrap script (setup-openfga.sh)

- **File (C):** `scripts/setup-openfga.sh`
- **Dep:** TASK-011, TASK-012
- **CP:** yes
- **Action:** Create bash script that:
  1. Waits for OpenFGA healthcheck (max 30s)
  2. Creates a store named `siopv` via REST API
  3. Writes the authorization model (JSON format) to the store
  4. Outputs store_id, model_id, and `.env` configuration lines
- **Key detail:** Script uses `Authorization: Bearer ${OPENFGA_API_TOKEN}` header for authenticated calls
- **Acceptance Criteria:**
  - [ ] Script is executable (`chmod +x`)
  - [ ] Script uses `set -euo pipefail` for safety
  - [ ] Running after `docker compose up -d` outputs valid store_id and model_id
  - [ ] Outputs copy-pasteable `.env` lines

---

### TASK-014: Create real-server integration tests

- **File (C):** `tests/integration/test_openfga_real_server.py`
- **Dep:** TASK-006, TASK-013
- **CP:** no (optional but valuable)
- **Action:** Create integration test file with:
  - `pytestmark = pytest.mark.skipif(not OPENFGA_API_URL ...)` — auto-skip when no server
  - `real_settings` fixture from env vars
  - `TestRealOpenFGAConnection` class with:
    1. `test_health_check` — verify real server health
    2. `test_get_model_id` — verify model retrieval
- **Acceptance Criteria:**
  - [ ] Tests skip gracefully when `SIOPV_OPENFGA_*` env vars not set
  - [ ] Tests pass when Docker Compose is running and env vars configured
  - [ ] Tests use `pytest.mark.real_openfga` marker
  - [ ] Each test properly calls `adapter.close()` in finally block

---

## Phase 4: OIDC Migration

### TASK-015: Add Keycloak to Docker Compose (optional dev setup)

- **File (M):** `docker-compose.yml`
- **Dep:** TASK-011
- **CP:** no
- **Action:** Append `keycloak` service:
  - Image: `quay.io/keycloak/keycloak:latest`
  - Command: `start-dev`
  - Port: 8180:8080 (avoids conflict with OpenFGA)
  - Admin credentials: `admin/admin`
- **Acceptance Criteria:**
  - [ ] `docker compose up -d keycloak` starts without errors
  - [ ] Keycloak admin console accessible at `http://localhost:8180`
  - [ ] Does not interfere with OpenFGA services

---

### TASK-016: Update OpenFGA Docker Compose for OIDC mode

- **File (M):** `docker-compose.yml`
- **Dep:** TASK-015
- **CP:** no
- **Action:** Add commented OIDC environment variables to openfga service:
  ```yaml
  # Uncomment for OIDC mode (requires Keycloak setup):
  # - OPENFGA_AUTHN_METHOD=oidc
  # - OPENFGA_AUTHN_OIDC_ISSUER=http://keycloak:8080/realms/siopv
  # - OPENFGA_AUTHN_OIDC_AUDIENCE=openfga-api
  ```
- **Acceptance Criteria:**
  - [ ] Commented OIDC config present but not active by default
  - [ ] Pre-shared key mode remains the default
  - [ ] Instructions in comments explain how to switch

---

### TASK-017: Add token refresh validation test

- **File (M):** `tests/unit/adapters/authorization/test_openfga_adapter.py`
- **Dep:** TASK-009
- **CP:** no
- **Action:** Add `test_client_credentials_token_refresh` to verify SDK config is passed correctly for OIDC:
  - Set `auth_method="client_credentials"` with all OIDC fields
  - Verify adapter stores config correctly (SDK handles token lifecycle)
- **Acceptance Criteria:**
  - [ ] Test verifies all OIDC fields are stored in adapter
  - [ ] Test passes with mocked settings

---

## Phase 5: Production Hardening

### TASK-018: Add Pydantic model validator for auth config consistency

- **File (M):** `src/siopv/infrastructure/config/settings.py`
- **Dep:** TASK-001
- **CP:** no
- **Action:** Add `@model_validator(mode="after")` method `validate_openfga_auth`:
  - If `auth_method == "api_token"` but no `api_token` → emit `warnings.warn()`
  - If `auth_method == "client_credentials"` but missing `client_id`/`client_secret`/`api_token_issuer` → emit `warnings.warn()` listing missing fields
- **Import:** `from pydantic import model_validator` (add to existing import line)
- **Acceptance Criteria:**
  - [ ] Validator method exists on `Settings` class
  - [ ] Misconfigured `api_token` mode warns (does not raise)
  - [ ] Misconfigured `client_credentials` lists all missing fields in warning
  - [ ] Valid configs pass without warnings
  - [ ] `auth_method="none"` never warns

---

### TASK-019: Add settings validation tests

- **File (M):** `tests/unit/infrastructure/test_settings.py`
- **Dep:** TASK-018
- **CP:** no
- **Action:** Add 2-3 tests for the model validator:
  1. `test_settings_openfga_api_token_warns_if_missing_token()` — `auth_method="api_token"` + no token → warning
  2. `test_settings_openfga_oidc_warns_if_missing_fields()` — `auth_method="client_credentials"` + missing fields → warning
  3. `test_settings_openfga_valid_config_no_warnings()` — valid config → no warnings
- **Acceptance Criteria:**
  - [ ] Tests use `pytest.warns()` or `warnings.catch_warnings()` to verify
  - [ ] All settings test file passes

---

### TASK-020: Add TLS and production config comments to Docker Compose

- **File (M):** `docker-compose.yml`
- **Dep:** TASK-011
- **CP:** no
- **Action:** Add commented production hardening section:
  ```yaml
  # === Production Hardening (uncomment for production) ===
  # - OPENFGA_HTTP_TLS_ENABLED=true
  # - OPENFGA_HTTP_TLS_CERT=/certs/server.crt
  # - OPENFGA_HTTP_TLS_KEY=/certs/server.key
  # - OPENFGA_PLAYGROUND_ENABLED=false
  # - OPENFGA_METRICS_ENABLED=true
  ```
- **Acceptance Criteria:**
  - [ ] Production config documented as comments
  - [ ] Default dev config unchanged

---

### TASK-021: Run full test suite — final validation

- **File:** n/a (verification task)
- **Dep:** TASK-010, TASK-017, TASK-019
- **CP:** yes (final gate)
- **Action:** Run complete validation:
  ```bash
  # Unit tests
  pytest tests/unit/ -v --tb=short
  # Type checking
  mypy src/siopv/infrastructure/config/settings.py src/siopv/adapters/authorization/openfga_adapter.py
  # Lint
  ruff check src/siopv/infrastructure/config/settings.py src/siopv/adapters/authorization/openfga_adapter.py
  ```
- **Acceptance Criteria:**
  - [ ] All unit tests pass
  - [ ] mypy reports no errors on modified files
  - [ ] ruff reports no lint violations on modified files
  - [ ] Zero regressions in existing test suite

---

## Dependency Graph

```
TASK-001 (Settings fields) ──┬──> TASK-003 (Settings tests) ──────────┐
                             ├──> TASK-004 (Adapter __init__) ─┐      │
                             ├──> TASK-007 (DI logging)        │      │
                             └──> TASK-018 (Validator)         │      │
                                                               │      │
TASK-002 (.env.example) ── independent                         │      │
                                                               v      │
                             TASK-005 (Credentials import) ─> TASK-006 (initialize()) ─┐
                                                               │                        │
                             TASK-008 (Test fixtures) ────────>│                        │
                                                               v                        │
                             TASK-009 (Auth tests) ────────────┘                        │
                                                                                        │
                             TASK-003 + TASK-006 + TASK-007 + TASK-009 ──> TASK-010 (Gate)
                                                                               │
                             TASK-010 ──> TASK-011 (Docker Compose)            │
                             TASK-011 ──> TASK-012 (model.fga) ──> TASK-013 (bootstrap)
                             TASK-013 + TASK-006 ──> TASK-014 (integration tests)
                             TASK-011 ──> TASK-015 (Keycloak) ──> TASK-016 (OIDC config)
                             TASK-009 ──> TASK-017 (Token refresh test)
                             TASK-018 ──> TASK-019 (Validator tests)
                             TASK-011 ──> TASK-020 (TLS comments)
                             TASK-010 + TASK-017 + TASK-019 ──> TASK-021 (Final gate)
```

---

## Critical Path

```
TASK-001 → TASK-004 → TASK-005 → TASK-006 → TASK-010 → TASK-011 → TASK-013 → TASK-014
    │           │                                │
    ├→ TASK-003 ├→ TASK-008 → TASK-009 ──────────┘
    └→ TASK-007─┘
```

**Critical path tasks:** 001, 003, 004, 005, 006, 007, 008, 009, 010, 011, 012, 013

---

## PR Grouping Strategy

| PR | Tasks | Description | Dep |
|----|-------|-------------|-----|
| **PR 1** | TASK-001 through TASK-010 | Config + adapter auth + all unit tests | None |
| **PR 2** | TASK-011 through TASK-014 | Docker Compose + model + bootstrap + integration tests | PR 1 |
| **PR 3** | TASK-015 through TASK-017 | OIDC support (Keycloak + tests) | PR 2 |
| **PR 4** | TASK-018 through TASK-021 | Production hardening + validation | PR 1 |

---

## File Change Summary

### Modified (6 files)

| File | Tasks | Lines Changed (est.) |
|------|-------|---------------------|
| `src/siopv/infrastructure/config/settings.py` | 001, 018 | +20 |
| `src/siopv/adapters/authorization/openfga_adapter.py` | 004, 005, 006 | +35 |
| `src/siopv/infrastructure/di/authorization.py` | 007 | +2 |
| `tests/unit/infrastructure/test_settings.py` | 003, 019 | +80 |
| `tests/unit/adapters/authorization/test_openfga_adapter.py` | 008, 009, 017 | +60 |
| `.env.example` | 002 | +0 (already updated) |

### Created (4 files)

| File | Task | Lines (est.) |
|------|------|-------------|
| `docker-compose.yml` | 011, 015, 016, 020 | ~80 |
| `openfga/model.fga` | 012 | ~35 |
| `scripts/setup-openfga.sh` | 013 | ~60 |
| `tests/integration/test_openfga_real_server.py` | 014 | ~50 |

### Not Changed (confirmed safe)

| File | Reason |
|------|--------|
| `src/siopv/application/ports/authorization.py` | Port interfaces unchanged |
| `src/siopv/application/use_cases/authorization.py` | Use cases use ports, no changes |
| `src/siopv/domain/authorization/*` | Domain layer untouched |
| `tests/integration/test_authorization_integration.py` | Existing integration tests use mocks |
