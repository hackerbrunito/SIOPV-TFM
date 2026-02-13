# EXECUTION PLAN: OpenFGA Authentication Integration for SIOPV

**Date:** 2026-02-11 | **Project:** `~/siopv/` | **Scope:** OpenFGA authentication ONLY

---

## Quick Start

1. This plan adds authentication (pre-shared key + OIDC) to SIOPV's existing OpenFGA adapter
2. Work ONLY in `~/siopv/` — only OpenFGA scope, no other functionality touched
3. 5 phases, 21 tasks, 4 PRs — each phase independently deployable
4. `.env.example` already has all auth env vars (verified). The gap is `settings.py` lacks matching fields
5. Critical path: TASK-001 -> TASK-004 -> TASK-005 -> TASK-006 -> TASK-010 -> TASK-011 -> TASK-013

---

## File Changes Map

### Modified (6 files)

| File | Tasks | What Changes |
|------|-------|-------------|
| `src/siopv/infrastructure/config/settings.py` | 001, 018 | +7 fields, +1 import, +1 validator |
| `src/siopv/adapters/authorization/openfga_adapter.py` | 004, 005, 006 | +1 import, +7 `__init__` lines, replace `initialize()` config block |
| `src/siopv/infrastructure/di/authorization.py` | 007 | +2 params in logging call |
| `tests/unit/infrastructure/test_settings.py` | 003, 019 | +3 test functions (~45 lines) |
| `tests/unit/adapters/authorization/test_openfga_adapter.py` | 008, 009 | Update fixture, +1 test class (8 tests) |
| `tests/unit/infrastructure/di/test_authorization_di.py` | 008 | Update fixture + inline settings |

### Created (4 files)

| File | Task | Purpose |
|------|------|---------|
| `docker-compose.yml` | 011 | Postgres + OpenFGA local dev |
| `openfga/model.fga` | 012 | Authorization model definition |
| `scripts/setup-openfga.sh` | 013 | Bootstrap script (store + model) |
| `tests/integration/test_openfga_real_server.py` | 014 | Real server integration tests |

### NOT Changed (confirmed safe)

- `src/siopv/application/ports/authorization.py` — Port interfaces unchanged
- `src/siopv/application/use_cases/authorization.py` — Uses ports, unaffected
- `src/siopv/domain/authorization/*` — Domain layer untouched
- `.env.example` — Already has all needed vars (no changes needed)

---

## Phase 1: Configuration Foundation (PR 1)

### TASK-001: Add 7 new settings fields to Settings class

**File:** `src/siopv/infrastructure/config/settings.py` | **Dep:** none | **CRITICAL PATH**

REPLACE lines 64-66:

```python
    # === OpenFGA ===
    openfga_api_url: str | None = None
    openfga_store_id: str | None = None
```

WITH:

```python
    # === OpenFGA ===
    openfga_api_url: str | None = None
    openfga_store_id: str | None = None
    openfga_api_token: SecretStr | None = None
    openfga_authorization_model_id: str | None = None
    # === OpenFGA OIDC (client_credentials) ===
    openfga_auth_method: Literal["none", "api_token", "client_credentials"] = "none"
    openfga_client_id: str | None = None
    openfga_client_secret: SecretStr | None = None
    openfga_api_audience: str | None = None
    openfga_api_token_issuer: str | None = None
```

`SecretStr` (line 10) and `Literal` (line 8) already imported. All defaults = backward compatible.

**Verify:** `pytest tests/unit/infrastructure/test_settings.py -v`

---

### TASK-002: Verify .env.example (ALREADY DONE — skip)

`.env.example` already has all OpenFGA auth vars at lines 33-51. No action needed.

---

### TASK-003: Add 3 new settings tests

**File:** `tests/unit/infrastructure/test_settings.py` | **Dep:** TASK-001

APPEND after existing OpenFGA tests (~line 396):

```python


# === OpenFGA Authentication Tests ===


def test_settings_openfga_auth_defaults():
    """Test OpenFGA auth fields have correct defaults."""
    with patch.dict(os.environ, {"SIOPV_ANTHROPIC_API_KEY": "test-key"}, clear=True):
        settings = Settings()

    assert settings.openfga_api_token is None
    assert settings.openfga_authorization_model_id is None
    assert settings.openfga_auth_method == "none"
    assert settings.openfga_client_id is None
    assert settings.openfga_client_secret is None
    assert settings.openfga_api_audience is None
    assert settings.openfga_api_token_issuer is None


def test_settings_openfga_api_token_from_env():
    """Test OpenFGA API token loads from env as SecretStr."""
    env_vars = {
        "SIOPV_ANTHROPIC_API_KEY": "test-key",
        "SIOPV_OPENFGA_API_TOKEN": "my-secret-token",
        "SIOPV_OPENFGA_AUTH_METHOD": "api_token",
    }
    with patch.dict(os.environ, env_vars, clear=True):
        settings = Settings()

    assert settings.openfga_api_token is not None
    assert settings.openfga_api_token.get_secret_value() == "my-secret-token"
    assert settings.openfga_auth_method == "api_token"


def test_settings_openfga_oidc_from_env():
    """Test OpenFGA OIDC settings load from env."""
    env_vars = {
        "SIOPV_ANTHROPIC_API_KEY": "test-key",
        "SIOPV_OPENFGA_AUTH_METHOD": "client_credentials",
        "SIOPV_OPENFGA_CLIENT_ID": "my-client-id",
        "SIOPV_OPENFGA_CLIENT_SECRET": "my-client-secret",
        "SIOPV_OPENFGA_API_AUDIENCE": "openfga-audience",
        "SIOPV_OPENFGA_API_TOKEN_ISSUER": "https://idp.example.com/",
    }
    with patch.dict(os.environ, env_vars, clear=True):
        settings = Settings()

    assert settings.openfga_auth_method == "client_credentials"
    assert settings.openfga_client_id == "my-client-id"
    assert settings.openfga_client_secret.get_secret_value() == "my-client-secret"
    assert settings.openfga_api_audience == "openfga-audience"
    assert settings.openfga_api_token_issuer == "https://idp.example.com/"
```

**Verify:** `pytest tests/unit/infrastructure/test_settings.py -v`

---

## Phase 2: Adapter Authentication Support (PR 1)

### TASK-004: Store new auth settings in adapter `__init__`

**File:** `src/siopv/adapters/authorization/openfga_adapter.py` | **Dep:** TASK-001 | **CRITICAL PATH**

REPLACE lines 113-114:

```python
        self._api_url = settings.openfga_api_url
        self._store_id = settings.openfga_store_id
```

WITH:

```python
        self._api_url = settings.openfga_api_url
        self._store_id = settings.openfga_store_id
        self._authorization_model_id = getattr(settings, "openfga_authorization_model_id", None)
        self._auth_method = getattr(settings, "openfga_auth_method", "none")
        self._api_token = getattr(settings, "openfga_api_token", None)
        self._client_id = getattr(settings, "openfga_client_id", None)
        self._client_secret = getattr(settings, "openfga_client_secret", None)
        self._api_audience = getattr(settings, "openfga_api_audience", None)
        self._api_token_issuer = getattr(settings, "openfga_api_token_issuer", None)
```

Also update `__init__` logging (lines 133-137) to add `auth_method` and `model_id`:

```python
        logger.info(
            "openfga_adapter_initialized",
            api_url=self._api_url,
            store_id=self._store_id,
            auth_method=self._auth_method,
            model_id=self._authorization_model_id,
        )
```

---

### TASK-005: Add credentials import

**File:** `src/siopv/adapters/authorization/openfga_adapter.py` | **Dep:** TASK-004 | **CRITICAL PATH**

ADD after line 32 (after `from openfga_sdk.exceptions import FgaValidationException`):

```python
from openfga_sdk.credentials import Credentials, CredentialConfiguration
```

---

### TASK-006: Update adapter `initialize()` with credential support

**File:** `src/siopv/adapters/authorization/openfga_adapter.py` | **Dep:** TASK-004, TASK-005 | **CRITICAL PATH**

REPLACE lines 159-164:

```python
        configuration = ClientConfiguration(
            api_url=self._api_url,
            store_id=self._store_id,
        )

        self._owned_client = OpenFgaClient(configuration)
```

WITH:

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
        elif (
            self._auth_method == "client_credentials"
            and self._client_id
            and self._client_secret
        ):
            config_kwargs["credentials"] = Credentials(
                method="client_credentials",
                configuration=CredentialConfiguration(
                    client_id=self._client_id,
                    client_secret=self._client_secret.get_secret_value(),
                    api_audience=self._api_audience or "",
                    api_issuer=self._api_token_issuer or "",
                ),
            )

        configuration = ClientConfiguration(**config_kwargs)

        self._owned_client = OpenFgaClient(configuration)
```

**SDK NOTE:** The parameter is `api_issuer` (NOT `api_token_issuer`). The SDK appends `/oauth/token` internally.

Also update `initialize()` logging (~lines 167-171) to add `auth_method`:

```python
        logger.info(
            "openfga_client_connected",
            api_url=self._api_url,
            store_id=self._store_id,
            auth_method=self._auth_method,
        )
```

---

### TASK-007: Update DI container logging

**File:** `src/siopv/infrastructure/di/authorization.py` | **Dep:** TASK-001

REPLACE lines 82-86:

```python
    logger.debug(
        "creating_authorization_adapter",
        api_url=settings.openfga_api_url,
        store_id=settings.openfga_store_id,
    )
```

WITH:

```python
    logger.debug(
        "creating_authorization_adapter",
        api_url=settings.openfga_api_url,
        store_id=settings.openfga_store_id,
        auth_method=getattr(settings, "openfga_auth_method", "none"),
        model_id=getattr(settings, "openfga_authorization_model_id", None),
    )
```

---

### TASK-008: Update ALL mock_settings fixtures

**Files:** `tests/unit/adapters/authorization/test_openfga_adapter.py` (lines 36-43), `tests/unit/infrastructure/di/test_authorization_di.py` (lines 33-41) | **Dep:** TASK-004 | **CRITICAL PATH**

Add these 7 lines to EVERY `mock_settings` fixture (after `openfga_store_id`, before `circuit_breaker_*`):

```python
    settings.openfga_api_token = None
    settings.openfga_authorization_model_id = None
    settings.openfga_auth_method = "none"
    settings.openfga_client_id = None
    settings.openfga_client_secret = None
    settings.openfga_api_audience = None
    settings.openfga_api_token_issuer = None
```

Also update inline `MagicMock()` settings in `test_authorization_di.py` `test_different_settings_*` methods.

**Verify:** `pytest tests/unit/adapters/authorization/test_openfga_adapter.py tests/unit/infrastructure/di/test_authorization_di.py -v`

---

### TASK-009: Add adapter authentication unit tests

**File:** `tests/unit/adapters/authorization/test_openfga_adapter.py` | **Dep:** TASK-008 | **CRITICAL PATH**

ADD new test class after `TestOpenFGAAdapterInitialization`:

```python
class TestOpenFGAAdapterAuthentication:
    """Tests for adapter authentication configuration."""

    def test_init_stores_auth_method_none(self, mock_settings: MagicMock) -> None:
        adapter = OpenFGAAdapter(mock_settings)
        assert adapter._auth_method == "none"
        assert adapter._api_token is None

    def test_init_stores_api_token_settings(self, mock_settings: MagicMock) -> None:
        mock_settings.openfga_auth_method = "api_token"
        mock_settings.openfga_api_token = MagicMock()
        mock_settings.openfga_api_token.get_secret_value.return_value = "test-token"
        adapter = OpenFGAAdapter(mock_settings)
        assert adapter._auth_method == "api_token"
        assert adapter._api_token is not None

    def test_init_stores_client_credentials_settings(self, mock_settings: MagicMock) -> None:
        mock_settings.openfga_auth_method = "client_credentials"
        mock_settings.openfga_client_id = "my-client-id"
        mock_settings.openfga_client_secret = MagicMock()
        mock_settings.openfga_client_secret.get_secret_value.return_value = "my-secret"
        mock_settings.openfga_api_audience = "openfga-audience"
        mock_settings.openfga_api_token_issuer = "https://idp.example.com/"
        adapter = OpenFGAAdapter(mock_settings)
        assert adapter._auth_method == "client_credentials"
        assert adapter._client_id == "my-client-id"

    def test_init_stores_authorization_model_id(self, mock_settings: MagicMock) -> None:
        mock_settings.openfga_authorization_model_id = "01HXY..."
        adapter = OpenFGAAdapter(mock_settings)
        assert adapter._authorization_model_id == "01HXY..."

    @pytest.mark.asyncio
    async def test_initialize_with_api_token_creates_credentials(self, mock_settings: MagicMock) -> None:
        mock_settings.openfga_auth_method = "api_token"
        mock_settings.openfga_api_token = MagicMock()
        mock_settings.openfga_api_token.get_secret_value.return_value = "test-token"
        adapter = OpenFGAAdapter(mock_settings)
        with patch("siopv.adapters.authorization.openfga_adapter.ClientConfiguration") as mock_config, \
             patch("siopv.adapters.authorization.openfga_adapter.OpenFgaClient") as mock_client_cls:
            mock_client_cls.return_value = AsyncMock()
            await adapter.initialize()
            assert "credentials" in mock_config.call_args[1]

    @pytest.mark.asyncio
    async def test_initialize_no_auth_no_credentials(self, mock_settings: MagicMock) -> None:
        adapter = OpenFGAAdapter(mock_settings)
        with patch("siopv.adapters.authorization.openfga_adapter.ClientConfiguration") as mock_config, \
             patch("siopv.adapters.authorization.openfga_adapter.OpenFgaClient") as mock_client_cls:
            mock_client_cls.return_value = AsyncMock()
            await adapter.initialize()
            assert "credentials" not in mock_config.call_args[1]
```

---

### TASK-010: Run full unit test suite — Phase 1+2 gate

**Dep:** TASK-003, TASK-006, TASK-007, TASK-009 | **CRITICAL PATH**

```bash
cd ~/siopv
pytest tests/unit/ -v --tb=short
mypy src/siopv/infrastructure/config/settings.py src/siopv/adapters/authorization/openfga_adapter.py --ignore-missing-imports
ruff check src/siopv/infrastructure/config/settings.py src/siopv/adapters/authorization/openfga_adapter.py
```

**Expected:** All tests pass, zero mypy/ruff errors, zero regressions.

---

## Phase 3: Infrastructure Setup (PR 2)

### TASK-011: Create docker-compose.yml

**File:** `docker-compose.yml` (NEW — project root) | **Dep:** TASK-010 | **CRITICAL PATH**

```yaml
# SIOPV Local Development -- OpenFGA + Postgres
# Usage: docker compose up -d
# Playground: http://localhost:3000

services:
  openfga-migrate:
    image: openfga/openfga:latest
    command: migrate
    environment:
      - OPENFGA_DATASTORE_ENGINE=postgres
      - OPENFGA_DATASTORE_URI=postgres://openfga:openfga@openfga-postgres:5432/openfga?sslmode=disable
    depends_on:
      openfga-postgres:
        condition: service_healthy

  openfga:
    image: openfga/openfga:latest
    command: run
    environment:
      - OPENFGA_DATASTORE_ENGINE=postgres
      - OPENFGA_DATASTORE_URI=postgres://openfga:openfga@openfga-postgres:5432/openfga?sslmode=disable
      - OPENFGA_AUTHN_METHOD=preshared
      - OPENFGA_AUTHN_PRESHARED_KEYS=dev-key-siopv-local-1
      - OPENFGA_PLAYGROUND_ENABLED=true
      - OPENFGA_LOG_FORMAT=json
    ports:
      - "8080:8080"
      - "8081:8081"
      - "3000:3000"
    depends_on:
      openfga-migrate:
        condition: service_completed_successfully
    healthcheck:
      test: ["CMD", "wget", "--no-verbose", "--tries=1", "--spider", "http://localhost:8080/healthz"]
      interval: 5s
      timeout: 5s
      retries: 5

  openfga-postgres:
    image: postgres:16-alpine
    environment:
      - POSTGRES_USER=openfga
      - POSTGRES_PASSWORD=openfga
      - POSTGRES_DB=openfga
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U openfga"]
      interval: 5s
      timeout: 5s
      retries: 5
    volumes:
      - openfga_data:/var/lib/postgresql/data

volumes:
  openfga_data:
```

**Verify:** `docker compose config --quiet && echo "OK"`

---

### TASK-012: Create authorization model file

**File:** `openfga/model.fga` (NEW) | **Dep:** none

```fga
model
  schema 1.1

type user

type organization
  relations
    define admin: [user]
    define member: [user] or admin

type project
  relations
    define organization: [organization]
    define owner: [user] or admin from organization
    define viewer: [user] or owner or member from organization
    define analyst: [user] or owner
    define auditor: [user] or admin from organization

type vulnerability
  relations
    define project: [project]
    define owner: [user] or owner from project
    define viewer: [user] or viewer from project
    define analyst: [user] or analyst from project

type report
  relations
    define project: [project]
    define owner: [user] or owner from project
    define viewer: [user] or viewer from project or auditor from project
    define auditor: [user] or auditor from project
```

Based on `src/siopv/domain/authorization/value_objects.py` enums: `ResourceType` + `Relation`.

---

### TASK-013: Create bootstrap script

**File:** `scripts/setup-openfga.sh` (NEW, `chmod +x`) | **Dep:** TASK-011, TASK-012 | **CRITICAL PATH**

See full script in code-snippets doc (Snippet 3.3). Key flow:
1. Waits for OpenFGA healthcheck (30s max)
2. Creates store "siopv" via REST API with `Authorization: Bearer dev-key-siopv-local-1`
3. Writes authorization model (JSON format) to the store
4. Outputs store_id, model_id, and copy-pasteable `.env` lines

**Verify:**
```bash
docker compose up -d && sleep 30 && chmod +x scripts/setup-openfga.sh && ./scripts/setup-openfga.sh
```

---

### TASK-014: Create real-server integration tests

**File:** `tests/integration/test_openfga_real_server.py` (NEW) | **Dep:** TASK-006, TASK-013

See full code in code-snippets doc (Snippet 3.4). Key features:
- `pytestmark = pytest.mark.skipif(not OPENFGA_API_URL ...)` — auto-skip when no server
- `@pytest.mark.real_openfga` marker
- Tests: `test_health_check`, `test_get_model_id`, `test_write_and_read_tuple`

**Verify (without server):** `pytest tests/integration/test_openfga_real_server.py -v` (should skip)
**Verify (with server):**
```bash
export SIOPV_OPENFGA_API_URL=http://localhost:8080
export SIOPV_OPENFGA_STORE_ID=<from-setup-script>
export SIOPV_OPENFGA_API_TOKEN=dev-key-siopv-local-1
export SIOPV_OPENFGA_AUTH_METHOD=api_token
pytest tests/integration/test_openfga_real_server.py -v -m real_openfga
```

---

## Phase 4: OIDC Migration (PR 3)

### TASK-015: Add Keycloak to Docker Compose

**File:** `docker-compose.yml` (MODIFY) | **Dep:** TASK-011

Append service:
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

---

### TASK-016: Add OIDC config comments to OpenFGA service

**File:** `docker-compose.yml` (MODIFY) | **Dep:** TASK-015

Add commented OIDC env vars to openfga service:
```yaml
      # Uncomment for OIDC mode (requires Keycloak setup):
      # - OPENFGA_AUTHN_METHOD=oidc
      # - OPENFGA_AUTHN_OIDC_ISSUER=http://keycloak:8080/realms/siopv
      # - OPENFGA_AUTHN_OIDC_AUDIENCE=openfga-api
```

---

### TASK-017: Add token refresh validation test

**File:** `tests/unit/adapters/authorization/test_openfga_adapter.py` | **Dep:** TASK-009

Add test verifying SDK config is passed correctly for OIDC `client_credentials`.

---

## Phase 5: Production Hardening (PR 4)

### TASK-018: Add Pydantic model_validator for auth config consistency

**File:** `src/siopv/infrastructure/config/settings.py` | **Dep:** TASK-001

Update import (line 10): `from pydantic import Field, SecretStr, model_validator`

Add validator inside Settings class (after OpenFGA OIDC fields):

```python
    @model_validator(mode="after")
    def _validate_openfga_auth(self) -> Settings:
        """Validate OpenFGA auth configuration consistency."""
        if self.openfga_auth_method == "api_token" and not self.openfga_api_token:
            import warnings
            warnings.warn(
                "SIOPV_OPENFGA_AUTH_METHOD=api_token but SIOPV_OPENFGA_API_TOKEN is not set",
                stacklevel=2,
            )
        if self.openfga_auth_method == "client_credentials":
            missing = []
            if not self.openfga_client_id:
                missing.append("SIOPV_OPENFGA_CLIENT_ID")
            if not self.openfga_client_secret:
                missing.append("SIOPV_OPENFGA_CLIENT_SECRET")
            if not self.openfga_api_token_issuer:
                missing.append("SIOPV_OPENFGA_API_TOKEN_ISSUER")
            if missing:
                import warnings
                warnings.warn(
                    f"SIOPV_OPENFGA_AUTH_METHOD=client_credentials but missing: {', '.join(missing)}",
                    stacklevel=2,
                )
        return self
```

---

### TASK-019: Add settings validation tests

**File:** `tests/unit/infrastructure/test_settings.py` | **Dep:** TASK-018

Test `warnings.warn()` fires for misconfigured api_token and client_credentials.

---

### TASK-020: Add TLS/production config comments to Docker Compose

**File:** `docker-compose.yml` | **Dep:** TASK-011

Add commented production hardening section.

---

### TASK-021: Final full validation gate

**Dep:** TASK-010, TASK-017, TASK-019

```bash
cd ~/siopv
pytest tests/unit/ -v --tb=short
mypy src/siopv/infrastructure/config/settings.py src/siopv/adapters/authorization/openfga_adapter.py src/siopv/infrastructure/di/authorization.py --ignore-missing-imports
ruff check src/siopv/infrastructure/config/settings.py src/siopv/adapters/authorization/openfga_adapter.py src/siopv/infrastructure/di/authorization.py
```

---

## Dependency Graph

```
TASK-001 (Settings fields) --+--> TASK-003 (Settings tests) --------+
                             +--> TASK-004 (Adapter __init__) --+    |
                             +--> TASK-007 (DI logging)         |    |
                             +--> TASK-018 (Validator)          |    |
                                                                v    |
                             TASK-005 (Import) --> TASK-006 (initialize)
                                                                |    |
                             TASK-008 (Fixtures) ---------> TASK-009 (Auth tests)
                                                                |    |
                     TASK-003 + TASK-006 + TASK-007 + TASK-009 --> TASK-010 (Gate)
                                                                     |
                     TASK-010 --> TASK-011 (Docker) --> TASK-012 (model.fga) --> TASK-013 (bootstrap)
                     TASK-013 + TASK-006 --> TASK-014 (integration tests)
                     TASK-011 --> TASK-015 (Keycloak) --> TASK-016 (OIDC config)
                     TASK-009 --> TASK-017 (Token refresh)
                     TASK-018 --> TASK-019 (Validator tests)
                     TASK-010 + TASK-017 + TASK-019 --> TASK-021 (Final gate)
```

---

## PR Strategy

| PR | Tasks | Description |
|----|-------|-------------|
| **PR 1** | TASK-001 to TASK-010 | Config + adapter auth + all unit tests |
| **PR 2** | TASK-011 to TASK-014 | Docker Compose + model + bootstrap + integration tests |
| **PR 3** | TASK-015 to TASK-017 | OIDC support (Keycloak + tests) |
| **PR 4** | TASK-018 to TASK-021 | Production hardening + validation |

---

## Verification Commands (Copy-Paste Ready)

### After Phase 1+2 (PR 1):
```bash
cd ~/siopv
pytest tests/unit/infrastructure/test_settings.py -v
pytest tests/unit/adapters/authorization/test_openfga_adapter.py -v
pytest tests/unit/ -v --tb=short
mypy src/siopv/infrastructure/config/settings.py src/siopv/adapters/authorization/openfga_adapter.py --ignore-missing-imports
ruff check src/siopv/infrastructure/config/settings.py src/siopv/adapters/authorization/openfga_adapter.py
```

### After Phase 3 (PR 2):
```bash
cd ~/siopv
docker compose config --quiet && echo "YAML OK"
bash -n scripts/setup-openfga.sh && echo "Script syntax OK"
pytest tests/integration/test_openfga_real_server.py -v  # skips without server
# With server: docker compose up -d && sleep 30 && ./scripts/setup-openfga.sh
```

### Quick field count check:
```bash
python3 -c "
from siopv.infrastructure.config.settings import Settings
import os; os.environ['SIOPV_ANTHROPIC_API_KEY']='test'
s = Settings()
fields = [f for f in s.model_fields if 'openfga' in f]
print(f'OpenFGA fields: {len(fields)} (expected: 9)')
"
```

---

## Rollback Procedures

### Phase 1+2 (config + adapter): `git revert <commit>` — all changes backward-compatible
### Phase 3 (infrastructure): `docker compose down -v && rm docker-compose.yml openfga/ scripts/setup-openfga.sh`
### Phase 4 (OIDC -> pre-shared key): Change `.env` to `SIOPV_OPENFGA_AUTH_METHOD=api_token` + restart
### Emergency (disable all auth): Set `SIOPV_OPENFGA_AUTH_METHOD=none` + `OPENFGA_AUTHN_METHOD=none` + restart

---

## Critical Notes

1. **SDK parameter mapping:** `settings.openfga_api_token_issuer` maps to `CredentialConfiguration(api_issuer=...)` (NOT `api_token_issuer`)
2. **`.env.example` is already done** — the gap is only in `settings.py` Python fields
3. **`getattr()` with defaults** in adapter ensures backward compatibility with legacy settings objects
4. **Keycloak recommended** as OIDC provider (open-source, self-hosted, Docker-native)
5. **All new fields default to `None`/`"none"`** — zero breaking changes to existing 87+ tests after fixture updates

---

## References

- Detailed code snippets: `2026-02-11-ready-to-apply-code-snippets-*.md` (in this directory)
- Structured task list: `2026-02-11-structured-task-list-*.md` (in this directory)
- Verification steps: `2026-02-11-verification-steps-*.md` (in this directory)
- Discrete actions: `2026-02-11-openfga-oidc-authentication-discrete-executable-actions-*.md` (in this directory)
- Original 1078-line plan: `../openfga-zerotrust-oidc-authentication-research-2026-02-11/2026-02-11-IMPLEMENTATION-PLAN-*.md`
