# Ready-to-Apply Code Snippets: OpenFGA Authentication Integration

**Date:** 2026-02-11
**Author:** code-preparer (OpenFGA Execution Plan Team)
**Scope:** OpenFGA authentication ONLY — no other SIOPV functionality touched
**Status:** Copy-paste ready with exact file paths, line numbers, and diffs

---

## Table of Contents

1. [Phase 1: Configuration Foundation](#phase-1-configuration-foundation)
   - [Snippet 1.1: settings.py — Add 7 new OpenFGA fields](#snippet-11-settingspy)
   - [Snippet 1.2: .env.example — Already has auth vars (verify only)](#snippet-12-envexample)
   - [Snippet 1.3: test_settings.py — Add 3 new test functions](#snippet-13-test_settingspy)
2. [Phase 2: Adapter Authentication Support](#phase-2-adapter-authentication-support)
   - [Snippet 2.1: openfga_adapter.py — New import](#snippet-21-new-import)
   - [Snippet 2.2: openfga_adapter.py — Update `__init__`](#snippet-22-update-init)
   - [Snippet 2.3: openfga_adapter.py — Update `initialize()`](#snippet-23-update-initialize)
   - [Snippet 2.4: authorization.py (DI) — Update logging](#snippet-24-di-logging)
   - [Snippet 2.5: test_openfga_adapter.py — Update mock_settings fixture](#snippet-25-update-mock-fixture)
   - [Snippet 2.6: test_openfga_adapter.py — New auth test class](#snippet-26-new-auth-tests)
   - [Snippet 2.7: test_authorization_di.py — Update mock_settings fixtures](#snippet-27-update-di-test-fixtures)
3. [Phase 3: Infrastructure Setup](#phase-3-infrastructure-setup)
   - [Snippet 3.1: docker-compose.yml (NEW)](#snippet-31-docker-compose)
   - [Snippet 3.2: openfga/model.fga (NEW)](#snippet-32-modelfga)
   - [Snippet 3.3: scripts/setup-openfga.sh (NEW)](#snippet-33-bootstrap-script)
   - [Snippet 3.4: tests/integration/test_openfga_real_server.py (NEW)](#snippet-34-integration-tests)
4. [Phase 5: Production Hardening](#phase-5-production-hardening)
   - [Snippet 5.1: settings.py — Add model_validator](#snippet-51-model-validator)

---

## Phase 1: Configuration Foundation

### Snippet 1.1: settings.py

**File:** `src/siopv/infrastructure/config/settings.py`
**Action:** REPLACE lines 64–66 (the `# === OpenFGA ===` section)

**CURRENT CODE (lines 64–66):**
```python
    # === OpenFGA ===
    openfga_api_url: str | None = None
    openfga_store_id: str | None = None
```

**REPLACE WITH:**
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

**Why this is safe:**
- `SecretStr` already imported at line 10
- `Literal` already imported at line 8
- All new fields have defaults (`None` or `"none"`) — zero breaking changes
- No existing tests break

---

### Snippet 1.2: .env.example

**File:** `.env.example`
**Action:** VERIFY ONLY — the file already contains OpenFGA auth variables (lines 33–51)

The current `.env.example` already has all needed variables:
```bash
# === OpenFGA (Optional, for authorization) ===
SIOPV_OPENFGA_API_URL=
SIOPV_OPENFGA_STORE_ID=

# --- Model Version Pinning (recommended) ---
SIOPV_OPENFGA_AUTHORIZATION_MODEL_ID=

# --- Authentication Method ---
# Options: "none" (default), "api_token" (pre-shared key), "client_credentials" (OIDC)
SIOPV_OPENFGA_AUTH_METHOD=none

# --- Pre-Shared Key Auth (Phase 1) ---
SIOPV_OPENFGA_API_TOKEN=

# --- OIDC Auth via Keycloak (Phase 2) ---
SIOPV_OPENFGA_CLIENT_ID=
SIOPV_OPENFGA_CLIENT_SECRET=
SIOPV_OPENFGA_API_AUDIENCE=
SIOPV_OPENFGA_API_TOKEN_ISSUER=
```

**No changes needed.** The `.env.example` already has all OpenFGA auth env vars but the code (`settings.py`) does not yet have the matching fields. Snippet 1.1 fixes that mismatch.

---

### Snippet 1.3: test_settings.py

**File:** `tests/unit/infrastructure/test_settings.py`
**Action:** APPEND after line 396 (after `test_settings_openfga_configured`)

```python


# === OpenFGA Authentication Tests ===


def test_settings_openfga_auth_defaults():
    """Test OpenFGA auth fields have correct defaults."""
    # Arrange & Act
    with patch.dict(os.environ, {"SIOPV_ANTHROPIC_API_KEY": "test-key"}, clear=True):
        settings = Settings()

    # Assert
    assert settings.openfga_api_token is None
    assert settings.openfga_authorization_model_id is None
    assert settings.openfga_auth_method == "none"
    assert settings.openfga_client_id is None
    assert settings.openfga_client_secret is None
    assert settings.openfga_api_audience is None
    assert settings.openfga_api_token_issuer is None


def test_settings_openfga_api_token_from_env():
    """Test OpenFGA API token loads from env as SecretStr."""
    # Arrange
    env_vars = {
        "SIOPV_ANTHROPIC_API_KEY": "test-key",
        "SIOPV_OPENFGA_API_TOKEN": "my-secret-token",
        "SIOPV_OPENFGA_AUTH_METHOD": "api_token",
    }

    # Act
    with patch.dict(os.environ, env_vars, clear=True):
        settings = Settings()

    # Assert
    assert settings.openfga_api_token is not None
    assert settings.openfga_api_token.get_secret_value() == "my-secret-token"
    assert settings.openfga_auth_method == "api_token"


def test_settings_openfga_oidc_from_env():
    """Test OpenFGA OIDC settings load from env."""
    # Arrange
    env_vars = {
        "SIOPV_ANTHROPIC_API_KEY": "test-key",
        "SIOPV_OPENFGA_AUTH_METHOD": "client_credentials",
        "SIOPV_OPENFGA_CLIENT_ID": "my-client-id",
        "SIOPV_OPENFGA_CLIENT_SECRET": "my-client-secret",
        "SIOPV_OPENFGA_API_AUDIENCE": "openfga-audience",
        "SIOPV_OPENFGA_API_TOKEN_ISSUER": "https://idp.example.com/",
    }

    # Act
    with patch.dict(os.environ, env_vars, clear=True):
        settings = Settings()

    # Assert
    assert settings.openfga_auth_method == "client_credentials"
    assert settings.openfga_client_id == "my-client-id"
    assert settings.openfga_client_secret.get_secret_value() == "my-client-secret"
    assert settings.openfga_api_audience == "openfga-audience"
    assert settings.openfga_api_token_issuer == "https://idp.example.com/"
```

---

## Phase 2: Adapter Authentication Support

### Snippet 2.1: New Import

**File:** `src/siopv/adapters/authorization/openfga_adapter.py`
**Action:** ADD import after line 32 (after `from openfga_sdk.exceptions import FgaValidationException`)

**CURRENT (line 32):**
```python
from openfga_sdk.exceptions import FgaValidationException
```

**ADD AFTER:**
```python
from openfga_sdk.credentials import Credentials, CredentialConfiguration
```

---

### Snippet 2.2: Update `__init__`

**File:** `src/siopv/adapters/authorization/openfga_adapter.py`
**Action:** REPLACE lines 113–114 (inside `__init__`, the settings extraction)

**CURRENT (lines 113–114):**
```python
        self._api_url = settings.openfga_api_url
        self._store_id = settings.openfga_store_id
```

**REPLACE WITH:**
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

**Why `getattr` with defaults:** Ensures backward compatibility with any existing code that creates `OpenFGAAdapter` with a settings object that doesn't yet have these fields (e.g., in-progress test suites or mock objects). Once all mock fixtures are updated, these can be simplified to direct attribute access.

**Update `__init__` logging (lines 133–137):**

**CURRENT:**
```python
        logger.info(
            "openfga_adapter_initialized",
            api_url=self._api_url,
            store_id=self._store_id,
        )
```

**REPLACE WITH:**
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

### Snippet 2.3: Update `initialize()`

**File:** `src/siopv/adapters/authorization/openfga_adapter.py`
**Action:** REPLACE lines 159–164 (the `ClientConfiguration` creation block inside `initialize()`)

**CURRENT (lines 159–164):**
```python
        configuration = ClientConfiguration(
            api_url=self._api_url,
            store_id=self._store_id,
        )

        self._owned_client = OpenFgaClient(configuration)
```

**REPLACE WITH:**
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

**IMPORTANT SDK note:** The `CredentialConfiguration` parameter for the OIDC issuer is `api_issuer` (NOT `api_token_issuer`). The SDK internally appends `/oauth/token` to the issuer URL if not already present. See SDK research doc section 3.

**Update `initialize()` logging (lines 167–171):**

**CURRENT:**
```python
        logger.info(
            "openfga_client_connected",
            api_url=self._api_url,
            store_id=self._store_id,
        )
```

**REPLACE WITH:**
```python
        logger.info(
            "openfga_client_connected",
            api_url=self._api_url,
            store_id=self._store_id,
            auth_method=self._auth_method,
        )
```

---

### Snippet 2.4: DI Logging

**File:** `src/siopv/infrastructure/di/authorization.py`
**Action:** REPLACE lines 82–86 (the `logger.debug` call in `create_authorization_adapter`)

**CURRENT (lines 82–86):**
```python
    logger.debug(
        "creating_authorization_adapter",
        api_url=settings.openfga_api_url,
        store_id=settings.openfga_store_id,
    )
```

**REPLACE WITH:**
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

### Snippet 2.5: Update mock_settings Fixture

**File:** `tests/unit/adapters/authorization/test_openfga_adapter.py`
**Action:** REPLACE lines 36–43 (the `mock_settings` fixture)

**CURRENT (lines 36–43):**
```python
@pytest.fixture
def mock_settings() -> MagicMock:
    """Create mock settings for OpenFGA configuration."""
    settings = MagicMock()
    settings.openfga_api_url = "http://localhost:8080"
    settings.openfga_store_id = "test-store-id"
    settings.circuit_breaker_failure_threshold = 5
    settings.circuit_breaker_recovery_timeout = 60
    return settings
```

**REPLACE WITH:**
```python
@pytest.fixture
def mock_settings() -> MagicMock:
    """Create mock settings for OpenFGA configuration."""
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

---

### Snippet 2.6: New Auth Test Class

**File:** `tests/unit/adapters/authorization/test_openfga_adapter.py`
**Action:** ADD after `TestOpenFGAAdapterInitialization` class (after the existing initialization tests, approximately after line 135 — find the end of `TestOpenFGAAdapterInitialization` and add before `TestAuthorizationCheck`)

```python


class TestOpenFGAAdapterAuthentication:
    """Tests for adapter authentication configuration."""

    def test_init_stores_auth_method_none(self, mock_settings: MagicMock) -> None:
        """Test adapter stores auth_method=none by default."""
        adapter = OpenFGAAdapter(mock_settings)

        assert adapter._auth_method == "none"
        assert adapter._api_token is None
        assert adapter._client_id is None

    def test_init_stores_api_token_settings(self, mock_settings: MagicMock) -> None:
        """Test adapter stores pre-shared key settings."""
        mock_settings.openfga_auth_method = "api_token"
        mock_settings.openfga_api_token = MagicMock()
        mock_settings.openfga_api_token.get_secret_value.return_value = "test-token"

        adapter = OpenFGAAdapter(mock_settings)

        assert adapter._auth_method == "api_token"
        assert adapter._api_token is not None

    def test_init_stores_client_credentials_settings(
        self, mock_settings: MagicMock
    ) -> None:
        """Test adapter stores OIDC client_credentials settings."""
        mock_settings.openfga_auth_method = "client_credentials"
        mock_settings.openfga_client_id = "my-client-id"
        mock_settings.openfga_client_secret = MagicMock()
        mock_settings.openfga_client_secret.get_secret_value.return_value = "my-secret"
        mock_settings.openfga_api_audience = "openfga-audience"
        mock_settings.openfga_api_token_issuer = "https://idp.example.com/"

        adapter = OpenFGAAdapter(mock_settings)

        assert adapter._auth_method == "client_credentials"
        assert adapter._client_id == "my-client-id"
        assert adapter._api_audience == "openfga-audience"
        assert adapter._api_token_issuer == "https://idp.example.com/"

    def test_init_stores_authorization_model_id(
        self, mock_settings: MagicMock
    ) -> None:
        """Test adapter stores pinned model ID."""
        mock_settings.openfga_authorization_model_id = "01HXY..."

        adapter = OpenFGAAdapter(mock_settings)

        assert adapter._authorization_model_id == "01HXY..."

    @pytest.mark.asyncio
    async def test_initialize_with_api_token_creates_credentials(
        self, mock_settings: MagicMock
    ) -> None:
        """Test initialize() builds Credentials for api_token method."""
        mock_settings.openfga_auth_method = "api_token"
        mock_settings.openfga_api_token = MagicMock()
        mock_settings.openfga_api_token.get_secret_value.return_value = "test-token"

        adapter = OpenFGAAdapter(mock_settings)

        with patch(
            "siopv.adapters.authorization.openfga_adapter.ClientConfiguration"
        ) as mock_config, patch(
            "siopv.adapters.authorization.openfga_adapter.OpenFgaClient"
        ) as mock_client_cls:
            mock_client = AsyncMock()
            mock_client_cls.return_value = mock_client

            await adapter.initialize()

            # Verify ClientConfiguration was called with credentials
            call_kwargs = mock_config.call_args[1]
            assert "credentials" in call_kwargs

    @pytest.mark.asyncio
    async def test_initialize_with_client_credentials_creates_credentials(
        self, mock_settings: MagicMock
    ) -> None:
        """Test initialize() builds Credentials for client_credentials method."""
        mock_settings.openfga_auth_method = "client_credentials"
        mock_settings.openfga_client_id = "siopv-service"
        mock_settings.openfga_client_secret = MagicMock()
        mock_settings.openfga_client_secret.get_secret_value.return_value = "secret"
        mock_settings.openfga_api_audience = "openfga-api"
        mock_settings.openfga_api_token_issuer = "https://idp.example.com/"

        adapter = OpenFGAAdapter(mock_settings)

        with patch(
            "siopv.adapters.authorization.openfga_adapter.ClientConfiguration"
        ) as mock_config, patch(
            "siopv.adapters.authorization.openfga_adapter.OpenFgaClient"
        ) as mock_client_cls:
            mock_client = AsyncMock()
            mock_client_cls.return_value = mock_client

            await adapter.initialize()

            # Verify ClientConfiguration was called with credentials
            call_kwargs = mock_config.call_args[1]
            assert "credentials" in call_kwargs

    @pytest.mark.asyncio
    async def test_initialize_no_auth_no_credentials(
        self, mock_settings: MagicMock
    ) -> None:
        """Test initialize() creates config without credentials when auth=none."""
        adapter = OpenFGAAdapter(mock_settings)

        with patch(
            "siopv.adapters.authorization.openfga_adapter.ClientConfiguration"
        ) as mock_config, patch(
            "siopv.adapters.authorization.openfga_adapter.OpenFgaClient"
        ) as mock_client_cls:
            mock_client = AsyncMock()
            mock_client_cls.return_value = mock_client

            await adapter.initialize()

            # Verify ClientConfiguration was called WITHOUT credentials
            call_kwargs = mock_config.call_args[1]
            assert "credentials" not in call_kwargs

    @pytest.mark.asyncio
    async def test_initialize_with_model_id(self, mock_settings: MagicMock) -> None:
        """Test initialize() passes authorization_model_id to config."""
        mock_settings.openfga_authorization_model_id = "01HXY..."

        adapter = OpenFGAAdapter(mock_settings)

        with patch(
            "siopv.adapters.authorization.openfga_adapter.ClientConfiguration"
        ) as mock_config, patch(
            "siopv.adapters.authorization.openfga_adapter.OpenFgaClient"
        ) as mock_client_cls:
            mock_client = AsyncMock()
            mock_client_cls.return_value = mock_client

            await adapter.initialize()

            call_kwargs = mock_config.call_args[1]
            assert call_kwargs["authorization_model_id"] == "01HXY..."
```

---

### Snippet 2.7: Update DI Test Fixtures

**File:** `tests/unit/infrastructure/di/test_authorization_di.py`
**Action:** REPLACE lines 33–41 (the `mock_settings` fixture)

**CURRENT (lines 33–41):**
```python
@pytest.fixture
def mock_settings() -> MagicMock:
    """Create mock settings for authorization DI tests."""
    settings = MagicMock()
    settings.openfga_api_url = "http://localhost:8080"
    settings.openfga_store_id = "test-store-id"
    settings.circuit_breaker_failure_threshold = 5
    settings.circuit_breaker_recovery_timeout = 60
    return settings
```

**REPLACE WITH:**
```python
@pytest.fixture
def mock_settings() -> MagicMock:
    """Create mock settings for authorization DI tests."""
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

**Also update inline settings** in `test_different_settings_create_different_instances` methods (lines 144–154, 210–220, 270–280):

For every inline `MagicMock()` settings creation in the DI test file, add the 7 new fields:
```python
        settings1.openfga_api_token = None
        settings1.openfga_authorization_model_id = None
        settings1.openfga_auth_method = "none"
        settings1.openfga_client_id = None
        settings1.openfga_client_secret = None
        settings1.openfga_api_audience = None
        settings1.openfga_api_token_issuer = None
```

(Same for `settings2` in each test.)

---

## Phase 3: Infrastructure Setup

### Snippet 3.1: docker-compose.yml

**File:** `docker-compose.yml` (NEW — project root `/Users/bruno/siopv/docker-compose.yml`)
**Action:** CREATE new file

```yaml
# SIOPV Local Development — OpenFGA + Postgres
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
      - "8080:8080"   # HTTP API
      - "8081:8081"   # gRPC API
      - "3000:3000"   # Playground UI
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

---

### Snippet 3.2: model.fga

**File:** `openfga/model.fga` (NEW — `/Users/bruno/siopv/openfga/model.fga`)
**Action:** CREATE new file

Based on domain value objects at `src/siopv/domain/authorization/value_objects.py`:
- `ResourceType`: project, vulnerability, report, organization
- `Relation`: owner, viewer, analyst, auditor, member, admin

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

---

### Snippet 3.3: Bootstrap Script

**File:** `scripts/setup-openfga.sh` (NEW — `/Users/bruno/siopv/scripts/setup-openfga.sh`)
**Action:** CREATE new file (make executable: `chmod +x scripts/setup-openfga.sh`)

```bash
#!/usr/bin/env bash
# Setup OpenFGA store and model for SIOPV local development.
# Usage: ./scripts/setup-openfga.sh
#
# Prerequisites: docker compose running (docker compose up -d)
# Outputs store_id and model_id for .env configuration.

set -euo pipefail

OPENFGA_API_URL="${OPENFGA_API_URL:-http://localhost:8080}"
OPENFGA_API_TOKEN="${OPENFGA_API_TOKEN:-dev-key-siopv-local-1}"
AUTH_HEADER="Authorization: Bearer ${OPENFGA_API_TOKEN}"

echo "=== SIOPV OpenFGA Setup ==="
echo "API URL: ${OPENFGA_API_URL}"

# Wait for OpenFGA to be healthy
echo "Waiting for OpenFGA..."
for i in $(seq 1 30); do
    if curl -sf "${OPENFGA_API_URL}/healthz" > /dev/null 2>&1; then
        echo "OpenFGA is ready."
        break
    fi
    if [ "$i" -eq 30 ]; then
        echo "ERROR: OpenFGA not ready after 30s"
        exit 1
    fi
    sleep 1
done

# Create store
echo "Creating store..."
STORE_RESPONSE=$(curl -sf -X POST "${OPENFGA_API_URL}/stores" \
    -H "${AUTH_HEADER}" \
    -H "Content-Type: application/json" \
    -d '{"name": "siopv"}')

STORE_ID=$(echo "${STORE_RESPONSE}" | python3 -c "import sys, json; print(json.load(sys.stdin)['id'])")
echo "Store ID: ${STORE_ID}"

# Write authorization model (JSON format matching model.fga)
echo "Writing authorization model..."
MODEL_JSON=$(python3 -c "
import json
model = {
    'schema_version': '1.1',
    'type_definitions': [
        {'type': 'user'},
        {
            'type': 'organization',
            'relations': {
                'admin': {'this': {}},
                'member': {'union': {'child': [{'this': {}}, {'computedUserset': {'relation': 'admin'}}]}}
            },
            'metadata': {
                'relations': {
                    'admin': {'directly_related_user_types': [{'type': 'user'}]},
                    'member': {'directly_related_user_types': [{'type': 'user'}]}
                }
            }
        },
        {
            'type': 'project',
            'relations': {
                'organization': {'this': {}},
                'owner': {'union': {'child': [{'this': {}}, {'tupleToUserset': {'tupleset': {'relation': 'organization'}, 'computedUserset': {'relation': 'admin'}}}]}},
                'viewer': {'union': {'child': [{'this': {}}, {'computedUserset': {'relation': 'owner'}}, {'tupleToUserset': {'tupleset': {'relation': 'organization'}, 'computedUserset': {'relation': 'member'}}}]}},
                'analyst': {'union': {'child': [{'this': {}}, {'computedUserset': {'relation': 'owner'}}]}},
                'auditor': {'union': {'child': [{'this': {}}, {'tupleToUserset': {'tupleset': {'relation': 'organization'}, 'computedUserset': {'relation': 'admin'}}}]}}
            },
            'metadata': {
                'relations': {
                    'organization': {'directly_related_user_types': [{'type': 'organization'}]},
                    'owner': {'directly_related_user_types': [{'type': 'user'}]},
                    'viewer': {'directly_related_user_types': [{'type': 'user'}]},
                    'analyst': {'directly_related_user_types': [{'type': 'user'}]},
                    'auditor': {'directly_related_user_types': [{'type': 'user'}]}
                }
            }
        },
        {
            'type': 'vulnerability',
            'relations': {
                'project': {'this': {}},
                'owner': {'union': {'child': [{'this': {}}, {'tupleToUserset': {'tupleset': {'relation': 'project'}, 'computedUserset': {'relation': 'owner'}}}]}},
                'viewer': {'union': {'child': [{'this': {}}, {'tupleToUserset': {'tupleset': {'relation': 'project'}, 'computedUserset': {'relation': 'viewer'}}}]}},
                'analyst': {'union': {'child': [{'this': {}}, {'tupleToUserset': {'tupleset': {'relation': 'project'}, 'computedUserset': {'relation': 'analyst'}}}]}}
            },
            'metadata': {
                'relations': {
                    'project': {'directly_related_user_types': [{'type': 'project'}]},
                    'owner': {'directly_related_user_types': [{'type': 'user'}]},
                    'viewer': {'directly_related_user_types': [{'type': 'user'}]},
                    'analyst': {'directly_related_user_types': [{'type': 'user'}]}
                }
            }
        },
        {
            'type': 'report',
            'relations': {
                'project': {'this': {}},
                'owner': {'union': {'child': [{'this': {}}, {'tupleToUserset': {'tupleset': {'relation': 'project'}, 'computedUserset': {'relation': 'owner'}}}]}},
                'viewer': {'union': {'child': [{'this': {}}, {'tupleToUserset': {'tupleset': {'relation': 'project'}, 'computedUserset': {'relation': 'viewer'}}}, {'tupleToUserset': {'tupleset': {'relation': 'project'}, 'computedUserset': {'relation': 'auditor'}}}]}},
                'auditor': {'union': {'child': [{'this': {}}, {'tupleToUserset': {'tupleset': {'relation': 'project'}, 'computedUserset': {'relation': 'auditor'}}}]}}
            },
            'metadata': {
                'relations': {
                    'project': {'directly_related_user_types': [{'type': 'project'}]},
                    'owner': {'directly_related_user_types': [{'type': 'user'}]},
                    'viewer': {'directly_related_user_types': [{'type': 'user'}]},
                    'auditor': {'directly_related_user_types': [{'type': 'user'}]}
                }
            }
        }
    ]
}
print(json.dumps({
    'type_definitions': model['type_definitions'],
    'schema_version': model['schema_version']
}))
")

MODEL_RESPONSE=$(curl -sf -X POST "${OPENFGA_API_URL}/stores/${STORE_ID}/authorization-models" \
    -H "${AUTH_HEADER}" \
    -H "Content-Type: application/json" \
    -d "${MODEL_JSON}")

MODEL_ID=$(echo "${MODEL_RESPONSE}" | python3 -c "import sys, json; print(json.load(sys.stdin)['authorization_model_id'])")
echo "Model ID: ${MODEL_ID}"

echo ""
echo "=== Add to your .env file ==="
echo "SIOPV_OPENFGA_API_URL=${OPENFGA_API_URL}"
echo "SIOPV_OPENFGA_STORE_ID=${STORE_ID}"
echo "SIOPV_OPENFGA_API_TOKEN=${OPENFGA_API_TOKEN}"
echo "SIOPV_OPENFGA_AUTHORIZATION_MODEL_ID=${MODEL_ID}"
echo "SIOPV_OPENFGA_AUTH_METHOD=api_token"
echo ""
echo "=== Setup complete ==="
```

---

### Snippet 3.4: Integration Tests

**File:** `tests/integration/test_openfga_real_server.py` (NEW)
**Action:** CREATE new file

```python
"""Integration tests against a real OpenFGA server.

These tests require a running OpenFGA server. Skip if not available.
Run with: pytest tests/integration/test_openfga_real_server.py -m real_openfga -v

Prerequisites:
    docker compose up -d
    ./scripts/setup-openfga.sh
    # Copy the output env vars to your .env or export them
"""

from __future__ import annotations

import os

import pytest
from pydantic import SecretStr
from unittest.mock import MagicMock

from siopv.adapters.authorization import OpenFGAAdapter
from siopv.domain.authorization import (
    Relation,
    RelationshipTuple,
    ResourceType,
)

OPENFGA_API_URL = os.environ.get("SIOPV_OPENFGA_API_URL")
OPENFGA_STORE_ID = os.environ.get("SIOPV_OPENFGA_STORE_ID")

pytestmark = pytest.mark.skipif(
    not OPENFGA_API_URL or not OPENFGA_STORE_ID,
    reason="Real OpenFGA server not configured (set SIOPV_OPENFGA_* env vars)",
)


@pytest.fixture
def real_settings() -> MagicMock:
    """Create settings from environment for real server tests."""
    settings = MagicMock()
    settings.openfga_api_url = OPENFGA_API_URL
    settings.openfga_store_id = OPENFGA_STORE_ID
    settings.openfga_api_token = (
        SecretStr(os.environ["SIOPV_OPENFGA_API_TOKEN"])
        if os.environ.get("SIOPV_OPENFGA_API_TOKEN")
        else None
    )
    settings.openfga_authorization_model_id = os.environ.get(
        "SIOPV_OPENFGA_AUTHORIZATION_MODEL_ID"
    )
    settings.openfga_auth_method = os.environ.get("SIOPV_OPENFGA_AUTH_METHOD", "none")
    settings.openfga_client_id = None
    settings.openfga_client_secret = None
    settings.openfga_api_audience = None
    settings.openfga_api_token_issuer = None
    settings.circuit_breaker_failure_threshold = 5
    settings.circuit_breaker_recovery_timeout = 60
    return settings


@pytest.mark.real_openfga
class TestRealOpenFGAHealthCheck:
    """Health check tests against real server."""

    @pytest.mark.asyncio
    async def test_health_check(self, real_settings: MagicMock) -> None:
        """Test health check passes against running server."""
        adapter = OpenFGAAdapter(real_settings)
        await adapter.initialize()
        try:
            result = await adapter.health_check()
            assert result is True
        finally:
            await adapter.close()

    @pytest.mark.asyncio
    async def test_get_model_id(self, real_settings: MagicMock) -> None:
        """Test model retrieval from real server."""
        adapter = OpenFGAAdapter(real_settings)
        await adapter.initialize()
        try:
            model_id = await adapter.get_model_id()
            assert model_id is not None
            assert len(model_id) > 0
        finally:
            await adapter.close()


@pytest.mark.real_openfga
class TestRealOpenFGATupleOperations:
    """Tuple operations against real server."""

    @pytest.mark.asyncio
    async def test_write_and_read_tuple(self, real_settings: MagicMock) -> None:
        """Test writing and reading a tuple from real server."""
        adapter = OpenFGAAdapter(real_settings)
        await adapter.initialize()
        try:
            # Write a tuple
            relationship = RelationshipTuple.create(
                user_id="test-user-integration",
                relation=Relation.VIEWER,
                resource_type=ResourceType.PROJECT,
                resource_id="test-project-integration",
            )
            await adapter.write_tuple(relationship)

            # Verify tuple exists
            exists = await adapter.tuple_exists(
                relationship.user, Relation.VIEWER, relationship.resource
            )
            assert exists is True

            # Cleanup
            await adapter.delete_tuple(relationship)
        finally:
            await adapter.close()
```

---

## Phase 5: Production Hardening

### Snippet 5.1: Model Validator

**File:** `src/siopv/infrastructure/config/settings.py`
**Action:** ADD after the `openfga_api_token_issuer` field (after the new OpenFGA OIDC section), before the `# === ML Model ===` section

**ADD import at top of file** (line 8, extend existing `from typing import Literal`):
```python
from typing import Literal
```
(Already exists — no change needed.)

**ADD `model_validator` import** — update line 10:

**CURRENT (line 10):**
```python
from pydantic import Field, SecretStr
```

**REPLACE WITH:**
```python
from pydantic import Field, SecretStr, model_validator
```

**ADD validator method inside the `Settings` class**, after the OpenFGA OIDC fields and before `# === ML Model ===`:

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

## Summary of All Changes

### Files Modified (6 files)

| # | File | Phase | What Changes |
|---|------|-------|-------------|
| 1 | `src/siopv/infrastructure/config/settings.py` | 1, 5 | +7 fields, +1 import, +1 validator |
| 2 | `src/siopv/adapters/authorization/openfga_adapter.py` | 2 | +1 import, +7 lines in `__init__`, replace `initialize()` config block |
| 3 | `src/siopv/infrastructure/di/authorization.py` | 2 | +2 params in logging call |
| 4 | `tests/unit/infrastructure/test_settings.py` | 1 | +3 test functions (~45 lines) |
| 5 | `tests/unit/adapters/authorization/test_openfga_adapter.py` | 2 | Update fixture, +1 test class with 8 tests |
| 6 | `tests/unit/infrastructure/di/test_authorization_di.py` | 2 | Update fixture + inline settings |

### Files Created (4 files)

| # | File | Phase | Purpose |
|---|------|-------|---------|
| 7 | `docker-compose.yml` | 3 | Postgres + OpenFGA local dev |
| 8 | `openfga/model.fga` | 3 | Authorization model definition |
| 9 | `scripts/setup-openfga.sh` | 3 | Bootstrap script (store + model) |
| 10 | `tests/integration/test_openfga_real_server.py` | 3 | Real server integration tests |

### Files NOT Changed (confirmed safe)

| File | Reason |
|------|--------|
| `src/siopv/application/ports/authorization.py` | Port interfaces unchanged |
| `src/siopv/application/use_cases/authorization.py` | Use cases use ports, unaffected |
| `src/siopv/domain/authorization/*` | Domain layer untouched |
| `.env.example` | Already has all needed vars |

---

## Critical SDK Note

The OpenFGA Python SDK `CredentialConfiguration` uses **`api_issuer`** (not `api_token_issuer`) for the OIDC issuer URL. The settings field is named `openfga_api_token_issuer` for clarity, but the mapping to the SDK is:

```python
# Settings field → SDK parameter
settings.openfga_api_token_issuer → CredentialConfiguration(api_issuer=...)
```

The SDK internally appends `/oauth/token` to the issuer URL if the path is not already present.

---

## Backward Compatibility Guarantee

All changes maintain full backward compatibility:
- All new settings fields default to `None` or `"none"`
- When `openfga_auth_method == "none"` (default), the adapter falls through to the original unauthenticated `ClientConfiguration` — behavior is identical to current code
- Existing 87+ unit tests continue to pass after updating mock fixtures
- `getattr()` with defaults in adapter prevents `AttributeError` on legacy settings objects
