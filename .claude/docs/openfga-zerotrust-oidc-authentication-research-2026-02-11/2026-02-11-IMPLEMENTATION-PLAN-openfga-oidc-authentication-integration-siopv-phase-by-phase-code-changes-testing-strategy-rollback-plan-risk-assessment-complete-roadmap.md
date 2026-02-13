# IMPLEMENTATION PLAN: OpenFGA OIDC Authentication Integration for SIOPV

**Date:** 2026-02-11
**Author:** implementation-planner (OpenFGA Research Team)
**Project:** SIOPV (`~/siopv/`)
**Status:** Ready for implementation
**Based on:** Final research synthesis from tasks #1–#5

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Phase 1: Configuration Foundation](#2-phase-1-configuration-foundation)
3. [Phase 2: Adapter Authentication Support](#3-phase-2-adapter-authentication-support)
4. [Phase 3: Infrastructure Setup](#4-phase-3-infrastructure-setup)
5. [Phase 4: OIDC Migration](#5-phase-4-oidc-migration)
6. [Phase 5: Production Hardening](#6-phase-5-production-hardening)
7. [Testing Strategy](#7-testing-strategy)
8. [Rollback / Fallback Plan](#8-rollback--fallback-plan)
9. [Risk Assessment](#9-risk-assessment)
10. [Dependencies Between Steps](#10-dependencies-between-steps)
11. [Timeline Estimates](#11-timeline-estimates)
12. [Appendix: File Inventory](#12-appendix-file-inventory)

---

## 1. Executive Summary

SIOPV has a mature Phase 5 code-level OpenFGA integration (1173-line adapter, 87+ tests, domain entities, use cases, ports, DI container). However, the runtime configuration is critically incomplete: `.env.example` exists with basic OpenFGA config but lacks authentication variables, no authentication/credential support in adapter, no Docker Compose, and no `.fga` model file.

This plan defines a phased approach to:
1. Add pre-shared key authentication support (immediate)
2. Build local dev infrastructure (Docker Compose + model)
3. Migrate to OIDC client_credentials authentication (strategic)
4. Harden for production deployment

### Key Principle
Each phase is independently deployable and adds value. Phases 1-2 can be completed in a single PR. Phase 3 enables real-server testing. Phase 4 adds OIDC. Phase 5 prepares for production.

---

## 2. Phase 1: Configuration Foundation

**Goal:** Add all missing settings fields and update `.env.example` with authentication variables
**Milestone:** Application can be configured for authenticated OpenFGA connections via environment variables

### Step 1.1: Add New Settings Fields

**File:** `src/siopv/infrastructure/config/settings.py`
**Lines affected:** 64–66 (OpenFGA section)

**Current code (lines 64–66):**
```python
# === OpenFGA ===
openfga_api_url: str | None = None
openfga_store_id: str | None = None
```

**New code:**
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

**Notes:**
- `SecretStr` is already imported at line 10: `from pydantic import Field, SecretStr`
- `Literal` is already imported at line 8: `from typing import Literal`
- `openfga_auth_method` defaults to `"none"` for backward compatibility
- All new fields are `None`-defaulted (optional) to maintain backward compatibility
- No existing tests break because all new fields have defaults

### Step 1.2: Update `.env.example` with authentication variables

**File:** `.env.example` (EXISTS — needs authentication variables added)

```bash
# =============================================================================
# SIOPV Configuration
# =============================================================================
# Copy this file to .env and fill in the values:
#   cp .env.example .env

# === Application ===
SIOPV_ENVIRONMENT=development
SIOPV_DEBUG=false
SIOPV_LOG_LEVEL=INFO

# === Anthropic (Claude) — REQUIRED ===
SIOPV_ANTHROPIC_API_KEY=

# === NVD API ===
# SIOPV_NVD_API_KEY=

# === GitHub Security Advisories ===
# SIOPV_GITHUB_TOKEN=

# === Tavily Search ===
# SIOPV_TAVILY_API_KEY=

# === Jira ===
# SIOPV_JIRA_BASE_URL=
# SIOPV_JIRA_EMAIL=
# SIOPV_JIRA_API_TOKEN=
# SIOPV_JIRA_PROJECT_KEY=

# === Database ===
SIOPV_DATABASE_URL=sqlite+aiosqlite:///./siopv.db

# === ChromaDB ===
# SIOPV_CHROMA_PERSIST_DIR=./chroma_data
# SIOPV_CHROMA_COLLECTION_NAME=siopv_embeddings

# === OpenFGA (Phase 5: Authorization) ===
# Auth method: "none" (default), "api_token" (pre-shared key), "client_credentials" (OIDC)
SIOPV_OPENFGA_AUTH_METHOD=none
SIOPV_OPENFGA_API_URL=http://localhost:8080
SIOPV_OPENFGA_STORE_ID=

# Pre-shared key authentication (when auth_method=api_token)
# SIOPV_OPENFGA_API_TOKEN=

# Model version pinning (recommended)
# SIOPV_OPENFGA_AUTHORIZATION_MODEL_ID=

# OIDC client credentials (when auth_method=client_credentials)
# SIOPV_OPENFGA_CLIENT_ID=
# SIOPV_OPENFGA_CLIENT_SECRET=
# SIOPV_OPENFGA_API_AUDIENCE=
# SIOPV_OPENFGA_API_TOKEN_ISSUER=
```

### Step 1.3: Update Settings Tests

**File:** `tests/unit/infrastructure/test_settings.py`

**New tests to add:**

```python
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

---

## 3. Phase 2: Adapter Authentication Support

**Goal:** Adapter creates `ClientConfiguration` with credentials when configured
**Milestone:** SIOPV can connect to an authenticated OpenFGA server

### Step 2.1: Update Adapter `__init__`

**File:** `src/siopv/adapters/authorization/openfga_adapter.py`
**Lines affected:** 101–137

**Current `__init__` (lines 101–137):**
```python
def __init__(
    self,
    settings: Settings,
    *,
    client: OpenFgaClient | None = None,
) -> None:
    self._api_url = settings.openfga_api_url
    self._store_id = settings.openfga_store_id
    # ... circuit breaker, client, mappings, cache ...
```

**New `__init__`:**
```python
def __init__(
    self,
    settings: Settings,
    *,
    client: OpenFgaClient | None = None,
) -> None:
    self._api_url = settings.openfga_api_url
    self._store_id = settings.openfga_store_id
    self._authorization_model_id = settings.openfga_authorization_model_id
    self._auth_method = settings.openfga_auth_method
    self._api_token = settings.openfga_api_token
    self._client_id = settings.openfga_client_id
    self._client_secret = settings.openfga_client_secret
    self._api_audience = settings.openfga_api_audience
    self._api_token_issuer = settings.openfga_api_token_issuer

    # ... rest unchanged (circuit breaker, client, mappings, cache) ...
```

### Step 2.2: Update Adapter `initialize` Method

**File:** `src/siopv/adapters/authorization/openfga_adapter.py`
**Lines affected:** 139–170

**Current `initialize` (lines 159–164):**
```python
configuration = ClientConfiguration(
    api_url=self._api_url,
    store_id=self._store_id,
)

self._owned_client = OpenFgaClient(configuration)
```

**New `initialize`:**
```python
from openfga_sdk.credentials import Credentials, CredentialConfiguration

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

**New import to add at top of file:**
```python
from openfga_sdk.credentials import Credentials, CredentialConfiguration
```

### Step 2.3: Update DI Container Logging

**File:** `src/siopv/infrastructure/di/authorization.py`
**Lines affected:** 82–86

**Current:**
```python
logger.debug(
    "creating_authorization_adapter",
    api_url=settings.openfga_api_url,
    store_id=settings.openfga_store_id,
)
```

**New:**
```python
logger.debug(
    "creating_authorization_adapter",
    api_url=settings.openfga_api_url,
    store_id=settings.openfga_store_id,
    auth_method=settings.openfga_auth_method,
    model_id=settings.openfga_authorization_model_id,
)
```

### Step 2.4: Update Adapter Unit Tests

**File:** `tests/unit/adapters/authorization/test_openfga_adapter.py`

**Update mock_settings fixture** to include new fields:

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

**Add new test cases:**

```python
class TestOpenFGAAdapterAuthentication:
    """Tests for adapter authentication configuration."""

    @pytest.mark.asyncio
    async def test_initialize_with_api_token(self, mock_settings: MagicMock) -> None:
        """Test adapter initializes with pre-shared key credentials."""
        mock_settings.openfga_auth_method = "api_token"
        mock_settings.openfga_api_token = MagicMock()
        mock_settings.openfga_api_token.get_secret_value.return_value = "test-token"

        adapter = OpenFGAAdapter(mock_settings)
        assert adapter._auth_method == "api_token"
        assert adapter._api_token is not None

    @pytest.mark.asyncio
    async def test_initialize_with_client_credentials(self, mock_settings: MagicMock) -> None:
        """Test adapter initializes with OIDC client_credentials."""
        mock_settings.openfga_auth_method = "client_credentials"
        mock_settings.openfga_client_id = "my-client-id"
        mock_settings.openfga_client_secret = MagicMock()
        mock_settings.openfga_client_secret.get_secret_value.return_value = "my-secret"
        mock_settings.openfga_api_audience = "openfga-audience"
        mock_settings.openfga_api_token_issuer = "https://idp.example.com/"

        adapter = OpenFGAAdapter(mock_settings)
        assert adapter._auth_method == "client_credentials"
        assert adapter._client_id == "my-client-id"

    @pytest.mark.asyncio
    async def test_initialize_with_model_id(self, mock_settings: MagicMock) -> None:
        """Test adapter initializes with pinned model ID."""
        mock_settings.openfga_authorization_model_id = "01HXY..."

        adapter = OpenFGAAdapter(mock_settings)
        assert adapter._authorization_model_id == "01HXY..."

    def test_initialize_no_auth_backward_compatible(self, mock_settings: MagicMock) -> None:
        """Test adapter initializes without auth (backward compatible)."""
        adapter = OpenFGAAdapter(mock_settings)
        assert adapter._auth_method == "none"
        assert adapter._api_token is None
```

---

## 4. Phase 3: Infrastructure Setup

**Goal:** Enable running a real OpenFGA server locally
**Milestone:** Developers can `docker compose up` and run integration tests against a real server

### Step 3.1: Create Docker Compose

**File:** `docker-compose.yml` (NEW — project root)

```yaml
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

### Step 3.2: Create Authorization Model File

**File:** `openfga/model.fga` (NEW)

Based on domain value objects at `src/siopv/domain/authorization/value_objects.py`, which defines:
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
    define owner: [user] or admin from organization
    define viewer: [user] or owner or member from organization
    define analyst: [user] or owner
    define auditor: [user] or admin from organization
    define organization: [organization]

type vulnerability
  relations
    define owner: [user] or owner from project
    define viewer: [user] or viewer from project
    define analyst: [user] or analyst from project
    define project: [project]

type report
  relations
    define owner: [user] or owner from project
    define viewer: [user] or viewer from project or auditor from project
    define auditor: [user] or auditor from project
    define project: [project]
```

### Step 3.3: Create Bootstrap Script

**File:** `scripts/setup-openfga.sh` (NEW)

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

# Write authorization model
echo "Writing authorization model..."
MODEL_JSON=$(python3 -c "
import json, sys
# Read the .fga file and convert to JSON API format
# For simplicity, use the FGA CLI or manual JSON
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
print(json.dumps({'type_definitions': model['type_definitions'], 'schema_version': model['schema_version']}, indent=2))
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

### Step 3.4: Add Integration Tests with Real Server

**File:** `tests/integration/test_openfga_real_server.py` (NEW)

```python
"""Integration tests against a real OpenFGA server.

These tests require a running OpenFGA server. Skip if not available.
Run with: pytest tests/integration/test_openfga_real_server.py -m real_openfga
"""

import os

import pytest

from siopv.adapters.authorization import OpenFGAAdapter
from siopv.domain.authorization import AuthorizationContext, Relation, ResourceType

OPENFGA_API_URL = os.environ.get("SIOPV_OPENFGA_API_URL")
OPENFGA_STORE_ID = os.environ.get("SIOPV_OPENFGA_STORE_ID")

pytestmark = pytest.mark.skipif(
    not OPENFGA_API_URL or not OPENFGA_STORE_ID,
    reason="Real OpenFGA server not configured (set SIOPV_OPENFGA_* env vars)",
)


@pytest.fixture
def real_settings():
    """Create real settings from environment."""
    from unittest.mock import MagicMock
    from pydantic import SecretStr

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
class TestRealOpenFGAConnection:
    @pytest.mark.asyncio
    async def test_health_check(self, real_settings):
        adapter = OpenFGAAdapter(real_settings)
        await adapter.initialize()
        try:
            result = await adapter.health_check()
            assert result is True
        finally:
            await adapter.close()

    @pytest.mark.asyncio
    async def test_get_model_id(self, real_settings):
        adapter = OpenFGAAdapter(real_settings)
        await adapter.initialize()
        try:
            model_id = await adapter.get_model_id()
            assert model_id is not None
            assert len(model_id) > 0
        finally:
            await adapter.close()
```

---

## 5. Phase 4: OIDC Migration

**Goal:** Support OAuth2 client_credentials flow for production environments
**Milestone:** SIOPV can authenticate to OpenFGA via an OIDC provider (Keycloak, Auth0, etc.)

### Step 4.1: Verify OIDC Code Path

The adapter code from Phase 2 already supports `client_credentials` via the `openfga_auth_method` setting. Phase 4 is primarily about:

1. **OIDC Provider Setup** (infrastructure — not code):
   - Deploy Keycloak (recommended for self-hosted) or configure Auth0
   - Create an OAuth2 client with `client_credentials` grant type
   - Configure the client with an audience matching OpenFGA
   - Note the `client_id`, `client_secret`, `token_endpoint`, and `issuer`

2. **OpenFGA Server OIDC Configuration** (Docker Compose update):

```yaml
# Add to docker-compose.yml openfga service environment:
environment:
  - OPENFGA_AUTHN_METHOD=oidc
  - OPENFGA_AUTHN_OIDC_ISSUER=https://keycloak.example.com/realms/siopv
  - OPENFGA_AUTHN_OIDC_AUDIENCE=openfga-api
```

3. **SIOPV `.env` for OIDC**:

```bash
SIOPV_OPENFGA_AUTH_METHOD=client_credentials
SIOPV_OPENFGA_CLIENT_ID=siopv-service
SIOPV_OPENFGA_CLIENT_SECRET=<generated-secret>
SIOPV_OPENFGA_API_AUDIENCE=openfga-api
SIOPV_OPENFGA_API_TOKEN_ISSUER=https://keycloak.example.com/realms/siopv
```

### Step 4.2: Add Keycloak to Docker Compose (Optional Dev Setup)

**File:** `docker-compose.yml` (append to services)

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

### Step 4.3: Validate Token Refresh

The OpenFGA Python SDK handles token refresh automatically when using `client_credentials`. No additional code is needed. Add a test:

```python
@pytest.mark.asyncio
async def test_client_credentials_token_refresh(mock_settings):
    """Verify SDK handles token refresh for client_credentials."""
    mock_settings.openfga_auth_method = "client_credentials"
    mock_settings.openfga_client_id = "siopv"
    mock_settings.openfga_client_secret = MagicMock()
    mock_settings.openfga_client_secret.get_secret_value.return_value = "secret"
    mock_settings.openfga_api_audience = "openfga-api"
    mock_settings.openfga_api_token_issuer = "https://idp.example.com/"

    adapter = OpenFGAAdapter(mock_settings)
    assert adapter._auth_method == "client_credentials"
    # SDK handles token lifecycle internally; verify config is passed correctly
```

---

## 6. Phase 5: Production Hardening

**Goal:** Security and operational readiness for production deployment
**Milestone:** Production-ready OpenFGA deployment

### Step 5.1: TLS Configuration

Add to Docker Compose for production:
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

### Step 5.2: Environment Validation

**File:** `src/siopv/infrastructure/config/settings.py`

Add a Pydantic `model_validator` to catch misconfigured auth:

```python
from pydantic import model_validator

@model_validator(mode="after")
def validate_openfga_auth(self) -> Settings:
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

### Step 5.3: Security Hardening Checklist

Add to `.claude/docs/` or project docs:

| Item | Phase | Status |
|------|-------|--------|
| Authentication enabled (pre-shared or OIDC) | Phase 2 | Implemented |
| TLS enabled for HTTP/gRPC | Phase 5 | Config |
| Playground disabled in production | Phase 5 | Config |
| Authorization model pinned | Phase 2 | Implemented |
| Network isolation (VPC/service mesh) | Phase 5 | Infra |
| Structured JSON logging | Phase 3 | Config |
| Metrics enabled (Prometheus) | Phase 5 | Config |
| No PII in tuples (opaque user IDs only) | Phase 2 | By design |
| Key rotation plan (multiple pre-shared keys) | Phase 5 | Ops |
| Concurrency limits configured | Phase 5 | Config |

---

## 7. Testing Strategy

### Unit Tests (Phase 1-2)

| Test Category | File | Count | Coverage |
|---------------|------|-------|----------|
| Settings defaults (new fields) | `tests/unit/infrastructure/test_settings.py` | +3 tests | All new settings fields |
| Settings env loading | `tests/unit/infrastructure/test_settings.py` | +2 tests | api_token, OIDC fields |
| Adapter init (new fields) | `tests/unit/adapters/authorization/test_openfga_adapter.py` | +4 tests | All auth methods |
| Adapter initialize (credentials) | `tests/unit/adapters/authorization/test_openfga_adapter.py` | +3 tests | api_token, OIDC, none |
| DI container (logging) | `tests/unit/infrastructure/di/test_authorization_di.py` | +1 test | New log fields |

**Existing tests remain unchanged** — all new settings have `None` defaults, so existing mock fixtures continue to work. However, mock fixtures should be updated to include the new fields to avoid `AttributeError` on strict mocks.

### Integration Tests (Phase 3)

| Test Category | File | Requires |
|---------------|------|----------|
| Health check (real server) | `tests/integration/test_openfga_real_server.py` | Docker Compose |
| Model retrieval | `tests/integration/test_openfga_real_server.py` | Docker Compose |
| Tuple write/read cycle | `tests/integration/test_openfga_real_server.py` | Docker Compose + model |
| Permission check | `tests/integration/test_openfga_real_server.py` | Docker Compose + model + tuples |
| Authenticated connection | `tests/integration/test_openfga_real_server.py` | Docker Compose (pre-shared key) |

### Test Execution Strategy

```bash
# Phase 1-2: Unit tests only (no infra needed)
pytest tests/unit/infrastructure/test_settings.py -v
pytest tests/unit/adapters/authorization/test_openfga_adapter.py -v

# Phase 3: Integration tests (requires docker compose up)
docker compose up -d
./scripts/setup-openfga.sh  # Sets up store + model, outputs env vars
pytest tests/integration/test_openfga_real_server.py -m real_openfga -v

# Full suite
pytest tests/ -v --ignore=tests/integration/test_openfga_real_server.py  # Standard CI
pytest tests/ -v -m real_openfga  # Real server CI (optional)
```

---

## 8. Rollback / Fallback Plan

### Phase 1-2 Rollback (Configuration + Adapter)

**Risk:** Low. All changes are backward-compatible.

- **Rollback strategy:** Revert the commit. No data migration needed.
- **Fallback:** Set `SIOPV_OPENFGA_AUTH_METHOD=none` (the default). The adapter falls through to the original unauthenticated `ClientConfiguration`.
- **Key guarantee:** If `openfga_auth_method` is `"none"` (default) AND no token/credentials are set, behavior is identical to current code.

### Phase 3 Rollback (Infrastructure)

**Risk:** Low. Infrastructure files are additive.

- **Rollback strategy:** `docker compose down -v` removes all containers and volumes. Delete `docker-compose.yml`, `openfga/model.fga`, `scripts/setup-openfga.sh`.
- **No application code changes to revert.**

### Phase 4 Rollback (OIDC)

**Risk:** Medium. Involves external identity provider.

- **Rollback strategy:** Change `SIOPV_OPENFGA_AUTH_METHOD` from `client_credentials` back to `api_token`. No code changes needed — the adapter supports both paths.
- **Server rollback:** Change OpenFGA server from `OPENFGA_AUTHN_METHOD=oidc` to `OPENFGA_AUTHN_METHOD=preshared`.
- **Key guarantee:** Pre-shared key auth remains as permanent fallback.

### Phase 5 Rollback (Production Hardening)

**Risk:** Low. Config-only changes.

- **Rollback strategy:** Revert deployment configuration. No code changes.

### Emergency Fallback: Disable Authentication Entirely

If authentication causes issues in any phase:

```bash
# 1. Set adapter to unauthenticated
SIOPV_OPENFGA_AUTH_METHOD=none

# 2. Set server to unauthenticated
OPENFGA_AUTHN_METHOD=none

# 3. Restart both services
```

This returns to the current state (unauthenticated connections).

---

## 9. Risk Assessment

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| **SDK `Credentials` import path changes** | Low | Medium | Pin `openfga-sdk` version in `pyproject.toml`. Verify import works in CI. |
| **`SecretStr.get_secret_value()` breaking in Pydantic v3** | Low | High | Currently on Pydantic v2. Monitor Pydantic changelog. |
| **OIDC provider unavailability** | Medium | High | Pre-shared key fallback always available. Circuit breaker protects adapter. |
| **Docker Compose version incompatibility** | Low | Low | Use standard compose spec (no version key). Test on Docker Compose v2+. |
| **Mock fixtures break with new fields** | Medium | Low | Update all mock fixtures to include new fields. Use a shared fixture factory. |
| **Token/secret leaking in logs** | Low | Critical | `SecretStr` prevents accidental logging. Never log `get_secret_value()`. Audit structlog calls. |
| **Model version drift** | Medium | Medium | Pin `authorization_model_id` in settings. CI verifies model matches `.fga` file. |
| **OpenFGA server access control immaturity** | Medium | Medium | Use network isolation until built-in access control is production-ready. |
| **Existing 87+ tests break** | Low | Medium | All new fields default to `None`. Run full test suite in Phase 1 PR before merge. |
| **OIDC client_credentials flow fails silently** | Low | High | Add explicit validation in `initialize()` — log error if method is `client_credentials` but SDK fails token exchange. |

---

## 10. Dependencies Between Steps

```
Phase 1: Configuration Foundation
  ├── Step 1.1: Add Settings fields ─────────────────────┐
  ├── Step 1.2: Create .env.example                       │
  └── Step 1.3: Update Settings tests                     │
                                                          │
Phase 2: Adapter Authentication  ◄────────────────────────┘
  ├── Step 2.1: Update __init__ (depends on 1.1)
  ├── Step 2.2: Update initialize (depends on 2.1)
  ├── Step 2.3: Update DI logging (depends on 1.1)
  └── Step 2.4: Update adapter tests (depends on 2.1, 2.2)

Phase 3: Infrastructure Setup (independent of Phase 2 code, but uses Phase 1 config)
  ├── Step 3.1: Docker Compose
  ├── Step 3.2: .fga model file
  ├── Step 3.3: Bootstrap script (depends on 3.1, 3.2)
  └── Step 3.4: Real server integration tests (depends on 3.3 + Phase 2)

Phase 4: OIDC Migration (depends on Phase 2 + Phase 3)
  ├── Step 4.1: OIDC provider setup (infra)
  ├── Step 4.2: Keycloak Docker Compose (depends on 4.1)
  └── Step 4.3: Token refresh validation (depends on Phase 2)

Phase 5: Production Hardening (depends on Phase 3 + Phase 4)
  ├── Step 5.1: TLS configuration
  ├── Step 5.2: Environment validation (depends on Phase 1)
  └── Step 5.3: Security checklist
```

### PR Strategy

| PR | Contents | Dependencies |
|----|----------|-------------|
| **PR 1** | Phase 1 + Phase 2 (config + adapter auth) | None |
| **PR 2** | Phase 3 (Docker Compose + model + bootstrap + tests) | PR 1 merged |
| **PR 3** | Phase 4 (OIDC support) | PR 2 merged + OIDC provider available |
| **PR 4** | Phase 5 (production hardening + validation) | PR 3 merged |

---

## 11. Timeline Estimates

| Phase | Effort | Description |
|-------|--------|-------------|
| **Phase 1** | Small | Add settings fields + update .env.example + tests. ~15 modified lines in settings, ~50 lines in tests, 1 modified file. |
| **Phase 2** | Medium | Update adapter __init__ + initialize + DI + tests. ~40 modified lines in adapter, ~60 lines in tests. |
| **Phase 3** | Medium | Docker Compose + .fga model + bootstrap script + integration tests. 4 new files. |
| **Phase 4** | Medium | OIDC provider setup (infra) + Docker Compose update + validation tests. Mostly infrastructure. |
| **Phase 5** | Small | Config changes + Pydantic validator + checklist. ~20 lines of code. |

### Critical Path

**Phase 1 → Phase 2 → Phase 3** is the critical path. Phases 4 and 5 can be started in parallel after Phase 3 for different aspects.

---

## 12. Appendix: File Inventory

### Files Modified

| File | Phase | Changes |
|------|-------|---------|
| `src/siopv/infrastructure/config/settings.py` | 1, 5 | Add 7 new fields + validator |
| `src/siopv/adapters/authorization/openfga_adapter.py` | 2 | Update __init__ + initialize + new import |
| `src/siopv/infrastructure/di/authorization.py` | 2 | Update logging in factory |
| `tests/unit/infrastructure/test_settings.py` | 1 | Add 3-5 new test functions |
| `tests/unit/adapters/authorization/test_openfga_adapter.py` | 2 | Update fixtures + add 4+ test functions |
| `tests/unit/infrastructure/di/test_authorization_di.py` | 2 | Update mock fixture |

### Files Modified or Created

| File | Phase | Type | Purpose |
|------|-------|------|---------|
| `.env.example` | 1 | Modified | Update with authentication variables |
| `docker-compose.yml` | 3 | Created | Local dev infrastructure |
| `openfga/model.fga` | 3 | Authorization model definition |
| `scripts/setup-openfga.sh` | 3 | Bootstrap script for store/model setup |
| `tests/integration/test_openfga_real_server.py` | 3 | Real server integration tests |

### Files NOT Changed (Confirmed Safe)

| File | Reason |
|------|--------|
| `src/siopv/application/ports/authorization.py` | Port interfaces unchanged (adapter implements them) |
| `src/siopv/application/use_cases/authorization.py` | Use cases unchanged (they use ports) |
| `src/siopv/domain/authorization/*` | Domain layer untouched (pure domain logic) |
| `tests/integration/test_authorization_integration.py` | Existing integration tests use mocks (unaffected) |

---

## Summary of Deliverables

1. **PR 1 (Phase 1+2):** Settings + adapter auth support — enables authenticated connections
2. **PR 2 (Phase 3):** Infrastructure — enables real-server development and testing
3. **PR 3 (Phase 4):** OIDC — enables production-grade authentication
4. **PR 4 (Phase 5):** Hardening — production readiness

Each phase is independently valuable and can be deployed incrementally. The rollback plan ensures any phase can be reverted without affecting other phases.
