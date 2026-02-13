# FINAL REPORT: OpenFGA OIDC Authentication Integration for SIOPV

**Date:** 2026-02-11
**Author:** final-report-writer (OpenFGA OIDC Implementation Team)
**Project:** SIOPV (`~/siopv/`)
**Task:** #5 — Comprehensive synthesis of all OIDC research findings from Tasks #1–#4

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Recommended OIDC Provider for SIOPV](#2-recommended-oidc-provider-for-siopv)
3. [Complete Requirements List](#3-complete-requirements-list)
4. [Settings.py Changes Required](#4-settingspy-changes-required)
5. [Adapter Changes Required](#5-adapter-changes-required)
6. [Environment Variables Needed](#6-environment-variables-needed)
7. [Docker Compose Setup](#7-docker-compose-setup)
8. [Security Considerations](#8-security-considerations)
9. [Migration Path: Pre-Shared Key → OIDC](#9-migration-path-pre-shared-key--oidc)
10. [Current SIOPV Architecture Analysis](#10-current-siopv-architecture-analysis)
11. [Implementation Roadmap](#11-implementation-roadmap)
12. [Source Reports](#12-source-reports)

---

## 1. Executive Summary

SIOPV has a **mature Phase 5 OpenFGA authorization implementation** at the code level (1173-line adapter, 87+ tests, domain entities, use cases, ports, DI container). However, the **runtime configuration is critically incomplete** — the project currently supports only unauthenticated OpenFGA connections and has no OIDC capability whatsoever.

### Key Findings

| Area | Current State | Target State |
|------|---------------|--------------|
| **Authentication** | None (unauthenticated only) | Pre-shared key (Phase 1) → OIDC (Phase 2) |
| **OIDC Provider** | Not configured | **Keycloak** (recommended) |
| **Settings** | 2 OpenFGA fields | 8+ OpenFGA fields |
| **Adapter** | No credentials param | Full credential support (api_token + client_credentials) |
| **Infrastructure** | `.env.example` exists with basic OpenFGA config, no Docker Compose | Full Docker stack with OpenFGA + Keycloak + PostgreSQL |
| **Model File** | Conceptual only (in code enums) | Declarative `.fga` model file |

### Bottom Line

**Keycloak** is the recommended OIDC provider for SIOPV. The integration requires changes to `settings.py` (6 new fields), `openfga_adapter.py` (credential support), the DI container, updating `.env.example` with authentication variables, and new infrastructure (Docker Compose, bootstrap scripts). A phased approach is recommended: start with pre-shared key authentication, then migrate to OIDC with Keycloak when the identity layer is ready.

---

## 2. Recommended OIDC Provider for SIOPV

### Primary Recommendation: **Keycloak**

| Criterion | Keycloak | Auth0 | Okta |
|-----------|----------|-------|------|
| **License** | Apache 2.0 (open-source) | Proprietary (free tier) | Proprietary (free tier) |
| **Self-hosted** | Yes (full control) | No (SaaS only) | No (SaaS only) |
| **Cost** | Free (infrastructure costs only) | Free tier limited, paid beyond | Free tier limited, paid beyond |
| **Docker support** | Official image, easy setup | N/A | N/A |
| **OpenFGA integration** | Proven (community plugins exist) | Native (Auth0 FGA) | Via OIDC standard |
| **OIDC compliance** | Full (certified) | Full (certified) | Full (certified) |
| **Client credentials flow** | Built-in | Built-in | Built-in |
| **SIOPV alignment** | Matches self-hosted philosophy | Vendor lock-in | Vendor lock-in |

### Why Keycloak for SIOPV

1. **Open-source and self-hosted** — aligns with SIOPV's architecture philosophy (no vendor lock-in)
2. **Docker-native** — runs alongside OpenFGA in Docker Compose with minimal configuration
3. **Full OIDC compliance** — supports all flows needed (client_credentials for service-to-service, authorization_code for user-facing)
4. **Proven OpenFGA integration** — documented patterns exist (Keycloak → OIDC tokens → OpenFGA validates)
5. **Enterprise-ready** — CNCF ecosystem compatibility, production-proven at scale
6. **Zero licensing cost** — only infrastructure costs (important for a security research tool)

### Alternative: Auth0 FGA (Managed)

If the team prefers a managed solution and is willing to accept SaaS dependency:
- Auth0 FGA uses client_credentials exclusively
- SDK handles token exchange automatically
- Zero-ops for the authorization layer
- Trade-off: vendor lock-in, SaaS pricing, less control

### How Keycloak + OpenFGA Work Together

```
┌───────────────────────────────────────────────────────────────┐
│                    SIOPV Application                          │
│                                                               │
│  1. Service starts → requests token from Keycloak             │
│  2. Keycloak returns JWT (client_credentials flow)            │
│  3. SIOPV sends request to OpenFGA with JWT in header         │
│  4. OpenFGA validates JWT against Keycloak's OIDC config      │
│  5. If valid → processes authorization check                  │
│  6. Returns allowed/denied to SIOPV                           │
└───────────────────────────────────────────────────────────────┘

┌──────────┐     OIDC tokens     ┌──────────┐     JWT validation     ┌──────────┐
│ Keycloak │ ──────────────────→ │   SIOPV  │ ─────────────────────→ │ OpenFGA  │
│  (IdP)   │ ←── token request   │  (App)   │ ←── allow/deny         │ (AuthZ)  │
└──────────┘                     └──────────┘                        └──────────┘
```

**Key insight:** OpenFGA does NOT implement the client_credentials flow itself. It only validates JWT tokens. Keycloak issues the tokens; SIOPV's SDK automatically handles token exchange and refresh.

---

## 3. Complete Requirements List

### 3.1 OIDC Server (Keycloak)

| Component | Details |
|-----------|---------|
| **Docker image** | `quay.io/keycloak/keycloak:latest` |
| **Port** | 8443 (HTTPS) or 8180 (HTTP for dev) |
| **Realm** | `siopv` (new realm for the project) |
| **Client** | `siopv-openfga-client` (service account with client_credentials grant) |
| **Client type** | Confidential (generates client_secret) |
| **Audience** | Custom audience mapper for OpenFGA (e.g., `openfga-api`) |
| **Storage** | PostgreSQL (can share cluster with OpenFGA, separate database) |

### 3.2 Keycloak Configuration

1. **Create realm** `siopv`
2. **Create client** `siopv-openfga-client`:
   - Client authentication: ON (confidential)
   - Service accounts roles: ON
   - Standard flow: OFF (not needed for machine-to-machine)
   - Direct access grants: OFF
3. **Add audience mapper**:
   - Mapper type: Audience
   - Included Custom Audience: `openfga-api`
   - Add to access token: ON
4. **Note the client_id and client_secret** for SIOPV `.env`

### 3.3 OpenFGA Server Configuration

| Setting | Value |
|---------|-------|
| `OPENFGA_AUTHN_METHOD` | `oidc` |
| `OPENFGA_AUTHN_OIDC_ISSUER` | `http://keycloak:8180/realms/siopv` (Docker network) |
| `OPENFGA_AUTHN_OIDC_AUDIENCE` | `openfga-api` |
| `OPENFGA_DATASTORE_ENGINE` | `postgres` |
| `OPENFGA_PLAYGROUND_ENABLED` | `true` (dev) / `false` (prod) |

### 3.4 Credentials Summary

| Credential | Purpose | Who Generates It |
|------------|---------|------------------|
| `client_id` | Identifies SIOPV to Keycloak | Keycloak admin (during client creation) |
| `client_secret` | Authenticates SIOPV to Keycloak | Keycloak (auto-generated for confidential clients) |
| `api_audience` | Tells OpenFGA which audience to expect in JWTs | Configured in Keycloak audience mapper |
| `api_token_issuer` | Keycloak's OIDC issuer URL | Derived from Keycloak realm URL |

---

## 4. Settings.py Changes Required

### Current State (`settings.py:64-66`)

```python
# === OpenFGA ===
openfga_api_url: str | None = None
openfga_store_id: str | None = None
```

### Required Changes

```python
from pydantic import Field, SecretStr

# === OpenFGA ===
openfga_api_url: str | None = None
openfga_store_id: str | None = None
openfga_authorization_model_id: str | None = None       # NEW: pin model version
openfga_api_token: SecretStr | None = None               # NEW: pre-shared key (Phase 1)

# === OpenFGA OIDC (Phase 2) ===
openfga_auth_method: str = "none"                        # NEW: "none" | "api_token" | "client_credentials"
openfga_client_id: str | None = None                     # NEW: Keycloak client ID
openfga_client_secret: SecretStr | None = None           # NEW: Keycloak client secret
openfga_api_audience: str | None = None                  # NEW: OIDC audience for OpenFGA
openfga_api_token_issuer: str | None = None              # NEW: Keycloak issuer URL
```

### Field Details

| Field | Type | Env Var | Default | Purpose |
|-------|------|---------|---------|---------|
| `openfga_authorization_model_id` | `str \| None` | `SIOPV_OPENFGA_AUTHORIZATION_MODEL_ID` | `None` | Pin specific model version |
| `openfga_api_token` | `SecretStr \| None` | `SIOPV_OPENFGA_API_TOKEN` | `None` | Pre-shared key for Phase 1 auth |
| `openfga_auth_method` | `str` | `SIOPV_OPENFGA_AUTH_METHOD` | `"none"` | Selects credential method |
| `openfga_client_id` | `str \| None` | `SIOPV_OPENFGA_CLIENT_ID` | `None` | Keycloak client identifier |
| `openfga_client_secret` | `SecretStr \| None` | `SIOPV_OPENFGA_CLIENT_SECRET` | `None` | Keycloak client secret |
| `openfga_api_audience` | `str \| None` | `SIOPV_OPENFGA_API_AUDIENCE` | `None` | Expected JWT audience |
| `openfga_api_token_issuer` | `str \| None` | `SIOPV_OPENFGA_API_TOKEN_ISSUER` | `None` | Keycloak realm issuer URL |

---

## 5. Adapter Changes Required

### 5.1 `__init__` Method Changes

**File:** `src/siopv/adapters/authorization/openfga_adapter.py`

Current (`__init__`, lines 101-137):
```python
self._api_url = settings.openfga_api_url
self._store_id = settings.openfga_store_id
```

Add:
```python
self._api_url = settings.openfga_api_url
self._store_id = settings.openfga_store_id
self._authorization_model_id = settings.openfga_authorization_model_id    # NEW
self._auth_method = settings.openfga_auth_method                          # NEW
self._api_token = settings.openfga_api_token                              # NEW
self._client_id = settings.openfga_client_id                              # NEW
self._client_secret = settings.openfga_client_secret                      # NEW
self._api_audience = settings.openfga_api_audience                        # NEW
self._api_token_issuer = settings.openfga_api_token_issuer                # NEW
```

### 5.2 `initialize` Method Changes

**Current** (lines 159-162):
```python
configuration = ClientConfiguration(
    api_url=self._api_url,
    store_id=self._store_id,
)
```

**Required** — Replace with credential-aware configuration:
```python
from openfga_sdk.credentials import Credentials, CredentialConfiguration

config_kwargs: dict[str, Any] = {
    "api_url": self._api_url,
    "store_id": self._store_id,
}

if self._authorization_model_id:
    config_kwargs["authorization_model_id"] = self._authorization_model_id

# Configure credentials based on auth method
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
```

### 5.3 New Imports Required

Add to the adapter's import block:
```python
from openfga_sdk.credentials import Credentials, CredentialConfiguration
```

### 5.4 SDK Notes

- The Python SDK `openfga-sdk>=0.6.0` (already in `pyproject.toml`) supports both `api_token` and `client_credentials` methods
- For `client_credentials`: the SDK **automatically handles token exchange and refresh** with the OIDC provider
- The `OpenFgaClient` should be initialized **once** and reused (already the pattern in SIOPV)
- The SDK automatically retries on 429 and 5xx errors (up to 3 times)

---

## 6. Environment Variables Needed

### 6.1 Complete `.env.example` Template

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

# === Anthropic (Claude) ===
SIOPV_ANTHROPIC_API_KEY=sk-ant-...

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

# =============================================================================
# OpenFGA (Phase 5: Authorization)
# =============================================================================

# --- Connection ---
SIOPV_OPENFGA_API_URL=http://localhost:8080
SIOPV_OPENFGA_STORE_ID=

# --- Model Version Pinning (recommended) ---
# SIOPV_OPENFGA_AUTHORIZATION_MODEL_ID=

# --- Authentication Method ---
# Options: "none" (default), "api_token" (pre-shared key), "client_credentials" (OIDC)
SIOPV_OPENFGA_AUTH_METHOD=none

# --- Pre-Shared Key Auth (Phase 1) ---
# SIOPV_OPENFGA_API_TOKEN=your-pre-shared-key

# --- OIDC Auth via Keycloak (Phase 2) ---
# SIOPV_OPENFGA_CLIENT_ID=siopv-openfga-client
# SIOPV_OPENFGA_CLIENT_SECRET=your-keycloak-client-secret
# SIOPV_OPENFGA_API_AUDIENCE=openfga-api
# SIOPV_OPENFGA_API_TOKEN_ISSUER=http://localhost:8180/realms/siopv

# === ML Model ===
# SIOPV_MODEL_SIGNING_KEY=
```

### 6.2 OpenFGA-Specific Variables Summary

| Variable | Required? | Phase | Description |
|----------|-----------|-------|-------------|
| `SIOPV_OPENFGA_API_URL` | Yes | All | OpenFGA server endpoint |
| `SIOPV_OPENFGA_STORE_ID` | Yes | All | Target authorization store |
| `SIOPV_OPENFGA_AUTHORIZATION_MODEL_ID` | Recommended | All | Pin specific model version |
| `SIOPV_OPENFGA_AUTH_METHOD` | Yes | All | `none`, `api_token`, or `client_credentials` |
| `SIOPV_OPENFGA_API_TOKEN` | Phase 1 | Pre-shared key | Bearer token for OpenFGA |
| `SIOPV_OPENFGA_CLIENT_ID` | Phase 2 | OIDC | Keycloak client ID |
| `SIOPV_OPENFGA_CLIENT_SECRET` | Phase 2 | OIDC | Keycloak client secret |
| `SIOPV_OPENFGA_API_AUDIENCE` | Phase 2 | OIDC | Expected JWT audience |
| `SIOPV_OPENFGA_API_TOKEN_ISSUER` | Phase 2 | OIDC | Keycloak issuer URL |

---

## 7. Docker Compose Setup

### 7.1 Phase 1: OpenFGA + Pre-Shared Key (Minimal)

```yaml
version: '3.8'

services:
  openfga:
    image: openfga/openfga:latest
    command: run
    environment:
      - OPENFGA_DATASTORE_ENGINE=postgres
      - OPENFGA_DATASTORE_URI=postgres://openfga:openfga@postgres:5432/openfga?sslmode=disable
      - OPENFGA_AUTHN_METHOD=preshared
      - OPENFGA_AUTHN_PRESHARED_KEYS=dev-preshared-key-1
      - OPENFGA_PLAYGROUND_ENABLED=true
    ports:
      - "8080:8080"   # HTTP API
      - "8081:8081"   # gRPC API
      - "3000:3000"   # Playground
    depends_on:
      openfga-migrate:
        condition: service_completed_successfully

  openfga-migrate:
    image: openfga/openfga:latest
    command: migrate
    environment:
      - OPENFGA_DATASTORE_ENGINE=postgres
      - OPENFGA_DATASTORE_URI=postgres://openfga:openfga@postgres:5432/openfga?sslmode=disable
    depends_on:
      postgres:
        condition: service_healthy

  postgres:
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
    ports:
      - "5432:5432"
    volumes:
      - openfga_data:/var/lib/postgresql/data

volumes:
  openfga_data:
```

### 7.2 Phase 2: OpenFGA + Keycloak + OIDC (Full Stack)

```yaml
version: '3.8'

services:
  # --- Keycloak (OIDC Provider) ---
  keycloak:
    image: quay.io/keycloak/keycloak:latest
    command: start-dev
    environment:
      - KEYCLOAK_ADMIN=admin
      - KEYCLOAK_ADMIN_PASSWORD=admin
      - KC_HTTP_PORT=8180
      - KC_DB=postgres
      - KC_DB_URL=jdbc:postgresql://postgres-keycloak:5432/keycloak
      - KC_DB_USERNAME=keycloak
      - KC_DB_PASSWORD=keycloak
    ports:
      - "8180:8180"   # Keycloak HTTP
    depends_on:
      postgres-keycloak:
        condition: service_healthy

  postgres-keycloak:
    image: postgres:16-alpine
    environment:
      - POSTGRES_USER=keycloak
      - POSTGRES_PASSWORD=keycloak
      - POSTGRES_DB=keycloak
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U keycloak"]
      interval: 5s
      timeout: 5s
      retries: 5
    volumes:
      - keycloak_data:/var/lib/postgresql/data

  # --- OpenFGA (Authorization Server) ---
  openfga:
    image: openfga/openfga:latest
    command: run
    environment:
      - OPENFGA_DATASTORE_ENGINE=postgres
      - OPENFGA_DATASTORE_URI=postgres://openfga:openfga@postgres-openfga:5432/openfga?sslmode=disable
      - OPENFGA_AUTHN_METHOD=oidc
      - OPENFGA_AUTHN_OIDC_ISSUER=http://keycloak:8180/realms/siopv
      - OPENFGA_AUTHN_OIDC_AUDIENCE=openfga-api
      - OPENFGA_PLAYGROUND_ENABLED=true
    ports:
      - "8080:8080"   # HTTP API
      - "8081:8081"   # gRPC API
      - "3000:3000"   # Playground
    depends_on:
      openfga-migrate:
        condition: service_completed_successfully
      keycloak:
        condition: service_started

  openfga-migrate:
    image: openfga/openfga:latest
    command: migrate
    environment:
      - OPENFGA_DATASTORE_ENGINE=postgres
      - OPENFGA_DATASTORE_URI=postgres://openfga:openfga@postgres-openfga:5432/openfga?sslmode=disable
    depends_on:
      postgres-openfga:
        condition: service_healthy

  postgres-openfga:
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
  keycloak_data:
```

### 7.3 Keycloak Bootstrap Script

After `docker compose up`, configure Keycloak:

```bash
#!/bin/bash
# scripts/setup-keycloak.sh
# Configures Keycloak realm and client for SIOPV OpenFGA integration

KEYCLOAK_URL="http://localhost:8180"
ADMIN_USER="admin"
ADMIN_PASSWORD="admin"
REALM="siopv"
CLIENT_ID="siopv-openfga-client"

# Get admin token
TOKEN=$(curl -s -X POST "$KEYCLOAK_URL/realms/master/protocol/openid-connect/token" \
  -d "grant_type=client_credentials" \
  -d "client_id=admin-cli" \
  -d "username=$ADMIN_USER" \
  -d "password=$ADMIN_PASSWORD" \
  -d "grant_type=password" | jq -r '.access_token')

# Create realm
curl -s -X POST "$KEYCLOAK_URL/admin/realms" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"realm\": \"$REALM\", \"enabled\": true}"

# Create client (confidential, service account enabled)
curl -s -X POST "$KEYCLOAK_URL/admin/realms/$REALM/clients" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "clientId": "'"$CLIENT_ID"'",
    "enabled": true,
    "clientAuthenticatorType": "client-secret",
    "serviceAccountsEnabled": true,
    "standardFlowEnabled": false,
    "directAccessGrantsEnabled": false,
    "protocolMappers": [{
      "name": "openfga-audience",
      "protocol": "openid-connect",
      "protocolMapper": "oidc-audience-mapper",
      "config": {
        "included.custom.audience": "openfga-api",
        "access.token.claim": "true"
      }
    }]
  }'

# Get client secret
CLIENT_UUID=$(curl -s "$KEYCLOAK_URL/admin/realms/$REALM/clients?clientId=$CLIENT_ID" \
  -H "Authorization: Bearer $TOKEN" | jq -r '.[0].id')

CLIENT_SECRET=$(curl -s "$KEYCLOAK_URL/admin/realms/$REALM/clients/$CLIENT_UUID/client-secret" \
  -H "Authorization: Bearer $TOKEN" | jq -r '.value')

echo "=== Keycloak Configuration Complete ==="
echo "Client ID:     $CLIENT_ID"
echo "Client Secret: $CLIENT_SECRET"
echo "Issuer URL:    $KEYCLOAK_URL/realms/$REALM"
echo "Audience:      openfga-api"
echo ""
echo "Add to your .env:"
echo "SIOPV_OPENFGA_AUTH_METHOD=client_credentials"
echo "SIOPV_OPENFGA_CLIENT_ID=$CLIENT_ID"
echo "SIOPV_OPENFGA_CLIENT_SECRET=$CLIENT_SECRET"
echo "SIOPV_OPENFGA_API_AUDIENCE=openfga-api"
echo "SIOPV_OPENFGA_API_TOKEN_ISSUER=$KEYCLOAK_URL/realms/$REALM"
```

### 7.4 OpenFGA Bootstrap Script

```bash
#!/bin/bash
# scripts/setup-openfga.sh
# Creates OpenFGA store and writes authorization model

OPENFGA_URL="http://localhost:8080"
AUTH_HEADER=""

# If using pre-shared key
if [ -n "$OPENFGA_API_TOKEN" ]; then
  AUTH_HEADER="-H 'Authorization: Bearer $OPENFGA_API_TOKEN'"
fi

# Create store
STORE_RESPONSE=$(curl -s -X POST "$OPENFGA_URL/stores" \
  $AUTH_HEADER \
  -H "Content-Type: application/json" \
  -d '{"name": "siopv"}')

STORE_ID=$(echo $STORE_RESPONSE | jq -r '.id')
echo "Store ID: $STORE_ID"

# Write authorization model (from model.fga converted to JSON)
# Use: fga model transform --file=openfga/model.fga
MODEL_RESPONSE=$(curl -s -X POST "$OPENFGA_URL/stores/$STORE_ID/authorization-models" \
  $AUTH_HEADER \
  -H "Content-Type: application/json" \
  -d @openfga/model.json)

MODEL_ID=$(echo $MODEL_RESPONSE | jq -r '.authorization_model_id')
echo "Model ID: $MODEL_ID"

echo ""
echo "Add to your .env:"
echo "SIOPV_OPENFGA_STORE_ID=$STORE_ID"
echo "SIOPV_OPENFGA_AUTHORIZATION_MODEL_ID=$MODEL_ID"
```

---

## 8. Security Considerations

### 8.1 Critical Security Requirements

| # | Requirement | Priority | Phase |
|---|-------------|----------|-------|
| 1 | **Enable authentication** — Never run `authn.method=none` in production | CRITICAL | 1 |
| 2 | **Enable TLS** — Pre-shared tokens sent as Bearer headers in plaintext without TLS | CRITICAL | 1 (prod) |
| 3 | **Disable playground** in production (`--playground-enabled=false`) | HIGH | 1 (prod) |
| 4 | **Pin authorization model version** in all check calls | HIGH | 1 |
| 5 | **Network isolation** — OpenFGA reachable only from SIOPV services | HIGH | 1 (prod) |
| 6 | **Use SecretStr** for all secrets in Settings (already done for api_token, add for client_secret) | HIGH | 1 |
| 7 | **No PII in tuples** — Store opaque user identifiers only (GDPR compliance) | HIGH | 1 |
| 8 | **Key/secret rotation plan** — Multiple pre-shared keys or OIDC token rotation | MEDIUM | 2 |
| 9 | **Structured logging** — JSON format, info level, no secrets in logs | MEDIUM | 1 |
| 10 | **Metrics and tracing** — Prometheus + OTLP for observability | MEDIUM | 2 |

### 8.2 CNCF-Flagged Security Risk

> **Critical finding from CNCF Security Assessment:** Authenticated clients can both execute authorization checks (read) AND update the authorization model (write). This means a compromised client credential could rewrite the authorization model to grant itself elevated permissions.

**Mitigation strategies (until experimental access control matures):**
1. **Network-level restriction** — Only SIOPV application services can reach OpenFGA (no direct access from user-facing services)
2. **Separate credentials** — Use different clients for read-only checks vs. model writes
3. **Monitor model changes** — Alert on any `WriteAuthorizationModel` calls in production
4. **Pin model ID** — Always specify `authorization_model_id` in check calls (prevents using unvalidated model changes)

### 8.3 OIDC-Specific Security

| Concern | Mitigation |
|---------|-----------|
| **Client secret exposure** | Store as `SecretStr`, never log, use env vars |
| **Token leakage** | SDK handles token lifecycle; tokens expire automatically |
| **OIDC provider compromise** | Monitor Keycloak logs, enable MFA for admin access |
| **JWT audience mismatch** | Configure `OPENFGA_AUTHN_OIDC_AUDIENCE` to match exactly |
| **Issuer URL spoofing** | Use HTTPS for Keycloak in production, pin issuer URL |
| **Token replay** | Short token TTL (default 5 min), TLS prevents interception |

### 8.4 Pre-Shared Key Security

| Concern | Mitigation |
|---------|-----------|
| **Key in plaintext** | TLS mandatory; use `SecretStr` in Python |
| **Key rotation** | Configure multiple keys, rotate without downtime |
| **Key compromise** | Immediately rotate all keys, audit access logs |
| **Shared across services** | Use unique keys per service when possible |

---

## 9. Migration Path: Pre-Shared Key → OIDC

### Phase 1: Pre-Shared Key (Immediate)

**Configuration:**
```bash
SIOPV_OPENFGA_AUTH_METHOD=api_token
SIOPV_OPENFGA_API_TOKEN=your-strong-random-key
```

**Server:**
```bash
OPENFGA_AUTHN_METHOD=preshared
OPENFGA_AUTHN_PRESHARED_KEYS=your-strong-random-key
```

**Advantages:** Simple setup, no external dependencies, sufficient for development and initial deployments.

**Limitations:** Keys don't expire, no revocation, weaker than cryptographic tokens.

### Phase 2: OIDC with Keycloak (When Ready)

**When to migrate:**
- When deploying to production/staging
- When multiple services need to access OpenFGA
- When compliance requires auditable authentication
- When token rotation/revocation is needed

**Migration steps:**
1. Deploy Keycloak alongside existing setup
2. Configure Keycloak realm, client, and audience mapper
3. Update OpenFGA server from `preshared` to `oidc` authentication
4. Update SIOPV `.env` from `api_token` to `client_credentials`
5. Test with both methods temporarily (OpenFGA supports only one at a time, so use a canary deployment)
6. Remove pre-shared key configuration

**Configuration:**
```bash
SIOPV_OPENFGA_AUTH_METHOD=client_credentials
SIOPV_OPENFGA_CLIENT_ID=siopv-openfga-client
SIOPV_OPENFGA_CLIENT_SECRET=keycloak-generated-secret
SIOPV_OPENFGA_API_AUDIENCE=openfga-api
SIOPV_OPENFGA_API_TOKEN_ISSUER=https://keycloak.example.com/realms/siopv
```

### Zero-Downtime Migration Strategy

Since OpenFGA supports only one authentication method at a time, use this approach:
1. Deploy new OpenFGA instance with OIDC config
2. Route a percentage of traffic to new instance
3. Verify OIDC authentication works correctly
4. Gradually shift all traffic to OIDC instance
5. Decommission pre-shared key instance

---

## 10. Current SIOPV Architecture Analysis

### 10.1 What's Already Built (Phase 5 Complete)

| Layer | Files | Status |
|-------|-------|--------|
| **Domain** | `entities.py` (558 lines), `value_objects.py` (387 lines), `exceptions.py` (293 lines) | Complete |
| **Application** | `authorization.py` ports (556 lines), `authorization.py` use cases (853 lines) | Complete |
| **Adapter** | `openfga_adapter.py` (1173 lines) | Complete (needs credential support) |
| **Infrastructure** | `authorization.py` DI (211 lines), `settings.py` OpenFGA section | Partial (needs new fields) |
| **Orchestration** | `authorization_node.py` (393 lines) | Complete |
| **Tests** | 87+ tests (unit + integration, all with mocks) | Complete (needs real server tests) |

### 10.2 Resource Types and Relations

From `value_objects.py`:

| Resource Type | Relations |
|---------------|-----------|
| `project` | owner, viewer, analyst, auditor, member, admin |
| `vulnerability` | owner, viewer, analyst, auditor, member, admin |
| `report` | owner, viewer, analyst, auditor, member, admin |
| `organization` | owner, viewer, analyst, auditor, member, admin |

### 10.3 What's Missing

| Component | Status | Impact |
|-----------|--------|--------|
| Authentication variables in `.env.example` | **Missing** | Existing `.env.example` has only basic OpenFGA config (api_url, store_id); needs 6+ auth variables added |
| Credential support in adapter | **Missing** | Only unauthenticated connections work |
| `authorization_model_id` in settings | **Missing** | Cannot pin model version |
| Docker Compose | **Missing** | No local dev environment for OpenFGA |
| `.fga` model file | **Missing** | Authorization model exists only in code enums |
| Bootstrap scripts | **Missing** | No automated store/model setup |
| Integration tests (real server) | **Missing** | All tests use mocks |

---

## 11. Implementation Roadmap

### Phase A: Configuration Foundation (Effort: Small-Medium)

| # | Task | Files | Effort |
|---|------|-------|--------|
| A1 | Update `.env.example` with authentication variables | `.env.example` | Small |
| A2 | Add 6 new OpenFGA fields to `Settings` | `settings.py` | Small |
| A3 | Update adapter `__init__` to accept new settings | `openfga_adapter.py` | Small |
| A4 | Update adapter `initialize()` with credential support | `openfga_adapter.py` | Medium |
| A5 | Update DI container to pass new settings | `authorization.py` (DI) | Small |
| A6 | Update existing tests for credential paths | Test files | Medium |

### Phase B: Infrastructure (Effort: Medium)

| # | Task | Files | Effort |
|---|------|-------|--------|
| B1 | Create Docker Compose (Phase 1: pre-shared key) | New: `docker-compose.yml` | Medium |
| B2 | Create `.fga` authorization model file | New: `openfga/model.fga` | Medium |
| B3 | Create OpenFGA bootstrap script | New: `scripts/setup-openfga.sh` | Medium |
| B4 | Add integration tests against real OpenFGA | Test files | Large |

### Phase C: OIDC Integration (Effort: Medium-Large)

| # | Task | Files | Effort |
|---|------|-------|--------|
| C1 | Add Keycloak to Docker Compose | `docker-compose.yml` | Medium |
| C2 | Create Keycloak bootstrap script | New: `scripts/setup-keycloak.sh` | Medium |
| C3 | Test OIDC flow end-to-end | Integration tests | Large |
| C4 | Document OIDC setup in project docs | Documentation | Small |

### Phase D: Production Hardening (Effort: Small-Medium)

| # | Task | Files | Effort |
|---|------|-------|--------|
| D1 | Configure TLS for OpenFGA + Keycloak | Docker/deployment config | Medium |
| D2 | Disable playground in production | Deployment config | Small |
| D3 | Enable observability (metrics + tracing) | Deployment config | Small |
| D4 | Set concurrency limits | Deployment config | Small |
| D5 | Implement key/token rotation strategy | Documentation + config | Small |

### Phase E: Zero-Trust Maturity (Effort: Large)

| # | Task | Files | Effort |
|---|------|-------|--------|
| E1 | Contextual tuples for JWT claims | Adapter/middleware | Medium |
| E2 | Shadow mode deployment | Application layer | Large |
| E3 | Smart consistency strategy | Adapter | Medium |

---

## 12. Source Reports

This final report synthesizes findings from the following research:

### Task #1: OpenFGA OIDC Authentication Requirements
- **File:** `2026-02-11-openfga-authentication-mechanisms-api-keys-preshared-tokens-oidc-client-credentials-sdk-setup-production-security-migration-patterns-comprehensive-research.md`
- **Key findings:** Three auth methods (none/preshared/oidc), SDK credential patterns, TLS requirements, migration patterns

### Task #2: OIDC Providers and Setup Options
- **File:** `2026-02-11-openfga-integration-patterns-security-best-practices-zero-trust-architecture-production-deployment-token-management-python-sdk-research.md`
- **Key findings:** Zero-trust architecture patterns, Keycloak integration, contextual tuples, consistency model, CNCF security assessment

### Task #3: Python SDK OIDC Client Credentials
- **File:** `2026-02-11-openfga-authentication-mechanisms-api-keys-preshared-tokens-oidc-client-credentials-sdk-setup-production-security-migration-patterns-comprehensive-research.md`
- **Key findings:** SDK credential configuration, api_token vs client_credentials, automatic token refresh, FastAPI integration patterns

### Task #4: SIOPV Architecture Analysis
- **File:** `2026-02-11-siopv-architecture-analysis-openfga-oidc-integration-requirements-adapter-settings-dependency-injection-authentication-infrastructure-review.md`
- **Key findings:** `.env.example` exists with basic OpenFGA config (api_url, store_id), only 2 OpenFGA settings fields (needs 6+ more), no credential support in adapter, 87+ tests all using mocks

### External Sources Referenced
- [OpenFGA Official Documentation](https://openfga.dev/docs)
- [OpenFGA Configuration Guide](https://openfga.dev/docs/getting-started/setup-openfga/configure-openfga)
- [Running OpenFGA in Production](https://openfga.dev/docs/best-practices/running-in-production)
- [OpenFGA Python SDK](https://github.com/openfga/python-sdk)
- [CNCF Security Self-Assessment](https://tag-security.cncf.io/community/assessments/projects/openfga/self-assessment/)
- [Keycloak + OpenFGA Integration Patterns](https://embesozzi.medium.com/keycloak-integration-with-openfga-based-on-zanzibar-for-fine-grained-authorization-at-scale-d3376de00f9a)
- [GoDaddy: Fine-grained Authorization with OpenFGA](https://www.godaddy.com/resources/news/authorization-oauth-openfga)
- [OpenFGA Adoption Patterns](https://openfga.dev/docs/best-practices/adoption-patterns)
