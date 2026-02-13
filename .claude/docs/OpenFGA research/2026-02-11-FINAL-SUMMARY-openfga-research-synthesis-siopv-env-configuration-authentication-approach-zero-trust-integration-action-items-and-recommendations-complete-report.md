# FINAL SUMMARY: OpenFGA Research Synthesis for SIOPV — Configuration, Authentication, Zero-Trust Integration & Action Items

**Date:** 2026-02-11
**Author:** final-report-synthesizer (OpenFGA Research Team)
**Project:** SIOPV (~/siopv/)
**Status:** Comprehensive synthesis of all research findings from 3 parallel research agents

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Key Findings Across All Research Tracks](#2-key-findings-across-all-research-tracks)
3. [ANSWER: Does SIOPV .env Need Updating?](#3-answer-does-siopv-env-need-updating)
4. [ANSWER: Correct Authentication Approach](#4-answer-correct-authentication-approach)
5. [ANSWER: Action Items for Zero-Trust Phase](#5-answer-action-items-for-zero-trust-phase)
6. [Detailed Gap Analysis](#6-detailed-gap-analysis)
7. [Recommended .env.example Template](#7-recommended-envexample-template)
8. [Recommended Settings.py Changes](#8-recommended-settingspy-changes)
9. [Recommended Adapter Changes](#9-recommended-adapter-changes)
10. [Infrastructure Requirements](#10-infrastructure-requirements)
11. [Migration & Adoption Strategy](#11-migration--adoption-strategy)
12. [Security Hardening Checklist](#12-security-hardening-checklist)
13. [Priority-Ordered Implementation Roadmap](#13-priority-ordered-implementation-roadmap)
14. [Source Reports](#14-source-reports)

---

## 1. Executive Summary

SIOPV has a **mature Phase 5 code-level implementation** of OpenFGA authorization (1173-line adapter, 87+ tests, domain entities, use cases, ports, and DI container). However, **the runtime configuration is critically incomplete** — the project cannot connect to a real OpenFGA server without significant configuration and infrastructure additions.

### The Three Critical Gaps

| Gap | Severity | Current State |
|-----|----------|---------------|
| **No .env/.env.example file** | HIGH | Missing entirely despite being documented in README and Phase 0 report |
| **No authentication support** | HIGH | Adapter only supports unauthenticated connections (development-only mode) |
| **No server infrastructure** | MEDIUM | No Docker Compose, no .fga model file, no bootstrap scripts |

### Bottom Line

**Yes**, the SIOPV .env needs creating from scratch (it doesn't exist). The correct authentication approach for the current phase is **pre-shared key (api_token)** with a clear migration path to OIDC. The zero-trust integration requires 13 specific action items detailed below.

---

## 2. Key Findings Across All Research Tracks

### From Authentication Research (Task #1)
- OpenFGA supports 3 auth methods: `none` (dev only), `preshared` (bearer tokens), `oidc` (JWT validation)
- OpenFGA does NOT use traditional API keys — it uses **pre-shared bearer tokens** passed as `Authorization: Bearer <token>`
- The Python SDK supports 3 credential methods: no credentials, `api_token`, and `client_credentials`
- Pre-shared keys require TLS in production; OIDC is recommended for enterprise/production
- Multiple pre-shared keys can be configured for zero-downtime rotation
- Auth0 FGA (managed service) uses client_credentials exclusively; self-hosted supports all methods

### From Integration & Zero-Trust Research (Task #2)
- OpenFGA is a CNCF Incubating project (promoted October 2025) — production-ready
- OpenFGA handles **authorization only** — authentication must come from an external identity provider
- For zero-trust: OpenFGA sits between the identity layer and application logic
- Contextual tuples enable JWT claim-based authorization without tuple synchronization
- The OpenFGA client should be initialized **once** and reused (not per-request)
- CNCF security assessment flagged that authenticated clients can both read AND write models — need least-privilege scoping
- GoDaddy production case study: OAuth2 for AuthN + OpenFGA for AuthZ, pre-shared keys, weak consistency
- Built-in access control (v1.7.0+) is experimental — not production-ready yet

### From SIOPV Configuration Analysis (Task #3)
- **No `.env` or `.env.example` file exists** despite being referenced in README and Phase 0 report
- Settings only defines 2 OpenFGA fields: `openfga_api_url` and `openfga_store_id` (both optional, None defaults)
- **Zero** authentication/credential support — no `openfga_api_token`, no OAuth fields
- No `openfga_authorization_model_id` setting for model version pinning
- `ClientConfiguration` is created with only `api_url` and `store_id` — no `credentials` parameter
- No Docker Compose, no `.fga` model file, no store bootstrapping script
- All 87+ tests use mocks — no real OpenFGA server validation exists

---

## 3. ANSWER: Does SIOPV .env Need Updating?

### Yes — it needs to be CREATED from scratch.

The `.env` and `.env.example` files **do not exist** in the project, despite documentation claiming they do (README line 12, Phase 0 report line 135). This is a critical discrepancy.

### What Must Be Added

| Variable | Purpose | Required? |
|----------|---------|-----------|
| `SIOPV_OPENFGA_API_URL` | OpenFGA server endpoint | Yes (for any connection) |
| `SIOPV_OPENFGA_STORE_ID` | Target authorization store | Yes (for any connection) |
| `SIOPV_OPENFGA_API_TOKEN` | **NEW** — Pre-shared key for authenticated access | Yes (for production) |
| `SIOPV_OPENFGA_AUTHORIZATION_MODEL_ID` | **NEW** — Pin to specific model version | Recommended |

### Additionally for OIDC (Future)

| Variable | Purpose | Required? |
|----------|---------|-----------|
| `SIOPV_OPENFGA_CLIENT_ID` | OAuth2 client ID | Only for OIDC |
| `SIOPV_OPENFGA_CLIENT_SECRET` | OAuth2 client secret | Only for OIDC |
| `SIOPV_OPENFGA_API_AUDIENCE` | OIDC audience | Only for OIDC |
| `SIOPV_OPENFGA_API_TOKEN_ISSUER` | OIDC token issuer URL | Only for OIDC |

---

## 4. ANSWER: Correct Authentication Approach

### Phase 1 (Now): Pre-Shared Key Authentication

**Why:** Simplest to implement, sufficient for local development and initial deployments, doesn't require an external identity provider.

```python
# How the adapter should create ClientConfiguration:
from openfga_sdk.credentials import Credentials, CredentialConfiguration

configuration = ClientConfiguration(
    api_url=self._api_url,
    store_id=self._store_id,
    authorization_model_id=self._model_id,  # NEW: pin model version
    credentials=Credentials(
        method='api_token',
        configuration=CredentialConfiguration(
            api_token=self._api_token,
        )
    ) if self._api_token else None,
)
```

**Server-side configuration:**
```bash
# OpenFGA server must be started with:
OPENFGA_AUTHN_METHOD=preshared
OPENFGA_AUTHN_PRESHARED_KEYS=your-secret-key-1,your-secret-key-2
```

**Requirements:**
- Enable TLS when using pre-shared keys in production (tokens sent as Bearer headers)
- Use strong, randomly generated key values
- Configure multiple keys for zero-downtime rotation

### Phase 2 (Future): OIDC Authentication

**When:** When SIOPV deploys with an identity provider (Keycloak, Auth0, Okta, etc.)

```python
configuration = ClientConfiguration(
    api_url=self._api_url,
    store_id=self._store_id,
    authorization_model_id=self._model_id,
    credentials=Credentials(
        method='client_credentials',
        configuration=CredentialConfiguration(
            client_id=self._client_id,
            client_secret=self._client_secret,
            api_audience=self._api_audience,
            api_token_issuer=self._api_token_issuer,
        )
    ),
)
```

**Why upgrade to OIDC:**
- Tokens expire and can be revoked (better security)
- Cryptographically signed (stronger than plain bearer tokens)
- Standard OAuth2 client_credentials flow (machine-to-machine)
- SDK handles token refresh automatically

### Key Insight
OpenFGA is an **authorization** engine, NOT an authentication system. It answers "can user X do Y on resource Z?" but does not handle login, tokens, or identity. The existing authentication infrastructure (whatever SIOPV uses for user identity) stays in place — OpenFGA replaces only the authorization decision layer.

---

## 5. ANSWER: Action Items for Zero-Trust Phase

### Priority 1: Configuration Foundation (CRITICAL — Do First)

1. **Create `.env.example`** with the complete OpenFGA section (see template below)
2. **Add `openfga_api_token` to `Settings`** as `SecretStr | None` for authenticated deployments
3. **Add `openfga_authorization_model_id` to `Settings`** for model version pinning
4. **Update `OpenFGAAdapter.initialize()`** to pass `credentials` to `ClientConfiguration` when token is configured

### Priority 2: Infrastructure Setup (MEDIUM — Required for Runtime)

5. **Create `docker-compose.yml`** with OpenFGA server + PostgreSQL storage backend
6. **Create `.fga` authorization model file** defining SIOPV's types (project, vulnerability, report, organization) and relations (owner, viewer, analyst, auditor, member, admin)
7. **Create a bootstrap/seed script** (`scripts/setup-openfga.sh` or Python equivalent) to:
   - Start OpenFGA via Docker
   - Create the authorization store
   - Write the authorization model
   - Output store ID and model ID for `.env`

### Priority 3: Security Hardening (HIGH — Required for Production)

8. **Enable TLS** — Configure HTTPS for OpenFGA server (HTTP TLS + optionally gRPC TLS)
9. **Disable playground** in production (`--playground-enabled=false`)
10. **Pin authorization model version** in all check calls (prevents using unvalidated model changes)
11. **Implement network isolation** — OpenFGA server should only be reachable from application services (VPC/service mesh)

### Priority 4: Adoption & Migration (STRATEGIC)

12. **Start with shadow mode** — Run OpenFGA alongside existing authorization, log discrepancies
13. **Use contextual tuples for JWT claims** — Extract group/role claims from authentication tokens and pass as contextual tuples to avoid synchronizing all user data into OpenFGA

---

## 6. Detailed Gap Analysis

| Component | Expected State | Actual State | Impact |
|-----------|---------------|--------------|--------|
| `.env.example` | Exists (per README + Phase 0 docs) | **Missing** | Cannot configure application |
| `.env` | Created from .env.example | **Missing** | No runtime config |
| Settings: `openfga_api_token` | Present for authenticated access | **Missing** | Cannot authenticate to OpenFGA server |
| Settings: `openfga_authorization_model_id` | Present for model pinning | **Missing** | Always uses latest model (non-deterministic) |
| Adapter: `credentials` param | Passed to ClientConfiguration | **Missing** | Only supports unauthenticated connections |
| Docker Compose | OpenFGA + PostgreSQL | **Missing** | No local dev environment |
| `.fga` model file | Declarative authorization model | **Missing** | Model exists only conceptually in code enums |
| Bootstrap script | Store creation + model write | **Missing** | No automated setup |
| Integration tests with real server | Validates against real OpenFGA | **Missing** | All tests use mocks |

### Code-Level Maturity (What's Already Done Well)
- Domain layer: entities, value objects, exceptions (8 files) -- COMPLETE
- Application layer: 3 Protocol interfaces, 3 use case classes -- COMPLETE
- Adapter layer: 1173-line `OpenFGAAdapter` with full SDK integration -- COMPLETE
- Infrastructure: DI container, circuit breaker, retry logic -- COMPLETE
- Tests: 87+ authorization-specific tests (unit + integration) -- COMPLETE
- LangGraph node: `authorization_node.py` (393 lines) -- COMPLETE

---

## 7. Recommended .env.example Template

```bash
# =============================================================================
# SIOPV Configuration
# =============================================================================
# Copy this file to .env and fill in the values:
#   cp .env.example .env

# === OpenFGA (Phase 5: Authorization) ===
# Required: OpenFGA server connection
SIOPV_OPENFGA_API_URL=http://localhost:8080
SIOPV_OPENFGA_STORE_ID=

# Authentication (required for production, optional for local dev)
# SIOPV_OPENFGA_API_TOKEN=              # Pre-shared key for server authentication

# Model version pinning (recommended for reproducibility)
# SIOPV_OPENFGA_AUTHORIZATION_MODEL_ID= # Specific model version ID

# === Future: OIDC Authentication (uncomment when migrating to OIDC) ===
# SIOPV_OPENFGA_AUTH_METHOD=client_credentials
# SIOPV_OPENFGA_CLIENT_ID=
# SIOPV_OPENFGA_CLIENT_SECRET=
# SIOPV_OPENFGA_API_AUDIENCE=
# SIOPV_OPENFGA_API_TOKEN_ISSUER=
```

---

## 8. Recommended Settings.py Changes

Current state (`settings.py:64-66`):
```python
# === OpenFGA ===
openfga_api_url: str | None = None
openfga_store_id: str | None = None
```

Recommended changes:
```python
from pydantic import SecretStr

# === OpenFGA ===
openfga_api_url: str | None = None
openfga_store_id: str | None = None
openfga_api_token: SecretStr | None = None                 # NEW: pre-shared key auth
openfga_authorization_model_id: str | None = None           # NEW: model version pinning
```

---

## 9. Recommended Adapter Changes

The `OpenFGAAdapter.initialize()` method currently creates `ClientConfiguration` without credentials:

```python
# CURRENT (unauthenticated only):
configuration = ClientConfiguration(
    api_url=self._api_url,
    store_id=self._store_id,
)
```

Should be updated to:

```python
# RECOMMENDED (supports authenticated + unauthenticated):
from openfga_sdk.credentials import Credentials, CredentialConfiguration

config_kwargs = {
    "api_url": self._api_url,
    "store_id": self._store_id,
}

if self._authorization_model_id:
    config_kwargs["authorization_model_id"] = self._authorization_model_id

if self._api_token:
    config_kwargs["credentials"] = Credentials(
        method="api_token",
        configuration=CredentialConfiguration(
            api_token=self._api_token.get_secret_value(),
        ),
    )

configuration = ClientConfiguration(**config_kwargs)
```

### Important SDK Notes
- Initialize `OpenFgaClient` **once** and reuse — do NOT create per request
- The Python SDK automatically retries on 429 and 5xx errors (up to 3 times)
- Use `async with OpenFgaClient(configuration) as fga_client:` for proper lifecycle management
- Use `batch_check` for operations requiring multiple permission checks

---

## 10. Infrastructure Requirements

### Minimum Docker Compose for Local Development

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
      - OPENFGA_AUTHN_PRESHARED_KEYS=dev-key-1
      - OPENFGA_PLAYGROUND_ENABLED=true  # Disable in production
    ports:
      - "8080:8080"   # HTTP API
      - "8081:8081"   # gRPC API
      - "3000:3000"   # Playground
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
    volumes:
      - openfga_data:/var/lib/postgresql/data

  migrate:
    image: openfga/openfga:latest
    command: migrate
    environment:
      - OPENFGA_DATASTORE_ENGINE=postgres
      - OPENFGA_DATASTORE_URI=postgres://openfga:openfga@postgres:5432/openfga?sslmode=disable
    depends_on:
      postgres:
        condition: service_healthy

volumes:
  openfga_data:
```

### Production Additions
- Enable TLS (`OPENFGA_HTTP_TLS_ENABLED=true` + cert/key paths)
- Disable playground (`OPENFGA_PLAYGROUND_ENABLED=false`)
- Enable metrics (`OPENFGA_METRICS_ENABLED=true`)
- Enable tracing (`OPENFGA_TRACE_ENABLED=true`, low sampling ratio ~0.3)
- Configure connection pool tuning for PostgreSQL
- Set concurrency limits appropriate to workload

---

## 11. Migration & Adoption Strategy

### Recommended: Shadow Mode + Coarse-to-Fine Progression

1. **Shadow Mode:** Deploy OpenFGA alongside existing authorization. Run both systems in parallel. Log discrepancies between old and new. Validate before full cutover.

2. **Start Coarse:** Begin by replicating existing RBAC structure (admin, editor, viewer roles). This validates the infrastructure without complex modeling.

3. **Refine Gradually:** Add fine-grained resource-level permissions (project-level, vulnerability-level access). Use modular models so teams can evolve independently.

4. **Contextual Tuples for JWT Claims:** Extract user groups/roles from authentication tokens and pass as contextual tuples to OpenFGA's Check API. This minimizes the need to synchronize all user data into stored tuples.

### Key Principles
- OpenFGA should NOT be source of truth for user profiles, entity hierarchies, or search data
- OpenFGA IS appropriate as source of truth for fine-grained permissions and role assignments
- The `Read` API is for troubleshooting, not routine data retrieval
- Store user identifiers (not PII) in relationship tuples (GDPR compliance)

---

## 12. Security Hardening Checklist

Based on CNCF security assessment and official production recommendations:

- [ ] **Authentication enabled** — Configure `preshared` or `oidc` (never `none` in production)
- [ ] **TLS enabled** — HTTP TLS and/or gRPC TLS
- [ ] **Playground disabled** in production
- [ ] **Authorization model pinned** — Specify `authorization_model_id` in all check calls
- [ ] **Network isolation** — OpenFGA reachable only from application services
- [ ] **Structured logging** — JSON format, info level
- [ ] **Metrics enabled** — Prometheus at `0.0.0.0:2112/metrics`
- [ ] **No PII in tuples** — Use opaque user identifiers only
- [ ] **Key rotation plan** — Multiple pre-shared keys for zero-downtime rotation
- [ ] **Concurrency limits** — Set `OPENFGA_RESOLVE_NODE_LIMIT` and breadth limits

### CNCF-Flagged Risk
> Authenticated clients can both execute authorization checks (read) AND update the authorization model (write). Until the experimental access control feature matures, mitigate by restricting write access at the network level.

---

## 13. Priority-Ordered Implementation Roadmap

### Phase A: Configuration (Immediate — unblocks everything)

| # | Action | Files Affected | Effort |
|---|--------|---------------|--------|
| A1 | Create `.env.example` with full OpenFGA section | New: `.env.example` | Small |
| A2 | Add `openfga_api_token: SecretStr \| None` to Settings | `settings.py` | Small |
| A3 | Add `openfga_authorization_model_id: str \| None` to Settings | `settings.py` | Small |
| A4 | Update adapter to pass credentials to ClientConfiguration | `openfga_adapter.py` | Medium |
| A5 | Update DI container to pass new settings to adapter | `authorization.py` (DI) | Small |
| A6 | Update tests for new credential flow | Test files | Medium |

### Phase B: Infrastructure (Next — enables real server testing)

| # | Action | Files Affected | Effort |
|---|--------|---------------|--------|
| B1 | Create Docker Compose for OpenFGA + PostgreSQL | New: `docker-compose.yml` | Medium |
| B2 | Create `.fga` authorization model file | New: `openfga/model.fga` | Medium |
| B3 | Create bootstrap script (store creation + model write) | New: `scripts/setup-openfga.sh` | Medium |
| B4 | Add integration tests against real OpenFGA server | Test files | Large |

### Phase C: Production Hardening (Before deployment)

| # | Action | Files Affected | Effort |
|---|--------|---------------|--------|
| C1 | Configure TLS for OpenFGA server | Docker/deployment config | Medium |
| C2 | Disable playground in production | Deployment config | Small |
| C3 | Enable observability (metrics + tracing) | Deployment config | Small |
| C4 | Set concurrency limits | Deployment config | Small |
| C5 | Implement key rotation strategy | Documentation + config | Small |

### Phase D: Zero-Trust Maturity (Ongoing)

| # | Action | Files Affected | Effort |
|---|--------|---------------|--------|
| D1 | Implement contextual tuples for JWT claims | Adapter/middleware | Medium |
| D2 | Shadow mode deployment (parallel with existing authz) | Application layer | Large |
| D3 | Migrate from pre-shared keys to OIDC | Settings + adapter | Medium |
| D4 | Implement consistency strategy (smart caching) | Adapter | Medium |

---

## 14. Source Reports

This synthesis is based on the following research reports (all in `~/.claude/docs/`):

1. **Authentication Research (Task #1):**
   `2026-02-11-openfga-authentication-mechanisms-api-keys-preshared-tokens-oidc-client-credentials-sdk-setup-production-security-migration-patterns-comprehensive-research.md`

2. **Integration & Zero-Trust Research (Task #2):**
   `2026-02-11-openfga-integration-patterns-security-best-practices-zero-trust-architecture-production-deployment-token-management-python-sdk-research.md`

3. **SIOPV Configuration Analysis (Task #3):**
   `2026-02-11-siopv-openfga-env-configuration-analysis-discrepancies-api-token-requirements-and-integration-gaps-report.md`

### External Sources Referenced (from sub-reports)
- [OpenFGA Official Docs](https://openfga.dev/docs)
- [OpenFGA Configuration](https://openfga.dev/docs/getting-started/setup-openfga/configure-openfga)
- [Running in Production](https://openfga.dev/docs/best-practices/running-in-production)
- [Adoption Patterns](https://openfga.dev/docs/best-practices/adoption-patterns)
- [CNCF Security Self-Assessment](https://tag-security.cncf.io/community/assessments/projects/openfga/self-assessment/)
- [GoDaddy: Fine-grained authorization with OpenFGA](https://www.godaddy.com/resources/news/authorization-oauth-openfga)
- [OpenFGA Python SDK](https://github.com/openfga/python-sdk)
- [OpenFGA Consistency Model](https://openfga.dev/docs/interacting/consistency)
