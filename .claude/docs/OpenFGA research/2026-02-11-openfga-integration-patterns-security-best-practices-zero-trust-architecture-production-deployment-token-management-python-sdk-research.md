# OpenFGA Integration Patterns, Security Best Practices & Zero-Trust Architecture Research

**Date:** 2026-02-11
**Researcher:** openfga-integration-researcher
**Scope:** Production integration patterns, security best practices, zero-trust architecture, authentication vs authorization, token management, Python SDK patterns

---

## Table of Contents

1. [OpenFGA Overview & Maturity](#1-openfga-overview--maturity)
2. [Production Deployment Best Practices](#2-production-deployment-best-practices)
3. [Authentication vs Authorization](#3-authentication-vs-authorization)
4. [Server Authentication Configuration](#4-server-authentication-configuration)
5. [Zero-Trust Architecture Patterns](#5-zero-trust-architecture-patterns)
6. [Token Management & Contextual Tuples](#6-token-management--contextual-tuples)
7. [Consistency Model & Caching](#7-consistency-model--caching)
8. [Access Control on the OpenFGA Server](#8-access-control-on-the-openfga-server)
9. [Adoption Patterns & Migration Strategies](#9-adoption-patterns--migration-strategies)
10. [Source of Truth Principles](#10-source-of-truth-principles)
11. [Python SDK Integration Patterns](#11-python-sdk-integration-patterns)
12. [Real-World Production Case Study: GoDaddy](#12-real-world-production-case-study-godaddy)
13. [CNCF Security Assessment Findings](#13-cncf-security-assessment-findings)
14. [Recommendations for SIOPV Integration](#14-recommendations-for-siopv-integration)
15. [Sources](#15-sources)

---

## 1. OpenFGA Overview & Maturity

OpenFGA is an open-source fine-grained authorization system inspired by Google's Zanzibar. It combines **Relationship-Based Access Control (ReBAC)** and **Attribute-Based Access Control (ABAC)** with a domain-specific language for modeling authorization.

### CNCF Status
- **Incubating project** (promoted October 28, 2025)
- Passed CNCF due diligence for security posture, documentation, community health, and adoption metrics
- Active contributors include Docker, Grafana Labs, Zuplo, TwinTag, Canonical (LXD), and GoDaddy

### Key Capabilities
- Sub-millisecond authorization checks at scale
- Stateless server design (horizontally scalable)
- Storage backends: PostgreSQL, MySQL, SQLite, in-memory
- SDKs for Python, Go, JavaScript, Java, C#, and more
- gRPC and HTTP APIs
- OpenTelemetry integration for observability
- Helm charts for Kubernetes deployment

---

## 2. Production Deployment Best Practices

### Security Configuration (CRITICAL)
| Setting | Recommendation |
|---------|---------------|
| **Authentication** | Enable pre-shared key or OIDC (never run unauthenticated in production) |
| **TLS** | Enable HTTP TLS and/or gRPC TLS |
| **Playground** | Disable in production (`--playground-enabled=false`) |
| **Logging** | Set to JSON format, info level; never disable logging |

### Database Configuration
- Place the database in the **same datacenter/network** as OpenFGA servers to minimize latency
- Reserve the database **exclusively for OpenFGA** to enable independent scaling
- Run `openfga migrate` before first use to ensure proper indexing
- **Connection pool tuning:**
  - `OPENFGA_DATASTORE_MAX_OPEN_CONNS` = DB max connections / number of instances
  - `OPENFGA_DATASTORE_MAX_IDLE_CONNS` = high enough to avoid reconnection cycles
  - `OPENFGA_DATASTORE_CONN_MAX_IDLE_TIME` = longer rather than shorter

### Cluster Topology
- Favor **smaller pools of high-capacity servers** over large pools of modest ones (optimizes cache hit ratios)
- Enable in-memory caching for Check API (reduces latency, increases staleness)
- Maintain dedicated server pool management

### Concurrency Limits
| Setting | Purpose |
|---------|---------|
| `OPENFGA_MAX_CONCURRENT_READS_FOR_LIST_OBJECTS` | Limit ListObjects query concurrency |
| `OPENFGA_MAX_CONCURRENT_READS_FOR_LIST_USERS` | Limit ListUsers query concurrency |
| `OPENFGA_MAX_CONCURRENT_READS_FOR_CHECK` | Limit Check query concurrency |
| `OPENFGA_RESOLVE_NODE_LIMIT` | Restrict query resolution depth |
| `OPENFGA_RESOLVE_NODE_BREADTH_LIMIT` | Constrain concurrent userset evaluations |

### Observability
- **Metrics:** Prometheus format at `0.0.0.0:2112/metrics`
- **Tracing:** OTLP format, use low sampling ratio (e.g., 0.3) in production
- **Logging:** Structured JSON, info level minimum
- **Health checks:** `/healthz` (HTTP) and gRPC health check

---

## 3. Authentication vs Authorization

### Clear Distinction
- **Authentication (AuthN):** Verifies *who* a user is (identity). Handled by identity providers (Auth0, Keycloak, Okta, Azure AD).
- **Authorization (AuthZ):** Determines *what* a user can do (permissions). This is OpenFGA's domain.

### Why Separation Matters
Authorization presents a more demanding architectural challenge than authentication because it deals with more complexity and far more data points. Decoupling authorization from identity management and delegating it to OpenFGA (designed specifically for authorization at scale) is the recommended approach.

### Integration Pattern
```
User → Identity Provider (AuthN) → JWT/Token → Application → OpenFGA (AuthZ) → Allow/Deny
```

OpenFGA does **not** handle:
- User login/registration
- Password management
- Multi-factor authentication
- Session management

OpenFGA **does** handle:
- Permission checks (`Check` API)
- Relationship management (tuple storage)
- Permission listing (`ListObjects`, `ListUsers`)
- Model-based authorization evaluation

---

## 4. Server Authentication Configuration

### Method 1: Pre-Shared Key (Simpler, Good for Internal Services)

```yaml
# config.yaml
authn:
  method: preshared
  preshared:
    keys:
      - "key1"
      - "key2"
```

Clients must send: `Authorization: Bearer <YOUR-KEY-HERE>`

**Requirements:**
- MUST enable HTTP TLS when using pre-shared keys
- Keys should be rotated regularly
- Multiple keys supported for zero-downtime rotation

### Method 2: OIDC (Recommended for Production)

```yaml
# config.yaml
authn:
  method: oidc
  oidc:
    issuer: "https://your-idp.example.com"
    audience: "your-api-audience"
    issuer_aliases: []  # optional
    subjects: []  # optional validation
```

**Requirements:**
- Requires OIDC-compatible identity provider
- More secure than pre-shared keys
- Supports client_credentials flow for service-to-service
- TLS recommended

### Method 3: No Authentication (Development Only)
Default setting. **NEVER use in production.**

---

## 5. Zero-Trust Architecture Patterns

### OpenFGA's Role in Zero Trust
OpenFGA serves as a **relationship-based authorization engine** within zero-trust ecosystems. It enforces the zero-trust principle of **continuous verification** by providing:
- High-performance authorization decisions for every access request
- Fine-grained permission modeling
- Centralized policy management decoupled from application code

### Position in the Zero-Trust Stack

```
┌─────────────────────────────────────┐
│        Network Security Layer       │  (Istio, Cilium, etc.)
├─────────────────────────────────────┤
│      Identity & Authentication      │  (Keycloak, Auth0, Okta)
├─────────────────────────────────────┤
│    Fine-Grained Authorization       │  ← OpenFGA (ReBAC + ABAC)
├─────────────────────────────────────┤
│       Application Logic             │  (Your services)
├─────────────────────────────────────┤
│         Data Layer                  │  (PostgreSQL, etc.)
└─────────────────────────────────────┘
```

### Strengths for Zero Trust
- Fast and scalable, built for high-throughput environments
- Strong fit for relationship-based access models
- Active development backed by Auth0/Okta and CNCF
- Straightforward integration through well-documented APIs

### Known Gaps (Requires Supplementary Tools)
- Focuses exclusively on relationship-based authorization; limited standalone ABAC
- No identity/context capabilities—requires external identity providers
- Enterprise audit logging and multi-tenancy are "maturing but not as extensive"
- Compared to OPA: trades broader policy flexibility for specialized performance in relationship scenarios

### Recommended Complementary Tools
| Layer | Tool | Purpose |
|-------|------|---------|
| Identity | Keycloak/Auth0 | Authentication, user management |
| Network | Istio/Cilium | Service mesh, mTLS |
| Policy | OPA (optional) | General policy enforcement |
| Authorization | **OpenFGA** | Fine-grained relationship-based access |
| Secrets | Vault | Secret management |

---

## 6. Token Management & Contextual Tuples

### Core Concept
Contextual tuples allow authorization checks based on **dynamic relationships not stored in OpenFGA**. Instead of synchronizing all user data as stored tuples, applications can pass token claims at check time.

### OIDC Token Integration Flow

```
1. User authenticates → receives JWT from IdP
2. Application extracts claims from JWT (groups, roles, etc.)
3. Application creates contextual tuples from claims
4. Passes contextual tuples to OpenFGA Check API
5. OpenFGA evaluates using BOTH stored tuples + contextual tuples
```

### Example: Using JWT Group Claims

```python
# Extract groups from JWT token
groups = token_claims.get("groups", [])

# Create contextual tuples
contextual_tuples = [
    ClientTuple(
        user=f"group:{group}",
        relation="member",
        object=f"user:{user_id}"
    )
    for group in groups
]

# Check authorization with contextual tuples
response = await fga_client.check(
    ClientCheckRequest(
        user=f"user:{user_id}",
        relation="viewer",
        object=f"document:{doc_id}",
    ),
    options={"contextual_tuples": contextual_tuples}
)
```

### Important Limitations
- Contextual tuples **do not persist**; they exist only for the current request
- Supported only on `Check`, `ListObjects`, and `ListUsers` API endpoints
- **NOT** supported on `Read`, `Expand`, or `ReadChanges` endpoints
- Token-based access persists until token expiration, even if underlying relationships change

### When to Use Contextual Tuples vs Stored Tuples

| Scenario | Approach |
|----------|----------|
| Relatively static relationships (user owns document) | Stored tuples |
| Dynamic/session-based claims (user groups from JWT) | Contextual tuples |
| Data already in token (no extra lookup needed) | Contextual tuples |
| Need to query with Read/Expand/ReadChanges | Stored tuples |
| High-frequency relationships that change often | Contextual tuples |

---

## 7. Consistency Model & Caching

### Two Consistency Modes

| Mode | Behavior | Use When |
|------|----------|----------|
| `MINIMIZE_LATENCY` (default) | Serves from cache when possible | Performance-critical reads, eventual consistency OK |
| `HIGHER_CONSISTENCY` | Skips cache, queries DB directly | Immediately after writes, security-critical checks |

### Caching Behavior
- **Caching disabled (default):** All queries have strong consistency regardless of mode
- **Caching enabled:** Only `MINIMIZE_LATENCY` queries use the cache
- **Applies to:** Check queries and partially to ListObjects
- **Configurable:** TTL, item limits, iterator caching via command-line flags

### Recommended Runtime Strategy

```python
# Smart consistency selection based on resource freshness
cache_ttl = 30  # seconds, match your OpenFGA cache TTL

if resource.modified_date > (now - cache_ttl):
    # Recent modification — use higher consistency
    consistency = ConsistencyPreference.HIGHER_CONSISTENCY
else:
    # Stable resource — cache is safe
    consistency = ConsistencyPreference.MINIMIZE_LATENCY

response = await fga_client.check(
    request,
    options={"consistency": consistency}
)
```

### Consistency Tokens (Future/Planned)
Inspired by Zanzibar's "Zookies": store tokens from write operations and reference them in subsequent queries for deterministic consistency guarantees.

---

## 8. Access Control on the OpenFGA Server

### Experimental Feature (v1.7.0+)
OpenFGA introduced built-in access control to restrict which clients can perform which operations.

**WARNING:** This feature is experimental and **not recommended for production** as of the current release.

### How It Works
- Uses a dedicated "control store" with its own authorization model
- Requires OIDC authentication
- Supports roles: `admin`, `model_writer`, `writer`, `reader` per store
- Module-level access restricts tuple writing to specific namespaced modules

### Configuration
```bash
OPENFGA_EXPERIMENTALS=enable-access-control
OPENFGA_ACCESS_CONTROL_ENABLED=true
OPENFGA_ACCESS_CONTROL_STORE_ID=<store-id>
OPENFGA_ACCESS_CONTROL_MODEL_ID=<model-id>
```

### Implication for SIOPV
Until access control matures, use **network-level isolation** (VPC, service mesh) combined with **pre-shared keys or OIDC** to restrict access to the OpenFGA server.

---

## 9. Adoption Patterns & Migration Strategies

### Pattern 1: Coarse-to-Fine-Grained Progression
Start with simple RBAC models replicating existing permissions, then evolve toward granular controls. Changes to the authorization model don't require changes to application check calls.

### Pattern 2: Hybrid Data Management
Combine stored tuples with contextual tuples. Use contextual tuples for data already available in tokens while synchronizing other data to OpenFGA.

### Pattern 3: JWT Enrichment Strategy
Use OpenFGA to generate authorization claims for tokens. Applications continue using token claims. Over time, migrate to direct `Check` API calls.

### Pattern 4: Shadow Mode Deployment
Run OpenFGA in parallel with existing authorization. Log discrepancies between systems. Analyze results before full cutover. This validates configurations and measures performance impact.

### Pattern 5: Wrapper Services
Wrap OpenFGA with domain-specific authorization services. Trade-off: adds latency but provides cleaner domain APIs.

### Organizational Adoption
- Enable independent team evolution through modular models
- Each team can independently evolve authorization policies
- Version models, test in staging stores, promote via CI/CD

---

## 10. Source of Truth Principles

### OpenFGA Should NOT Be Source of Truth For:
- **User profile data** → Identity providers (Auth0, Okta, Azure AD)
- **Entity hierarchies** → Application databases (project/ticket, folder/document)
- **Search/filtering data** → Application databases (better optimization, parallel permission checking)

### OpenFGA IS Appropriate as Source of Truth For:
- **Fine-grained permissions** → Direct user-to-resource permissions (e.g., document sharing)
- **Role membership** → When no other system manages role assignments (but role metadata still in app DB)

### Key Principle
The `Read` endpoint serves primarily for **troubleshooting consistency issues**, not routine data retrieval. OpenFGA is an authorization engine, not a general-purpose database.

---

## 11. Python SDK Integration Patterns

### Installation
```bash
pip install openfga_sdk
```

### Client Initialization (CRITICAL: Initialize Once, Reuse)

```python
from openfga_sdk import ClientConfiguration, OpenFgaClient
from openfga_sdk.credentials import Credentials, CredentialConfiguration

# Pre-shared key authentication
configuration = ClientConfiguration(
    api_url="http://openfga:8080",
    store_id="your-store-id",
    authorization_model_id="your-model-id",
    credentials=Credentials(
        method='api_token',
        configuration=CredentialConfiguration(
            api_token="your-pre-shared-key"
        )
    )
)

# OIDC client credentials authentication
configuration = ClientConfiguration(
    api_url="http://openfga:8080",
    store_id="your-store-id",
    authorization_model_id="your-model-id",
    credentials=Credentials(
        method='client_credentials',
        configuration=CredentialConfiguration(
            api_issuer="https://your-idp.example.com",
            api_audience="your-api-audience",
            client_id="your-client-id",
            client_secret="your-client-secret",
        )
    )
)
```

**IMPORTANT:** The `OpenFgaClient` should only be initialized **once** and then re-used. Re-initializing per request incurs:
- Initialization overhead
- Reduced connection pooling
- Extra cost in client_credentials flow (token fetching)

### Core Operations

```python
async with OpenFgaClient(configuration) as fga_client:
    # Check permission
    response = await fga_client.check(ClientCheckRequest(
        user="user:alice",
        relation="viewer",
        object="document:budget",
    ))
    # response.allowed -> bool

    # Write relationship tuple
    await fga_client.write_tuples([
        ClientTuple(
            user="user:alice",
            relation="editor",
            object="document:budget",
        )
    ])

    # List objects a user can access
    response = await fga_client.list_objects(ClientListObjectsRequest(
        user="user:alice",
        relation="viewer",
        type="document",
    ))
    # response.objects -> ["document:budget", ...]

    # Batch check (multiple permissions at once)
    response = await fga_client.batch_check([
        ClientCheckRequest(user="user:alice", relation="viewer", object="document:1"),
        ClientCheckRequest(user="user:alice", relation="editor", object="document:2"),
    ])
```

### Sync Client (for non-async contexts)
```python
from openfga_sdk.sync import OpenFgaClient as SyncOpenFgaClient

with SyncOpenFgaClient(configuration) as fga_client:
    response = fga_client.check(...)
```

### Retry Behavior
The client automatically retries API requests **up to 3 times** on 429 (rate limit) and 5xx errors.

### FastAPI Integration Pattern

```python
from fastapi import FastAPI, Depends, HTTPException
from openfga_sdk import ClientConfiguration, OpenFgaClient, ClientCheckRequest

app = FastAPI()

# Initialize ONCE at startup
fga_config = ClientConfiguration(
    api_url=settings.OPENFGA_API_URL,
    store_id=settings.OPENFGA_STORE_ID,
    authorization_model_id=settings.OPENFGA_MODEL_ID,
    credentials=Credentials(
        method='api_token',
        configuration=CredentialConfiguration(
            api_token=settings.OPENFGA_API_TOKEN
        )
    )
)

async def get_fga_client():
    async with OpenFgaClient(fga_config) as client:
        yield client

async def require_permission(relation: str, object_type: str):
    async def check(
        user_id: str = Depends(get_current_user),
        fga: OpenFgaClient = Depends(get_fga_client),
        resource_id: str = ...,
    ):
        response = await fga.check(ClientCheckRequest(
            user=f"user:{user_id}",
            relation=relation,
            object=f"{object_type}:{resource_id}",
        ))
        if not response.allowed:
            raise HTTPException(status_code=403, detail="Forbidden")
    return check
```

---

## 12. Real-World Production Case Study: GoDaddy

### Architecture
GoDaddy uses a two-pronged approach: **OAuth 2.0 for authentication** + **OpenFGA for fine-grained authorization**.

### Token Integration
- `sub` claim contains valid OpenFGA user strings: `$user:$user_id`
- Maintains a scope database linking OAuth scopes to OpenFGA types/relations

### Solving Wildcard Limitations
OpenFGA doesn't support wildcard object IDs (`domain:*`). GoDaddy's solution:
- Introduced "api types" (static global objects like `domains_api:global`)
- Used contextual tuples for service-wide permissions
- Avoids creating excessive individual tuples per resource

### Design Principles
- **One Check call per operation** against a single relation
- Authorization complexity abstracted into **client libraries**
- API developers focus on business logic, not authorization implementation

### Consistency Choice
- Deliberately chose **weak consistency semantics**
- Custom DynamoDB storage adapter (instead of PostgreSQL)
- Tolerate brief replication delays across regions

---

## 13. CNCF Security Assessment Findings

### Key Threats Identified

| Threat | Attack Vector | Impact | Likelihood |
|--------|---------------|--------|-----------|
| Compromised client credentials | Elevation of privilege | **High** | **High** |
| Malicious IdP | Spoofing | High | Low |
| Leaked pre-shared key | Information disclosure | High | Low |
| DoS via graph traversal | Resource exhaustion | Medium | Low |
| Flawed authorization model | Privilege escalation | High | Low |

### Critical Finding
> "Authenticated clients can both execute authorization checks (read) and update the authorization model (write)" — this risks elevation of privilege through compromised clients.

### Security Controls Implemented
- Input validation and payload verification
- Restricts simultaneous paths explored and depth of traversal (DoS protection)
- Request rate limiting and throttling
- Semantic model verification prevents cyclical definitions
- CodeQL + Semgrep SAST scanning
- Snyk + FOSSA dependency analysis
- OpenSSF Best Practices badge

### Recommendations from Assessment
1. Implement **least-privilege authorization scoping** for authenticated clients
2. Verify trusted IdP configurations before deployment
3. Enforce **model version specification** in all authorization check calls
4. Store **user identifiers, not PII**, in relationship tuples (GDPR)
5. Monitor **eventual consistency implications** in distributed deployments

---

## 14. Recommendations for SIOPV Integration

### Architecture Recommendations

1. **Use Pre-Shared Key Auth Initially**, migrate to OIDC when IdP is available
   - Configure via `OPENFGA_API_TOKEN` environment variable
   - Always enable TLS in production

2. **PostgreSQL as Storage Backend**
   - Co-locate with OpenFGA in same network
   - Dedicated database for OpenFGA (not shared with application)
   - Run `openfga migrate` before first deployment

3. **Python SDK Integration**
   - Initialize `OpenFgaClient` once at application startup
   - Use async client for FastAPI integration
   - Implement authorization middleware/dependency injection
   - Use `batch_check` for operations requiring multiple permission checks

4. **Consistency Strategy**
   - Start with caching **disabled** for simplicity and strong consistency
   - Enable caching later when performance requires it
   - Implement smart consistency selection based on resource freshness

5. **Security Hardening**
   - Disable playground in production
   - Enable TLS (HTTP and/or gRPC)
   - Use structured JSON logging
   - Configure concurrency limits appropriate to workload
   - Pin authorization model version in all check calls
   - Never store PII in tuples — use opaque identifiers

6. **Zero-Trust Integration**
   - OpenFGA handles authorization only — pair with identity provider for authentication
   - Enforce authorization checks on every request (no caching of allow decisions in application)
   - Use contextual tuples for session/token-based dynamic attributes
   - Implement network-level isolation until server access control matures

7. **Adoption Strategy**
   - Start with shadow mode: run OpenFGA alongside existing authz, compare results
   - Begin with coarse RBAC model, refine to fine-grained over time
   - Use contextual tuples for JWT claims to minimize tuple synchronization burden

---

## 15. Sources

- [OpenFGA Best Practices](https://openfga.dev/docs/best-practices)
- [Running OpenFGA in Production](https://openfga.dev/docs/best-practices/running-in-production)
- [OpenFGA Adoption Patterns](https://openfga.dev/docs/best-practices/adoption-patterns)
- [OpenFGA Source of Truth](https://openfga.dev/docs/best-practices/source-of-truth)
- [OpenFGA Configuration](https://openfga.dev/docs/getting-started/setup-openfga/configure-openfga)
- [OpenFGA Access Control](https://openfga.dev/docs/getting-started/setup-openfga/access-control)
- [Token Claims as Contextual Tuples](https://openfga.dev/docs/modeling/token-claims-contextual-tuples)
- [Query Consistency Modes](https://openfga.dev/docs/interacting/consistency)
- [OpenFGA Python SDK](https://github.com/openfga/python-sdk)
- [CNCF Security Self-Assessment](https://tag-security.cncf.io/community/assessments/projects/openfga/self-assessment/)
- [OpenFGA Becomes CNCF Incubating](https://www.cncf.io/blog/2025/11/11/openfga-becomes-a-cncf-incubating-project/)
- [GoDaddy: Fine-grained authorization with OpenFGA and OAuth](https://www.godaddy.com/resources/news/authorization-oauth-openfga)
- [Cerbos: 20 Open-Source Tools for Zero Trust Architecture](https://www.cerbos.dev/blog/20-open-source-tools-for-zero-trust-architecture)
- [Auth0: RBAC with FGA and FastAPI](https://auth0.com/blog/implementing-rbac-fastapi-auth0-fga/)
- [Keycloak + OpenFGA Integration](https://embesozzi.medium.com/keycloak-integration-with-openfga-based-on-zanzibar-for-fine-grained-authorization-at-scale-d3376de00f9a)
