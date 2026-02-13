# OpenFGA OIDC Authentication Requirements — Comprehensive Research

**Date:** 2026-02-11
**Scope:** Server-side OIDC configuration, JWT validation, Python SDK credentials, provider requirements, and comparison with pre-shared key authentication.

---

## Table of Contents

1. [Authentication Methods Overview](#1-authentication-methods-overview)
2. [OIDC Server-Side Configuration](#2-oidc-server-side-configuration)
3. [OIDC Configuration Parameters (Complete Reference)](#3-oidc-configuration-parameters-complete-reference)
4. [JWT Validation Requirements](#4-jwt-validation-requirements)
5. [OIDC Provider Requirements](#5-oidc-provider-requirements)
6. [Python SDK Client Credentials](#6-python-sdk-client-credentials)
7. [Token Claims and Authorization Integration](#7-token-claims-and-authorization-integration)
8. [Access Control (Experimental, v1.7.0+)](#8-access-control-experimental-v170)
9. [Pre-Shared Key vs OIDC Comparison](#9-pre-shared-key-vs-oidc-comparison)
10. [Security Considerations](#10-security-considerations)
11. [Compatible OIDC Providers](#11-compatible-oidc-providers)
12. [Docker Deployment with OIDC](#12-docker-deployment-with-oidc)
13. [Sources](#13-sources)

---

## 1. Authentication Methods Overview

OpenFGA supports three authentication methods:

| Method | Enum Value | Use Case |
|--------|-----------|----------|
| None | `none` | Development only, no authentication |
| Pre-Shared Key | `preshared` | Simple deployments, static secrets |
| OIDC | `oidc` | Production, dynamic token-based auth |

The method is selected via `authn.method` configuration (default: `none`).

---

## 2. OIDC Server-Side Configuration

### 2.1 Configuration Methods

OpenFGA OIDC can be configured via three equivalent methods:

#### Environment Variables

```bash
export OPENFGA_AUTHN_METHOD=oidc
export OPENFGA_AUTHN_OIDC_ISSUER=https://your-oidc-provider.com
export OPENFGA_AUTHN_OIDC_AUDIENCE=your-api-audience
# Optional:
export OPENFGA_AUTHN_OIDC_ISSUER_ALIASES=https://alias1.com,https://alias2.com
export OPENFGA_AUTHN_OIDC_SUBJECTS=subject1,subject2
export OPENFGA_AUTHN_OIDC_CLIENT_ID_CLAIMS=azp,client_id
```

#### YAML Configuration File (`config.yaml`)

```yaml
authn:
  method: oidc
  oidc:
    issuer: "https://your-oidc-provider.com"        # required
    issuerAliases: "https://alias1.com,https://alias2.com"  # optional
    audience: "your-api-audience"                    # required
    subjects: "subject1,subject2"                    # optional
    clientIdClaims: "azp,client_id"                  # optional, defaults to azp,client_id
```

#### Command-Line Flags

```bash
openfga run \
  --authn-method=oidc \
  --authn-oidc-issuer="https://your-oidc-provider.com" \
  --authn-oidc-audience="your-api-audience" \
  --authn-oidc-issuer-aliases="https://alias1.com,https://alias2.com" \
  --authn-oidc-subjects="subject1,subject2" \
  --authn-oidc-client-id-claims="azp,client_id"
```

### 2.2 TLS Configuration (Required for Production)

OIDC authentication in production requires TLS:

```bash
export OPENFGA_HTTP_TLS_ENABLED=true
export OPENFGA_HTTP_TLS_CERT=/path/to/server.crt
export OPENFGA_HTTP_TLS_KEY=/path/to/server.key
# For gRPC:
export OPENFGA_GRPC_TLS_ENABLED=true
export OPENFGA_GRPC_TLS_CERT=/path/to/server.crt
export OPENFGA_GRPC_TLS_KEY=/path/to/server.key
```

**After configuration changes, the OpenFGA server must be restarted.**

---

## 3. OIDC Configuration Parameters (Complete Reference)

| Config File Key | Environment Variable | CLI Flag | Type | Required | Default | Description |
|----------------|---------------------|----------|------|----------|---------|-------------|
| `authn.method` | `OPENFGA_AUTHN_METHOD` | `--authn-method` | string (enum: `none`, `preshared`, `oidc`) | Yes | `none` | Authentication method |
| `authn.oidc.issuer` | `OPENFGA_AUTHN_OIDC_ISSUER` | `--authn-oidc-issuer` | string | Yes (for OIDC) | — | OIDC issuer URL (authorization server signing tokens) |
| `authn.oidc.audience` | `OPENFGA_AUTHN_OIDC_AUDIENCE` | `--authn-oidc-audience` | string | Yes (for OIDC) | — | Expected `aud` claim in JWT |
| `authn.oidc.issuerAliases` | `OPENFGA_AUTHN_OIDC_ISSUER_ALIASES` | `--authn-oidc-issuer-aliases` | []string | No | — | DNS aliases accepted when verifying JWT `iss` field |
| `authn.oidc.subjects` | `OPENFGA_AUTHN_OIDC_SUBJECTS` | `--authn-oidc-subjects` | []string | No | (all allowed) | Valid subject names for JWT `sub` field; empty = all allowed |
| `authn.oidc.clientIdClaims` | `OPENFGA_AUTHN_OIDC_CLIENT_ID_CLAIMS` | `--authn-oidc-client-id-claims` | []string | No | `azp,client_id` | Claims parsed by priority to identify the client |

### Environment Variable Naming Convention

All OpenFGA environment variables follow the pattern: `OPENFGA_` + option path in UPPERCASE with dots replaced by underscores.

---

## 4. JWT Validation Requirements

### 4.1 Token Structure Requirements

OpenFGA validates the following JWT claims:

| Claim | Validation Rule | Required |
|-------|----------------|----------|
| `iss` (Issuer) | Must exactly match the configured `issuer` or one of `issuerAliases` | Yes |
| `aud` (Audience) | Must contain the configured `audience` value | Yes |
| `sub` (Subject) | If `subjects` is configured, must match one of the allowed values | Conditional |
| `exp` (Expiration) | Token must not be expired | Yes (standard JWT) |
| `nbf` (Not Before) | If present, current time must be after this value | No (standard JWT) |
| Client ID claims | `azp` or `client_id` (or custom via `clientIdClaims`) used to identify the calling client | Used for access control |

### 4.2 JWKS Discovery Process

1. OpenFGA fetches the OIDC discovery document from `{issuer}/.well-known/openid-configuration`
2. Extracts the `jwks_uri` from the discovery document
3. Fetches the JSON Web Key Set (JWKS) from that URI
4. Caches the JWKS keys for token validation

### 4.3 Signature Validation

- **With `kid` header present:** Standard lookup — matches `kid` in JWT header to the corresponding key in JWKS
- **Without `kid` header:** Fallback mechanism (added via PR #2617) — tries signature verification against each JWKS key matching the correct algorithm; accepts if exactly one key validates
- **Supported algorithm:** RS256 (RSA Signature with SHA-256) is the expected/primary algorithm
- **Error on validation failure:** `"token is unverifiable: error while executing keyfunc: the JWT has an invalid kid: could not find kid in JWT header"` (pre-fix versions)

### 4.4 Token Transmission

Clients send the JWT as a Bearer token in the Authorization header:

```
Authorization: Bearer <JWT-TOKEN>
```

---

## 5. OIDC Provider Requirements

For an OIDC provider to be compatible with OpenFGA, it must:

### Required Capabilities

1. **OIDC Discovery endpoint:** Must expose `/.well-known/openid-configuration` at the issuer URL
2. **JWKS endpoint:** Must provide a `jwks_uri` in the discovery document with public signing keys
3. **RS256 signing:** Must sign JWTs using RS256 algorithm (recommended)
4. **Standard JWT claims:** Must include `iss`, `aud`, `exp` in issued tokens
5. **Client credentials grant support:** If using SDK client_credentials flow, must support OAuth 2.0 client credentials grant type

### Required Claims in Issued Tokens

| Claim | Purpose |
|-------|---------|
| `iss` | Issuer identifier — must match OpenFGA server configuration |
| `aud` | Audience — must match OpenFGA server configuration |
| `exp` | Expiration time |
| `sub` | Subject identifier (optional but used for access control) |
| `azp` or `client_id` | Authorized party / Client ID (used to identify calling application) |

### Optional but Useful Claims

| Claim | Purpose |
|-------|---------|
| `groups` | Group memberships (used for contextual tuples) |
| `nbf` | Not Before time |
| `iat` | Issued At time |
| Custom claims | Can be mapped via `clientIdClaims` configuration |

---

## 6. Python SDK Client Credentials

### 6.1 Authentication Methods Supported by SDK

The OpenFGA Python SDK (`openfga-sdk`) supports three authentication methods:

| Method | `method` Value | Use Case |
|--------|---------------|----------|
| No credentials | (none) | Development, unauthenticated server |
| API Token | `api_token` | Pre-shared key authentication |
| Client Credentials | `client_credentials` | OIDC with OAuth 2.0 client credentials flow |

### 6.2 Client Credentials Configuration

```python
from openfga_sdk import ClientConfiguration, OpenFgaClient
from openfga_sdk.credentials import Credentials, CredentialConfiguration

credentials = Credentials(
    method='client_credentials',
    configuration=CredentialConfiguration(
        api_issuer='https://your-oidc-provider.com/oauth/token',  # Token endpoint
        api_audience='your-api-audience',
        client_id='your-client-id',
        client_secret='your-client-secret',
    )
)

configuration = ClientConfiguration(
    api_url='http://localhost:8080',
    store_id='your-store-id',
    authorization_model_id='your-model-id',
    credentials=credentials,
)

async with OpenFgaClient(configuration) as fga_client:
    response = await fga_client.read_authorization_models()
```

### 6.3 API Token Configuration (for Pre-Shared Key)

```python
credentials = Credentials(
    method='api_token',
    configuration=CredentialConfiguration(
        api_token='your-pre-shared-key',
    )
)
```

### 6.4 Key SDK Behaviors

- **Token exchange on every request:** The client credentials flow performs token exchange on every request (unless SDK handles caching internally)
- **Singleton pattern recommended:** Initialize `OpenFgaClient` once and reuse throughout the application to avoid repeated token exchanges
- **Important caveat:** "The OpenFGA server does not support the client credentials flow natively, however if you or your OpenFGA provider have implemented a client credentials wrapper on top, the SDK can handle the token exchange for you."
  - This means: OpenFGA server validates incoming JWTs but does NOT issue tokens. The SDK obtains tokens from the OIDC provider and sends them to OpenFGA.

### 6.5 Environment Variables for SDK

| Variable | Purpose |
|----------|---------|
| `FGA_API_URL` | OpenFGA server URL |
| `FGA_STORE_ID` | Store identifier |
| `FGA_MODEL_ID` | Authorization model identifier |
| `FGA_API_TOKEN_ISSUER` | OIDC token endpoint |
| `FGA_API_AUDIENCE` | API audience |
| `FGA_CLIENT_ID` | OAuth client ID |
| `FGA_CLIENT_SECRET` | OAuth client secret |

---

## 7. Token Claims and Authorization Integration

### 7.1 Contextual Tuples from Token Claims

OpenFGA supports using JWT claims as contextual tuples for authorization checks. This enables ABAC (Attribute-Based Access Control) patterns without storing tuples persistently.

**Example token:**
```json
{
  "sub": "6b0b14af-59dc-4ff3-a46f-ad351f428726",
  "groups": ["marketing", "everyone"],
  "iss": "https://your-provider.com",
  "aud": "your-audience",
  "exp": 1234567890
}
```

**Mapping to contextual tuples:**
- User identity from `sub` claim
- Group memberships from `groups` claim
- Dynamically create tuples like `user:6b0b14af member group:marketing`

### 7.2 Key Constraints

- Contextual tuples only exist during individual API calls (not persisted)
- Work only with Check, ListObjects, and ListUsers endpoints
- Token expiration determines access window

---

## 8. Access Control (Experimental, v1.7.0+)

OpenFGA v1.7.0 introduced experimental built-in access control on top of OIDC:

### Architecture

- Requires a dedicated "control store" with its own authorization model
- Uses OIDC tokens to identify clients via `client_id` claims
- Provides store-level and module-level permissions

### Permission Levels

| Relation | Scope | Description |
|----------|-------|-------------|
| `system.admin` | Global | Highest privilege level |
| `store.admin` | Store | Full control over a store |
| `store.model_writer` | Store | Can modify authorization models |
| `store.writer` | Store | Can create/update tuples |
| `store.reader` | Store | Read-only access |

### Configuration

```bash
export OPENFGA_EXPERIMENTALS=enable-access-control
export OPENFGA_ACCESS_CONTROL_ENABLED=true
export OPENFGA_ACCESS_CONTROL_STORE_ID=<control-store-id>
export OPENFGA_ACCESS_CONTROL_MODEL_ID=<control-model-id>
```

**Note:** This feature is experimental and NOT recommended for production use yet.

---

## 9. Pre-Shared Key vs OIDC Comparison

| Aspect | Pre-Shared Key (PSK) | OIDC |
|--------|----------------------|------|
| **Setup complexity** | Simple — configure keys and use Bearer header | Moderate — requires OIDC provider, issuer/audience config |
| **Security** | Static secrets; rotation requires server restart | Dynamic tokens; short-lived; supports rotation |
| **Token type** | Static key string | JWT with claims, expiration, signature |
| **Validation** | String comparison | Cryptographic signature verification + claim validation |
| **Identity** | Anonymous (key-based) | Identity-aware (subject, client_id claims) |
| **Access control** | Global only (all keys equal) | Can differentiate clients via claims |
| **Rotation** | Requires config change + restart | Automatic via OIDC provider key rotation |
| **Scalability** | Limited (shared secret distribution) | Scales via federated identity |
| **Use case** | Development, internal services | Production, multi-tenant, external clients |
| **SDK method** | `api_token` | `client_credentials` |
| **Server config** | `OPENFGA_AUTHN_PRESHARED_KEYS=key1,key2` | `OPENFGA_AUTHN_OIDC_ISSUER` + `AUDIENCE` |
| **Client header** | `Authorization: Bearer <static-key>` | `Authorization: Bearer <JWT>` |

### When to Use Each

**Pre-Shared Key:**
- Development and testing environments
- Internal service-to-service communication in trusted networks
- Simple deployments where OIDC infrastructure is unavailable

**OIDC:**
- Production environments
- When client identity tracking is needed
- Multi-tenant deployments
- When token rotation/expiration is required
- When integrating with existing identity infrastructure

---

## 10. Security Considerations

### 10.1 Threats (from CNCF Security Assessment)

| Threat | Impact | Likelihood | Mitigation |
|--------|--------|-----------|------------|
| External IDP issues token to malicious party | High | Low | Trusted issuer verification, audience validation |
| Token replay | Medium | Medium | Short expiration times, TLS requirement |
| Key compromise (PSK) | High | Medium | Use OIDC instead; rotate keys frequently |

### 10.2 Best Practices

1. **Always use TLS** in production (both HTTP and gRPC)
2. **Set short token expiration** times to limit replay window
3. **Configure `subjects`** to restrict which entities can authenticate
4. **Use `issuerAliases`** carefully — each alias must be trusted
5. **Prefer OIDC over PSK** for production deployments
6. **Initialize SDK client once** and reuse to minimize token exchange overhead
7. **Monitor JWKS rotation** events from your OIDC provider

### 10.3 Known Limitations

- OpenFGA server does NOT issue tokens (not a token provider)
- OpenFGA server does NOT support client credentials flow natively
- Access control feature (store-level permissions) is still experimental
- JWT tokens without `kid` header required OpenFGA version with PR #2617 fix

---

## 11. Compatible OIDC Providers

Any OIDC-compliant provider works. Known integrations:

| Provider | Notes |
|----------|-------|
| **Auth0** | Created by same team; native integration, well-documented |
| **Keycloak** | Community workshops available; event publisher extension for sync |
| **Okta** | Standard OIDC compliance |
| **Azure AD** | Standard OIDC compliance |
| **Google Identity** | Standard OIDC compliance |
| **AWS Cognito** | Standard OIDC compliance |
| **Authelia** | Self-hosted option |

---

## 12. Docker Deployment with OIDC

### Docker Run

```bash
docker run --name openfga \
  --network=openfga \
  -p 3000:3000 -p 8080:8080 -p 8081:8081 \
  openfga/openfga run \
  --authn-method=oidc \
  --authn-oidc-issuer="https://your-provider.com" \
  --authn-oidc-audience="your-audience" \
  --http-tls-enabled=true \
  --http-tls-cert="/certs/server.crt" \
  --http-tls-key="/certs/server.key"
```

### Docker Compose (YAML)

```yaml
services:
  openfga:
    image: openfga/openfga:latest
    command: run
    environment:
      OPENFGA_AUTHN_METHOD: oidc
      OPENFGA_AUTHN_OIDC_ISSUER: https://your-provider.com
      OPENFGA_AUTHN_OIDC_AUDIENCE: your-audience
      OPENFGA_HTTP_TLS_ENABLED: "true"
      OPENFGA_HTTP_TLS_CERT: /certs/server.crt
      OPENFGA_HTTP_TLS_KEY: /certs/server.key
      OPENFGA_DATASTORE_ENGINE: postgres
      OPENFGA_DATASTORE_URI: postgres://user:pass@postgres:5432/openfga
    ports:
      - "3000:3000"   # Playground
      - "8080:8080"   # HTTP API
      - "8081:8081"   # gRPC API
    volumes:
      - ./certs:/certs:ro
```

---

## 13. Sources

- [Configuring OpenFGA — Official Docs](https://openfga.dev/docs/getting-started/setup-openfga/configure-openfga)
- [OpenFGA Configuration Options](https://openfga.dev/docs/getting-started/setup-openfga/configuration)
- [Setup Access Control — OpenFGA](https://openfga.dev/docs/getting-started/setup-openfga/access-control)
- [Docker Setup Guide — OpenFGA](https://openfga.dev/docs/getting-started/setup-openfga/docker)
- [Setup SDK Client — OpenFGA](https://openfga.dev/docs/getting-started/setup-sdk-client)
- [OpenFGA Python SDK — GitHub](https://github.com/openfga/python-sdk)
- [OpenFGA Python SDK — PyPI](https://pypi.org/project/openfga-sdk/)
- [Token Claims as Contextual Tuples — OpenFGA](https://openfga.dev/docs/modeling/token-claims-contextual-tuples)
- [OpenFGA Security Self-Assessment — CNCF](https://tag-security.cncf.io/community/assessments/projects/openfga/self-assessment/)
- [OIDC JWT kid issue — GitHub #2309](https://github.com/openfga/openfga/issues/2309)
- [Keycloak + OpenFGA Integration — Medium](https://embesozzi.medium.com/keycloak-integration-with-openfga-based-on-zanzibar-for-fine-grained-authorization-at-scale-d3376de00f9a)
- [Keycloak OpenFGA Workshop — GitHub](https://github.com/embesozzi/keycloak-openfga-workshop)
- [Release 1.9.3 OIDC issue — GitHub #2634](https://github.com/openfga/openfga/issues/2634)
