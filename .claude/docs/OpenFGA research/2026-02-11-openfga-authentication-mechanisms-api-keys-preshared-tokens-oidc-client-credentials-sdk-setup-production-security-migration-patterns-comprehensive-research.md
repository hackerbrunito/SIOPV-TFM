# OpenFGA Authentication Mechanisms: Comprehensive Research Report

**Date:** 2026-02-11
**Task:** Research OpenFGA authentication mechanisms and API key usage patterns
**Sources:** Official OpenFGA documentation (openfga.dev), Auth0 FGA docs (docs.fga.dev), GitHub repositories

---

## Table of Contents

1. [Overview of Authentication Methods](#1-overview-of-authentication-methods)
2. [No Authentication (Development Only)](#2-no-authentication-development-only)
3. [Pre-Shared Key Authentication](#3-pre-shared-key-authentication)
4. [OIDC Authentication](#4-oidc-authentication)
5. [SDK Client Authentication Setup](#5-sdk-client-authentication-setup)
6. [Access Control (Experimental v1.7.0+)](#6-access-control-experimental-v170)
7. [TLS Configuration](#7-tls-configuration)
8. [Auth0 FGA vs OpenFGA (Self-Hosted)](#8-auth0-fga-vs-openfga-self-hosted)
9. [Migration Patterns](#9-migration-patterns)
10. [Production Security Recommendations](#10-production-security-recommendations)
11. [Complete Configuration Reference](#11-complete-configuration-reference)

---

## 1. Overview of Authentication Methods

OpenFGA supports **three authentication approaches** for securing API endpoints:

| Method | Env Value | Use Case | Production Ready |
|--------|-----------|----------|------------------|
| `none` | `OPENFGA_AUTHN_METHOD=none` | Development/testing only | No |
| `preshared` | `OPENFGA_AUTHN_METHOD=preshared` | Simple deployments, internal services | Yes (with TLS) |
| `oidc` | `OPENFGA_AUTHN_METHOD=oidc` | Production, enterprise environments | Yes (recommended) |

**Key Insight:** OpenFGA does NOT use traditional "API keys" in the way many SaaS APIs do. Instead, it uses **pre-shared bearer tokens** (similar to API keys but passed as `Authorization: Bearer <token>`) or **OIDC JWT validation**.

---

## 2. No Authentication (Development Only)

- Default configuration (`authn.method: none`)
- All API endpoints are open and unauthenticated
- **Never use in production**
- Useful for local development and testing

---

## 3. Pre-Shared Key Authentication

### How It Works

- One or more secret keys are configured on the server
- Clients must include `Authorization: Bearer <YOUR-KEY-HERE>` header on every request
- The server validates the bearer token against its configured list of keys
- Multiple keys can be configured (useful for key rotation)

### Configuration

**YAML (config.yaml):**
```yaml
authn:
  method: preshared
  preshared:
    keys: ["key1", "key2"]
```

**Environment Variables:**
```bash
export OPENFGA_AUTHN_METHOD=preshared
export OPENFGA_AUTHN_PRESHARED_KEYS=key1,key2
```

**Docker:**
```bash
docker run --name openfga -p 3000:3000 openfga/openfga run \
  --authn-method=preshared \
  --authn-preshared-keys="key1,key2"
```

**CLI Flags:**
```bash
openfga run --authn-method=preshared --authn-preshared-keys="key1,key2"
```

### Important Notes

- Keys are plain strings — use strong, randomly generated values
- **TLS is mandatory** when using pre-shared keys in production (otherwise tokens are sent in plaintext)
- Multiple keys allow zero-downtime key rotation
- The `FGA_API_TOKEN` environment variable is the standard way SDKs reference the key

---

## 4. OIDC Authentication

### How It Works

- OpenFGA validates JWT tokens from a configured OIDC provider
- Requires an OIDC issuer URL and audience
- The server fetches the OIDC discovery document and validates tokens against the provider's public keys
- Supports optional issuer aliases and subject restrictions

### Configuration

**YAML (config.yaml):**
```yaml
authn:
  method: oidc
  oidc:
    issuer: "https://your-identity-provider.com/"
    audience: "your-openfga-audience"
    issuerAliases: ["https://alias1.com/", "https://alias2.com/"]
    subjects: ["valid-subject-1", "valid-subject-2"]
```

**Environment Variables:**
```bash
export OPENFGA_AUTHN_METHOD=oidc
export OPENFGA_AUTHN_OIDC_ISSUER=https://your-identity-provider.com/     # Required
export OPENFGA_AUTHN_OIDC_AUDIENCE=your-openfga-audience                   # Required
export OPENFGA_AUTHN_OIDC_ISSUER_ALIASES=https://alias1.com/,https://alias2.com/  # Optional
export OPENFGA_AUTHN_OIDC_SUBJECTS=subject1,subject2                       # Optional
```

**Docker:**
```bash
docker run --name openfga -p 3000:3000 openfga/openfga run \
  --authn-method=oidc \
  --authn-oidc-issuer="https://your-identity-provider.com/" \
  --authn-oidc-audience="your-openfga-audience"
```

### OIDC Client ID Claims

The server identifies clients using OIDC token claims. By default, it checks `azp` (authorized party) or `client_id` claims. Customizable via:

```bash
export OPENFGA_AUTHN_OIDC_CLIENT_ID_CLAIMS=azp,client_id
```

### Important Notes

- **More secure than pre-shared keys** — tokens expire, can be revoked, and are cryptographically signed
- Recommended for production environments
- The OpenFGA server itself does NOT implement the client credentials flow — it only validates tokens. A separate OIDC provider (Auth0, Keycloak, Okta, etc.) must issue the tokens.

---

## 5. SDK Client Authentication Setup

### Three SDK Credential Methods

The OpenFGA SDKs support three credential methods:

#### Method 1: No Credentials (Development)

**Python:**
```python
from openfga_sdk import OpenFgaClient, ClientConfiguration

configuration = ClientConfiguration(
    api_url=os.environ.get('FGA_API_URL'),
    store_id=os.environ.get('FGA_STORE_ID'),
    authorization_model_id=os.environ.get('FGA_MODEL_ID'),
)
async with OpenFgaClient(configuration) as fga_client:
    response = await fga_client.read_authorization_models()
```

#### Method 2: API Token (Pre-Shared Key)

**Python:**
```python
from openfga_sdk import OpenFgaClient, ClientConfiguration
from openfga_sdk.credentials import CredentialConfiguration, Credentials

configuration = ClientConfiguration(
    api_url=os.environ.get('FGA_API_URL'),
    store_id=os.environ.get('FGA_STORE_ID'),
    credentials=Credentials(
        method='api_token',
        configuration=CredentialConfiguration(
            api_token=os.environ.get('FGA_API_TOKEN'),
        )
    )
)
```

**JavaScript/Node.js:**
```javascript
const { OpenFgaClient, CredentialsMethod } = require('@openfga/sdk');

const fgaClient = new OpenFgaClient({
    apiUrl: process.env.FGA_API_URL,
    storeId: process.env.FGA_STORE_ID,
    credentials: {
        method: CredentialsMethod.ApiToken,
        config: { token: process.env.FGA_API_TOKEN },
    }
});
```

**Go:**
```go
import (
    openfga "github.com/openfga/go-sdk/client"
    "github.com/openfga/go-sdk/credentials"
)

fgaClient, err := openfga.NewSdkClient(&openfga.ClientConfiguration{
    ApiUrl:  os.Getenv("FGA_API_URL"),
    StoreId: os.Getenv("FGA_STORE_ID"),
    Credentials: &credentials.Credentials{
        Method: credentials.CredentialsMethodApiToken,
        Config: &credentials.Config{
            ApiToken: os.Getenv("FGA_API_TOKEN"),
        },
    },
})
```

#### Method 3: Client Credentials (OIDC)

**Important:** The OpenFGA server does NOT implement the client credentials flow. This method is for when you (or your provider, e.g., Auth0 FGA) have implemented a client credentials wrapper. The SDK handles the OAuth2 token exchange automatically.

**Python:**
```python
configuration = ClientConfiguration(
    api_url=os.environ.get('FGA_API_URL'),
    store_id=os.environ.get('FGA_STORE_ID'),
    credentials=Credentials(
        method='client_credentials',
        configuration=CredentialConfiguration(
            client_id=os.environ.get('FGA_CLIENT_ID'),
            client_secret=os.environ.get('FGA_CLIENT_SECRET'),
            api_audience=os.environ.get('FGA_API_AUDIENCE'),
            api_token_issuer=os.environ.get('FGA_API_TOKEN_ISSUER'),
        )
    )
)
```

**Go:**
```go
Credentials: &credentials.Credentials{
    Method: credentials.CredentialsMethodClientCredentials,
    Config: &credentials.Config{
        ClientCredentialsClientId:       os.Getenv("FGA_CLIENT_ID"),
        ClientCredentialsClientSecret:   os.Getenv("FGA_CLIENT_SECRET"),
        ClientCredentialsApiAudience:    os.Getenv("FGA_API_AUDIENCE"),
        ClientCredentialsApiTokenIssuer: os.Getenv("FGA_API_TOKEN_ISSUER"),
    },
}
```

### SDK Environment Variables Summary

| Variable | Purpose | Used By |
|----------|---------|---------|
| `FGA_API_URL` | OpenFGA server URL | All methods |
| `FGA_STORE_ID` | Target store ID | All methods |
| `FGA_MODEL_ID` | Authorization model ID | All methods (optional) |
| `FGA_API_TOKEN` | Pre-shared bearer token | API Token method |
| `FGA_CLIENT_ID` | OAuth2 client ID | Client Credentials method |
| `FGA_CLIENT_SECRET` | OAuth2 client secret | Client Credentials method |
| `FGA_API_AUDIENCE` | OIDC audience | Client Credentials method |
| `FGA_API_TOKEN_ISSUER` | OIDC token issuer URL | Client Credentials method |

---

## 6. Access Control (Experimental v1.7.0+)

OpenFGA v1.7.0 introduced a **built-in access control system** (experimental, not production-ready) that uses OpenFGA itself to control access to its own API.

### Key Features

- Uses a dedicated "control store" with its own authorization model
- Requires OIDC authentication to be configured
- Supports granular permissions per store, per operation:
  - System level: `can_call_create_stores`, `can_call_list_stores`
  - Store level: `can_call_check`, `can_call_expand`, `can_call_read`, `can_call_write`
  - Module level: module-specific write permissions

### Configuration

```bash
export OPENFGA_ACCESS_CONTROL_ENABLED=true
export OPENFGA_ACCESS_CONTROL_STORE_ID=<control-store-id>
export OPENFGA_ACCESS_CONTROL_MODEL_ID=<control-model-id>
```

### Setup Process

1. Start server with access control disabled
2. Create the control store and deploy authorization model
3. Grant initial admin client ID access via relationship tuples
4. Enable access control via environment variables
5. Restart the server
6. Grant store/module-level access to additional clients

**Status:** Experimental — not recommended for production use yet.

---

## 7. TLS Configuration

### HTTP TLS

```bash
export OPENFGA_HTTP_TLS_ENABLED=true
export OPENFGA_HTTP_TLS_CERT=/path/to/server.crt
export OPENFGA_HTTP_TLS_KEY=/path/to/server.key
```

### gRPC TLS

```bash
export OPENFGA_GRPC_TLS_ENABLED=true
export OPENFGA_GRPC_TLS_CERT=/path/to/server.crt
export OPENFGA_GRPC_TLS_KEY=/path/to/server.key
```

### YAML Configuration

```yaml
http:
  tls:
    enabled: true
    cert: /path/to/server.crt
    key: /path/to/server.key
grpc:
  tls:
    enabled: true
    cert: /path/to/server.crt
    key: /path/to/server.key
```

### Certificate Rotation

OpenFGA uses `fsnotify` to automatically reload certificates when they change on disk — no server restart required.

---

## 8. Auth0 FGA vs OpenFGA (Self-Hosted)

| Aspect | OpenFGA (Self-Hosted) | Auth0 FGA (Managed) |
|--------|----------------------|---------------------|
| **Hosting** | Your infrastructure | Okta/Auth0 cloud |
| **Authentication** | Pre-shared keys or OIDC (you configure) | Client credentials (managed by Auth0) |
| **SDK Auth Method** | `ApiToken` or `ClientCredentials` | `ClientCredentials` (primary) |
| **TLS** | You configure certificates | Managed by Auth0 |
| **Scaling** | You manage | Auto-scaled, multi-region |
| **Access Control** | Experimental (v1.7.0+) | Built-in |
| **Cost** | Infrastructure costs only | SaaS pricing |
| **Key Difference** | Full control, more setup | Zero-ops, enterprise features |

### Auth0 FGA Authentication

Auth0 FGA uses OAuth2 Client Credentials flow:
- You create an API client in the Auth0 FGA dashboard
- You receive a `client_id` and `client_secret`
- The SDK automatically exchanges these for JWT tokens
- Tokens are refreshed automatically

---

## 9. Migration Patterns

### From RBAC/API-Key Systems to OpenFGA

#### Strategy 1: Shadow Mode (Recommended)

1. Deploy OpenFGA alongside existing authorization system
2. Replicate existing permission structures in OpenFGA model
3. Run both systems in parallel — existing system is authoritative
4. Make asynchronous calls to OpenFGA and log discrepancies
5. Once validated, switch to OpenFGA as the authoritative source

#### Strategy 2: JWT Enrichment (Gradual)

1. Use OpenFGA to generate authorization claims
2. Store claims in JWTs (existing applications keep using JWT-based checks)
3. Gradually migrate applications to use direct OpenFGA `Check()` calls
4. Eliminates need for big-bang migration

#### Strategy 3: Start Simple, Evolve

1. Begin by replicating existing RBAC structure in OpenFGA
2. Define coarse-grained roles (admin, editor, viewer)
3. Progressively add fine-grained resource-level permissions
4. Use modular models to allow teams to evolve independently

#### Strategy 4: Domain-Specific Wrapper APIs

1. Wrap OpenFGA with domain-specific APIs (e.g., `/share-document`)
2. Simplifies adoption for application developers
3. Trade-off: adds latency and complexity

### Key Migration Considerations

- **OpenFGA is an authorization engine, not an authentication system** — it answers "can user X do action Y on resource Z?" but does not handle login, tokens, or identity
- Existing authentication (OAuth2, API keys, SAML) stays in place
- OpenFGA replaces the authorization decision layer, not the authentication layer
- Use contextual tuples to bridge token claims with OpenFGA relationships during migration

---

## 10. Production Security Recommendations

From the official documentation:

1. **Enable Authentication:** Configure `preshared` or `oidc` authentication (never use `none`)
2. **Enable TLS:** Enable HTTP TLS, gRPC TLS, or both
3. **Disable Playground:** Turn off the interactive playground in production
4. **Structured Logging:** Set log format to `json` and log level to `info`
5. **Enable Metrics:** Use `--metrics-enabled` and `--datastore-metrics-enabled`
6. **Enable Tracing:** Use `--trace-enabled` with low sampling ratios (~0.3)
7. **Use OIDC over Pre-Shared Keys:** OIDC provides stronger security (token expiry, revocation, cryptographic signing)
8. **Key Rotation:** Use multiple pre-shared keys for zero-downtime rotation
9. **Certificate Rotation:** Leverage automatic certificate reloading via fsnotify

---

## 11. Complete Configuration Reference

### Authentication Settings

| Config File | Env Var | CLI Flag | Type | Default |
|---|---|---|---|---|
| `authn.method` | `OPENFGA_AUTHN_METHOD` | `--authn-method` | `none`/`preshared`/`oidc` | `none` |
| `authn.preshared.keys` | `OPENFGA_AUTHN_PRESHARED_KEYS` | `--authn-preshared-keys` | []string | — |
| `authn.oidc.issuer` | `OPENFGA_AUTHN_OIDC_ISSUER` | `--authn-oidc-issuer` | string | — |
| `authn.oidc.audience` | `OPENFGA_AUTHN_OIDC_AUDIENCE` | `--authn-oidc-audience` | string | — |
| `authn.oidc.issuerAliases` | `OPENFGA_AUTHN_OIDC_ISSUER_ALIASES` | `--authn-oidc-issuer-aliases` | []string | — |
| `authn.oidc.subjects` | `OPENFGA_AUTHN_OIDC_SUBJECTS` | `--authn-oidc-subjects` | []string | — |
| `authn.oidc.clientIdClaims` | `OPENFGA_AUTHN_OIDC_CLIENT_ID_CLAIMS` | `--authn-oidc-client-id-claims` | []string | `[azp, client_id]` |

### Access Control Settings

| Config File | Env Var | CLI Flag | Type | Default |
|---|---|---|---|---|
| `accessControl.enabled` | `OPENFGA_ACCESS_CONTROL_ENABLED` | `--access-control-enabled` | boolean | `false` |
| `accessControl.storeId` | `OPENFGA_ACCESS_CONTROL_STORE_ID` | `--access-control-store-id` | string | — |
| `accessControl.modelId` | `OPENFGA_ACCESS_CONTROL_MODEL_ID` | `--access-control-model-id` | string | — |

### TLS Settings

| Config File | Env Var | CLI Flag | Type | Default |
|---|---|---|---|---|
| `http.tls.enabled` | `OPENFGA_HTTP_TLS_ENABLED` | `--http-tls-enabled` | boolean | `false` |
| `http.tls.cert` | `OPENFGA_HTTP_TLS_CERT` | `--http-tls-cert` | string | — |
| `http.tls.key` | `OPENFGA_HTTP_TLS_KEY` | `--http-tls-key` | string | — |
| `grpc.tls.enabled` | `OPENFGA_GRPC_TLS_ENABLED` | `--grpc-tls-enabled` | boolean | `false` |
| `grpc.tls.cert` | `OPENFGA_GRPC_TLS_CERT` | `--grpc-tls-cert` | string | — |
| `grpc.tls.key` | `OPENFGA_GRPC_TLS_KEY` | `--grpc-tls-key` | string | — |

### Configuration Precedence

CLI flags > Environment variables > Config file (YAML)

---

## Sources

- [Configuring OpenFGA](https://openfga.dev/docs/getting-started/setup-openfga/configure-openfga)
- [OpenFGA Configuration Options](https://openfga.dev/docs/getting-started/setup-openfga/configuration)
- [Setup Access Control](https://openfga.dev/docs/getting-started/setup-openfga/access-control)
- [Setup SDK Client](https://openfga.dev/docs/getting-started/setup-sdk-client)
- [Running OpenFGA in Production](https://openfga.dev/docs/best-practices/running-in-production)
- [Adoption Patterns](https://openfga.dev/docs/best-practices/adoption-patterns)
- [Auth0 FGA vs OpenFGA](https://docs.fga.dev/openfga-vs-auth0-fga)
- [OpenFGA API Explorer](https://openfga.dev/api/service)
- [OpenFGA Python SDK](https://github.com/openfga/python-sdk)
- [OpenFGA Go SDK](https://github.com/openfga/go-sdk)
- [OpenFGA JS SDK](https://www.npmjs.com/package/@openfga/sdk)
- [Docker Setup Guide](https://openfga.dev/docs/getting-started/setup-openfga/docker)
