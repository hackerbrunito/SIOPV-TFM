# OIDC Provider Research for OpenFGA Integration in SIOPV

**Date:** 2026-02-11
**Purpose:** Evaluate OIDC provider options for securing OpenFGA API access in SIOPV using client credentials flow (service-to-service authentication).

---

## Table of Contents

1. [OpenFGA OIDC Requirements](#1-openfga-oidc-requirements)
2. [Self-Hosted Providers](#2-self-hosted-providers)
3. [Cloud Providers](#3-cloud-providers)
4. [Client Credentials Flow Comparison](#4-client-credentials-flow-comparison)
5. [JWT Token Structure for OpenFGA](#5-jwt-token-structure-for-openfga)
6. [Recommendation for SIOPV](#6-recommendation-for-siopv)

---

## 1. OpenFGA OIDC Requirements

### Configuration Variables

OpenFGA requires these environment variables for OIDC authentication:

| Variable | Required | Description |
|---|---|---|
| `OPENFGA_AUTHN_METHOD` | Yes | Set to `oidc` |
| `OPENFGA_AUTHN_OIDC_ISSUER` | Yes | The OIDC issuer URL signing the tokens |
| `OPENFGA_AUTHN_OIDC_AUDIENCE` | Yes | The audience claim expected in tokens |
| `OPENFGA_AUTHN_OIDC_ISSUER_ALIASES` | No | DNS aliases accepted when verifying `iss` |
| `OPENFGA_AUTHN_OIDC_SUBJECTS` | No | Accepted subject names in JWT `sub` field; empty allows all |
| `OPENFGA_AUTHN_OIDC_CLIENT_ID_CLAIMS` | No | Client ID claim names in priority order. Default: `[azp, client_id]` |

### Alternative: Preshared Keys

For simpler setups, OpenFGA also supports preshared key auth:

```
OPENFGA_AUTHN_METHOD=preshared
OPENFGA_AUTHN_PRESHARED_KEYS=key1,key2
```

Clients send `Authorization: Bearer <KEY>` headers. Simpler but less secure than OIDC.

### Config File Format (config.yaml)

```yaml
authn:
  method: oidc
  oidc:
    issuer: "https://your-oidc-issuer.example.com"
    audience: "openfga-api"
    issuerAliases: []
    subjects: []
http:
  tls:
    enabled: true
    cert: /path/to/server.crt
    key: /path/to/server.key
```

### Access Control (Experimental)

OpenFGA has an experimental access control feature requiring additional variables:

- `OPENFGA_EXPERIMENTALS=enable-access-control`
- `OPENFGA_ACCESS_CONTROL_ENABLED=true`
- `OPENFGA_ACCESS_CONTROL_STORE_ID=<store-id>`
- `OPENFGA_ACCESS_CONTROL_MODEL_ID=<model-id>`

**Note:** This is not recommended for production yet.

### Token Claims Used by OpenFGA

By default, OpenFGA identifies clients using these claims (in priority order):

1. `azp` (OpenID standard — Authorized Party)
2. `client_id` (RFC 9068)

The `sub` claim can be restricted via `OPENFGA_AUTHN_OIDC_SUBJECTS`. The `iss` must match the configured issuer. The `aud` must match the configured audience.

---

## 2. Self-Hosted Providers

### 2.1 Keycloak

**Overview:** The most widely adopted open-source Identity and Access Management (IAM) solution. Full-featured OIDC/OAuth2/SAML provider with admin UI.

**Current Version:** 26.5.2 (January 2026, Quarkus-based)

**Setup Complexity:** Medium

**Pros:**
- Comprehensive admin console with GUI
- Built-in service account support per client
- Extensive realm/client/role management
- Large community and documentation
- Full client credentials flow support out of the box
- Pre-configured realm export/import for reproducible deployments
- Integrated with OpenFGA via community plugins (Keycloak-OpenFGA event listener)

**Cons:**
- Heavy resource footprint (~512MB+ RAM for dev, 1GB+ for production)
- Requires PostgreSQL/MySQL for production
- Complex initial learning curve
- Overkill if only M2M auth is needed

**Docker Compose Setup:**

```yaml
services:
  keycloak:
    image: quay.io/keycloak/keycloak:26.5.2
    command: start-dev
    environment:
      KC_DB: postgres
      KC_DB_URL: jdbc:postgresql://postgres:5432/keycloak
      KC_DB_USERNAME: keycloak
      KC_DB_PASSWORD: password
      KC_HOSTNAME: localhost
      KEYCLOAK_ADMIN: admin
      KEYCLOAK_ADMIN_PASSWORD: admin
    ports:
      - "8080:8080"
    depends_on:
      - postgres
```

**Client Credentials Flow Setup:**
1. Create a realm (e.g., `siopv`)
2. Create a client with "confidential" access type
3. Enable "Service Accounts Enabled"
4. Disable all other flows (Standard, Direct Access, Implicit)
5. Token endpoint: `http://keycloak:8080/realms/siopv/protocol/openid-connect/token`
6. OIDC discovery: `http://keycloak:8080/realms/siopv/.well-known/openid-configuration`

**Token Request:**
```bash
curl -X POST http://keycloak:8080/realms/siopv/protocol/openid-connect/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials" \
  -d "client_id=siopv-service" \
  -d "client_secret=<client-secret>"
```

**JWT Token includes:** `iss`, `sub`, `aud`, `exp`, `iat`, `azp`, `scope`, `client_id`, `realm_access`, `resource_access`

**OpenFGA Config:**
```
OPENFGA_AUTHN_METHOD=oidc
OPENFGA_AUTHN_OIDC_ISSUER=http://keycloak:8080/realms/siopv
OPENFGA_AUTHN_OIDC_AUDIENCE=openfga-api
```

---

### 2.2 Ory Hydra

**Overview:** Lightweight, API-first OAuth2/OIDC server. Not an identity provider itself — connects to existing user management through a login/consent app. Trusted by OpenAI and many others.

**Setup Complexity:** Medium-High (API-only, no admin UI)

**Pros:**
- Lightweight and performant (written in Go)
- API-first design, excellent for automation
- Supports multiple auth methods: `client_secret_basic`, `client_secret_post`, `private_key_jwt`
- OpenID Certified
- Excellent for multi-tenant environments (thin clients)
- Scales horizontally easily
- Can self-host or use Ory Network (managed SaaS)

**Cons:**
- No built-in identity management (requires separate login/consent app)
- No admin GUI (CLI + API only)
- Higher initial complexity ("you're opting into complexity")
- Requires implementing login/consent endpoints yourself (for auth code flow — not needed for pure client_credentials)

**Docker Setup:**

```yaml
services:
  hydra:
    image: oryd/hydra:v2.3.0
    command: serve all --dev
    environment:
      DSN: postgres://hydra:secret@postgres:5432/hydra?sslmode=disable
      URLS_SELF_ISSUER: http://localhost:4444/
      URLS_CONSENT: http://consent:3000/consent
      URLS_LOGIN: http://consent:3000/login
    ports:
      - "4444:4444"  # Public (token endpoint)
      - "4445:4445"  # Admin (client management)
```

**Client Creation:**
```bash
docker exec hydra hydra create oauth2-client \
  --endpoint http://localhost:4445 \
  --grant-type client_credentials \
  --scope openid \
  --token-endpoint-auth-method client_secret_basic
```

**Token Request:**
```bash
docker exec hydra hydra perform client-credentials \
  --endpoint http://localhost:4444 \
  --client-id <client-id> \
  --client-secret <client-secret>
```

**JWT Claims for Bearer Authentication:**
- `iss` / `sub`: Contains the `client_id`
- `aud`: Authorization server's token endpoint URL
- `jti`: Unique token identifier
- `exp`: Expiration timestamp
- `iat`: Issued at (optional)

**OpenFGA Config:**
```
OPENFGA_AUTHN_METHOD=oidc
OPENFGA_AUTHN_OIDC_ISSUER=http://hydra:4444/
OPENFGA_AUTHN_OIDC_AUDIENCE=openfga-api
```

---

### 2.3 Authentik

**Overview:** Modern, full-featured identity provider with a clean web UI. Supports OIDC, SAML, LDAP, and SCIM. Good middle ground between Keycloak's heaviness and Hydra's minimalism.

**Setup Complexity:** Low-Medium

**Pros:**
- Modern, clean admin UI
- Supports all standard OAuth2 flows including client_credentials
- Expression policies for dynamic authorization
- Automatic service account creation
- Lower resource usage than Keycloak
- Active development (latest release: 2025.10)

**Cons:**
- **Non-standard M2M implementation**: Uses username + app-password instead of standard `client_id + client_secret`
- Smaller community than Keycloak
- Less documentation for advanced scenarios
- Less mature than Keycloak

**M2M Authentication Approach (Non-standard):**

Authentik does NOT use standard `client_id + client_secret` for M2M. Instead:
- Identification: based on username
- Authentication: based on app password tokens
- All user account types (internal, external, service account) can authenticate
- Can auto-create service accounts with pattern: `ak-<provider_name>-client_credentials`

**Setup:**
1. Navigate to Applications > Applications > Create with provider
2. Select OAuth2/OIDC as Provider Type
3. Configure scopes and signing key
4. Create a service account with app password for M2M

**Token format:** Signed JWT token validated using authentik's signing key.

**Concern for OpenFGA:** The non-standard client credentials implementation may cause friction. The JWT should still contain standard claims (`iss`, `sub`, `aud`) but the authentication mechanism differs.

---

## 3. Cloud Providers

### 3.1 Auth0

**Overview:** Industry-leading identity platform, now part of Okta. Excellent M2M support with dedicated Machine-to-Machine application type.

**Setup Complexity:** Low

**Pros:**
- Purpose-built M2M application type
- Excellent documentation and SDKs
- Standard client credentials flow
- Custom claims via Actions/Hooks
- Free tier: 1,000 M2M tokens/month
- Direct OpenFGA integration (Auth0 FGA is built on OpenFGA)

**Cons:**
- Pricing scales with M2M token volume
- Vendor lock-in concerns
- Free tier limited for production
- Okta now redirects Customer Identity to Auth0

**Pricing:**
- Free: 1,000 M2M tokens/month
- Essentials: Starts at ~$35/month
- Professional: Starts at ~$240/month
- Enterprise: Custom pricing

**Client Credentials Flow:**
```bash
curl -X POST https://YOUR_DOMAIN.auth0.com/oauth/token \
  -H "Content-Type: application/json" \
  -d '{
    "client_id": "YOUR_CLIENT_ID",
    "client_secret": "YOUR_CLIENT_SECRET",
    "audience": "https://openfga-api.example.com",
    "grant_type": "client_credentials"
  }'
```

**JWT Token Claims:**
```json
{
  "iss": "https://YOUR_DOMAIN.auth0.com/",
  "sub": "client-123@clients",
  "aud": "https://openfga-api.example.com",
  "exp": 1713290000,
  "iat": 1713286400,
  "scope": "read:tuples write:tuples",
  "azp": "YOUR_CLIENT_ID",
  "gty": "client-credentials"
}
```

**OpenFGA Config:**
```
OPENFGA_AUTHN_METHOD=oidc
OPENFGA_AUTHN_OIDC_ISSUER=https://YOUR_DOMAIN.auth0.com/
OPENFGA_AUTHN_OIDC_AUDIENCE=https://openfga-api.example.com
```

---

### 3.2 AWS Cognito

**Overview:** AWS-native identity service. Supports OAuth2/OIDC with resource servers and custom scopes for M2M.

**Setup Complexity:** Medium

**Pros:**
- Deeply integrated with AWS ecosystem
- Cost-effective at scale ($0.0055/MAU after free 50K tier)
- Custom access token support for M2M (since March 2025)
- Resource server with custom scopes

**Cons:**
- Complex setup for non-AWS workloads
- OAuth2 focus is primarily AWS-centric
- Requires resource server + custom scopes for client_credentials
- App client must have a client secret
- Requires a user pool domain
- Less flexible than Auth0 for M2M scenarios

**Setup Requirements:**
1. Create User Pool with domain
2. Create Resource Server with custom scopes
3. Create App Client with client secret
4. Enable `client_credentials` grant type
5. Assign custom scopes to the app client

**Token Request:**
```bash
curl -X POST https://YOUR_DOMAIN.auth.us-east-1.amazoncognito.com/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Authorization: Basic BASE64(client_id:client_secret)" \
  -d "grant_type=client_credentials&scope=openfga/read openfga/write"
```

**Note:** Cognito only authorizes **custom scopes** from resource servers in client credentials grants (not standard OIDC scopes).

**OpenFGA Config:**
```
OPENFGA_AUTHN_METHOD=oidc
OPENFGA_AUTHN_OIDC_ISSUER=https://cognito-idp.us-east-1.amazonaws.com/us-east-1_XXXXX
OPENFGA_AUTHN_OIDC_AUDIENCE=<resource-server-identifier>
```

---

### 3.3 Microsoft Entra ID (Azure AD)

**Overview:** Enterprise-grade identity platform from Microsoft. Supports OAuth2 client credentials flow with app registrations and service principals.

**Setup Complexity:** Medium-High

**Pros:**
- Enterprise-grade security
- Three auth methods: shared secret, certificate, federated credentials
- Workload Identity Federation for cross-cloud
- Deep Azure/Microsoft 365 integration

**Cons:**
- Complex app registration process
- Requires admin consent for application permissions
- Heavy Microsoft ecosystem dependency
- Pricing tied to Entra ID tier (M2M Premium add-on needed for External ID)
- Overkill for non-Microsoft environments

**Setup Steps:**
1. Register application in Azure Portal
2. Create service principal
3. Add client secret or certificate
4. Configure API permissions (application-level)
5. Grant admin consent

**Token Endpoint:**
```
POST https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token
```

**Token Request (shared secret):**
```bash
curl -X POST https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=APP_ID" \
  -d "scope=https://your-api/.default" \
  -d "client_secret=YOUR_SECRET" \
  -d "grant_type=client_credentials"
```

**OpenFGA Config:**
```
OPENFGA_AUTHN_METHOD=oidc
OPENFGA_AUTHN_OIDC_ISSUER=https://login.microsoftonline.com/{tenant}/v2.0
OPENFGA_AUTHN_OIDC_AUDIENCE=api://openfga
```

---

## 4. Client Credentials Flow Comparison

| Feature | Keycloak | Ory Hydra | Authentik | Auth0 | AWS Cognito | Azure AD |
|---|---|---|---|---|---|---|
| **Standard client_credentials** | Yes | Yes | Non-standard | Yes | Yes | Yes |
| **Auth methods** | Basic, Post | Basic, Post, JWT | Username+AppPassword | Basic, Post | Basic | Secret, Cert, Federated |
| **Token format** | JWT | JWT (or opaque) | JWT | JWT | JWT | JWT |
| **Custom claims** | Via mappers | Via webhooks | Via policies | Via Actions | Via Lambda triggers (2025+) | Via claims mapping |
| **Setup time (dev)** | ~30 min | ~45 min | ~20 min | ~10 min | ~30 min | ~45 min |
| **Self-hosted** | Yes | Yes | Yes | No | No | No |
| **Free tier** | Unlimited (OSS) | Unlimited (OSS) | Unlimited (OSS) | 1K tokens/mo | 50K MAU | Depends on plan |
| **Admin UI** | Full GUI | None (API/CLI) | Modern GUI | Full GUI | AWS Console | Azure Portal |
| **Docker support** | Official image | Official image | Official image | N/A | N/A | N/A |
| **RAM (dev mode)** | ~512MB+ | ~128MB | ~256MB | N/A | N/A | N/A |

---

## 5. JWT Token Structure for OpenFGA

### Minimum Required Claims

For OpenFGA OIDC authentication, tokens **must** include:

```json
{
  "iss": "<must-match-OPENFGA_AUTHN_OIDC_ISSUER>",
  "aud": "<must-match-OPENFGA_AUTHN_OIDC_AUDIENCE>",
  "exp": 1713290000,
  "iat": 1713286400,
  "azp": "<client-id>"
}
```

Or alternatively (RFC 9068 format):

```json
{
  "iss": "<must-match-OPENFGA_AUTHN_OIDC_ISSUER>",
  "aud": "<must-match-OPENFGA_AUTHN_OIDC_AUDIENCE>",
  "exp": 1713290000,
  "iat": 1713286400,
  "client_id": "<client-id>"
}
```

### Claim Lookup Priority

OpenFGA looks for the client identifier in this order (configurable via `OPENFGA_AUTHN_OIDC_CLIENT_ID_CLAIMS`):

1. `azp` (Authorized Party — OpenID standard)
2. `client_id` (RFC 9068)

### Optional Claims for Access Control

When using the experimental access control feature, additional claims like `sub` can be used to restrict which subjects can access specific stores.

### Provider-Specific Audience Configuration

| Provider | How to set `aud` claim |
|---|---|
| Keycloak | Configure client scope mapper or use `audience` client scope |
| Ory Hydra | Set via `--audience` flag when creating client |
| Authentik | Configure in OAuth2 provider settings |
| Auth0 | Pass `audience` parameter in token request |
| AWS Cognito | Resource server identifier becomes the audience |
| Azure AD | Use `scope=api://openfga/.default` |

**Important Keycloak note:** By default, Keycloak tokens may NOT include an `aud` claim matching your OpenFGA audience. You must add an "Audience" protocol mapper to the client or use the built-in `audience` client scope.

---

## 6. Recommendation for SIOPV

### Context

SIOPV is a Python 3.11+/3.12 application using `openfga-sdk>=0.6.0`, `httpx`, `pydantic`, and follows a clean architecture pattern. It needs service-to-service authentication for its components accessing the OpenFGA API.

### Recommended: Keycloak (Primary) or Preshared Keys (Quick Start)

#### Phase 1 — Development/Quick Start: Preshared Keys

For initial development and testing, use preshared key authentication:

```
OPENFGA_AUTHN_METHOD=preshared
OPENFGA_AUTHN_PRESHARED_KEYS=dev-key-1,dev-key-2
```

- Zero additional infrastructure
- Fast to configure
- Sufficient for local development and CI

#### Phase 2 — Staging/Production: Keycloak

**Why Keycloak:**

1. **Best OpenFGA integration**: Community-maintained Keycloak-OpenFGA event listener exists; Auth0 FGA (built on OpenFGA) documentation translates well to Keycloak
2. **Standard client credentials**: Clean, standard implementation that produces JWTs with all claims OpenFGA needs
3. **Self-hosted**: Full control, no vendor lock-in, no per-token pricing
4. **Admin UI**: Visual management of realms, clients, and service accounts
5. **Docker-native**: Easy to add to a Docker Compose stack alongside OpenFGA
6. **Community size**: Largest community among self-hosted options, extensive documentation
7. **Audience claim support**: Configurable via protocol mappers (requires explicit setup)

**Why NOT the others:**

- **Ory Hydra**: Lighter but no admin UI, requires implementing login/consent app (not needed for pure M2M but adds operational complexity), higher learning curve
- **Authentik**: Non-standard M2M implementation (username + app-password instead of client_id + client_secret) could cause integration friction with OpenFGA SDK
- **Auth0**: Excellent but adds cloud dependency and cost for a self-hostable project
- **AWS Cognito**: AWS-centric, complex setup for non-AWS deployments
- **Azure AD**: Too heavy for non-Microsoft environments, requires M2M Premium add-on

### Architecture Summary

```
┌──────────────┐     client_credentials      ┌──────────────┐
│  SIOPV App   │ ──────────────────────────→  │   Keycloak   │
│  (Python)    │ ←──── JWT access token ────  │  (Realm:     │
│              │                              │   siopv)     │
│              │                              └──────────────┘
│              │     Authorization: Bearer JWT
│              │ ──────────────────────────→  ┌──────────────┐
│              │                              │   OpenFGA    │
│              │ ←──── AuthZ decision ──────  │  (OIDC mode) │
└──────────────┘                              └──────────────┘
```

---

## Sources

- [OpenFGA: Setup Access Control](https://openfga.dev/docs/getting-started/setup-openfga/access-control)
- [OpenFGA: Configure OpenFGA](https://openfga.dev/docs/getting-started/setup-openfga/configure-openfga)
- [OpenFGA: Configuration Options](https://openfga.dev/docs/getting-started/setup-openfga/configuration)
- [OpenFGA: Token Claims as Contextual Tuples](https://openfga.dev/docs/modeling/token-claims-contextual-tuples)
- [Keycloak Integration with OpenFGA (Medium)](https://embesozzi.medium.com/keycloak-integration-with-openfga-based-on-zanzibar-for-fine-grained-authorization-at-scale-d3376de00f9a)
- [Keycloak OIDC Documentation](https://www.keycloak.org/securing-apps/oidc-layers)
- [Keycloak Docker Setup (2025 Edition)](https://www.mastertheboss.com/keycloak/keycloak-with-docker/)
- [Ory Hydra: Client Credentials Flow](https://www.ory.com/docs/oauth2-oidc/client-credentials)
- [Ory Hydra GitHub](https://github.com/ory/hydra)
- [Authentik: OAuth 2.0 Provider](https://docs.goauthentik.io/add-secure-apps/providers/oauth2/)
- [Authentik: Client Credentials](https://docs.goauthentik.io/add-secure-apps/providers/oauth2/client_credentials/)
- [Auth0: Using M2M Authorization](https://auth0.com/blog/using-m2m-authorization/)
- [Auth0: Supercharge Authorization with OpenFGA](https://auth0.com/blog/supercharge-your-authorization-system-with-openfga/)
- [AWS Cognito: M2M with Resource Servers](https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-define-resource-servers.html)
- [AWS Cognito: M2M Token Customization (2025)](https://aws.amazon.com/about-aws/whats-new/2025/03/amazon-cognito-access-token-m2m-authorization-flows/)
- [Azure AD: Client Credentials Flow](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-client-creds-grant-flow)
- [GoDaddy: Fine-grained Authorization with OpenFGA and OAuth](https://www.godaddy.com/resources/news/authorization-oauth-openfga)
- [Open Source Auth Providers in 2025 (Tesseral)](https://tesseral.com/guides/open-source-auth-providers-in-2025-best-solutions-for-open-source-auth)
