# OpenFGA Python SDK — OIDC Client Credentials Research Findings

**Date:** 2026-02-11
**SDK Version:** openfga-sdk 0.9.9 (latest as of 2025-12-09)
**PyPI:** https://pypi.org/project/openfga-sdk/
**Repository:** https://github.com/openfga/python-sdk

---

## 1. Authentication Methods Overview

The OpenFGA Python SDK (`openfga-sdk`) supports three credential methods:

| Method | Use Case |
|---|---|
| `none` | No authentication (development only) |
| `api_token` | Pre-shared bearer token |
| `client_credentials` | OAuth2/OIDC client credentials flow |

For production OIDC integration, `client_credentials` is the method to use. It implements a standard OAuth2 client credentials grant, requesting an access token from an OIDC provider (issuer) and attaching it as a Bearer token to all OpenFGA API requests.

---

## 2. ClientCredentials Configuration — Complete Example

### Required Imports

```python
import os
from openfga_sdk import ClientConfiguration, OpenFgaClient
from openfga_sdk.credentials import Credentials, CredentialConfiguration
```

### Full Async Configuration

```python
async def create_openfga_client() -> OpenFgaClient:
    credentials = Credentials(
        method='client_credentials',
        configuration=CredentialConfiguration(
            api_issuer=os.environ.get('FGA_API_TOKEN_ISSUER'),   # e.g. "https://auth.example.com"
            api_audience=os.environ.get('FGA_API_AUDIENCE'),      # e.g. "https://api.openfga.example.com"
            client_id=os.environ.get('FGA_CLIENT_ID'),            # OAuth2 client ID
            client_secret=os.environ.get('FGA_CLIENT_SECRET'),    # OAuth2 client secret
            scopes=os.environ.get('FGA_SCOPES', '').split(),      # Optional (since v0.9.6)
        )
    )

    configuration = ClientConfiguration(
        api_url=os.environ.get('FGA_API_URL'),                    # e.g. "https://openfga.example.com"
        store_id=os.environ.get('FGA_STORE_ID'),                  # FGA store ID
        authorization_model_id=os.environ.get('FGA_MODEL_ID'),    # Optional, uses latest if empty
        credentials=credentials,
    )

    return OpenFgaClient(configuration)
```

### Sync Configuration (also available)

```python
from openfga_sdk.client import ClientConfiguration
from openfga_sdk.sync import OpenFgaClient

def create_openfga_client_sync() -> OpenFgaClient:
    configuration = ClientConfiguration(
        api_url=FGA_API_URL,
        store_id=FGA_STORE_ID,
        authorization_model_id=FGA_MODEL_ID,
        credentials=Credentials(
            method='client_credentials',
            configuration=CredentialConfiguration(
                api_issuer=FGA_API_TOKEN_ISSUER,
                api_audience=FGA_API_AUDIENCE,
                client_id=FGA_CLIENT_ID,
                client_secret=FGA_CLIENT_SECRET,
            )
        )
    )
    return OpenFgaClient(configuration)
```

---

## 3. CredentialConfiguration Parameters

| Parameter | Type | Required | Description |
|---|---|---|---|
| `api_issuer` | `str` | Yes (for client_credentials) | OIDC issuer URL. SDK appends `/oauth/token` automatically if not present. |
| `api_audience` | `str` | Yes (for client_credentials) | Target API audience for the token request. |
| `client_id` | `str` | Yes (for client_credentials) | OAuth2 client identifier. |
| `client_secret` | `str` | Yes (for client_credentials) | OAuth2 client secret. |
| `scopes` | `str` or `list[str]` | No (since v0.9.6) | OAuth2 scopes. List is joined with spaces automatically. |
| `api_token` | `str` | Yes (for api_token method only) | Pre-shared bearer token. |

### Issuer URL Parsing (`_parse_issuer`)

The SDK's internal `_parse_issuer()` method:
- Validates the URL has an HTTP/HTTPS scheme
- Appends `/oauth/token` as the default token endpoint path when not present
- Raises `ApiValueError` for invalid URL formats

**Important:** This means `api_issuer` is the base issuer URL, NOT the full token endpoint. For example:
- Input: `https://auth.example.com` → Token URL: `https://auth.example.com/oauth/token`
- Input: `https://auth.example.com/oauth/token` → Kept as-is

---

## 4. Token Refresh Handling and Caching

### Automatic Token Management

The SDK handles token lifecycle automatically when using `client_credentials`:

1. **Initial Token Acquisition:** On the first API call, the SDK requests an access token from the issuer using the client credentials grant.
2. **Token Caching:** The obtained access token is cached internally by the `ApiClient` instance.
3. **Automatic Refresh:** When the token expires, the SDK automatically requests a new one before the next API call.
4. **Retry on Token Errors:** Since v0.9.4, the SDK retries on network errors during token acquisition (not just during API calls).

### Best Practice: Client Reuse

> It's **strongly recommended** to initialize the OpenFgaClient only once and then re-use it throughout your app. This is especially important in the client credentials flow as token exchange is performed transparently on every request cycle when needed.

```python
# GOOD: Create once, reuse everywhere
class OpenFGAService:
    def __init__(self):
        self._client: OpenFgaClient | None = None

    async def get_client(self) -> OpenFgaClient:
        if self._client is None:
            self._client = await create_openfga_client()
        return self._client
```

---

## 5. Retry Configuration

### Default Behavior

- **Retries:** Up to **3 attempts** on 429 (rate limit) and 5xx (server error) responses
- **Rate Limiting:** Respects `Retry-After` header from server (since v0.9.4)
- **Fallback:** Exponential backoff when `Retry-After` header is absent or on network errors
- **Scope:** Retries apply to BOTH OpenFGA API calls AND token issuer requests

### Custom RetryParams

```python
from openfga_sdk import ClientConfiguration
from openfga_sdk.client import RetryParams

configuration = ClientConfiguration(
    api_url=FGA_API_URL,
    store_id=FGA_STORE_ID,
    authorization_model_id=FGA_MODEL_ID,
    credentials=credentials,
    retry_params=RetryParams(
        max_retry=5,          # Max retries (up to 15)
        min_wait_in_ms=100,   # Minimum wait between retries in ms
    )
)
```

### Per-Request Retry Override

```python
response = await fga_client.check(
    body=check_request,
    options={
        "retry_params": RetryParams(max_retry=1, min_wait_in_ms=50),
    }
)
```

---

## 6. Error Handling

### Exception Hierarchy

| Exception | When Raised |
|---|---|
| `ApiException` | Base exception for all SDK errors. Has helper methods. |
| `AuthenticationError` | Token acquisition failure, invalid credentials. |
| `UnauthorizedException` | API returns 401 (expired/invalid token). |
| `FgaValidationException` | Invalid input (bad ULIDs, duplicate correlation IDs). |
| `ApiValueError` | Invalid configuration values (bad issuer URL, etc.). |

### Recommended Error Handling Pattern

```python
from openfga_sdk.exceptions import ApiException, AuthenticationError, FgaValidationException

async def check_permission(client: OpenFgaClient, user: str, relation: str, obj: str) -> bool:
    try:
        response = await client.check(
            body=ClientCheckRequest(
                user=user,
                relation=relation,
                object=obj,
            )
        )
        return response.allowed
    except AuthenticationError as e:
        # Credentials invalid or token endpoint unreachable
        logger.error(f"Authentication failed: {e}")
        raise
    except FgaValidationException as e:
        # Invalid input parameters
        logger.error(f"Validation error: {e}")
        raise
    except ApiException as e:
        if e.is_validation_error():
            logger.error(f"Validation: {e.error_message}")
        elif e.is_retryable():
            logger.warning(f"Retryable error (request_id={e.request_id}): {e}")
        else:
            logger.error(f"OpenFGA API error: {e}")
        raise
```

### Batch Operations — Partial Success

For batch operations (`write`, `batch_check`), the SDK returns errors in the response object rather than raising exceptions, allowing partial success:

```python
response = await client.write(body=write_request)
for write in response.writes:
    if write.error:
        logger.error(f"Write failed for {write.tuple_key}: {write.error}")
```

---

## 7. OpenFGA Server-Side OIDC Configuration

For the OIDC flow to work end-to-end, the OpenFGA server must also be configured for OIDC:

### Server Config (`config.yaml`)

```yaml
authn:
  method: oidc
  oidc:
    issuer: "https://auth.example.com"
    audience: "https://api.openfga.example.com"
    # Optional:
    # issuerAliases: ["https://alt-auth.example.com"]
    # subjects: ["specific-client-id"]
http:
  tls:
    enabled: true
    cert: /path/to/server.crt
    key: /path/to/server.key
```

### Server Environment Variables

```bash
OPENFGA_AUTHN_METHOD=oidc
OPENFGA_AUTHN_OIDC_ISSUER=https://auth.example.com
OPENFGA_AUTHN_OIDC_AUDIENCE=https://api.openfga.example.com
OPENFGA_HTTP_TLS_ENABLED=true
OPENFGA_HTTP_TLS_CERT=/path/to/server.crt
OPENFGA_HTTP_TLS_KEY=/path/to/server.key
# Optional: custom client ID claims
# OPENFGA_AUTHN_OIDC_CLIENT_ID_CLAIMS=sub,client_id
```

### TLS Requirement

TLS is **strongly recommended** when deploying with OIDC authentication in production.

---

## 8. SDK Version History — Credentials-Related Changes

| Version | Date | Change |
|---|---|---|
| **v0.9.6** | 2025-09-15 | Added `scopes` parameter to `CredentialConfiguration` (PR #213) |
| **v0.9.5** | 2025-07-09 | Fixed `aiohttp.ClientResponse.data` await issue |
| **v0.9.4** | 2025-04-30 | Rate limit header (`Retry-After`) support; retry on network errors for token issuer |
| **v0.9.2** | 2025-03-25 | Telemetry fixes for metrics tracking |
| **v0.9.9** | 2025-12-09 | Improved error messaging |

---

## 9. Integration Recommendations for SIOPV

### Environment Variables Needed

```bash
# OpenFGA connection
FGA_API_URL=https://openfga.example.com
FGA_STORE_ID=<store-id>
FGA_MODEL_ID=<model-id>

# OIDC client credentials
FGA_API_TOKEN_ISSUER=https://auth.example.com
FGA_API_AUDIENCE=https://api.openfga.example.com
FGA_CLIENT_ID=<client-id>
FGA_CLIENT_SECRET=<client-secret>
FGA_SCOPES=  # Optional, space-separated
```

### Singleton Pattern for DI

Since SIOPV uses dependency injection (based on project architecture analysis), the OpenFGA client should be registered as a singleton:

```python
# In infrastructure/adapters or similar DI setup
from openfga_sdk import ClientConfiguration, OpenFgaClient
from openfga_sdk.credentials import Credentials, CredentialConfiguration

def create_openfga_configuration(settings) -> ClientConfiguration:
    """Create OpenFGA client configuration from application settings."""
    return ClientConfiguration(
        api_url=settings.openfga_api_url,
        store_id=settings.openfga_store_id,
        authorization_model_id=settings.openfga_model_id,
        credentials=Credentials(
            method='client_credentials',
            configuration=CredentialConfiguration(
                api_issuer=settings.openfga_token_issuer,
                api_audience=settings.openfga_api_audience,
                client_id=settings.openfga_client_id,
                client_secret=settings.openfga_client_secret,
                scopes=settings.openfga_scopes,
            )
        ),
        retry_params=RetryParams(
            max_retry=settings.openfga_max_retries,
            min_wait_in_ms=settings.openfga_retry_wait_ms,
        )
    )
```

### Key Implementation Notes

1. **Use async client** — SIOPV likely uses async frameworks; use `OpenFgaClient` (async), not `openfga_sdk.sync.OpenFgaClient`.
2. **Initialize once** — Create the client once at startup, inject via DI container.
3. **Handle `AuthenticationError` separately** — OIDC credential failures should be logged and surfaced distinctly from authorization check failures.
4. **Configure retries** — Customize `RetryParams` based on environment (fewer retries in tests, more in production).
5. **TLS in production** — Ensure the OpenFGA server has TLS enabled when using OIDC.

---

## Sources

- [OpenFGA Setup SDK Client](https://openfga.dev/docs/getting-started/setup-sdk-client)
- [OpenFGA Configure Server](https://openfga.dev/docs/getting-started/setup-openfga/configure-openfga)
- [OpenFGA Python SDK — GitHub](https://github.com/openfga/python-sdk)
- [OpenFGA Python SDK — PyPI](https://pypi.org/project/openfga-sdk/)
- [OpenFGA Python SDK — CHANGELOG](https://github.com/openfga/python-sdk/blob/main/CHANGELOG.md)
- [OAuth2 Scopes PR #213](https://github.com/openfga/python-sdk/pull/213)
- [Error Handling Issue #184](https://github.com/openfga/python-sdk/issues/184)
- [OpenFGA Access Control Setup](https://openfga.dev/docs/getting-started/setup-openfga/access-control)
