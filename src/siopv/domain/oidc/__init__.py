"""OIDC authentication domain layer for SIOPV.

This module implements the domain layer for OIDC client_credentials
authentication, enabling machine-to-machine (M2M) API access via
OAuth2 tokens issued by Keycloak.

Value Objects:
    - TokenClaims: Validated JWT token claims (sub, iss, aud, exp, etc.)
    - ServiceIdentity: Authenticated service client identity
    - OIDCProviderConfig: OIDC discovery document endpoints

Exceptions:
    - OIDCError: Base exception for all OIDC errors
    - TokenValidationError: JWT validation failure
    - TokenExpiredError: Token has expired
    - InvalidIssuerError: Untrusted issuer
    - InvalidAudienceError: Audience mismatch
    - JWKSFetchError: Failed to fetch JWKS
    - OIDCProviderUnavailableError: Provider unreachable

Usage:
    from siopv.domain.oidc import (
        TokenClaims,
        ServiceIdentity,
        OIDCProviderConfig,
        TokenValidationError,
    )

    # Parse validated JWT claims
    claims = TokenClaims(
        sub="service-account-siopv-client",
        iss="http://localhost:8888/realms/siopv",
        aud="siopv-api",
        exp=1700000000,
        iat=1699996400,
        azp="siopv-client",
        scope="openid profile",
    )

    # Map to service identity
    identity = ServiceIdentity.from_claims(claims)
    user_id = identity.to_user_id()  # UserId(value="service-siopv-client")
"""

from siopv.domain.oidc.exceptions import (
    InvalidAudienceError,
    InvalidIssuerError,
    JWKSFetchError,
    OIDCError,
    OIDCProviderUnavailableError,
    TokenExpiredError,
    TokenValidationError,
)
from siopv.domain.oidc.value_objects import (
    OIDCProviderConfig,
    ServiceIdentity,
    TokenClaims,
)

__all__ = [
    "InvalidAudienceError",
    "InvalidIssuerError",
    "JWKSFetchError",
    "OIDCError",
    "OIDCProviderConfig",
    "OIDCProviderUnavailableError",
    "ServiceIdentity",
    "TokenClaims",
    "TokenExpiredError",
    "TokenValidationError",
]
