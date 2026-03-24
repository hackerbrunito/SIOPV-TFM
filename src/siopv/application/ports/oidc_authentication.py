"""Port interface for OIDC authentication in SIOPV.

Defines the contract for OIDC token validation and identity extraction.
Following hexagonal architecture, this port defines WHAT the application
needs for OIDC authentication, while adapters (in adapters/authentication/)
provide HOW it's implemented using Keycloak/PyJWT.

Ports use typing.Protocol for structural subtyping, allowing any class
that implements the required methods to be used without inheritance.

Usage:
    from siopv.application.ports import OIDCAuthenticationPort

    class OIDCMiddleware:
        def __init__(self, oidc: OIDCAuthenticationPort) -> None:
            self._oidc = oidc

        async def authenticate(self, raw_token: str) -> ServiceIdentity:
            claims = await self._oidc.validate_token(raw_token)
            return await self._oidc.extract_identity(claims)

OIDC Flow Reference:
    1. API client sends Bearer token in Authorization header
    2. validate_token() verifies JWT signature via JWKS, checks issuer/audience/expiry
    3. extract_identity() maps validated claims to domain ServiceIdentity
    4. ServiceIdentity.to_user_id() provides OpenFGA-compatible UserId
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from siopv.domain.oidc import (
        OIDCProviderConfig,
        ServiceIdentity,
        TokenClaims,
    )


@runtime_checkable
class OIDCAuthenticationPort(Protocol):
    """Port interface for OIDC token validation and identity extraction.

    This port defines the contract for validating JWT Bearer tokens
    issued by an OIDC provider (e.g., Keycloak) and extracting
    machine-to-machine service identities from validated claims.

    The port is designed to:
    - Accept raw JWT tokens and return domain entities (TokenClaims, ServiceIdentity)
    - Hide implementation details (PyJWT, JWKS fetching, caching)
    - Support async operations for non-blocking I/O

    All methods are async to support non-blocking HTTP calls to the
    OIDC provider for JWKS fetching and discovery.

    Example:
        async def authenticate_request(
            oidc: OIDCAuthenticationPort,
            authorization_header: str,
        ) -> ServiceIdentity:
            # Extract Bearer token
            token = authorization_header.removeprefix("Bearer ")

            # Validate and extract identity
            claims = await oidc.validate_token(token)
            identity = await oidc.extract_identity(claims)
            return identity
    """

    async def validate_token(self, raw_token: str) -> TokenClaims:
        """Validate a JWT Bearer token and return parsed claims.

        Performs full JWT validation including:
        1. Fetch JWKS public keys from the OIDC provider (cached)
        2. Verify token signature using RS256 algorithm
        3. Validate issuer matches configured OIDC provider
        4. Validate audience matches configured application
        5. Check token expiry (with configurable clock skew leeway)
        6. Parse payload into domain TokenClaims model

        Args:
            raw_token: The raw JWT string (without "Bearer " prefix).
                Must be a valid JWT with header, payload, and signature.

        Returns:
            TokenClaims containing parsed and validated token fields:
                - sub: Subject identifier
                - iss: Issuer URL
                - aud: Audience (string or list)
                - exp: Expiration timestamp
                - iat: Issued-at timestamp
                - azp: Authorized party (client_id for client_credentials)
                - scope: Space-delimited scope string
                - client_id: Client identifier
                - jti: JWT unique identifier

        Raises:
            TokenExpiredError: If the token has expired (past exp + leeway).
            InvalidIssuerError: If the token issuer doesn't match config.
            InvalidAudienceError: If the token audience doesn't match config.
            TokenValidationError: For any other validation failure
                (invalid signature, malformed JWT, missing required claims).
            JWKSFetchError: If JWKS public keys cannot be retrieved
                from the OIDC provider.

        Note:
            The implementation must pin the algorithm to RS256 to prevent
            algorithm confusion attacks. Never accept "none" or HS256
            when expecting RS256 tokens.

        Performance:
            First call may be slower due to JWKS fetch (~200-500ms).
            Subsequent calls use cached JWKS keys and should complete
            in < 5ms for local validation. JWKS cache TTL is configurable.
        """
        ...

    async def extract_identity(self, claims: TokenClaims) -> ServiceIdentity:
        """Extract service identity from validated token claims.

        Maps OIDC token fields to a domain ServiceIdentity that can be
        used for authorization checks via OpenFGA.

        The mapping convention for client_credentials tokens:
        - client_id: Extracted from ``azp`` claim (authorized party),
          with fallback to ``sub`` for client_credentials grants
        - issuer: From ``iss`` claim
        - scopes: From ``scope`` claim (space-delimited string split
          into frozenset)

        Args:
            claims: Validated TokenClaims from validate_token().
                Must contain at least ``iss`` and either ``azp`` or ``sub``.

        Returns:
            ServiceIdentity containing:
                - client_id: The OIDC client identifier
                - issuer: The token issuer URL
                - scopes: Set of granted scopes as frozenset[str]

            The returned identity supports ``to_user_id()`` which maps
            to OpenFGA format: ``service-{client_id}`` for authorization
            tuple lookups.

        Raises:
            TokenValidationError: If required identity fields are missing
                from the claims (no ``azp`` and no ``sub``).

        Example:
            claims = await oidc.validate_token(token)
            identity = await oidc.extract_identity(claims)

            # Map to OpenFGA user
            user_id = identity.to_user_id()
            # UserId(value="service-siopv-client")
        """
        ...

    async def discover_provider(self) -> OIDCProviderConfig:
        """Fetch OIDC discovery document from the provider.

        Retrieves the OpenID Connect discovery document from
        ``{issuer_url}/.well-known/openid-configuration`` and parses
        it into an OIDCProviderConfig domain object.

        The discovery document contains essential endpoints:
        - JWKS URI for public key retrieval
        - Token endpoint for token exchange
        - Authorization endpoint (if applicable)
        - Issuer identifier for validation

        Returns:
            OIDCProviderConfig containing:
                - issuer_url: Canonical issuer URL
                - jwks_uri: URI for JSON Web Key Set
                - token_endpoint: Token issuance endpoint
                - authorization_endpoint: Authorization endpoint (optional)

        Raises:
            OIDCProviderUnavailableError: If the OIDC provider is
                unreachable or returns a non-200 response.
            TokenValidationError: If the discovery document is
                malformed or missing required fields.

        Note:
            Implementations should cache the discovery document with
            a reasonable TTL (e.g., 1 hour) since OIDC configuration
            changes infrequently.

        Performance:
            First call requires HTTP request to provider (~100-500ms).
            Cached responses should return in < 1ms.
        """
        ...

    async def health_check(self) -> bool:
        """Check OIDC provider availability.

        Performs a lightweight check to verify the OIDC provider
        is reachable and responding. Suitable for liveness/readiness
        probes in container orchestration.

        The implementation should attempt to fetch the discovery
        document and return True on success.

        Returns:
            True if the OIDC provider is reachable and healthy.
            False if the provider is unreachable or unhealthy.

        Note:
            This method should never raise exceptions. All errors
            should be caught and result in a False return value.
            Implementations should log errors via structlog for
            observability.

        Performance:
            Should complete within 5 seconds. Implementations may
            use cached discovery results for faster checks.
        """
        ...


__all__ = [
    "OIDCAuthenticationPort",
]
