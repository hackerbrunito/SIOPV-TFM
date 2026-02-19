"""Keycloak OIDC adapter implementing OIDCAuthenticationPort.

Validates JWT Bearer tokens issued by Keycloak using RS256 with async
JWKS fetching and caching via httpx. Maps PyJWT errors to domain
exceptions for clean error handling in the application layer.

Follows patterns from openfga_adapter.py: structured logging,
error mapping to domain exceptions, async-first design.

Context7 Verified PyJWT patterns:
- jwt.decode() with algorithms=["RS256"] for algorithm pinning
- PyJWK for JWKS key parsing
- leeway parameter for clock skew tolerance
- get_unverified_header() for kid extraction
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any

import httpx
import jwt
import structlog
from jwt import PyJWK

from siopv.domain.oidc import (
    InvalidAudienceError,
    InvalidIssuerError,
    JWKSFetchError,
    OIDCProviderConfig,
    OIDCProviderUnavailableError,
    ServiceIdentity,
    TokenClaims,
    TokenExpiredError,
    TokenValidationError,
)

if TYPE_CHECKING:
    from siopv.infrastructure.config.settings import Settings

logger = structlog.get_logger(__name__)


class KeycloakOIDCAdapter:
    """Keycloak OIDC adapter for JWT Bearer token validation.

    Implements ``OIDCAuthenticationPort`` using PyJWT for RS256 JWT
    validation and httpx for async JWKS/discovery document fetching.

    Features:
    - Async HTTP via httpx for JWKS and discovery fetching
    - JWKS caching with configurable TTL (avoids per-request fetches)
    - RS256 algorithm pinning (prevents algorithm confusion attacks)
    - Automatic JWKS refresh on key rotation (kid mismatch)
    - Configurable clock skew leeway for token expiry
    - Structured logging via structlog (PII-safe, no raw tokens)
    - Domain exception mapping (PyJWT errors -> OIDC domain exceptions)

    Usage:
        adapter = KeycloakOIDCAdapter(settings)

        # Validate token and extract identity
        claims = await adapter.validate_token(raw_jwt)
        identity = await adapter.extract_identity(claims)
        user_id = identity.to_user_id()

        # Cleanup
        await adapter.close()
    """

    def __init__(
        self,
        settings: Settings,
        *,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        """Initialize Keycloak OIDC adapter.

        Args:
            settings: Application settings with OIDC configuration.
            http_client: Optional pre-configured httpx client (for testing).
        """
        self._issuer_url = settings.oidc_issuer_url.rstrip("/")
        self._audience = settings.oidc_audience
        self._jwks_cache_ttl = settings.oidc_jwks_cache_ttl_seconds
        self._clock_skew_leeway = settings.oidc_allowed_clock_skew_seconds
        self._jwks_uri = f"{self._issuer_url}/protocol/openid-connect/certs"

        # External client (for testing) or owned client
        self._external_client = http_client
        self._owned_client: httpx.AsyncClient | None = None

        # JWKS cache
        self._jwks_keys: dict[str, Any] | None = None
        self._jwks_fetched_at: float = 0.0

        # Discovery document cache
        self._discovery_cache: OIDCProviderConfig | None = None
        self._discovery_fetched_at: float = 0.0

        logger.info(
            "keycloak_oidc_adapter_initialized",
            issuer_url=self._issuer_url,
            audience=self._audience,
            jwks_cache_ttl=self._jwks_cache_ttl,
            clock_skew_leeway=self._clock_skew_leeway,
        )

    async def _get_http_client(self) -> httpx.AsyncClient:
        """Get the httpx async client instance.

        Returns:
            Configured httpx.AsyncClient.
        """
        if self._external_client is not None:
            return self._external_client
        if self._owned_client is None:
            self._owned_client = httpx.AsyncClient(timeout=10.0)
        return self._owned_client

    async def close(self) -> None:
        """Close the owned httpx client if present."""
        if self._owned_client is not None:
            await self._owned_client.aclose()
            self._owned_client = None
            logger.info("keycloak_oidc_client_closed")

    # ------------------------------------------------------------------
    # Shared Helpers (DRY: cache check + HTTP fetch)
    # ------------------------------------------------------------------

    def _is_cache_fresh(
        self,
        fetched_at: float,
        *,
        force_refresh: bool = False,
    ) -> bool:
        """Check if a cached resource is still within its TTL."""
        if force_refresh:
            return False
        return (time.monotonic() - fetched_at) < self._jwks_cache_ttl

    async def _http_get_json(self, url: str) -> dict[str, Any]:
        """Fetch JSON from a URL using the shared HTTP client."""
        client = await self._get_http_client()
        response = await client.get(url)
        response.raise_for_status()
        return response.json()

    # ------------------------------------------------------------------
    # JWKS Fetching & Key Resolution
    # ------------------------------------------------------------------

    async def _fetch_jwks(
        self,
        *,
        force_refresh: bool = False,
    ) -> dict[str, Any]:
        """Fetch JWKS from Keycloak, using cache if valid.

        Args:
            force_refresh: Bypass cache and fetch fresh JWKS.

        Returns:
            JWKS data dict containing ``keys`` array.

        Raises:
            JWKSFetchError: If JWKS cannot be fetched.
        """
        if self._jwks_keys is not None and self._is_cache_fresh(
            self._jwks_fetched_at, force_refresh=force_refresh
        ):
            return self._jwks_keys

        try:
            jwks_data: dict[str, Any] = await self._http_get_json(self._jwks_uri)
        except httpx.HTTPStatusError as e:
            logger.warning(
                "jwks_fetch_http_error",
                status_code=e.response.status_code,
            )
            raise JWKSFetchError(
                jwks_uri=self._jwks_uri,
                underlying_error=e,
            ) from e
        except httpx.HTTPError as e:
            logger.warning(
                "jwks_fetch_network_error",
                error_type=type(e).__name__,
            )
            raise JWKSFetchError(
                jwks_uri=self._jwks_uri,
                underlying_error=e,
            ) from e

        self._jwks_keys = jwks_data
        self._jwks_fetched_at = time.monotonic()
        logger.debug(
            "jwks_fetched_and_cached",
            key_count=len(jwks_data.get("keys", [])),
        )
        return jwks_data

    def _find_signing_key(
        self,
        jwks: dict[str, Any],
        raw_token: str,
    ) -> PyJWK:
        """Find the signing key matching the token's ``kid`` header.

        Args:
            jwks: JWKS data dict with ``keys`` array.
            raw_token: Raw JWT string to extract ``kid`` from.

        Returns:
            PyJWK matching the token's key ID.

        Raises:
            TokenValidationError: If token header is malformed,
                missing ``kid``, or no matching key found.
        """
        try:
            header = jwt.get_unverified_header(raw_token)
        except jwt.DecodeError as e:
            raise TokenValidationError(
                reason="Malformed JWT header",
            ) from e

        kid = header.get("kid")
        if not kid:
            raise TokenValidationError(
                reason="Token header missing 'kid' claim",
            )

        for key_data in jwks.get("keys", []):
            if key_data.get("kid") == kid:
                return PyJWK(key_data)

        raise TokenValidationError(
            reason="No matching signing key found in JWKS",
            details={"kid": kid},
        )

    # ------------------------------------------------------------------
    # OIDCAuthenticationPort Implementation
    # ------------------------------------------------------------------

    def _decode_jwt(
        self,
        raw_token: str,
        signing_key: PyJWK,
    ) -> dict[str, Any]:
        """Decode and validate JWT, mapping PyJWT errors to domain exceptions.

        Args:
            raw_token: Raw JWT string.
            signing_key: The RSA signing key to verify against.

        Returns:
            Decoded JWT payload as a dict.

        Raises:
            TokenExpiredError: If the token has expired.
            InvalidIssuerError: If the issuer doesn't match config.
            InvalidAudienceError: If the audience doesn't match config.
            TokenValidationError: For other validation failures.
        """
        try:
            return jwt.decode(
                raw_token,
                signing_key.key,
                algorithms=["RS256"],
                audience=self._audience,
                issuer=self._issuer_url,
                leeway=self._clock_skew_leeway,
            )
        except jwt.ExpiredSignatureError as e:
            jti = _extract_jti_safe(raw_token)
            raise TokenExpiredError(token_id=jti) from e
        except jwt.InvalidIssuerError as e:
            jti = _extract_jti_safe(raw_token)
            raise InvalidIssuerError(
                expected_issuer=self._issuer_url,
                token_id=jti,
            ) from e
        except jwt.InvalidAudienceError as e:
            jti = _extract_jti_safe(raw_token)
            raise InvalidAudienceError(
                expected_audience=self._audience,
                token_id=jti,
            ) from e
        except jwt.PyJWTError as e:
            raise TokenValidationError(
                reason=f"JWT validation failed: {type(e).__name__}",
            ) from e

    async def validate_token(self, raw_token: str) -> TokenClaims:
        """Validate a JWT Bearer token and return parsed claims.

        Fetches JWKS (cached), finds the matching signing key,
        decodes the JWT with RS256 algorithm pinning, and validates
        issuer/audience/expiry.

        On key rotation (kid mismatch), automatically refreshes
        JWKS cache and retries once.

        Args:
            raw_token: Raw JWT string (without "Bearer " prefix).

        Returns:
            Validated TokenClaims from the JWT payload.

        Raises:
            TokenExpiredError: If the token has expired.
            InvalidIssuerError: If the issuer doesn't match config.
            InvalidAudienceError: If the audience doesn't match config.
            TokenValidationError: For other validation failures.
            JWKSFetchError: If JWKS cannot be fetched.
        """
        start_time = time.perf_counter()

        # 1. Fetch JWKS (cached)
        jwks = await self._fetch_jwks()

        # 2. Find signing key; retry with fresh JWKS on kid mismatch
        try:
            signing_key = self._find_signing_key(jwks, raw_token)
        except TokenValidationError as exc:
            if "No matching signing key" in str(exc):
                jwks = await self._fetch_jwks(force_refresh=True)
                signing_key = self._find_signing_key(jwks, raw_token)
            else:
                raise

        # 3. Decode and validate JWT
        payload = self._decode_jwt(raw_token, signing_key)

        # 4. Parse into domain model
        try:
            claims = TokenClaims(**payload)
        except Exception as e:
            raise TokenValidationError(
                reason="Token claims structure is invalid",
            ) from e

        duration_ms = (time.perf_counter() - start_time) * 1000
        logger.info(
            "token_validated",
            client_id=claims.get_effective_client_id(),
            issuer=claims.iss,
            duration_ms=round(duration_ms, 2),
        )
        return claims

    async def extract_identity(
        self,
        claims: TokenClaims,
    ) -> ServiceIdentity:
        """Extract service identity from validated token claims.

        Uses ``ServiceIdentity.from_claims()`` factory method to
        map token fields to a domain identity. The identity's
        ``to_user_id()`` method provides OpenFGA-compatible user IDs.

        Args:
            claims: Validated TokenClaims from ``validate_token()``.

        Returns:
            ServiceIdentity with client_id, issuer, and scopes.

        Raises:
            TokenValidationError: If identity cannot be extracted.
        """
        try:
            identity = ServiceIdentity.from_claims(claims)
        except ValueError as e:
            raise TokenValidationError(
                reason=f"Failed to extract service identity: {e}",
            ) from e

        logger.info(
            "identity_extracted",
            client_id=identity.client_id,
            issuer=identity.issuer,
            scope_count=len(identity.scopes),
        )
        return identity

    async def discover_provider(self) -> OIDCProviderConfig:
        """Fetch OIDC discovery document from Keycloak.

        Retrieves ``{issuer_url}/.well-known/openid-configuration``
        and parses it into an ``OIDCProviderConfig``. Results are
        cached with the same TTL as JWKS.

        Returns:
            OIDCProviderConfig with provider endpoints.

        Raises:
            OIDCProviderUnavailableError: If provider is unreachable.
            TokenValidationError: If discovery document is malformed.
        """
        if self._discovery_cache is not None and self._is_cache_fresh(self._discovery_fetched_at):
            return self._discovery_cache

        discovery_url = f"{self._issuer_url}/.well-known/openid-configuration"

        try:
            data: dict[str, Any] = await self._http_get_json(discovery_url)
        except httpx.HTTPError as e:
            raise OIDCProviderUnavailableError(
                provider_url=self._issuer_url,
                underlying_error=e,
            ) from e

        try:
            config = OIDCProviderConfig(
                issuer_url=data["issuer"],
                jwks_uri=data["jwks_uri"],
                token_endpoint=data["token_endpoint"],
                authorization_endpoint=data.get("authorization_endpoint"),
            )
        except KeyError as e:
            raise TokenValidationError(
                reason=f"OIDC discovery document missing field: {e}",
            ) from e
        except Exception as e:
            raise TokenValidationError(
                reason="Malformed OIDC discovery document",
            ) from e

        self._discovery_cache = config
        self._discovery_fetched_at = time.monotonic()
        logger.info(
            "oidc_provider_discovered",
            issuer=config.issuer_url,
        )
        return config

    async def health_check(self) -> bool:
        """Check OIDC provider availability.

        Attempts to fetch the discovery document. Returns True on
        success, False on any error. Never raises exceptions.

        Returns:
            True if provider is reachable and healthy.
        """
        try:
            await self.discover_provider()
        except Exception as e:
            logger.warning(
                "oidc_health_check_failed",
                error_type=type(e).__name__,
            )
            return False

        logger.debug("oidc_health_check_passed")
        return True


def _extract_jti_safe(raw_token: str) -> str | None:
    """Extract jti from a JWT without signature verification.

    Used to include token ID in error messages for traceability.
    Never raises exceptions.

    Args:
        raw_token: Raw JWT string.

    Returns:
        The jti claim value, or None if extraction fails.
    """
    try:
        payload = jwt.decode(
            raw_token,
            algorithms=["RS256"],
            options={"verify_signature": False},
        )
    except Exception:
        return None
    else:
        jti = payload.get("jti")
        if isinstance(jti, str):
            return jti
        return None


__all__ = [
    "KeycloakOIDCAdapter",
]
