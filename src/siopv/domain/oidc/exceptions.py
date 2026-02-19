"""OIDC-specific domain exceptions for SIOPV.

These exceptions extend the base ``AuthorizationError`` from
``domain/exceptions.py`` with error types specific to OIDC
authentication flows (JWT validation, JWKS fetching, provider issues).

Security: Error messages are kept generic to avoid leaking
internal details (no PII, no token content, no raw URLs).
Detailed debugging information is stored in instance attributes.
"""

from __future__ import annotations

from typing import Any

from siopv.domain.exceptions import AuthorizationError


class OIDCError(AuthorizationError):
    """Base exception for all OIDC authentication errors.

    All OIDC-specific exceptions inherit from this class, which itself
    extends ``AuthorizationError``. This allows catching all OIDC errors
    with a single except clause while still distinguishing them from
    general authorization errors.
    """

    def __init__(
        self,
        message: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message, details)


class TokenValidationError(OIDCError):
    """Raised when JWT token validation fails.

    Covers signature verification failures, malformed tokens,
    and generic decoding errors. More specific subclasses exist
    for expired tokens, invalid issuers, and invalid audiences.
    """

    def __init__(
        self,
        reason: str,
        *,
        token_id: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        """Initialize TokenValidationError.

        Args:
            reason: Why validation failed (generic, no PII).
            token_id: Optional JWT ID (jti) for tracing.
            details: Additional error details for debugging.
        """
        self.reason = reason
        self.token_id = token_id

        # Security: Generic message, no raw token content
        message = f"Token validation failed: {reason}"
        super().__init__(message, details)


class TokenExpiredError(TokenValidationError):
    """Raised when a JWT token has expired.

    The ``exp`` claim is in the past beyond the allowed clock skew.
    """

    def __init__(
        self,
        *,
        token_id: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        """Initialize TokenExpiredError.

        Args:
            token_id: Optional JWT ID (jti) for tracing.
            details: Additional error details for debugging.
        """
        super().__init__(
            reason="Token has expired",
            token_id=token_id,
            details=details,
        )


class InvalidIssuerError(TokenValidationError):
    """Raised when the JWT issuer does not match the expected issuer.

    The ``iss`` claim does not match the configured OIDC issuer URL.
    """

    def __init__(
        self,
        *,
        expected_issuer: str | None = None,
        token_id: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        """Initialize InvalidIssuerError.

        Args:
            expected_issuer: The expected issuer URL (for debugging).
            token_id: Optional JWT ID (jti) for tracing.
            details: Additional error details for debugging.
        """
        self.expected_issuer = expected_issuer

        super().__init__(
            reason="Token issuer is not trusted",
            token_id=token_id,
            details=details,
        )


class InvalidAudienceError(TokenValidationError):
    """Raised when the JWT audience does not match the expected audience.

    The ``aud`` claim does not include the configured OIDC audience.
    """

    def __init__(
        self,
        *,
        expected_audience: str | None = None,
        token_id: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        """Initialize InvalidAudienceError.

        Args:
            expected_audience: The expected audience value (for debugging).
            token_id: Optional JWT ID (jti) for tracing.
            details: Additional error details for debugging.
        """
        self.expected_audience = expected_audience

        super().__init__(
            reason="Token audience mismatch",
            token_id=token_id,
            details=details,
        )


class JWKSFetchError(OIDCError):
    """Raised when fetching the JWKS (JSON Web Key Set) fails.

    This can occur due to network issues, invalid JWKS URI,
    or the OIDC provider being temporarily unavailable.
    """

    def __init__(
        self,
        *,
        jwks_uri: str | None = None,
        underlying_error: Exception | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        """Initialize JWKSFetchError.

        Args:
            jwks_uri: The JWKS URI that was attempted (for debugging).
            underlying_error: The original network/HTTP error.
            details: Additional error details for debugging.
        """
        self.jwks_uri = jwks_uri
        self.underlying_error = underlying_error

        # Security: Do not include the URI in the message
        message = "Failed to fetch JWKS from OIDC provider"
        if underlying_error:
            message += f" (caused by: {type(underlying_error).__name__})"

        super().__init__(message, details)


class OIDCProviderUnavailableError(OIDCError):
    """Raised when the OIDC provider is unreachable or unhealthy.

    Covers discovery document fetch failures, health check failures,
    and general connectivity issues with the OIDC provider.
    """

    def __init__(
        self,
        *,
        provider_url: str | None = None,
        underlying_error: Exception | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        """Initialize OIDCProviderUnavailableError.

        Args:
            provider_url: The provider URL that was attempted (for debugging).
            underlying_error: The original network/HTTP error.
            details: Additional error details for debugging.
        """
        self.provider_url = provider_url
        self.underlying_error = underlying_error

        # Security: Do not include the URL in the message
        message = "OIDC provider is unavailable"
        if underlying_error:
            message += f" (caused by: {type(underlying_error).__name__})"

        super().__init__(message, details)


__all__ = [
    "InvalidAudienceError",
    "InvalidIssuerError",
    "JWKSFetchError",
    "OIDCError",
    "OIDCProviderUnavailableError",
    "TokenExpiredError",
    "TokenValidationError",
]
