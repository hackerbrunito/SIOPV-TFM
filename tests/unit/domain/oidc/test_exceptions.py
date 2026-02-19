"""Unit tests for OIDC domain exceptions.

Tests the OIDC exception hierarchy:
- OIDCError: Base exception
- TokenValidationError: Generic validation failures
- TokenExpiredError: Expired tokens
- InvalidIssuerError: Issuer mismatch
- InvalidAudienceError: Audience mismatch
- JWKSFetchError: JWKS fetching failures
- OIDCProviderUnavailableError: Provider connectivity issues
"""

from __future__ import annotations

import httpx
import pytest

from siopv.domain.exceptions import AuthorizationError
from siopv.domain.oidc.exceptions import (
    InvalidAudienceError,
    InvalidIssuerError,
    JWKSFetchError,
    OIDCError,
    OIDCProviderUnavailableError,
    TokenExpiredError,
    TokenValidationError,
)

# === Test Exception Hierarchy ===


class TestExceptionHierarchy:
    """Tests for exception inheritance structure."""

    def test_oidc_error_extends_authorization_error(self) -> None:
        """Test OIDCError extends AuthorizationError."""
        exc = OIDCError("test error")
        assert isinstance(exc, AuthorizationError)

    def test_token_validation_error_extends_oidc_error(self) -> None:
        """Test TokenValidationError extends OIDCError."""
        exc = TokenValidationError("test")
        assert isinstance(exc, OIDCError)
        assert isinstance(exc, AuthorizationError)

    def test_token_expired_error_extends_token_validation_error(self) -> None:
        """Test TokenExpiredError extends TokenValidationError."""
        exc = TokenExpiredError()
        assert isinstance(exc, TokenValidationError)
        assert isinstance(exc, OIDCError)
        assert isinstance(exc, AuthorizationError)

    def test_invalid_issuer_error_extends_token_validation_error(self) -> None:
        """Test InvalidIssuerError extends TokenValidationError."""
        exc = InvalidIssuerError()
        assert isinstance(exc, TokenValidationError)
        assert isinstance(exc, OIDCError)

    def test_invalid_audience_error_extends_token_validation_error(self) -> None:
        """Test InvalidAudienceError extends TokenValidationError."""
        exc = InvalidAudienceError()
        assert isinstance(exc, TokenValidationError)
        assert isinstance(exc, OIDCError)

    def test_jwks_fetch_error_extends_oidc_error(self) -> None:
        """Test JWKSFetchError extends OIDCError."""
        exc = JWKSFetchError()
        assert isinstance(exc, OIDCError)
        assert isinstance(exc, AuthorizationError)

    def test_provider_unavailable_error_extends_oidc_error(self) -> None:
        """Test OIDCProviderUnavailableError extends OIDCError."""
        exc = OIDCProviderUnavailableError()
        assert isinstance(exc, OIDCError)
        assert isinstance(exc, AuthorizationError)


# === Test OIDCError ===


class TestOIDCError:
    """Tests for OIDCError base exception."""

    def test_oidc_error_message(self) -> None:
        """Test OIDCError stores message."""
        exc = OIDCError("Test error message")
        assert str(exc) == "Test error message"

    def test_oidc_error_with_details(self) -> None:
        """Test OIDCError stores details dict and formats message."""
        details = {"key": "value", "code": 123}
        exc = OIDCError("Test error", details=details)

        # Parent class formats details into __str__
        assert str(exc) == "Test error | Details: {'key': 'value', 'code': 123}"
        assert exc.details == details

    def test_oidc_error_without_details(self) -> None:
        """Test OIDCError with no details."""
        exc = OIDCError("Test error")
        # Parent class sets details = {} when None
        assert exc.details == {}
        assert str(exc) == "Test error"


# === Test TokenValidationError ===


class TestTokenValidationError:
    """Tests for TokenValidationError."""

    def test_token_validation_error_message_format(self) -> None:
        """Test TokenValidationError formats message with reason."""
        exc = TokenValidationError("Malformed JWT")
        assert str(exc) == "Token validation failed: Malformed JWT"

    def test_token_validation_error_stores_reason(self) -> None:
        """Test TokenValidationError stores reason attribute."""
        exc = TokenValidationError("Invalid signature")
        assert exc.reason == "Invalid signature"

    def test_token_validation_error_with_token_id(self) -> None:
        """Test TokenValidationError with token ID."""
        exc = TokenValidationError("Test reason", token_id="token-123")
        assert exc.token_id == "token-123"
        assert exc.reason == "Test reason"

    def test_token_validation_error_with_details(self) -> None:
        """Test TokenValidationError with details dict."""
        details = {"kid": "key-123"}
        exc = TokenValidationError("No matching key", details=details)

        assert exc.reason == "No matching key"
        assert exc.details == details

    def test_token_validation_error_without_token_id(self) -> None:
        """Test TokenValidationError defaults token_id to None."""
        exc = TokenValidationError("Test reason")
        assert exc.token_id is None


# === Test TokenExpiredError ===


class TestTokenExpiredError:
    """Tests for TokenExpiredError."""

    def test_token_expired_error_message(self) -> None:
        """Test TokenExpiredError has correct message."""
        exc = TokenExpiredError()
        assert "Token has expired" in str(exc)

    def test_token_expired_error_with_token_id(self) -> None:
        """Test TokenExpiredError with token ID."""
        exc = TokenExpiredError(token_id="expired-token-456")
        assert exc.token_id == "expired-token-456"
        assert exc.reason == "Token has expired"

    def test_token_expired_error_with_details(self) -> None:
        """Test TokenExpiredError with details dict."""
        details = {"exp": 1234567890, "now": 1234567900}
        exc = TokenExpiredError(details=details)

        assert exc.details == details
        assert exc.reason == "Token has expired"


# === Test InvalidIssuerError ===


class TestInvalidIssuerError:
    """Tests for InvalidIssuerError."""

    def test_invalid_issuer_error_message(self) -> None:
        """Test InvalidIssuerError has correct message."""
        exc = InvalidIssuerError()
        assert "Token issuer is not trusted" in str(exc)

    def test_invalid_issuer_error_with_expected_issuer(self) -> None:
        """Test InvalidIssuerError stores expected_issuer."""
        exc = InvalidIssuerError(
            expected_issuer="http://localhost:8888/realms/siopv",
        )
        assert exc.expected_issuer == "http://localhost:8888/realms/siopv"
        assert exc.reason == "Token issuer is not trusted"

    def test_invalid_issuer_error_with_token_id(self) -> None:
        """Test InvalidIssuerError with token ID."""
        exc = InvalidIssuerError(token_id="token-789")
        assert exc.token_id == "token-789"

    def test_invalid_issuer_error_with_details(self) -> None:
        """Test InvalidIssuerError with details dict."""
        details = {"actual_iss": "http://wrong-issuer"}
        exc = InvalidIssuerError(
            expected_issuer="http://correct-issuer",
            details=details,
        )

        assert exc.expected_issuer == "http://correct-issuer"
        assert exc.details == details


# === Test InvalidAudienceError ===


class TestInvalidAudienceError:
    """Tests for InvalidAudienceError."""

    def test_invalid_audience_error_message(self) -> None:
        """Test InvalidAudienceError has correct message."""
        exc = InvalidAudienceError()
        assert "Token audience mismatch" in str(exc)

    def test_invalid_audience_error_with_expected_audience(self) -> None:
        """Test InvalidAudienceError stores expected_audience."""
        exc = InvalidAudienceError(expected_audience="siopv-api")
        assert exc.expected_audience == "siopv-api"
        assert exc.reason == "Token audience mismatch"

    def test_invalid_audience_error_with_token_id(self) -> None:
        """Test InvalidAudienceError with token ID."""
        exc = InvalidAudienceError(token_id="token-abc")
        assert exc.token_id == "token-abc"

    def test_invalid_audience_error_with_details(self) -> None:
        """Test InvalidAudienceError with details dict."""
        details = {"actual_aud": ["wrong-api"]}
        exc = InvalidAudienceError(
            expected_audience="correct-api",
            details=details,
        )

        assert exc.expected_audience == "correct-api"
        assert exc.details == details


# === Test JWKSFetchError ===


class TestJWKSFetchError:
    """Tests for JWKSFetchError."""

    def test_jwks_fetch_error_message(self) -> None:
        """Test JWKSFetchError has correct message."""
        exc = JWKSFetchError()
        assert "Failed to fetch JWKS from OIDC provider" in str(exc)

    def test_jwks_fetch_error_with_jwks_uri(self) -> None:
        """Test JWKSFetchError stores jwks_uri."""
        exc = JWKSFetchError(
            jwks_uri="http://localhost:8888/certs",
        )
        assert exc.jwks_uri == "http://localhost:8888/certs"

    def test_jwks_fetch_error_message_no_uri_in_message(self) -> None:
        """Test JWKSFetchError doesn't include URI in message (security)."""
        exc = JWKSFetchError(
            jwks_uri="http://localhost:8888/certs",
        )
        # Security: URI should NOT appear in the message
        assert "http://localhost:8888" not in str(exc)

    def test_jwks_fetch_error_with_underlying_error(self) -> None:
        """Test JWKSFetchError stores underlying error."""
        underlying = httpx.ConnectError("Connection refused")
        exc = JWKSFetchError(underlying_error=underlying)

        assert exc.underlying_error is underlying
        # Error type should be in message
        assert "ConnectError" in str(exc)

    def test_jwks_fetch_error_with_details(self) -> None:
        """Test JWKSFetchError with details dict."""
        details = {"status_code": 500}
        exc = JWKSFetchError(details=details)

        assert exc.details == details


# === Test OIDCProviderUnavailableError ===


class TestOIDCProviderUnavailableError:
    """Tests for OIDCProviderUnavailableError."""

    def test_provider_unavailable_error_message(self) -> None:
        """Test OIDCProviderUnavailableError has correct message."""
        exc = OIDCProviderUnavailableError()
        assert "OIDC provider is unavailable" in str(exc)

    def test_provider_unavailable_error_with_provider_url(self) -> None:
        """Test OIDCProviderUnavailableError stores provider_url."""
        exc = OIDCProviderUnavailableError(
            provider_url="http://localhost:8888/realms/siopv",
        )
        assert exc.provider_url == "http://localhost:8888/realms/siopv"

    def test_provider_unavailable_error_message_no_url_in_message(self) -> None:
        """Test OIDCProviderUnavailableError doesn't include URL in message (security)."""
        exc = OIDCProviderUnavailableError(
            provider_url="http://localhost:8888/realms/siopv",
        )
        # Security: URL should NOT appear in the message
        assert "http://localhost:8888" not in str(exc)

    def test_provider_unavailable_error_with_underlying_error(self) -> None:
        """Test OIDCProviderUnavailableError stores underlying error."""
        underlying = httpx.TimeoutException("Request timeout")
        exc = OIDCProviderUnavailableError(underlying_error=underlying)

        assert exc.underlying_error is underlying
        # Error type should be in message
        assert "TimeoutException" in str(exc)

    def test_provider_unavailable_error_with_details(self) -> None:
        """Test OIDCProviderUnavailableError with details dict."""
        details = {"retry_count": 3}
        exc = OIDCProviderUnavailableError(details=details)

        assert exc.details == details


# === Test Catching Exceptions ===


class TestCatchingExceptions:
    """Tests for catching exceptions at different levels."""

    def test_catch_all_oidc_errors(self) -> None:
        """Test catching all OIDC errors with base class."""
        oidc_exceptions = [
            OIDCError("test"),
            TokenValidationError("test"),
            TokenExpiredError(),
            InvalidIssuerError(),
            InvalidAudienceError(),
            JWKSFetchError(),
            OIDCProviderUnavailableError(),
        ]

        for exc in oidc_exceptions:
            with pytest.raises(OIDCError):
                raise exc

    def test_catch_all_token_validation_errors(self) -> None:
        """Test catching token validation errors with base class."""
        validation_exceptions = [
            TokenValidationError("test"),
            TokenExpiredError(),
            InvalidIssuerError(),
            InvalidAudienceError(),
        ]

        for exc in validation_exceptions:
            with pytest.raises(TokenValidationError):
                raise exc

    def test_catch_all_authorization_errors(self) -> None:
        """Test catching OIDC errors as AuthorizationError."""
        exc = OIDCError("test")

        with pytest.raises(AuthorizationError):
            raise exc
