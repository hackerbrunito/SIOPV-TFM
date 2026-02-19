"""Unit tests for OIDC value objects.

Tests the core OIDC value objects:
- TokenClaims: JWT token claims validation
- ServiceIdentity: Service identity mapping to UserId
- OIDCProviderConfig: OIDC provider configuration
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from siopv.domain.authorization.value_objects import UserId
from siopv.domain.oidc.value_objects import (
    OIDCProviderConfig,
    ServiceIdentity,
    TokenClaims,
)

# === Fixtures ===


@pytest.fixture
def sample_token_claims() -> dict[str, object]:
    """Sample valid token claims payload."""
    return {
        "sub": "service-account-siopv-client",
        "iss": "http://localhost:8888/realms/siopv",
        "aud": "siopv-api",
        "exp": 1234567890,
        "iat": 1234560000,
        "azp": "siopv-client",
        "scope": "read write",
        "client_id": "siopv-client",
        "jti": "unique-token-id-123",
    }


@pytest.fixture
def minimal_token_claims() -> dict[str, object]:
    """Minimal valid token claims (only required fields)."""
    return {
        "sub": "service-account-test",
        "iss": "http://localhost:8888/realms/test",
        "aud": "test-api",
        "exp": 1234567890,
        "iat": 1234560000,
    }


@pytest.fixture
def sample_provider_config() -> dict[str, str]:
    """Sample OIDC provider configuration."""
    return {
        "issuer_url": "http://localhost:8888/realms/siopv",
        "jwks_uri": "http://localhost:8888/realms/siopv/protocol/openid-connect/certs",
        "token_endpoint": "http://localhost:8888/realms/siopv/protocol/openid-connect/token",
        "authorization_endpoint": "http://localhost:8888/realms/siopv/protocol/openid-connect/auth",
    }


# === Test TokenClaims ===


class TestTokenClaims:
    """Tests for TokenClaims value object."""

    def test_token_claims_creation_with_all_fields(
        self,
        sample_token_claims: dict[str, object],
    ) -> None:
        """Test creating TokenClaims with all fields."""
        claims = TokenClaims(**sample_token_claims)

        assert claims.sub == "service-account-siopv-client"
        assert claims.iss == "http://localhost:8888/realms/siopv"
        assert claims.aud == "siopv-api"
        assert claims.exp == 1234567890
        assert claims.iat == 1234560000
        assert claims.azp == "siopv-client"
        assert claims.scope == "read write"
        assert claims.client_id == "siopv-client"
        assert claims.jti == "unique-token-id-123"

    def test_token_claims_creation_minimal(
        self,
        minimal_token_claims: dict[str, object],
    ) -> None:
        """Test creating TokenClaims with only required fields."""
        claims = TokenClaims(**minimal_token_claims)

        assert claims.sub == "service-account-test"
        assert claims.iss == "http://localhost:8888/realms/test"
        assert claims.aud == "test-api"
        assert claims.exp == 1234567890
        assert claims.iat == 1234560000
        # Optional fields should be None
        assert claims.azp is None
        assert claims.scope is None
        assert claims.client_id is None
        assert claims.jti is None

    def test_token_claims_frozen(
        self,
        sample_token_claims: dict[str, object],
    ) -> None:
        """Test that TokenClaims is immutable (frozen)."""
        claims = TokenClaims(**sample_token_claims)

        with pytest.raises(ValidationError, match="frozen"):
            claims.sub = "new-subject"  # type: ignore[misc]

    def test_token_claims_aud_as_list(self) -> None:
        """Test TokenClaims with audience as list."""
        claims = TokenClaims(
            sub="test",
            iss="http://issuer",
            aud=["api1", "api2"],
            exp=1234567890,
            iat=1234560000,
        )

        assert claims.aud == ["api1", "api2"]

    def test_token_claims_validate_exp_positive(self) -> None:
        """Test exp validator rejects non-positive timestamps."""
        with pytest.raises(ValidationError, match="Expiration time must be a positive"):
            TokenClaims(
                sub="test",
                iss="http://issuer",
                aud="api",
                exp=0,  # Invalid: not positive
                iat=1234560000,
            )

        with pytest.raises(ValidationError, match="Expiration time must be a positive"):
            TokenClaims(
                sub="test",
                iss="http://issuer",
                aud="api",
                exp=-100,  # Invalid: negative
                iat=1234560000,
            )

    def test_token_claims_validate_iat_positive(self) -> None:
        """Test iat validator rejects non-positive timestamps."""
        with pytest.raises(ValidationError, match="Issued-at time must be a positive"):
            TokenClaims(
                sub="test",
                iss="http://issuer",
                aud="api",
                exp=1234567890,
                iat=0,  # Invalid: not positive
            )

        with pytest.raises(ValidationError, match="Issued-at time must be a positive"):
            TokenClaims(
                sub="test",
                iss="http://issuer",
                aud="api",
                exp=1234567890,
                iat=-100,  # Invalid: negative
            )

    def test_get_effective_client_id_from_azp(self) -> None:
        """Test get_effective_client_id prioritizes azp."""
        claims = TokenClaims(
            sub="service-account-test",
            iss="http://issuer",
            aud="api",
            exp=1234567890,
            iat=1234560000,
            azp="client-from-azp",
            client_id="client-from-client-id",
        )

        assert claims.get_effective_client_id() == "client-from-azp"

    def test_get_effective_client_id_from_client_id(self) -> None:
        """Test get_effective_client_id falls back to client_id."""
        claims = TokenClaims(
            sub="service-account-test",
            iss="http://issuer",
            aud="api",
            exp=1234567890,
            iat=1234560000,
            azp=None,
            client_id="client-from-client-id",
        )

        assert claims.get_effective_client_id() == "client-from-client-id"

    def test_get_effective_client_id_from_sub(self) -> None:
        """Test get_effective_client_id falls back to sub."""
        claims = TokenClaims(
            sub="service-account-fallback",
            iss="http://issuer",
            aud="api",
            exp=1234567890,
            iat=1234560000,
            azp=None,
            client_id=None,
        )

        assert claims.get_effective_client_id() == "service-account-fallback"

    def test_get_scopes_with_space_delimited_string(self) -> None:
        """Test get_scopes parses space-delimited scope string."""
        claims = TokenClaims(
            sub="test",
            iss="http://issuer",
            aud="api",
            exp=1234567890,
            iat=1234560000,
            scope="read write admin",
        )

        scopes = claims.get_scopes()
        assert scopes == frozenset({"read", "write", "admin"})

    def test_get_scopes_empty_string(self) -> None:
        """Test get_scopes returns empty frozenset for empty string."""
        claims = TokenClaims(
            sub="test",
            iss="http://issuer",
            aud="api",
            exp=1234567890,
            iat=1234560000,
            scope="",
        )

        scopes = claims.get_scopes()
        assert scopes == frozenset()

    def test_get_scopes_none(self) -> None:
        """Test get_scopes returns empty frozenset when scope is None."""
        claims = TokenClaims(
            sub="test",
            iss="http://issuer",
            aud="api",
            exp=1234567890,
            iat=1234560000,
            scope=None,
        )

        scopes = claims.get_scopes()
        assert scopes == frozenset()

    def test_get_scopes_with_extra_whitespace(self) -> None:
        """Test get_scopes handles extra whitespace."""
        claims = TokenClaims(
            sub="test",
            iss="http://issuer",
            aud="api",
            exp=1234567890,
            iat=1234560000,
            scope="  read   write  ",
        )

        scopes = claims.get_scopes()
        assert scopes == frozenset({"read", "write"})


# === Test ServiceIdentity ===


class TestServiceIdentity:
    """Tests for ServiceIdentity value object."""

    def test_service_identity_creation(self) -> None:
        """Test creating ServiceIdentity with all fields."""
        identity = ServiceIdentity(
            client_id="siopv-client",
            issuer="http://localhost:8888/realms/siopv",
            scopes=frozenset({"read", "write"}),
        )

        assert identity.client_id == "siopv-client"
        assert identity.issuer == "http://localhost:8888/realms/siopv"
        assert identity.scopes == frozenset({"read", "write"})

    def test_service_identity_frozen(self) -> None:
        """Test that ServiceIdentity is immutable (frozen)."""
        identity = ServiceIdentity(
            client_id="test-client",
            issuer="http://issuer",
        )

        with pytest.raises(ValidationError, match="frozen"):
            identity.client_id = "new-client"  # type: ignore[misc]

    def test_service_identity_default_scopes(self) -> None:
        """Test ServiceIdentity defaults scopes to empty frozenset."""
        identity = ServiceIdentity(
            client_id="test-client",
            issuer="http://issuer",
        )

        assert identity.scopes == frozenset()

    def test_service_identity_validate_client_id_safe_characters(self) -> None:
        """Test client_id validator accepts safe characters."""
        # Valid characters: a-zA-Z0-9_@.-
        valid_client_ids = [
            "client123",
            "client_test",
            "client@example.com",
            "client.test",
            "client-test",
        ]

        for client_id in valid_client_ids:
            identity = ServiceIdentity(
                client_id=client_id,
                issuer="http://issuer",
            )
            assert identity.client_id == client_id

    def test_service_identity_validate_client_id_unsafe_characters(self) -> None:
        """Test client_id validator rejects unsafe characters."""
        invalid_client_ids = [
            "client:test",  # Colon not allowed (UserId regex constraint)
            "client/test",  # Slash not allowed
            "client test",  # Space not allowed
            "client#test",  # Hash not allowed
        ]

        for client_id in invalid_client_ids:
            with pytest.raises(
                ValidationError,
                match="Client ID contains invalid characters",
            ):
                ServiceIdentity(
                    client_id=client_id,
                    issuer="http://issuer",
                )

    def test_to_user_id_format(self) -> None:
        """Test to_user_id returns UserId with service- prefix."""
        identity = ServiceIdentity(
            client_id="siopv-client",
            issuer="http://localhost:8888/realms/siopv",
        )

        user_id = identity.to_user_id()

        assert isinstance(user_id, UserId)
        assert user_id.value == "service-siopv-client"

    def test_to_user_id_different_client_ids(self) -> None:
        """Test to_user_id with various client IDs."""
        test_cases = [
            ("test-client", "service-test-client"),
            ("client123", "service-client123"),
            ("my_client", "service-my_client"),
        ]

        for client_id, expected_user_id in test_cases:
            identity = ServiceIdentity(
                client_id=client_id,
                issuer="http://issuer",
            )
            user_id = identity.to_user_id()
            assert user_id.value == expected_user_id

    def test_from_claims_with_all_fields(
        self,
        sample_token_claims: dict[str, object],
    ) -> None:
        """Test from_claims factory method with all fields."""
        claims = TokenClaims(**sample_token_claims)
        identity = ServiceIdentity.from_claims(claims)

        assert identity.client_id == "siopv-client"  # From azp
        assert identity.issuer == "http://localhost:8888/realms/siopv"
        assert identity.scopes == frozenset({"read", "write"})

    def test_from_claims_minimal(
        self,
        minimal_token_claims: dict[str, object],
    ) -> None:
        """Test from_claims factory method with minimal claims."""
        claims = TokenClaims(**minimal_token_claims)
        identity = ServiceIdentity.from_claims(claims)

        assert identity.client_id == "service-account-test"  # From sub (fallback)
        assert identity.issuer == "http://localhost:8888/realms/test"
        assert identity.scopes == frozenset()  # No scope claim

    def test_from_claims_uses_effective_client_id(self) -> None:
        """Test from_claims uses get_effective_client_id logic."""
        # Priority: azp > client_id > sub
        claims = TokenClaims(
            sub="sub-value",
            iss="http://issuer",
            aud="api",
            exp=1234567890,
            iat=1234560000,
            azp="azp-value",
            client_id="client-id-value",
        )

        identity = ServiceIdentity.from_claims(claims)
        assert identity.client_id == "azp-value"


# === Test OIDCProviderConfig ===


class TestOIDCProviderConfig:
    """Tests for OIDCProviderConfig value object."""

    def test_provider_config_creation_with_all_fields(
        self,
        sample_provider_config: dict[str, str],
    ) -> None:
        """Test creating OIDCProviderConfig with all fields."""
        config = OIDCProviderConfig(**sample_provider_config)

        assert config.issuer_url == "http://localhost:8888/realms/siopv"
        assert config.jwks_uri == "http://localhost:8888/realms/siopv/protocol/openid-connect/certs"
        assert (
            config.token_endpoint
            == "http://localhost:8888/realms/siopv/protocol/openid-connect/token"
        )
        assert (
            config.authorization_endpoint
            == "http://localhost:8888/realms/siopv/protocol/openid-connect/auth"
        )

    def test_provider_config_creation_without_authorization_endpoint(self) -> None:
        """Test creating OIDCProviderConfig without authorization_endpoint."""
        config = OIDCProviderConfig(
            issuer_url="http://localhost:8888/realms/siopv",
            jwks_uri="http://localhost:8888/realms/siopv/protocol/openid-connect/certs",
            token_endpoint="http://localhost:8888/realms/siopv/protocol/openid-connect/token",
        )

        assert config.authorization_endpoint is None

    def test_provider_config_frozen(
        self,
        sample_provider_config: dict[str, str],
    ) -> None:
        """Test that OIDCProviderConfig is immutable (frozen)."""
        config = OIDCProviderConfig(**sample_provider_config)

        with pytest.raises(ValidationError, match="frozen"):
            config.issuer_url = "http://new-issuer"  # type: ignore[misc]

    def test_provider_config_validate_url_scheme_http(self) -> None:
        """Test URL validator accepts http scheme."""
        config = OIDCProviderConfig(
            issuer_url="http://localhost:8888/realms/siopv",
            jwks_uri="http://localhost:8888/certs",
            token_endpoint="http://localhost:8888/token",
        )

        assert config.issuer_url.startswith("http://")

    def test_provider_config_validate_url_scheme_https(self) -> None:
        """Test URL validator accepts https scheme."""
        config = OIDCProviderConfig(
            issuer_url="https://auth.example.com/realms/siopv",
            jwks_uri="https://auth.example.com/certs",
            token_endpoint="https://auth.example.com/token",
        )

        assert config.issuer_url.startswith("https://")

    def test_provider_config_validate_url_scheme_invalid_issuer(self) -> None:
        """Test URL validator rejects invalid scheme for issuer_url."""
        with pytest.raises(ValidationError, match="URL must use http or https scheme"):
            OIDCProviderConfig(
                issuer_url="ftp://invalid-scheme/realms/siopv",
                jwks_uri="http://localhost:8888/certs",
                token_endpoint="http://localhost:8888/token",
            )

    def test_provider_config_validate_url_scheme_invalid_jwks_uri(self) -> None:
        """Test URL validator rejects invalid scheme for jwks_uri."""
        with pytest.raises(ValidationError, match="URL must use http or https scheme"):
            OIDCProviderConfig(
                issuer_url="http://localhost:8888/realms/siopv",
                jwks_uri="file:///tmp/certs",
                token_endpoint="http://localhost:8888/token",
            )

    def test_provider_config_validate_url_scheme_invalid_token_endpoint(self) -> None:
        """Test URL validator rejects invalid scheme for token_endpoint."""
        with pytest.raises(ValidationError, match="URL must use http or https scheme"):
            OIDCProviderConfig(
                issuer_url="http://localhost:8888/realms/siopv",
                jwks_uri="http://localhost:8888/certs",
                token_endpoint="ws://invalid-scheme/token",
            )

    def test_provider_config_missing_required_fields(self) -> None:
        """Test creating OIDCProviderConfig without required fields fails."""
        with pytest.raises(ValidationError):
            OIDCProviderConfig(  # type: ignore[call-arg]
                issuer_url="http://issuer",
                # Missing jwks_uri and token_endpoint
            )
