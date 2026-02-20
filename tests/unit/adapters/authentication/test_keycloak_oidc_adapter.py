"""Unit tests for KeycloakOIDCAdapter.

Tests OIDC authentication adapter with:
- JWT token validation with RS256
- JWKS fetching and caching
- Provider discovery
- Error mapping to domain exceptions
- httpx mocking via respx
"""

from __future__ import annotations

import time
from typing import Any

import httpx
import jwt
import pytest
import respx
from cryptography.hazmat.primitives.asymmetric import rsa

from siopv.adapters.authentication.keycloak_oidc_adapter import (
    KeycloakOIDCAdapter,
)
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
from siopv.infrastructure.config.settings import Settings

# === Fixtures ===


@pytest.fixture
def rsa_keypair() -> tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    """Generate RSA key pair for JWT signing."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    return private_key, public_key


@pytest.fixture
def jwks_data(rsa_keypair: tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]) -> dict[str, Any]:
    """Generate JWKS data from RSA public key."""
    import base64

    _, public_key = rsa_keypair

    # Extract public key numbers for JWK
    public_numbers = public_key.public_numbers()

    # Convert integers to base64url-encoded strings (RFC 7518)
    def int_to_base64url(num: int) -> str:
        """Convert integer to base64url-encoded string."""
        # Convert to bytes (big-endian)
        num_bytes = num.to_bytes((num.bit_length() + 7) // 8, byteorder="big")
        # Base64url encode (no padding)
        return base64.urlsafe_b64encode(num_bytes).rstrip(b"=").decode("ascii")

    # Build JWKS response with RSA public key components
    return {
        "keys": [
            {
                "kty": "RSA",
                "use": "sig",
                "kid": "test-key-id",
                "alg": "RS256",
                "n": int_to_base64url(public_numbers.n),
                "e": int_to_base64url(public_numbers.e),
            },
        ],
    }


@pytest.fixture
def valid_token_payload() -> dict[str, Any]:
    """Valid token payload for testing."""
    now = int(time.time())
    return {
        "sub": "service-account-siopv-client",
        "iss": "http://localhost:8888/realms/siopv",
        "aud": "siopv-api",
        "exp": now + 3600,  # 1 hour from now
        "iat": now,
        "azp": "siopv-client",
        "scope": "read write",
        "client_id": "siopv-client",
        "jti": "test-token-123",
    }


@pytest.fixture
def create_jwt_token(
    rsa_keypair: tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey],
) -> Any:
    """Factory fixture to create signed JWT tokens."""

    def _create_token(
        payload: dict[str, Any],
        kid: str = "test-key-id",
    ) -> str:
        private_key, _ = rsa_keypair
        return jwt.encode(
            payload,
            private_key,
            algorithm="RS256",
            headers={"kid": kid},
        )

    return _create_token


@pytest.fixture
def settings() -> Settings:
    """Settings with OIDC configuration."""
    return Settings(
        oidc_enabled=True,
        oidc_issuer_url="http://localhost:8888/realms/siopv",
        oidc_audience="siopv-api",
        oidc_jwks_cache_ttl_seconds=3600,
        oidc_allowed_clock_skew_seconds=30,
        # Required base settings
        openfga_api_url="http://localhost:8080",
        openfga_store_id="test-store",
        openfga_authorization_model_id="test-model",
    )


@pytest.fixture
def discovery_document() -> dict[str, Any]:
    """OIDC discovery document."""
    return {
        "issuer": "http://localhost:8888/realms/siopv",
        "jwks_uri": "http://localhost:8888/realms/siopv/protocol/openid-connect/certs",
        "token_endpoint": "http://localhost:8888/realms/siopv/protocol/openid-connect/token",
        "authorization_endpoint": "http://localhost:8888/realms/siopv/protocol/openid-connect/auth",
    }


# === Test Initialization ===


class TestKeycloakOIDCAdapterInitialization:
    """Tests for adapter initialization."""

    def test_adapter_initialization(self, settings: Settings) -> None:
        """Test adapter initializes with settings."""
        adapter = KeycloakOIDCAdapter(settings)

        # Internal state should be set
        assert adapter._issuer_url == "http://localhost:8888/realms/siopv"
        assert adapter._audience == "siopv-api"
        assert adapter._jwks_cache_ttl == 3600
        assert adapter._clock_skew_leeway == 30

    def test_adapter_strips_trailing_slash_from_issuer(self) -> None:
        """Test adapter strips trailing slash from issuer URL."""
        settings = Settings(
            oidc_enabled=True,
            oidc_issuer_url="http://localhost:8888/realms/siopv/",  # With trailing slash
            oidc_audience="siopv-api",
            openfga_api_url="http://localhost:8080",
            openfga_store_id="test-store",
            openfga_authorization_model_id="test-model",
        )

        adapter = KeycloakOIDCAdapter(settings)
        assert adapter._issuer_url == "http://localhost:8888/realms/siopv"

    def test_adapter_with_custom_http_client(self, settings: Settings) -> None:
        """Test adapter accepts custom httpx client."""
        custom_client = httpx.AsyncClient(timeout=5.0)
        adapter = KeycloakOIDCAdapter(settings, http_client=custom_client)

        assert adapter._external_client is custom_client

    @pytest.mark.asyncio
    async def test_adapter_close(self, settings: Settings) -> None:
        """Test adapter cleanup closes owned client."""
        adapter = KeycloakOIDCAdapter(settings)

        # Force client creation
        await adapter._get_http_client()

        assert adapter._owned_client is not None

        await adapter.close()

        assert adapter._owned_client is None


# === Test JWKS Fetching ===


class TestJWKSFetching:
    """Tests for JWKS fetching and caching."""

    @pytest.mark.asyncio
    @respx.mock
    async def test_fetch_jwks_success(
        self,
        settings: Settings,
        jwks_data: dict[str, Any],
    ) -> None:
        """Test successful JWKS fetching."""
        jwks_url = "http://localhost:8888/realms/siopv/protocol/openid-connect/certs"
        respx.get(jwks_url).mock(return_value=httpx.Response(200, json=jwks_data))

        adapter = KeycloakOIDCAdapter(settings)
        result = await adapter._fetch_jwks()

        assert result == jwks_data
        assert adapter._jwks_keys == jwks_data

    @pytest.mark.asyncio
    @respx.mock
    async def test_fetch_jwks_caching(
        self,
        settings: Settings,
        jwks_data: dict[str, Any],
    ) -> None:
        """Test JWKS caching avoids repeated fetches."""
        jwks_url = "http://localhost:8888/realms/siopv/protocol/openid-connect/certs"
        route = respx.get(jwks_url).mock(
            return_value=httpx.Response(200, json=jwks_data),
        )

        adapter = KeycloakOIDCAdapter(settings)

        # First call fetches
        await adapter._fetch_jwks()
        assert route.call_count == 1

        # Second call uses cache
        await adapter._fetch_jwks()
        assert route.call_count == 1  # No additional fetch

    @pytest.mark.asyncio
    @respx.mock
    async def test_fetch_jwks_force_refresh(
        self,
        settings: Settings,
        jwks_data: dict[str, Any],
    ) -> None:
        """Test force refresh bypasses cache."""
        jwks_url = "http://localhost:8888/realms/siopv/protocol/openid-connect/certs"
        route = respx.get(jwks_url).mock(
            return_value=httpx.Response(200, json=jwks_data),
        )

        adapter = KeycloakOIDCAdapter(settings)

        # First call
        await adapter._fetch_jwks()
        assert route.call_count == 1

        # Force refresh
        await adapter._fetch_jwks(force_refresh=True)
        assert route.call_count == 2

    @pytest.mark.asyncio
    @respx.mock
    async def test_fetch_jwks_http_error(self, settings: Settings) -> None:
        """Test JWKS fetch handles HTTP errors."""
        jwks_url = "http://localhost:8888/realms/siopv/protocol/openid-connect/certs"
        respx.get(jwks_url).mock(return_value=httpx.Response(500))

        adapter = KeycloakOIDCAdapter(settings)

        with pytest.raises(JWKSFetchError) as exc_info:
            await adapter._fetch_jwks()

        assert exc_info.value.jwks_uri == jwks_url
        assert exc_info.value.underlying_error is not None

    @pytest.mark.asyncio
    @respx.mock
    async def test_fetch_jwks_network_error(self, settings: Settings) -> None:
        """Test JWKS fetch handles network errors."""
        jwks_url = "http://localhost:8888/realms/siopv/protocol/openid-connect/certs"
        respx.get(jwks_url).mock(side_effect=httpx.ConnectError("Connection refused"))

        adapter = KeycloakOIDCAdapter(settings)

        with pytest.raises(JWKSFetchError) as exc_info:
            await adapter._fetch_jwks()

        assert exc_info.value.jwks_uri == jwks_url
        assert isinstance(exc_info.value.underlying_error, httpx.ConnectError)


# === Test Token Validation ===


class TestTokenValidation:
    """Tests for JWT token validation."""

    @pytest.mark.asyncio
    @respx.mock
    async def test_validate_token_success(
        self,
        settings: Settings,
        valid_token_payload: dict[str, Any],
        create_jwt_token: Any,
        jwks_data: dict[str, Any],
    ) -> None:
        """Test successful token validation."""
        jwks_url = "http://localhost:8888/realms/siopv/protocol/openid-connect/certs"
        respx.get(jwks_url).mock(return_value=httpx.Response(200, json=jwks_data))

        token = create_jwt_token(valid_token_payload)

        adapter = KeycloakOIDCAdapter(settings)
        claims = await adapter.validate_token(token)

        assert isinstance(claims, TokenClaims)
        assert claims.sub == "service-account-siopv-client"
        assert claims.iss == "http://localhost:8888/realms/siopv"
        assert claims.aud == "siopv-api"

    @pytest.mark.asyncio
    @respx.mock
    async def test_validate_token_expired(
        self,
        settings: Settings,
        create_jwt_token: Any,
        jwks_data: dict[str, Any],
    ) -> None:
        """Test validation rejects expired token."""
        jwks_url = "http://localhost:8888/realms/siopv/protocol/openid-connect/certs"
        respx.get(jwks_url).mock(return_value=httpx.Response(200, json=jwks_data))

        # Create expired token
        now = int(time.time())
        expired_payload = {
            "sub": "test",
            "iss": "http://localhost:8888/realms/siopv",
            "aud": "siopv-api",
            "exp": now - 3600,  # 1 hour ago
            "iat": now - 7200,  # 2 hours ago
        }
        token = create_jwt_token(expired_payload)

        adapter = KeycloakOIDCAdapter(settings)

        with pytest.raises(TokenExpiredError):
            await adapter.validate_token(token)

    @pytest.mark.asyncio
    @respx.mock
    async def test_validate_token_invalid_issuer(
        self,
        settings: Settings,
        create_jwt_token: Any,
        jwks_data: dict[str, Any],
    ) -> None:
        """Test validation rejects wrong issuer."""
        jwks_url = "http://localhost:8888/realms/siopv/protocol/openid-connect/certs"
        respx.get(jwks_url).mock(return_value=httpx.Response(200, json=jwks_data))

        now = int(time.time())
        invalid_payload = {
            "sub": "test",
            "iss": "http://wrong-issuer/realms/other",
            "aud": "siopv-api",
            "exp": now + 3600,
            "iat": now,
        }
        token = create_jwt_token(invalid_payload)

        adapter = KeycloakOIDCAdapter(settings)

        with pytest.raises(InvalidIssuerError) as exc_info:
            await adapter.validate_token(token)

        assert exc_info.value.expected_issuer == "http://localhost:8888/realms/siopv"

    @pytest.mark.asyncio
    @respx.mock
    async def test_validate_token_invalid_audience(
        self,
        settings: Settings,
        create_jwt_token: Any,
        jwks_data: dict[str, Any],
    ) -> None:
        """Test validation rejects wrong audience."""
        jwks_url = "http://localhost:8888/realms/siopv/protocol/openid-connect/certs"
        respx.get(jwks_url).mock(return_value=httpx.Response(200, json=jwks_data))

        now = int(time.time())
        invalid_payload = {
            "sub": "test",
            "iss": "http://localhost:8888/realms/siopv",
            "aud": "wrong-api",
            "exp": now + 3600,
            "iat": now,
        }
        token = create_jwt_token(invalid_payload)

        adapter = KeycloakOIDCAdapter(settings)

        with pytest.raises(InvalidAudienceError) as exc_info:
            await adapter.validate_token(token)

        assert exc_info.value.expected_audience == "siopv-api"

    @pytest.mark.asyncio
    @respx.mock
    async def test_validate_token_malformed_header(
        self,
        settings: Settings,
        jwks_data: dict[str, Any],
    ) -> None:
        """Test validation rejects malformed JWT."""
        jwks_url = "http://localhost:8888/realms/siopv/protocol/openid-connect/certs"
        respx.get(jwks_url).mock(return_value=httpx.Response(200, json=jwks_data))

        adapter = KeycloakOIDCAdapter(settings)

        with pytest.raises(TokenValidationError, match="Malformed JWT header"):
            await adapter.validate_token("not-a-valid-jwt")

    @pytest.mark.asyncio
    @pytest.mark.usefixtures("create_jwt_token")
    @respx.mock
    async def test_validate_token_missing_kid(
        self,
        settings: Settings,
        valid_token_payload: dict[str, Any],
        jwks_data: dict[str, Any],
    ) -> None:
        """Test validation rejects token without kid header."""
        jwks_url = "http://localhost:8888/realms/siopv/protocol/openid-connect/certs"
        respx.get(jwks_url).mock(return_value=httpx.Response(200, json=jwks_data))

        # Create token without kid in header
        from cryptography.hazmat.primitives.asymmetric import rsa

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        token_no_kid = jwt.encode(
            valid_token_payload,
            private_key,
            algorithm="RS256",
            # No kid header
        )

        adapter = KeycloakOIDCAdapter(settings)

        with pytest.raises(TokenValidationError, match="missing 'kid' claim"):
            await adapter.validate_token(token_no_kid)

    @pytest.mark.asyncio
    @respx.mock
    async def test_validate_token_kid_not_in_jwks(
        self,
        settings: Settings,
        create_jwt_token: Any,
        valid_token_payload: dict[str, Any],
        jwks_data: dict[str, Any],
    ) -> None:
        """Test validation handles kid not found in JWKS."""
        jwks_url = "http://localhost:8888/realms/siopv/protocol/openid-connect/certs"
        route = respx.get(jwks_url).mock(
            return_value=httpx.Response(200, json=jwks_data),
        )

        # Create token with different kid
        token = create_jwt_token(valid_token_payload, kid="different-key-id")

        adapter = KeycloakOIDCAdapter(settings)

        with pytest.raises(TokenValidationError, match="No matching signing key"):
            await adapter.validate_token(token)

        # Should trigger JWKS refresh
        assert route.call_count == 2

    @pytest.mark.asyncio
    @respx.mock
    async def test_validate_token_invalid_signature(
        self,
        settings: Settings,
        valid_token_payload: dict[str, Any],
        jwks_data: dict[str, Any],
    ) -> None:
        """Test validation rejects token with invalid signature."""
        jwks_url = "http://localhost:8888/realms/siopv/protocol/openid-connect/certs"
        respx.get(jwks_url).mock(return_value=httpx.Response(200, json=jwks_data))

        # Create token with different private key
        different_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        token = jwt.encode(
            valid_token_payload,
            different_private_key,
            algorithm="RS256",
            headers={"kid": "test-key-id"},
        )

        adapter = KeycloakOIDCAdapter(settings)

        with pytest.raises(TokenValidationError):
            await adapter.validate_token(token)


# === Test Extract Identity ===


class TestExtractIdentity:
    """Tests for identity extraction from claims."""

    @pytest.mark.asyncio
    async def test_extract_identity_success(
        self,
        settings: Settings,
    ) -> None:
        """Test successful identity extraction."""
        claims = TokenClaims(
            sub="service-account-test",
            iss="http://localhost:8888/realms/siopv",
            aud="siopv-api",
            exp=9999999999,
            iat=1234567890,
            azp="test-client",
            scope="read write",
        )

        adapter = KeycloakOIDCAdapter(settings)
        identity = await adapter.extract_identity(claims)

        assert isinstance(identity, ServiceIdentity)
        assert identity.client_id == "test-client"
        assert identity.issuer == "http://localhost:8888/realms/siopv"
        assert identity.scopes == frozenset({"read", "write"})

    @pytest.mark.asyncio
    async def test_extract_identity_uses_from_claims(
        self,
        settings: Settings,
    ) -> None:
        """Test extract_identity uses ServiceIdentity.from_claims."""
        claims = TokenClaims(
            sub="service-account-fallback",
            iss="http://issuer",
            aud="api",
            exp=9999999999,
            iat=1234567890,
        )

        adapter = KeycloakOIDCAdapter(settings)
        identity = await adapter.extract_identity(claims)

        # Should fall back to sub for client_id
        assert identity.client_id == "service-account-fallback"


# === Test Discover Provider ===


class TestDiscoverProvider:
    """Tests for OIDC provider discovery."""

    @pytest.mark.asyncio
    @respx.mock
    async def test_discover_provider_success(
        self,
        settings: Settings,
        discovery_document: dict[str, Any],
    ) -> None:
        """Test successful provider discovery."""
        discovery_url = "http://localhost:8888/realms/siopv/.well-known/openid-configuration"
        respx.get(discovery_url).mock(
            return_value=httpx.Response(200, json=discovery_document),
        )

        adapter = KeycloakOIDCAdapter(settings)
        config = await adapter.discover_provider()

        assert isinstance(config, OIDCProviderConfig)
        assert config.issuer_url == "http://localhost:8888/realms/siopv"
        assert config.jwks_uri.endswith("/certs")

    @pytest.mark.asyncio
    @respx.mock
    async def test_discover_provider_caching(
        self,
        settings: Settings,
        discovery_document: dict[str, Any],
    ) -> None:
        """Test provider discovery caching."""
        discovery_url = "http://localhost:8888/realms/siopv/.well-known/openid-configuration"
        route = respx.get(discovery_url).mock(
            return_value=httpx.Response(200, json=discovery_document),
        )

        adapter = KeycloakOIDCAdapter(settings)

        # First call fetches
        await adapter.discover_provider()
        assert route.call_count == 1

        # Second call uses cache
        await adapter.discover_provider()
        assert route.call_count == 1

    @pytest.mark.asyncio
    @respx.mock
    async def test_discover_provider_network_error(
        self,
        settings: Settings,
    ) -> None:
        """Test discovery handles network errors."""
        discovery_url = "http://localhost:8888/realms/siopv/.well-known/openid-configuration"
        respx.get(discovery_url).mock(
            side_effect=httpx.TimeoutException("Timeout"),
        )

        adapter = KeycloakOIDCAdapter(settings)

        with pytest.raises(OIDCProviderUnavailableError) as exc_info:
            await adapter.discover_provider()

        assert exc_info.value.provider_url == "http://localhost:8888/realms/siopv"

    @pytest.mark.asyncio
    @respx.mock
    async def test_discover_provider_malformed_document(
        self,
        settings: Settings,
    ) -> None:
        """Test discovery handles malformed document."""
        discovery_url = "http://localhost:8888/realms/siopv/.well-known/openid-configuration"
        # Missing required fields
        respx.get(discovery_url).mock(
            return_value=httpx.Response(200, json={"issuer": "http://issuer"}),
        )

        adapter = KeycloakOIDCAdapter(settings)

        with pytest.raises(TokenValidationError, match="missing field"):
            await adapter.discover_provider()


# === Test Health Check ===


class TestHealthCheck:
    """Tests for OIDC provider health check."""

    @pytest.mark.asyncio
    @respx.mock
    async def test_health_check_success(
        self,
        settings: Settings,
        discovery_document: dict[str, Any],
    ) -> None:
        """Test health check returns True when provider is healthy."""
        discovery_url = "http://localhost:8888/realms/siopv/.well-known/openid-configuration"
        respx.get(discovery_url).mock(
            return_value=httpx.Response(200, json=discovery_document),
        )

        adapter = KeycloakOIDCAdapter(settings)
        result = await adapter.health_check()

        assert result is True

    @pytest.mark.asyncio
    @respx.mock
    async def test_health_check_failure(
        self,
        settings: Settings,
    ) -> None:
        """Test health check returns False when provider is unavailable."""
        discovery_url = "http://localhost:8888/realms/siopv/.well-known/openid-configuration"
        respx.get(discovery_url).mock(
            side_effect=httpx.ConnectError("Connection refused"),
        )

        adapter = KeycloakOIDCAdapter(settings)
        result = await adapter.health_check()

        assert result is False

    @pytest.mark.asyncio
    @respx.mock
    async def test_health_check_never_raises(
        self,
        settings: Settings,
    ) -> None:
        """Test health check never raises exceptions."""
        discovery_url = "http://localhost:8888/realms/siopv/.well-known/openid-configuration"
        respx.get(discovery_url).mock(return_value=httpx.Response(500))

        adapter = KeycloakOIDCAdapter(settings)

        # Should not raise, just return False
        result = await adapter.health_check()
        assert result is False
