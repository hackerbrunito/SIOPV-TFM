"""Integration tests for full OIDC authentication flow.

Tests the complete OIDC client_credentials flow against a real Keycloak instance:
- Token acquisition from Keycloak
- Token validation via adapter
- Identity extraction
- Permission checking with OpenFGA

Tests are marked with @pytest.mark.real_keycloak and auto-skip when
Keycloak is unavailable (similar to test_openfga_real_server.py pattern).
"""

from __future__ import annotations

import httpx
import pytest

from siopv.adapters.authentication.keycloak_oidc_adapter import (
    KeycloakOIDCAdapter,
)
from siopv.domain.oidc import (
    ServiceIdentity,
    TokenClaims,
)
from siopv.infrastructure.config.settings import Settings

# === Helper Functions ===


async def is_keycloak_available(base_url: str = "http://localhost:8888") -> bool:
    """Check if Keycloak is reachable.

    Args:
        base_url: Keycloak base URL.

    Returns:
        True if Keycloak is available, False otherwise.
    """
    try:
        async with httpx.AsyncClient(timeout=2.0) as client:
            response = await client.get(f"{base_url}/health/ready")
            return response.status_code == 200
    except Exception:
        return False


async def get_access_token_from_keycloak(
    base_url: str,
    realm: str,
    client_id: str,
    client_secret: str,
) -> str:
    """Obtain access token from Keycloak using client_credentials grant.

    Args:
        base_url: Keycloak base URL.
        realm: Realm name.
        client_id: Client ID.
        client_secret: Client secret.

    Returns:
        Access token string.

    Raises:
        httpx.HTTPError: If token request fails.
    """
    token_url = f"{base_url}/realms/{realm}/protocol/openid-connect/token"

    async with httpx.AsyncClient() as client:
        response = await client.post(
            token_url,
            data={
                "grant_type": "client_credentials",
                "client_id": client_id,
                "client_secret": client_secret,
            },
        )
        response.raise_for_status()
        data = response.json()
        return data["access_token"]


# === Fixtures ===


@pytest.fixture
async def keycloak_available() -> bool:
    """Check if Keycloak is available for testing."""
    return await is_keycloak_available()


@pytest.fixture
def settings_real_keycloak() -> Settings:
    """Settings for real Keycloak integration tests."""
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


# === Integration Tests ===


@pytest.mark.real_keycloak
@pytest.mark.asyncio
async def test_full_oidc_flow_with_real_keycloak(
    keycloak_available: bool,
    settings_real_keycloak: Settings,
) -> None:
    """Test full OIDC flow: token acquisition → validation → identity extraction.

    This test exercises the complete flow against a real Keycloak instance.
    It auto-skips if Keycloak is not running.
    """
    if not keycloak_available:
        pytest.skip("Keycloak not available at http://localhost:8888")

    # Step 1: Obtain access token from Keycloak
    # NOTE: This requires setup-keycloak.py to have been run
    try:
        access_token = await get_access_token_from_keycloak(
            base_url="http://localhost:8888",
            realm="siopv",
            client_id="siopv-client",
            client_secret="test-secret",  # From setup script
        )
    except httpx.HTTPError as e:
        pytest.skip(
            f"Could not obtain token from Keycloak (realm/client not configured): {e}",
        )

    # Step 2: Validate token via adapter
    adapter = KeycloakOIDCAdapter(settings_real_keycloak)

    try:
        claims = await adapter.validate_token(access_token)

        # Verify claims structure
        assert isinstance(claims, TokenClaims)
        assert claims.iss == "http://localhost:8888/realms/siopv"
        assert claims.aud == "siopv-api"
        assert claims.azp == "siopv-client" or claims.client_id == "siopv-client"

        # Step 3: Extract identity
        identity = await adapter.extract_identity(claims)

        assert isinstance(identity, ServiceIdentity)
        assert identity.client_id == "siopv-client"
        assert identity.issuer == "http://localhost:8888/realms/siopv"

        # Step 4: Verify identity maps to UserId correctly
        user_id = identity.to_user_id()
        assert user_id.value == "service-siopv-client"

    finally:
        await adapter.close()


@pytest.mark.real_keycloak
@pytest.mark.asyncio
async def test_oidc_provider_discovery_with_real_keycloak(
    keycloak_available: bool,
    settings_real_keycloak: Settings,
) -> None:
    """Test OIDC provider discovery against real Keycloak.

    Verifies that the discovery document can be fetched and parsed.
    """
    if not keycloak_available:
        pytest.skip("Keycloak not available at http://localhost:8888")

    adapter = KeycloakOIDCAdapter(settings_real_keycloak)

    try:
        config = await adapter.discover_provider()

        assert config.issuer_url == "http://localhost:8888/realms/siopv"
        assert config.jwks_uri.endswith("/certs")
        assert config.token_endpoint.endswith("/token")
        assert config.authorization_endpoint is not None

    finally:
        await adapter.close()


@pytest.mark.real_keycloak
@pytest.mark.asyncio
async def test_oidc_health_check_with_real_keycloak(
    keycloak_available: bool,
    settings_real_keycloak: Settings,
) -> None:
    """Test OIDC health check against real Keycloak.

    Verifies that health check correctly detects available provider.
    """
    if not keycloak_available:
        pytest.skip("Keycloak not available at http://localhost:8888")

    adapter = KeycloakOIDCAdapter(settings_real_keycloak)

    try:
        is_healthy = await adapter.health_check()

        assert is_healthy is True

    finally:
        await adapter.close()


@pytest.mark.real_keycloak
@pytest.mark.asyncio
async def test_oidc_jwks_caching_with_real_keycloak(
    keycloak_available: bool,
    settings_real_keycloak: Settings,
) -> None:
    """Test JWKS caching behavior with real Keycloak.

    Verifies that JWKS is fetched once and cached for subsequent requests.
    """
    if not keycloak_available:
        pytest.skip("Keycloak not available at http://localhost:8888")

    # Obtain token
    try:
        access_token = await get_access_token_from_keycloak(
            base_url="http://localhost:8888",
            realm="siopv",
            client_id="siopv-client",
            client_secret="test-secret",
        )
    except httpx.HTTPError:
        pytest.skip("Could not obtain token (realm/client not configured)")

    adapter = KeycloakOIDCAdapter(settings_real_keycloak)

    try:
        # First validation fetches JWKS
        await adapter.validate_token(access_token)

        # Check JWKS is cached
        assert adapter._jwks_keys is not None
        assert adapter._jwks_fetched_at > 0

        # Second validation uses cache
        cached_jwks = adapter._jwks_keys
        await adapter.validate_token(access_token)

        # Should still be same cached JWKS
        assert adapter._jwks_keys is cached_jwks

    finally:
        await adapter.close()


@pytest.mark.real_keycloak
@pytest.mark.asyncio
async def test_token_refresh_scenario(
    keycloak_available: bool,
    settings_real_keycloak: Settings,
) -> None:
    """Test token acquisition and validation multiple times.

    Simulates a scenario where a client obtains multiple tokens over time.
    """
    if not keycloak_available:
        pytest.skip("Keycloak not available at http://localhost:8888")

    adapter = KeycloakOIDCAdapter(settings_real_keycloak)

    try:
        # Obtain and validate first token
        try:
            token1 = await get_access_token_from_keycloak(
                base_url="http://localhost:8888",
                realm="siopv",
                client_id="siopv-client",
                client_secret="test-secret",
            )
        except httpx.HTTPError:
            pytest.skip("Could not obtain token (realm/client not configured)")

        claims1 = await adapter.validate_token(token1)
        identity1 = await adapter.extract_identity(claims1)

        assert identity1.client_id == "siopv-client"

        # Obtain and validate second token
        token2 = await get_access_token_from_keycloak(
            base_url="http://localhost:8888",
            realm="siopv",
            client_id="siopv-client",
            client_secret="test-secret",
        )

        claims2 = await adapter.validate_token(token2)
        identity2 = await adapter.extract_identity(claims2)

        assert identity2.client_id == "siopv-client"

        # Both identities should map to same UserId
        assert identity1.to_user_id() == identity2.to_user_id()

    finally:
        await adapter.close()
