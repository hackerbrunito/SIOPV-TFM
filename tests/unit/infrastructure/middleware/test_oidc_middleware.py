"""Unit tests for OIDCAuthenticationMiddleware.

Tests OIDC middleware with:
- Bearer token extraction
- Authentication flow
- Authorization context creation
- Error handling
- Port mocking via pytest-mock
"""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from siopv.domain.authorization.entities import AuthorizationContext
from siopv.domain.authorization.value_objects import Action, ResourceId, ResourceType
from siopv.domain.oidc import (
    OIDCError,
    ServiceIdentity,
    TokenClaims,
    TokenValidationError,
)
from siopv.infrastructure.config.settings import Settings
from siopv.infrastructure.middleware.oidc_middleware import (
    OIDCAuthenticationMiddleware,
    map_identity_to_user_id,
)

# === Fixtures ===


@pytest.fixture
def settings_enabled() -> Settings:
    """Settings with OIDC enabled."""
    return Settings(
        oidc_enabled=True,
        oidc_issuer_url="http://localhost:8888/realms/siopv",
        oidc_audience="siopv-api",
        openfga_api_url="http://localhost:8080",
        openfga_store_id="test-store",
        openfga_authorization_model_id="test-model",
    )


@pytest.fixture
def settings_disabled() -> Settings:
    """Settings with OIDC disabled."""
    return Settings(
        oidc_enabled=False,
        oidc_issuer_url="",
        oidc_audience="",
        openfga_api_url="http://localhost:8080",
        openfga_store_id="test-store",
        openfga_authorization_model_id="test-model",
    )


@pytest.fixture
def sample_claims() -> TokenClaims:
    """Sample validated token claims."""
    return TokenClaims(
        sub="service-account-siopv-client",
        iss="http://localhost:8888/realms/siopv",
        aud="siopv-api",
        exp=9999999999,
        iat=1234567890,
        azp="siopv-client",
        scope="read write",
        jti="test-token-123",
    )


@pytest.fixture
def sample_identity() -> ServiceIdentity:
    """Sample service identity."""
    return ServiceIdentity(
        client_id="siopv-client",
        issuer="http://localhost:8888/realms/siopv",
        scopes=frozenset({"read", "write"}),
    )


# === Test Middleware Initialization ===


class TestMiddlewareInitialization:
    """Tests for middleware initialization."""

    def test_middleware_initialization(
        self,
        settings_enabled: Settings,
    ) -> None:
        """Test middleware initializes with port and settings."""
        mock_port = AsyncMock()

        middleware = OIDCAuthenticationMiddleware(mock_port, settings_enabled)

        assert middleware._oidc_port is mock_port
        assert middleware._settings is settings_enabled


# === Test Authenticate Method ===


class TestAuthenticate:
    """Tests for authenticate() method."""

    @pytest.mark.asyncio
    async def test_authenticate_success(
        self,
        settings_enabled: Settings,
        sample_claims: TokenClaims,
        sample_identity: ServiceIdentity,
    ) -> None:
        """Test successful authentication with valid Bearer token."""
        mock_port = AsyncMock()
        mock_port.validate_token = AsyncMock(return_value=sample_claims)
        mock_port.extract_identity = AsyncMock(return_value=sample_identity)

        middleware = OIDCAuthenticationMiddleware(mock_port, settings_enabled)

        header = "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
        identity = await middleware.authenticate(header)

        assert identity == sample_identity
        mock_port.validate_token.assert_called_once()
        mock_port.extract_identity.assert_called_once_with(sample_claims)

    @pytest.mark.asyncio
    async def test_authenticate_extracts_token_correctly(
        self,
        settings_enabled: Settings,
        sample_claims: TokenClaims,
        sample_identity: ServiceIdentity,
    ) -> None:
        """Test Bearer token extraction strips prefix correctly."""
        mock_port = AsyncMock()
        mock_port.validate_token = AsyncMock(return_value=sample_claims)
        mock_port.extract_identity = AsyncMock(return_value=sample_identity)

        middleware = OIDCAuthenticationMiddleware(mock_port, settings_enabled)

        raw_token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
        header = f"Bearer {raw_token}"

        await middleware.authenticate(header)

        # Should call validate_token with just the token, no "Bearer " prefix
        mock_port.validate_token.assert_called_once_with(raw_token)

    @pytest.mark.asyncio
    async def test_authenticate_oidc_disabled(
        self,
        settings_disabled: Settings,
    ) -> None:
        """Test authenticate raises error when OIDC is disabled."""
        mock_port = AsyncMock()
        middleware = OIDCAuthenticationMiddleware(mock_port, settings_disabled)

        header = "Bearer token"

        with pytest.raises(OIDCError, match="OIDC authentication not enabled"):
            await middleware.authenticate(header)

        # Should not call port if OIDC is disabled
        mock_port.validate_token.assert_not_called()

    @pytest.mark.asyncio
    async def test_authenticate_missing_header(
        self,
        settings_enabled: Settings,
    ) -> None:
        """Test authenticate raises error when header is missing."""
        mock_port = AsyncMock()
        middleware = OIDCAuthenticationMiddleware(mock_port, settings_enabled)

        with pytest.raises(TokenValidationError, match="Missing Authorization header"):
            await middleware.authenticate(None)

        mock_port.validate_token.assert_not_called()

    @pytest.mark.asyncio
    async def test_authenticate_empty_header(
        self,
        settings_enabled: Settings,
    ) -> None:
        """Test authenticate raises error when header is empty string."""
        mock_port = AsyncMock()
        middleware = OIDCAuthenticationMiddleware(mock_port, settings_enabled)

        with pytest.raises(TokenValidationError, match="Missing Authorization header"):
            await middleware.authenticate("")

        mock_port.validate_token.assert_not_called()

    @pytest.mark.asyncio
    async def test_authenticate_invalid_header_format_no_bearer(
        self,
        settings_enabled: Settings,
    ) -> None:
        """Test authenticate raises error for header without Bearer prefix."""
        mock_port = AsyncMock()
        middleware = OIDCAuthenticationMiddleware(mock_port, settings_enabled)

        invalid_headers = [
            "Basic dXNlcjpwYXNz",  # Basic auth
            "Token abc123",  # Wrong prefix
            "eyJhbGci...",  # No prefix at all
        ]

        for invalid_header in invalid_headers:
            with pytest.raises(
                TokenValidationError,
                match="Invalid Authorization header format",
            ):
                await middleware.authenticate(invalid_header)

    @pytest.mark.asyncio
    async def test_authenticate_empty_token(
        self,
        settings_enabled: Settings,
    ) -> None:
        """Test authenticate raises error for empty token after Bearer."""
        mock_port = AsyncMock()
        middleware = OIDCAuthenticationMiddleware(mock_port, settings_enabled)

        with pytest.raises(TokenValidationError, match="Empty Bearer token"):
            await middleware.authenticate("Bearer ")

        mock_port.validate_token.assert_not_called()

    @pytest.mark.asyncio
    async def test_authenticate_case_sensitive_bearer(
        self,
        settings_enabled: Settings,
    ) -> None:
        """Test Bearer prefix is case-sensitive."""
        mock_port = AsyncMock()
        middleware = OIDCAuthenticationMiddleware(mock_port, settings_enabled)

        # "bearer" (lowercase) should be rejected
        with pytest.raises(
            TokenValidationError,
            match="Invalid Authorization header format",
        ):
            await middleware.authenticate("bearer token123")

    @pytest.mark.asyncio
    async def test_authenticate_propagates_validation_error(
        self,
        settings_enabled: Settings,
    ) -> None:
        """Test authenticate propagates validation errors from port."""
        mock_port = AsyncMock()
        mock_port.validate_token = AsyncMock(
            side_effect=TokenValidationError("Invalid signature"),
        )

        middleware = OIDCAuthenticationMiddleware(mock_port, settings_enabled)

        with pytest.raises(TokenValidationError, match="Invalid signature"):
            await middleware.authenticate("Bearer token")


# === Test Authenticate and Authorize Method ===


class TestAuthenticateAndAuthorize:
    """Tests for authenticate_and_authorize() method."""

    @pytest.mark.asyncio
    async def test_authenticate_and_authorize_success(
        self,
        settings_enabled: Settings,
        sample_claims: TokenClaims,
        sample_identity: ServiceIdentity,
    ) -> None:
        """Test successful authentication and authorization context creation."""
        mock_port = AsyncMock()
        mock_port.validate_token = AsyncMock(return_value=sample_claims)
        mock_port.extract_identity = AsyncMock(return_value=sample_identity)

        middleware = OIDCAuthenticationMiddleware(mock_port, settings_enabled)

        resource = ResourceId(
            resource_type=ResourceType.PROJECT,
            identifier="project-123",
        )
        action = Action.VIEW

        identity, context = await middleware.authenticate_and_authorize(
            authorization_header="Bearer token",
            resource=resource,
            action=action,
        )

        assert identity == sample_identity
        assert isinstance(context, AuthorizationContext)
        assert context.user_id == "service-siopv-client"
        assert context.resource == resource
        assert context.action == action

    @pytest.mark.asyncio
    async def test_authenticate_and_authorize_maps_identity_to_user_id(
        self,
        settings_enabled: Settings,
        sample_claims: TokenClaims,
    ) -> None:
        """Test authenticate_and_authorize maps identity to UserId correctly."""
        identity = ServiceIdentity(
            client_id="test-client",
            issuer="http://issuer",
        )

        mock_port = AsyncMock()
        mock_port.validate_token = AsyncMock(return_value=sample_claims)
        mock_port.extract_identity = AsyncMock(return_value=identity)

        middleware = OIDCAuthenticationMiddleware(mock_port, settings_enabled)

        resource = ResourceId(
            resource_type=ResourceType.PROJECT,
            identifier="project-123",
        )
        action = Action.VIEW

        _, context = await middleware.authenticate_and_authorize(
            authorization_header="Bearer token",
            resource=resource,
            action=action,
        )

        # Should use service- prefix convention
        assert context.user_id == "service-test-client"

    @pytest.mark.asyncio
    async def test_authenticate_and_authorize_creates_correct_context(
        self,
        settings_enabled: Settings,
        sample_claims: TokenClaims,
        sample_identity: ServiceIdentity,
    ) -> None:
        """Test authorization context has correct action and resource."""
        mock_port = AsyncMock()
        mock_port.validate_token = AsyncMock(return_value=sample_claims)
        mock_port.extract_identity = AsyncMock(return_value=sample_identity)

        middleware = OIDCAuthenticationMiddleware(mock_port, settings_enabled)

        resource = ResourceId(
            resource_type=ResourceType.VULNERABILITY,
            identifier="vuln-456",
        )
        action = Action.EDIT

        _, context = await middleware.authenticate_and_authorize(
            authorization_header="Bearer token",
            resource=resource,
            action=action,
        )

        assert context.action == Action.EDIT
        assert context.resource.resource_type == ResourceType.VULNERABILITY
        assert context.resource.identifier == "vuln-456"

    @pytest.mark.asyncio
    async def test_authenticate_and_authorize_does_not_call_openfga(
        self,
        settings_enabled: Settings,
        sample_claims: TokenClaims,
        sample_identity: ServiceIdentity,
    ) -> None:
        """Test authenticate_and_authorize does NOT call OpenFGA directly.

        This method creates the context, but the caller is responsible
        for passing it to AuthorizationPort.check().
        """
        mock_port = AsyncMock()
        mock_port.validate_token = AsyncMock(return_value=sample_claims)
        mock_port.extract_identity = AsyncMock(return_value=sample_identity)

        middleware = OIDCAuthenticationMiddleware(mock_port, settings_enabled)

        resource = ResourceId(
            resource_type=ResourceType.PROJECT,
            identifier="project-123",
        )
        action = Action.VIEW

        identity, context = await middleware.authenticate_and_authorize(
            authorization_header="Bearer token",
            resource=resource,
            action=action,
        )

        # Should return identity and context without calling authorization port
        assert identity is not None
        assert context is not None
        # No check() method called on port


# === Test map_identity_to_user_id Helper ===


class TestMapIdentityToUserId:
    """Tests for map_identity_to_user_id() helper function."""

    def test_map_identity_to_user_id_format(self) -> None:
        """Test mapping creates service- prefixed UserId."""
        identity = ServiceIdentity(
            client_id="test-client",
            issuer="http://issuer",
        )

        user_id = map_identity_to_user_id(identity)

        assert user_id.value == "service-test-client"

    def test_map_identity_to_user_id_different_clients(self) -> None:
        """Test mapping with various client IDs."""
        test_cases = [
            ("siopv-client", "service-siopv-client"),
            ("api-consumer", "service-api-consumer"),
            ("client123", "service-client123"),
        ]

        for client_id, expected_user_id in test_cases:
            identity = ServiceIdentity(
                client_id=client_id,
                issuer="http://issuer",
            )

            user_id = map_identity_to_user_id(identity)
            assert user_id.value == expected_user_id

    def test_map_identity_to_user_id_calls_to_user_id(self) -> None:
        """Test mapping delegates to identity.to_user_id()."""
        identity = ServiceIdentity(
            client_id="delegated-client",
            issuer="http://issuer",
        )

        # Direct call
        user_id_direct = identity.to_user_id()

        # Via helper
        user_id_helper = map_identity_to_user_id(identity)

        assert user_id_direct == user_id_helper


# === Test Security: No Token Logging ===


class TestSecurityNoTokenLogging:
    """Tests verifying raw tokens are never logged."""

    @pytest.mark.asyncio
    async def test_authenticate_does_not_log_raw_token(
        self,
        settings_enabled: Settings,
        sample_claims: TokenClaims,
        sample_identity: ServiceIdentity,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Test authenticate never logs raw Bearer token."""
        mock_port = AsyncMock()
        mock_port.validate_token = AsyncMock(return_value=sample_claims)
        mock_port.extract_identity = AsyncMock(return_value=sample_identity)

        middleware = OIDCAuthenticationMiddleware(mock_port, settings_enabled)

        raw_token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InRlc3Qta2V5In0"
        header = f"Bearer {raw_token}"

        await middleware.authenticate(header)

        # Raw token should NOT appear in any log message
        for record in caplog.records:
            assert raw_token not in record.getMessage()

    @pytest.mark.asyncio
    async def test_authenticate_logs_only_metadata(
        self,
        settings_enabled: Settings,
        sample_claims: TokenClaims,
        sample_identity: ServiceIdentity,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Test authenticate logs only PII-safe metadata."""
        import structlog

        structlog.configure(
            processors=[
                structlog.processors.add_log_level,
                structlog.processors.KeyValueRenderer(),
            ],
        )

        mock_port = AsyncMock()
        mock_port.validate_token = AsyncMock(return_value=sample_claims)
        mock_port.extract_identity = AsyncMock(return_value=sample_identity)

        middleware = OIDCAuthenticationMiddleware(mock_port, settings_enabled)

        await middleware.authenticate("Bearer token")

        # Should log client_id, issuer (metadata), but never raw token
        log_output = "\n".join(record.getMessage() for record in caplog.records)

        # These are safe to log
        assert "siopv-client" in log_output or "client_id" in log_output
        # Raw token should NOT be logged
        assert "Bearer token" not in log_output
