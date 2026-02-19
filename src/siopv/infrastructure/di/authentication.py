"""Dependency injection container for authentication components.

Factory functions for creating and configuring authentication components
that implement the OIDC authentication ports. Following Python 2026 standards
with proper type hints, structlog logging, and dependency injection patterns.

Usage:
    from siopv.infrastructure.di.authentication import (
        create_oidc_adapter,
        get_oidc_authentication_port,
        create_oidc_middleware,
    )
    from siopv.infrastructure.config import get_settings

    settings = get_settings()

    # Get port from factory function (singleton)
    oidc_port = get_oidc_authentication_port(settings)

    # Or directly create the adapter
    adapter = create_oidc_adapter(settings)

    # Create middleware with wired dependencies
    middleware = create_oidc_middleware(settings)

    # Use in application code
    identity = await middleware.authenticate(auth_header)
"""

from __future__ import annotations

from functools import lru_cache
from typing import TYPE_CHECKING

import structlog

from siopv.adapters.authentication import KeycloakOIDCAdapter
from siopv.application.ports import OIDCAuthenticationPort
from siopv.infrastructure.middleware.oidc_middleware import (
    OIDCAuthenticationMiddleware,
)

if TYPE_CHECKING:
    from siopv.infrastructure.config.settings import Settings

logger = structlog.get_logger(__name__)


def create_oidc_adapter(settings: Settings) -> KeycloakOIDCAdapter:
    """Create and initialize Keycloak OIDC authentication adapter.

    Factory function that creates a properly configured KeycloakOIDCAdapter
    instance with settings and logging. The adapter implements the
    OIDCAuthenticationPort for JWT Bearer token validation using RS256.

    The adapter handles:
    - JWT validation with RS256 signature verification
    - JWKS fetching and caching from Keycloak
    - OIDC provider discovery
    - Token claims extraction and identity mapping

    Args:
        settings: Application settings containing OIDC configuration:
            - oidc_enabled: Whether OIDC authentication is enabled
            - oidc_issuer_url: Keycloak realm URL (e.g., http://localhost:8888/realms/siopv)
            - oidc_audience: Expected audience claim (e.g., siopv-api)
            - oidc_jwks_cache_ttl_seconds: JWKS cache TTL (default: 3600)
            - oidc_allowed_clock_skew_seconds: Clock skew leeway (default: 30)

    Returns:
        Initialized KeycloakOIDCAdapter instance ready for use.

    Raises:
        ValueError: If OIDC settings are incomplete when oidc_enabled=True.

    Example:
        >>> settings = get_settings()
        >>> adapter = create_oidc_adapter(settings)
        >>> claims = await adapter.validate_token(raw_token)
        >>> identity = await adapter.extract_identity(claims)
    """
    logger.debug(
        "creating_oidc_adapter",
        issuer_url=settings.oidc_issuer_url,
        audience=settings.oidc_audience,
        enabled=settings.oidc_enabled,
        jwks_cache_ttl=settings.oidc_jwks_cache_ttl_seconds,
    )

    adapter = KeycloakOIDCAdapter(settings)

    logger.info(
        "oidc_adapter_created",
        adapter_class="KeycloakOIDCAdapter",
    )

    return adapter


@lru_cache(maxsize=1)
def get_oidc_authentication_port(settings: Settings) -> OIDCAuthenticationPort:
    """Get the OIDC authentication port implementation.

    Lazy factory function that returns a singleton OIDCAuthenticationPort
    implementation. Uses lru_cache to ensure only one instance is created
    for a given settings object.

    The returned port implements the OIDC authentication contract:
    - validate_token(): JWT Bearer token validation with RS256
    - extract_identity(): Map token claims to ServiceIdentity
    - discover_provider(): Fetch OIDC discovery document
    - health_check(): Check OIDC provider availability

    Args:
        settings: Application settings instance.

    Returns:
        OIDCAuthenticationPort implementation (KeycloakOIDCAdapter).

    Note:
        The port is cached as a singleton. Subsequent calls with the same
        settings object will return the same instance.

    Example:
        >>> settings = get_settings()
        >>> port = get_oidc_authentication_port(settings)
        >>> claims = await port.validate_token(raw_token)
        >>> identity = await port.extract_identity(claims)
    """
    adapter = create_oidc_adapter(settings)
    logger.debug("oidc_authentication_port_created", port_type="OIDCAuthenticationPort")
    return adapter


def create_oidc_middleware(settings: Settings) -> OIDCAuthenticationMiddleware:
    """Create OIDC authentication middleware with wired dependencies.

    Factory function that creates an OIDCAuthenticationMiddleware instance
    with the OIDC authentication port and settings properly wired.

    The middleware handles:
    - Bearer token extraction from Authorization headers
    - Token validation via the OIDCAuthenticationPort
    - Identity extraction and mapping to OpenFGA UserId
    - AuthorizationContext creation for permission checks

    Args:
        settings: Application settings containing OIDC configuration.

    Returns:
        OIDCAuthenticationMiddleware instance with dependencies wired.

    Example:
        >>> settings = get_settings()
        >>> middleware = create_oidc_middleware(settings)
        >>> identity = await middleware.authenticate(auth_header)
        >>> user_id = middleware.map_identity_to_user_id(identity)
    """
    oidc_port = get_oidc_authentication_port(settings)

    logger.debug(
        "creating_oidc_middleware",
        enabled=settings.oidc_enabled,
    )

    middleware = OIDCAuthenticationMiddleware(
        oidc_port=oidc_port,
        settings=settings,
    )

    logger.info(
        "oidc_middleware_created",
        middleware_class="OIDCAuthenticationMiddleware",
    )

    return middleware


__all__ = [
    "create_oidc_adapter",
    "create_oidc_middleware",
    "get_oidc_authentication_port",
]
