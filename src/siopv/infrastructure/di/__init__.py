"""Dependency injection container for SIOPV infrastructure.

Provides factory functions for creating and configuring application components
that implement hexagonal architecture ports. This is the central place for
component wiring.

Usage:
    from siopv.infrastructure.di import (
        get_authorization_port,
        get_authorization_store_port,
        get_authorization_model_port,
    )
    from siopv.infrastructure.config import get_settings

    settings = get_settings()

    # Get ports from DI container
    authz = get_authorization_port(settings)
    store = get_authorization_store_port(settings)
    model = get_authorization_model_port(settings)

    # Use in application code
    await authz.initialize()
    context = AuthorizationContext.for_action(user_id, resource, action)
    result = await authz.check(context)
"""

from siopv.infrastructure.di.authorization import (
    create_authorization_adapter,
    get_authorization_model_port,
    get_authorization_port,
    get_authorization_store_port,
)

__all__ = [
    "create_authorization_adapter",
    "get_authorization_model_port",
    "get_authorization_port",
    "get_authorization_store_port",
]
