"""OIDC authentication middleware for SIOPV.

Sits between API endpoints and the authorization layer, handling:
1. Bearer token extraction from Authorization headers
2. JWT validation via the OIDCAuthenticationPort
3. Identity extraction and mapping to OpenFGA UserId
4. AuthorizationContext creation for downstream permission checks

Security: Raw tokens are never logged. Only metadata (client_id, issuer,
action, resource) appears in structured log entries.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import structlog

from siopv.domain.authorization.entities import AuthorizationContext
from siopv.domain.oidc.exceptions import OIDCError, TokenValidationError

if TYPE_CHECKING:
    from siopv.application.ports.oidc_authentication import (
        OIDCAuthenticationPort,
    )
    from siopv.domain.authorization.value_objects import (
        Action,
        ResourceId,
        UserId,
    )
    from siopv.domain.oidc.value_objects import ServiceIdentity
    from siopv.infrastructure.config.settings import Settings

logger: structlog.stdlib.BoundLogger = structlog.get_logger(__name__)


_BEARER_PREFIX = "Bearer "
_BEARER_PREFIX_LEN = len(_BEARER_PREFIX)

# Error messages (ruff EM101: no string literals in raise)
_ERR_OIDC_NOT_ENABLED = "OIDC authentication not enabled"
_ERR_MISSING_HEADER = "Missing Authorization header"
_ERR_INVALID_HEADER_FORMAT = "Invalid Authorization header format"
_ERR_EMPTY_TOKEN = "Empty Bearer token"


class OIDCAuthenticationMiddleware:
    """Async OIDC authentication middleware.

    Extracts Bearer tokens from HTTP Authorization headers, validates
    them via the configured OIDC provider, and maps authenticated
    identities to OpenFGA-compatible user IDs.

    This middleware does NOT perform authorization (permission checks)
    itself — it creates an ``AuthorizationContext`` that the caller
    passes to ``AuthorizationPort.check()``.

    Args:
        oidc_port: Port for JWT validation and identity extraction.
        settings: Application settings (reads ``oidc_enabled``).

    Example:
        middleware = OIDCAuthenticationMiddleware(oidc_port, settings)
        identity = await middleware.authenticate(request.headers["Authorization"])
        user_id = identity.to_user_id()
    """

    __slots__ = ("_oidc_port", "_settings")

    def __init__(
        self,
        oidc_port: OIDCAuthenticationPort,
        settings: Settings,
    ) -> None:
        self._oidc_port = oidc_port
        self._settings = settings

    async def authenticate(
        self,
        authorization_header: str | None,
    ) -> ServiceIdentity:
        """Authenticate a request using the Bearer token in the Authorization header.

        Validates the JWT and extracts a ``ServiceIdentity`` representing
        the authenticated M2M client.

        Args:
            authorization_header: The full ``Authorization`` header value
                (e.g., ``"Bearer eyJhbGci..."``). May be ``None`` if the
                header is absent.

        Returns:
            Authenticated ``ServiceIdentity`` with client_id, issuer, and scopes.

        Raises:
            OIDCError: If OIDC authentication is not enabled.
            TokenValidationError: If the header is missing, malformed,
                or the token fails validation.
        """
        if not self._settings.oidc_enabled:
            raise OIDCError(_ERR_OIDC_NOT_ENABLED)

        if not authorization_header:
            raise TokenValidationError(_ERR_MISSING_HEADER)

        if not authorization_header.startswith(_BEARER_PREFIX):
            raise TokenValidationError(_ERR_INVALID_HEADER_FORMAT)

        raw_token = authorization_header[_BEARER_PREFIX_LEN:]

        if not raw_token:
            raise TokenValidationError(_ERR_EMPTY_TOKEN)

        claims = await self._oidc_port.validate_token(raw_token)
        identity = await self._oidc_port.extract_identity(claims)

        logger.info(
            "oidc_authentication_success",
            client_id=identity.client_id,
            issuer=identity.issuer,
            scopes=sorted(identity.scopes),
        )

        return identity

    async def authenticate_and_authorize(
        self,
        authorization_header: str | None,
        resource: ResourceId,
        action: Action,
    ) -> tuple[ServiceIdentity, AuthorizationContext]:
        """Authenticate and prepare an authorization context.

        Performs authentication, then maps the identity to a ``UserId``
        and builds an ``AuthorizationContext`` for the requested action
        on the given resource.

        The caller is responsible for passing the returned context to
        ``AuthorizationPort.check()`` — this method does **not** call
        OpenFGA directly (separation of concerns).

        Args:
            authorization_header: The full ``Authorization`` header value.
            resource: The resource being accessed.
            action: The action the client wants to perform.

        Returns:
            A tuple of:
                - ``ServiceIdentity``: The authenticated service client.
                - ``AuthorizationContext``: Ready to pass to
                  ``AuthorizationPort.check()``.

        Raises:
            OIDCError: If OIDC authentication is not enabled.
            TokenValidationError: If authentication fails.
        """
        identity = await self.authenticate(authorization_header)
        user_id = map_identity_to_user_id(identity)

        context = AuthorizationContext.for_action(
            user_id=user_id.value,
            resource=resource,
            action=action,
        )

        logger.info(
            "oidc_authorization_context_created",
            client_id=identity.client_id,
            user_id=user_id.value,
            action=str(action),
            resource=str(resource),
        )

        return identity, context


def map_identity_to_user_id(identity: ServiceIdentity) -> UserId:
    """Map a ``ServiceIdentity`` to an OpenFGA-compatible ``UserId``.

    Convention: ``service-{client_id}`` maps to OpenFGA ``user:service-{client_id}``.

    Args:
        identity: The authenticated service identity.

    Returns:
        A ``UserId`` with the ``service-`` prefix.
    """
    return identity.to_user_id()


__all__ = [
    "OIDCAuthenticationMiddleware",
    "map_identity_to_user_id",
]
