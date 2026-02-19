"""Value objects for OIDC authentication in SIOPV.

These value objects represent the core concepts for OIDC client_credentials
flow, enabling machine-to-machine (M2M) API authentication via Keycloak.

Token claims are parsed from JWT Bearer tokens, service identities map
to OpenFGA user IDs for ReBAC authorization checks.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

from siopv.domain.authorization.value_objects import UserId


class TokenClaims(BaseModel):
    """Validated JWT token claims from an OIDC provider.

    Represents the decoded and validated payload of a JWT Bearer token
    issued by Keycloak (or any OIDC-compliant provider) for the
    client_credentials grant type.

    All fields follow the OIDC Core and RFC 7519 (JWT) specifications.
    The model is frozen (immutable) since claims are read-only after validation.
    """

    model_config = ConfigDict(frozen=True)

    sub: str = Field(
        ...,
        min_length=1,
        description="Subject identifier (client service account ID)",
    )
    iss: str = Field(
        ...,
        min_length=1,
        description="Issuer URL (Keycloak realm URL)",
    )
    aud: str | list[str] = Field(
        ...,
        description="Audience (intended recipient, e.g. 'siopv-api')",
    )
    exp: int = Field(
        ...,
        description="Expiration time (Unix timestamp)",
    )
    iat: int = Field(
        ...,
        description="Issued at time (Unix timestamp)",
    )
    azp: str | None = Field(
        default=None,
        description="Authorized party (client_id for client_credentials)",
    )
    scope: str | None = Field(
        default=None,
        description="Space-delimited scope string",
    )
    client_id: str | None = Field(
        default=None,
        description="Client identifier (Keycloak-specific claim)",
    )
    jti: str | None = Field(
        default=None,
        description="JWT ID (unique token identifier)",
    )

    @field_validator("exp")
    @classmethod
    def validate_exp_positive(cls, v: int) -> int:
        """Validate expiration timestamp is positive."""
        if v <= 0:
            msg = "Expiration time must be a positive timestamp"
            raise ValueError(msg)
        return v

    @field_validator("iat")
    @classmethod
    def validate_iat_positive(cls, v: int) -> int:
        """Validate issued-at timestamp is positive."""
        if v <= 0:
            msg = "Issued-at time must be a positive timestamp"
            raise ValueError(msg)
        return v

    def get_effective_client_id(self) -> str:
        """Return the effective client ID from the token claims.

        For client_credentials tokens, the client ID comes from the ``azp``
        claim. Falls back to ``client_id`` claim (Keycloak-specific), then
        to ``sub`` as last resort.

        Returns:
            The client identifier string.

        Raises:
            ValueError: If no client identifier can be determined.
        """
        if self.azp:
            return self.azp
        if self.client_id:
            return self.client_id
        if self.sub:
            return self.sub
        msg = "No client identifier found in token claims"
        raise ValueError(msg)

    def get_scopes(self) -> frozenset[str]:
        """Parse the scope claim into a frozenset of individual scopes.

        Returns:
            Frozenset of scope strings. Empty frozenset if no scope claim.
        """
        if not self.scope:
            return frozenset()
        return frozenset(s for s in self.scope.split() if s)


class ServiceIdentity(BaseModel):
    """Identity of an authenticated M2M service client.

    Maps an OIDC client_credentials token to an identity usable within
    the SIOPV authorization system. The ``to_user_id()`` method produces
    an OpenFGA-compatible ``UserId`` with the ``service-`` prefix.

    Note:
        Uses ``-`` as separator (not ``:``) because the existing
        ``UserId`` regex ``^[a-zA-Z0-9_@.\\-]+$`` does not allow ``:``.
        Convention: ``service-{client_id}`` maps to OpenFGA ``user:service-{client_id}``.
    """

    model_config = ConfigDict(frozen=True)

    client_id: str = Field(
        ...,
        min_length=1,
        description="OIDC client identifier",
    )
    issuer: str = Field(
        ...,
        min_length=1,
        description="OIDC issuer URL",
    )
    scopes: frozenset[str] = Field(
        default_factory=frozenset,
        description="Granted scopes",
    )

    @field_validator("client_id")
    @classmethod
    def validate_client_id_safe(cls, v: str) -> str:
        """Validate client_id contains only safe characters for UserId mapping."""
        if not re.match(r"^[a-zA-Z0-9_@.\-]+$", v):
            msg = "Client ID contains invalid characters"
            raise ValueError(msg)
        return v

    def to_user_id(self) -> UserId:
        """Map this service identity to an OpenFGA-compatible UserId.

        Returns:
            UserId with ``service-{client_id}`` format.

        Example:
            >>> identity = ServiceIdentity(
            ...     client_id="siopv-client",
            ...     issuer="http://localhost:8888/realms/siopv",
            ... )
            >>> identity.to_user_id()
            UserId(value='service-siopv-client')
        """
        return UserId(value=f"service-{self.client_id}")

    @classmethod
    def from_claims(cls, claims: TokenClaims) -> ServiceIdentity:
        """Factory method to create a ServiceIdentity from validated token claims.

        Args:
            claims: Validated JWT token claims.

        Returns:
            ServiceIdentity derived from the claims.
        """
        return cls(
            client_id=claims.get_effective_client_id(),
            issuer=claims.iss,
            scopes=claims.get_scopes(),
        )


class OIDCProviderConfig(BaseModel):
    """OIDC provider configuration from the discovery document.

    Holds the endpoints and metadata retrieved from the OIDC
    ``/.well-known/openid-configuration`` endpoint. Frozen since
    provider config is immutable once fetched.
    """

    model_config = ConfigDict(frozen=True)

    issuer_url: str = Field(
        ...,
        min_length=1,
        description="Issuer URL from the discovery document",
    )
    jwks_uri: str = Field(
        ...,
        min_length=1,
        description="URL to fetch JSON Web Key Set",
    )
    token_endpoint: str = Field(
        ...,
        min_length=1,
        description="Token endpoint for client_credentials exchange",
    )
    authorization_endpoint: str | None = Field(
        default=None,
        description="Authorization endpoint (may be absent for M2M-only providers)",
    )

    @field_validator("issuer_url", "jwks_uri", "token_endpoint")
    @classmethod
    def validate_url_scheme(cls, v: str) -> str:
        """Validate that URL fields use http or https scheme."""
        if not v.startswith(("http://", "https://")):
            msg = "URL must use http or https scheme"
            raise ValueError(msg)
        return v


__all__ = [
    "OIDCProviderConfig",
    "ServiceIdentity",
    "TokenClaims",
]
