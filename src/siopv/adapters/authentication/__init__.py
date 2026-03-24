"""OIDC authentication adapters for SIOPV.

Provides Keycloak-specific OIDC adapter implementing OIDCAuthenticationPort
for M2M (machine-to-machine) JWT Bearer token validation.
"""

from siopv.adapters.authentication.keycloak_oidc_adapter import KeycloakOIDCAdapter

__all__ = [
    "KeycloakOIDCAdapter",
]
