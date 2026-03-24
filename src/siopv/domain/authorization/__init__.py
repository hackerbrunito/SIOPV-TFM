"""Authorization domain layer for SIOPV Phase 5 (OpenFGA).

This module implements the domain layer for ReBAC (Relationship-Based Access
Control) authorization using OpenFGA. It provides:

Value Objects:
    - UserId: User identifier wrapper
    - ResourceId: Resource identifier with type
    - ResourceType: Enum for resource types (PROJECT, VULNERABILITY, REPORT)
    - Relation: Enum for relations (OWNER, VIEWER, ANALYST, AUDITOR)
    - Action: Enum for actions (VIEW, EDIT, REMEDIATE, EXPORT, DELETE)
    - ActionPermissionMapping: Maps actions to required relations

Entities:
    - AuthorizationContext: Input for permission checks
    - AuthorizationResult: Output from permission checks with audit metadata
    - RelationshipTuple: OpenFGA tuple (user, relation, object)
    - BatchAuthorizationResult: Results from batch checks

Exceptions:
    - InvalidRelationError: Relation invalid for resource type
    - InvalidResourceFormatError: Bad resource format
    - InvalidUserFormatError: Bad user format
    - TupleValidationError: Invalid relationship tuple
    - AuthorizationCheckError: Check failed (not denial, but error)
    - AuthorizationModelError: Model configuration error
    - StoreNotFoundError: OpenFGA store not found
    - ActionNotMappedError: Action has no relation mapping

Usage:
    from siopv.domain.authorization import (
        UserId,
        ResourceId,
        ResourceType,
        Action,
        Relation,
        AuthorizationContext,
        AuthorizationResult,
    )

    # Create authorization context
    context = AuthorizationContext.for_action(
        user_id="alice",
        resource=ResourceId.for_project("siopv"),
        action=Action.VIEW,
    )

    # The adapter layer will use this context to call OpenFGA
    # and return an AuthorizationResult
"""

from siopv.domain.authorization.entities import (
    AuthorizationContext,
    AuthorizationResult,
    BatchAuthorizationResult,
    RelationshipTuple,
)
from siopv.domain.authorization.exceptions import (
    ActionNotMappedError,
    AuthorizationCheckError,
    AuthorizationModelError,
    InvalidRelationError,
    InvalidResourceFormatError,
    InvalidUserFormatError,
    StoreNotFoundError,
    TupleValidationError,
)
from siopv.domain.authorization.value_objects import (
    Action,
    ActionPermissionMapping,
    Relation,
    ResourceId,
    ResourceType,
    UserId,
)

__all__ = [
    "Action",
    "ActionNotMappedError",
    "ActionPermissionMapping",
    "AuthorizationCheckError",
    "AuthorizationContext",
    "AuthorizationModelError",
    "AuthorizationResult",
    "BatchAuthorizationResult",
    "InvalidRelationError",
    "InvalidResourceFormatError",
    "InvalidUserFormatError",
    "Relation",
    "RelationshipTuple",
    "ResourceId",
    "ResourceType",
    "StoreNotFoundError",
    "TupleValidationError",
    "UserId",
]
