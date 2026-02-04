"""Authorization Use Cases for OpenFGA-based access control.

Orchestrates authorization operations by coordinating domain entities and port calls:
1. CheckAuthorizationUseCase - Single permission check
2. BatchCheckAuthorizationUseCase - Multiple permission checks
3. ManageRelationshipsUseCase - Admin operations for relationship tuples

Based on Phase 5 specification: OpenFGA ReBAC authorization integration.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING
from uuid import UUID, uuid4

import structlog

from siopv.domain.authorization import (
    Action,
    ActionNotMappedError,
    ActionPermissionMapping,
    AuthorizationCheckError,
    AuthorizationContext,
    AuthorizationResult,
    BatchAuthorizationResult,
    Relation,
    RelationshipTuple,
    ResourceId,
    ResourceType,
    UserId,
)

if TYPE_CHECKING:
    from siopv.application.ports.authorization import (
        AuthorizationPort,
        AuthorizationStorePort,
    )

logger = structlog.get_logger(__name__)


# Maximum batch size for OpenFGA operations (SDK limit)
MAX_BATCH_SIZE = 100

# Error messages as constants for ruff EM101/EM102 compliance
_ERR_CHECKS_EMPTY = "Checks list cannot be empty"
_ERR_CONTEXTS_EMPTY = "Contexts list cannot be empty"
_ERR_GRANTS_EMPTY = "Grants list cannot be empty"
_ERR_REVOCATIONS_EMPTY = "Revocations list cannot be empty"


def _batch_size_error(size: int, max_size: int) -> str:
    """Generate batch size exceeded error message."""
    return f"Batch size {size} exceeds maximum {max_size}"


@dataclass(frozen=True)
class AuthorizationStats:
    """Statistics from authorization operations."""

    total_checks: int
    allowed_count: int
    denied_count: int
    error_count: int
    avg_duration_ms: float


@dataclass(frozen=True)
class CheckAuthorizationResult:
    """Result of a single authorization check use case execution."""

    result: AuthorizationResult
    audit_logged: bool = True

    @property
    def allowed(self) -> bool:
        """Whether the authorization was granted."""
        return self.result.allowed

    @property
    def decision_id(self) -> UUID:
        """Unique identifier for audit purposes."""
        return self.result.decision_id


@dataclass(frozen=True)
class BatchCheckResult:
    """Result of batch authorization check use case execution."""

    results: list[AuthorizationResult]
    batch_id: UUID
    stats: AuthorizationStats

    @property
    def all_allowed(self) -> bool:
        """Check if all authorizations were granted."""
        return all(r.allowed for r in self.results)

    @property
    def any_denied(self) -> bool:
        """Check if any authorization was denied."""
        return any(not r.allowed for r in self.results)

    def get_denied_results(self) -> list[AuthorizationResult]:
        """Get all denied authorization results."""
        return [r for r in self.results if not r.allowed]


@dataclass(frozen=True)
class RelationshipWriteResult:
    """Result of a relationship write operation."""

    success: bool
    tuple: RelationshipTuple
    operation: str  # "grant" or "revoke"
    error: str | None = None


class CheckAuthorizationUseCase:
    """Use case for checking if a user can perform an action on a resource.

    This is the primary authorization entry point for the SIOPV pipeline.
    It coordinates:
    - Domain value object validation (UserId, ResourceId, Action)
    - Action-to-relation mapping
    - Authorization port invocation
    - Audit logging

    Per spec: "check(user:X, relation:viewer, object:project:Y)"
    """

    def __init__(
        self,
        authorization_port: AuthorizationPort,
        *,
        action_mappings: dict[Action, ActionPermissionMapping] | None = None,
    ) -> None:
        """Initialize the check authorization use case.

        Args:
            authorization_port: Port for authorization checks (OpenFGA adapter)
            action_mappings: Optional custom action-to-relation mappings.
                           Uses default mappings if not provided.
        """
        self._auth = authorization_port
        self._mappings = action_mappings or ActionPermissionMapping.default_mappings()

        logger.info("check_authorization_use_case_initialized")

    async def execute(
        self,
        user_id: str,
        action: Action,
        resource_type: ResourceType,
        resource_id: str,
        *,
        contextual_tuples: list[RelationshipTuple] | None = None,
        authorization_model_id: str | None = None,
    ) -> CheckAuthorizationResult:
        """Execute authorization check for a single user-action-resource.

        Args:
            user_id: User identifier (without 'user:' prefix)
            action: The action the user wants to perform
            resource_type: Type of the resource
            resource_id: Resource identifier
            contextual_tuples: Optional additional context tuples
            authorization_model_id: Optional OpenFGA model ID

        Returns:
            CheckAuthorizationResult with the authorization decision

        Raises:
            ActionNotMappedError: If action has no relation mapping
            AuthorizationCheckError: If the check cannot be performed
        """
        log = logger.bind(
            user_id=user_id,
            action=action.value,
            resource_type=resource_type.value,
            resource_id=resource_id,
        )
        log.info("authorization_check_started")

        # Validate action mapping exists
        mapping = self._mappings.get(action)
        if mapping is None:
            log.error("action_not_mapped", action=action.value)
            raise ActionNotMappedError(action)

        # Build domain objects
        resource = ResourceId(resource_type=resource_type, identifier=resource_id)

        # Create authorization context
        context = AuthorizationContext.for_action(
            user_id=user_id,
            resource=resource,
            action=action,
            contextual_tuples=contextual_tuples,
            authorization_model_id=authorization_model_id,
        )

        try:
            # Delegate to port
            result = await self._auth.check(context)

            # Log audit entry
            log.info(
                "authorization_check_complete",
                allowed=result.allowed,
                checked_relation=result.checked_relation.value,
                decision_id=str(result.decision_id),
                duration_ms=result.check_duration_ms,
            )

            return CheckAuthorizationResult(result=result, audit_logged=True)

        except Exception as e:
            log.exception(
                "authorization_check_failed",
                error=str(e),
                error_type=type(e).__name__,
            )
            raise AuthorizationCheckError(
                user=user_id,
                action=action,
                resource=resource,
                reason=str(e),
                underlying_error=e,
            ) from e

    async def execute_with_resource(
        self,
        user_id: str,
        action: Action,
        resource: ResourceId,
        *,
        contextual_tuples: list[RelationshipTuple] | None = None,
    ) -> CheckAuthorizationResult:
        """Execute authorization check with pre-built ResourceId.

        Convenience method when you already have a ResourceId object.

        Args:
            user_id: User identifier
            action: The action to check
            resource: Pre-built ResourceId
            contextual_tuples: Optional context tuples

        Returns:
            CheckAuthorizationResult with the decision
        """
        return await self.execute(
            user_id=user_id,
            action=action,
            resource_type=resource.resource_type,
            resource_id=resource.identifier,
            contextual_tuples=contextual_tuples,
        )

    def get_required_relations(self, action: Action) -> frozenset[Relation]:
        """Get the relations that can satisfy an action.

        Args:
            action: The action to look up

        Returns:
            Set of relations that grant this action

        Raises:
            ActionNotMappedError: If action has no mapping
        """
        mapping = self._mappings.get(action)
        if mapping is None:
            raise ActionNotMappedError(action)
        return mapping.required_relations


class BatchCheckAuthorizationUseCase:
    """Use case for checking multiple authorizations at once.

    Efficiently batch checks multiple user-action-resource combinations
    using OpenFGA's batch_check API. This is ~3-5x faster than individual
    checks due to reduced network overhead.

    Max batch size: 100 (OpenFGA limit)
    """

    def __init__(
        self,
        authorization_port: AuthorizationPort,
        *,
        max_batch_size: int = MAX_BATCH_SIZE,
    ) -> None:
        """Initialize batch check use case.

        Args:
            authorization_port: Port for authorization checks
            max_batch_size: Maximum items per batch (default 100)
        """
        self._auth = authorization_port
        self._max_batch_size = max_batch_size

        logger.info(
            "batch_check_authorization_use_case_initialized",
            max_batch_size=max_batch_size,
        )

    async def execute(
        self,
        checks: list[tuple[str, Action, ResourceType, str]],
        *,
        authorization_model_id: str | None = None,
    ) -> BatchCheckResult:
        """Execute batch authorization checks.

        Args:
            checks: List of (user_id, action, resource_type, resource_id) tuples
            authorization_model_id: Optional OpenFGA model ID

        Returns:
            BatchCheckResult with all results and statistics

        Raises:
            ValueError: If checks list is empty or exceeds max size
            AuthorizationCheckError: If the batch check fails
        """
        batch_id = uuid4()
        log = logger.bind(batch_id=str(batch_id), check_count=len(checks))

        log.info("batch_authorization_check_started")

        if not checks:
            log.warning("batch_authorization_empty_checks")
            raise ValueError(_ERR_CHECKS_EMPTY)

        if len(checks) > self._max_batch_size:
            log.warning(
                "batch_authorization_exceeds_limit",
                requested=len(checks),
                max_allowed=self._max_batch_size,
            )
            raise ValueError(_batch_size_error(len(checks), self._max_batch_size))

        # Build authorization contexts
        contexts: list[AuthorizationContext] = []
        for user_id, action, resource_type, resource_id in checks:
            resource = ResourceId(resource_type=resource_type, identifier=resource_id)
            context = AuthorizationContext.for_action(
                user_id=user_id,
                resource=resource,
                action=action,
                authorization_model_id=authorization_model_id,
            )
            contexts.append(context)

        try:
            # Delegate to port
            batch_result = await self._auth.batch_check(contexts)

            # Calculate statistics
            stats = self._calculate_stats(batch_result)

            log.info(
                "batch_authorization_check_complete",
                allowed_count=stats.allowed_count,
                denied_count=stats.denied_count,
                error_count=stats.error_count,
                avg_duration_ms=stats.avg_duration_ms,
            )

            return BatchCheckResult(
                results=batch_result.results,
                batch_id=batch_id,
                stats=stats,
            )

        except Exception as e:
            log.exception(
                "batch_authorization_check_failed",
                error=str(e),
                error_type=type(e).__name__,
            )
            raise AuthorizationCheckError(
                user="batch",
                action="batch_check",
                resource="multiple",
                reason=str(e),
                underlying_error=e,
            ) from e

    async def execute_from_contexts(
        self,
        contexts: list[AuthorizationContext],
    ) -> BatchCheckResult:
        """Execute batch check with pre-built AuthorizationContext objects.

        Args:
            contexts: List of AuthorizationContext objects

        Returns:
            BatchCheckResult with all results
        """
        batch_id = uuid4()
        log = logger.bind(batch_id=str(batch_id), context_count=len(contexts))

        log.info("batch_authorization_from_contexts_started")

        if not contexts:
            raise ValueError(_ERR_CONTEXTS_EMPTY)

        if len(contexts) > self._max_batch_size:
            raise ValueError(_batch_size_error(len(contexts), self._max_batch_size))

        batch_result = await self._auth.batch_check(contexts)
        stats = self._calculate_stats(batch_result)

        log.info(
            "batch_authorization_from_contexts_complete",
            allowed_count=stats.allowed_count,
            denied_count=stats.denied_count,
        )

        return BatchCheckResult(
            results=batch_result.results,
            batch_id=batch_id,
            stats=stats,
        )

    def _calculate_stats(self, batch_result: BatchAuthorizationResult) -> AuthorizationStats:
        """Calculate statistics from batch results.

        Args:
            batch_result: BatchAuthorizationResult from port

        Returns:
            AuthorizationStats instance
        """
        total = len(batch_result.results)
        allowed = sum(1 for r in batch_result.results if r.allowed)
        denied = total - allowed
        error_count = 0  # Errors would raise exception before reaching here

        durations = [r.check_duration_ms for r in batch_result.results]
        avg_duration = sum(durations) / len(durations) if durations else 0.0

        return AuthorizationStats(
            total_checks=total,
            allowed_count=allowed,
            denied_count=denied,
            error_count=error_count,
            avg_duration_ms=avg_duration,
        )


class ManageRelationshipsUseCase:
    """Use case for managing authorization relationships (admin operations).

    Provides operations for:
    - Granting permissions (creating relationship tuples)
    - Revoking permissions (deleting relationship tuples)
    - Querying existing relationships

    Security Note: Callers must verify administrative permissions
    before invoking these methods.
    """

    def __init__(self, store_port: AuthorizationStorePort) -> None:
        """Initialize relationship management use case.

        Args:
            store_port: Port for authorization store operations
        """
        self._store = store_port

        logger.info("manage_relationships_use_case_initialized")

    async def grant_permission(
        self,
        user_id: str,
        relation: Relation,
        resource_type: ResourceType,
        resource_id: str,
    ) -> RelationshipWriteResult:
        """Grant a permission by creating a relationship tuple.

        Args:
            user_id: User identifier (without 'user:' prefix)
            relation: The relation to grant
            resource_type: Type of the resource
            resource_id: Resource identifier

        Returns:
            RelationshipWriteResult indicating success or failure
        """
        log = logger.bind(
            user_id=user_id,
            relation=relation.value,
            resource_type=resource_type.value,
            resource_id=resource_id,
            operation="grant",
        )
        log.info("grant_permission_started")

        # Build relationship tuple
        relationship = RelationshipTuple.create(
            user_id=user_id,
            relation=relation,
            resource_type=resource_type,
            resource_id=resource_id,
        )

        try:
            await self._store.write_tuple(relationship)

            log.info(
                "grant_permission_complete",
                tuple_str=str(relationship),
            )

            return RelationshipWriteResult(
                success=True,
                tuple=relationship,
                operation="grant",
            )

        except Exception as e:
            log.exception(
                "grant_permission_failed",
                error=str(e),
                error_type=type(e).__name__,
            )

            return RelationshipWriteResult(
                success=False,
                tuple=relationship,
                operation="grant",
                error=str(e),
            )

    async def revoke_permission(
        self,
        user_id: str,
        relation: Relation,
        resource_type: ResourceType,
        resource_id: str,
    ) -> RelationshipWriteResult:
        """Revoke a permission by deleting a relationship tuple.

        Args:
            user_id: User identifier (without 'user:' prefix)
            relation: The relation to revoke
            resource_type: Type of the resource
            resource_id: Resource identifier

        Returns:
            RelationshipWriteResult indicating success or failure
        """
        log = logger.bind(
            user_id=user_id,
            relation=relation.value,
            resource_type=resource_type.value,
            resource_id=resource_id,
            operation="revoke",
        )
        log.info("revoke_permission_started")

        # Build relationship tuple
        relationship = RelationshipTuple.create(
            user_id=user_id,
            relation=relation,
            resource_type=resource_type,
            resource_id=resource_id,
        )

        try:
            await self._store.delete_tuple(relationship)

            log.info(
                "revoke_permission_complete",
                tuple_str=str(relationship),
            )

            return RelationshipWriteResult(
                success=True,
                tuple=relationship,
                operation="revoke",
            )

        except Exception as e:
            log.exception(
                "revoke_permission_failed",
                error=str(e),
                error_type=type(e).__name__,
            )

            return RelationshipWriteResult(
                success=False,
                tuple=relationship,
                operation="revoke",
                error=str(e),
            )

    async def grant_permissions_batch(
        self,
        grants: list[tuple[str, Relation, ResourceType, str]],
    ) -> list[RelationshipWriteResult]:
        """Grant multiple permissions atomically.

        Args:
            grants: List of (user_id, relation, resource_type, resource_id) tuples

        Returns:
            List of RelationshipWriteResult (one result for entire batch)

        Raises:
            ValueError: If batch is empty or exceeds limit
        """
        log = logger.bind(grant_count=len(grants), operation="batch_grant")
        log.info("batch_grant_permissions_started")

        if not grants:
            raise ValueError(_ERR_GRANTS_EMPTY)

        if len(grants) > MAX_BATCH_SIZE:
            raise ValueError(_batch_size_error(len(grants), MAX_BATCH_SIZE))

        # Build all tuples
        tuples: list[RelationshipTuple] = []
        for user_id, relation, resource_type, resource_id in grants:
            relationship = RelationshipTuple.create(
                user_id=user_id,
                relation=relation,
                resource_type=resource_type,
                resource_id=resource_id,
            )
            tuples.append(relationship)

        try:
            await self._store.write_tuples(tuples)

            log.info("batch_grant_permissions_complete", count=len(tuples))

            return [
                RelationshipWriteResult(success=True, tuple=t, operation="grant") for t in tuples
            ]

        except Exception as e:
            log.exception(
                "batch_grant_permissions_failed",
                error=str(e),
                error_type=type(e).__name__,
            )

            return [
                RelationshipWriteResult(success=False, tuple=t, operation="grant", error=str(e))
                for t in tuples
            ]

    async def revoke_permissions_batch(
        self,
        revocations: list[tuple[str, Relation, ResourceType, str]],
    ) -> list[RelationshipWriteResult]:
        """Revoke multiple permissions atomically.

        Args:
            revocations: List of (user_id, relation, resource_type, resource_id) tuples

        Returns:
            List of RelationshipWriteResult

        Raises:
            ValueError: If batch is empty or exceeds limit
        """
        log = logger.bind(revocation_count=len(revocations), operation="batch_revoke")
        log.info("batch_revoke_permissions_started")

        if not revocations:
            raise ValueError(_ERR_REVOCATIONS_EMPTY)

        if len(revocations) > MAX_BATCH_SIZE:
            raise ValueError(_batch_size_error(len(revocations), MAX_BATCH_SIZE))

        # Build all tuples
        tuples: list[RelationshipTuple] = []
        for user_id, relation, resource_type, resource_id in revocations:
            relationship = RelationshipTuple.create(
                user_id=user_id,
                relation=relation,
                resource_type=resource_type,
                resource_id=resource_id,
            )
            tuples.append(relationship)

        try:
            await self._store.delete_tuples(tuples)

            log.info("batch_revoke_permissions_complete", count=len(tuples))

            return [
                RelationshipWriteResult(success=True, tuple=t, operation="revoke") for t in tuples
            ]

        except Exception as e:
            log.exception(
                "batch_revoke_permissions_failed",
                error=str(e),
                error_type=type(e).__name__,
            )

            return [
                RelationshipWriteResult(success=False, tuple=t, operation="revoke", error=str(e))
                for t in tuples
            ]

    async def list_user_permissions(
        self,
        user_id: str,
    ) -> list[RelationshipTuple]:
        """List all permissions for a user.

        Args:
            user_id: User identifier

        Returns:
            List of RelationshipTuple representing user's permissions
        """
        log = logger.bind(user_id=user_id)
        log.info("list_user_permissions_started")

        user = UserId(value=user_id)
        tuples = await self._store.read_tuples_for_user(user)

        log.info("list_user_permissions_complete", count=len(tuples))

        return tuples

    async def list_resource_permissions(
        self,
        resource_type: ResourceType,
        resource_id: str,
    ) -> list[RelationshipTuple]:
        """List all permissions for a resource.

        Args:
            resource_type: Type of the resource
            resource_id: Resource identifier

        Returns:
            List of RelationshipTuple for the resource
        """
        log = logger.bind(
            resource_type=resource_type.value,
            resource_id=resource_id,
        )
        log.info("list_resource_permissions_started")

        resource = ResourceId(resource_type=resource_type, identifier=resource_id)
        tuples = await self._store.read_tuples_for_resource(resource)

        log.info("list_resource_permissions_complete", count=len(tuples))

        return tuples

    async def check_tuple_exists(
        self,
        user_id: str,
        relation: Relation,
        resource_type: ResourceType,
        resource_id: str,
    ) -> bool:
        """Check if a specific permission tuple exists.

        Args:
            user_id: User identifier
            relation: The relation to check
            resource_type: Type of the resource
            resource_id: Resource identifier

        Returns:
            True if the tuple exists, False otherwise
        """
        user = UserId(value=user_id)
        resource = ResourceId(resource_type=resource_type, identifier=resource_id)

        return await self._store.tuple_exists(user, relation, resource)


# Factory functions for clean instantiation


def create_check_authorization_use_case(
    authorization_port: AuthorizationPort,
) -> CheckAuthorizationUseCase:
    """Factory function to create CheckAuthorizationUseCase.

    Args:
        authorization_port: Port for authorization checks

    Returns:
        Configured CheckAuthorizationUseCase
    """
    return CheckAuthorizationUseCase(authorization_port=authorization_port)


def create_batch_check_authorization_use_case(
    authorization_port: AuthorizationPort,
    *,
    max_batch_size: int = MAX_BATCH_SIZE,
) -> BatchCheckAuthorizationUseCase:
    """Factory function to create BatchCheckAuthorizationUseCase.

    Args:
        authorization_port: Port for authorization checks
        max_batch_size: Maximum batch size

    Returns:
        Configured BatchCheckAuthorizationUseCase
    """
    return BatchCheckAuthorizationUseCase(
        authorization_port=authorization_port,
        max_batch_size=max_batch_size,
    )


def create_manage_relationships_use_case(
    store_port: AuthorizationStorePort,
) -> ManageRelationshipsUseCase:
    """Factory function to create ManageRelationshipsUseCase.

    Args:
        store_port: Port for authorization store operations

    Returns:
        Configured ManageRelationshipsUseCase
    """
    return ManageRelationshipsUseCase(store_port=store_port)


__all__ = [
    "AuthorizationStats",
    "BatchCheckAuthorizationUseCase",
    "BatchCheckResult",
    "CheckAuthorizationResult",
    "CheckAuthorizationUseCase",
    "ManageRelationshipsUseCase",
    "RelationshipWriteResult",
    "create_batch_check_authorization_use_case",
    "create_check_authorization_use_case",
    "create_manage_relationships_use_case",
]
