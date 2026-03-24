"""Unit tests for Authorization Use Cases.

Tests the authorization use cases for OpenFGA-based access control:
- CheckAuthorizationUseCase
- BatchCheckAuthorizationUseCase
- ManageRelationshipsUseCase
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest

from siopv.application.ports.authorization import (
    AuthorizationPort,
    AuthorizationStorePort,
)
from siopv.application.use_cases.authorization import (
    AuthorizationStats,
    BatchCheckAuthorizationUseCase,
    BatchCheckResult,
    CheckAuthorizationResult,
    CheckAuthorizationUseCase,
    ManageRelationshipsUseCase,
    RelationshipWriteResult,
    create_batch_check_authorization_use_case,
    create_check_authorization_use_case,
    create_manage_relationships_use_case,
)
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
)

# === Fixtures ===


@pytest.fixture
def sample_user_id() -> str:
    """Sample user ID for testing."""
    return "alice"


@pytest.fixture
def sample_resource_type() -> ResourceType:
    """Sample resource type for testing."""
    return ResourceType.PROJECT


@pytest.fixture
def sample_resource_id() -> str:
    """Sample resource ID for testing."""
    return "siopv"


@pytest.fixture
def sample_action() -> Action:
    """Sample action for testing."""
    return Action.VIEW


@pytest.fixture
def sample_authorization_context(
    sample_user_id: str,
    sample_resource_type: ResourceType,
    sample_resource_id: str,
    sample_action: Action,
) -> AuthorizationContext:
    """Create a sample authorization context."""
    resource = ResourceId(resource_type=sample_resource_type, identifier=sample_resource_id)
    return AuthorizationContext.for_action(
        user_id=sample_user_id,
        resource=resource,
        action=sample_action,
    )


@pytest.fixture
def sample_allowed_result(
    sample_authorization_context: AuthorizationContext,
) -> AuthorizationResult:
    """Create a sample allowed authorization result."""
    return AuthorizationResult.allowed_result(
        context=sample_authorization_context,
        checked_relation=Relation.VIEWER,
        reason="User has viewer relation",
        check_duration_ms=5.0,
    )


@pytest.fixture
def sample_denied_result(sample_authorization_context: AuthorizationContext) -> AuthorizationResult:
    """Create a sample denied authorization result."""
    return AuthorizationResult.denied_result(
        context=sample_authorization_context,
        checked_relation=Relation.VIEWER,
        reason="User lacks viewer relation",
        check_duration_ms=5.0,
    )


@pytest.fixture
def mock_authorization_port(sample_allowed_result: AuthorizationResult) -> MagicMock:
    """Create a mock authorization port."""
    mock = MagicMock(spec=AuthorizationPort)
    mock.check = AsyncMock(return_value=sample_allowed_result)
    mock.batch_check = AsyncMock(
        return_value=BatchAuthorizationResult(
            results=[sample_allowed_result],
            total_duration_ms=10.0,
        )
    )
    mock.check_relation = AsyncMock(return_value=sample_allowed_result)
    mock.list_user_relations = AsyncMock(return_value=[Relation.VIEWER, Relation.ANALYST])
    return mock


@pytest.fixture
def mock_authorization_port_denied(sample_denied_result: AuthorizationResult) -> MagicMock:
    """Create a mock authorization port that returns denied."""
    mock = MagicMock(spec=AuthorizationPort)
    mock.check = AsyncMock(return_value=sample_denied_result)
    mock.batch_check = AsyncMock(
        return_value=BatchAuthorizationResult(
            results=[sample_denied_result],
            total_duration_ms=10.0,
        )
    )
    return mock


@pytest.fixture
def mock_store_port() -> MagicMock:
    """Create a mock authorization store port."""
    mock = MagicMock(spec=AuthorizationStorePort)
    mock.write_tuple = AsyncMock(return_value=None)
    mock.write_tuples = AsyncMock(return_value=None)
    mock.delete_tuple = AsyncMock(return_value=None)
    mock.delete_tuples = AsyncMock(return_value=None)
    mock.read_tuples = AsyncMock(return_value=[])
    mock.read_tuples_for_user = AsyncMock(return_value=[])
    mock.read_tuples_for_resource = AsyncMock(return_value=[])
    mock.tuple_exists = AsyncMock(return_value=True)
    return mock


# === CheckAuthorizationUseCase Tests ===


class TestCheckAuthorizationUseCase:
    """Tests for CheckAuthorizationUseCase."""

    @pytest.mark.asyncio
    async def test_execute_allowed(
        self,
        mock_authorization_port: MagicMock,
        sample_user_id: str,
        sample_action: Action,
        sample_resource_type: ResourceType,
        sample_resource_id: str,
    ):
        """Test successful authorization check that is allowed."""
        use_case = CheckAuthorizationUseCase(authorization_port=mock_authorization_port)

        result = await use_case.execute(
            user_id=sample_user_id,
            action=sample_action,
            resource_type=sample_resource_type,
            resource_id=sample_resource_id,
        )

        assert result.allowed is True
        assert result.audit_logged is True
        assert result.decision_id is not None
        mock_authorization_port.check.assert_called_once()

    @pytest.mark.asyncio
    async def test_execute_denied(
        self,
        mock_authorization_port_denied: MagicMock,
        sample_user_id: str,
        sample_action: Action,
        sample_resource_type: ResourceType,
        sample_resource_id: str,
    ):
        """Test authorization check that is denied."""
        use_case = CheckAuthorizationUseCase(authorization_port=mock_authorization_port_denied)

        result = await use_case.execute(
            user_id=sample_user_id,
            action=sample_action,
            resource_type=sample_resource_type,
            resource_id=sample_resource_id,
        )

        assert result.allowed is False
        assert result.audit_logged is True

    @pytest.mark.asyncio
    async def test_execute_with_contextual_tuples(
        self,
        mock_authorization_port: MagicMock,
        sample_user_id: str,
    ):
        """Test authorization check with contextual tuples."""
        use_case = CheckAuthorizationUseCase(authorization_port=mock_authorization_port)

        contextual_tuple = RelationshipTuple.create(
            user_id="bob",
            relation=Relation.VIEWER,
            resource_type=ResourceType.PROJECT,
            resource_id="other-project",
        )

        result = await use_case.execute(
            user_id=sample_user_id,
            action=Action.VIEW,
            resource_type=ResourceType.PROJECT,
            resource_id="siopv",
            contextual_tuples=[contextual_tuple],
        )

        assert result.allowed is True

    @pytest.mark.asyncio
    async def test_execute_raises_on_unmapped_action(
        self,
        mock_authorization_port: MagicMock,
    ):
        """Test that unmapped action raises ActionNotMappedError."""
        # Create use case with mappings that don't include VIEW action
        # Note: empty dict {} is falsy in Python, so it would use defaults
        # We need a non-empty dict without the action we're testing
        use_case = CheckAuthorizationUseCase(
            authorization_port=mock_authorization_port,
            action_mappings={
                Action.DELETE: ActionPermissionMapping(
                    action=Action.DELETE,
                    required_relations=frozenset({Relation.OWNER}),
                )
            },  # Only DELETE mapped, not VIEW
        )

        with pytest.raises(ActionNotMappedError):
            await use_case.execute(
                user_id="alice",
                action=Action.VIEW,  # VIEW is not mapped
                resource_type=ResourceType.PROJECT,
                resource_id="siopv",
            )

    @pytest.mark.asyncio
    async def test_execute_raises_on_port_error(
        self,
        sample_user_id: str,
    ):
        """Test that port errors are wrapped in AuthorizationCheckError."""
        mock_port = MagicMock(spec=AuthorizationPort)
        mock_port.check = AsyncMock(side_effect=RuntimeError("Connection failed"))

        use_case = CheckAuthorizationUseCase(authorization_port=mock_port)

        with pytest.raises(AuthorizationCheckError) as exc_info:
            await use_case.execute(
                user_id=sample_user_id,
                action=Action.VIEW,
                resource_type=ResourceType.PROJECT,
                resource_id="siopv",
            )

        assert "Connection failed" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_execute_with_resource(
        self,
        mock_authorization_port: MagicMock,
        sample_user_id: str,
    ):
        """Test execute_with_resource convenience method."""
        use_case = CheckAuthorizationUseCase(authorization_port=mock_authorization_port)

        resource = ResourceId.for_project("siopv")
        result = await use_case.execute_with_resource(
            user_id=sample_user_id,
            action=Action.VIEW,
            resource=resource,
        )

        assert result.allowed is True

    def test_get_required_relations(
        self,
        mock_authorization_port: MagicMock,
    ):
        """Test getting required relations for an action."""
        use_case = CheckAuthorizationUseCase(authorization_port=mock_authorization_port)

        relations = use_case.get_required_relations(Action.VIEW)

        assert Relation.VIEWER in relations
        assert Relation.OWNER in relations
        assert Relation.ANALYST in relations

    def test_get_required_relations_raises_on_unmapped(
        self,
        mock_authorization_port: MagicMock,
    ):
        """Test that getting relations for unmapped action raises error."""
        # Use non-empty dict without the action we're testing
        use_case = CheckAuthorizationUseCase(
            authorization_port=mock_authorization_port,
            action_mappings={
                Action.DELETE: ActionPermissionMapping(
                    action=Action.DELETE,
                    required_relations=frozenset({Relation.OWNER}),
                )
            },  # Only DELETE mapped, not VIEW
        )

        with pytest.raises(ActionNotMappedError):
            use_case.get_required_relations(Action.VIEW)


# === BatchCheckAuthorizationUseCase Tests ===


class TestBatchCheckAuthorizationUseCase:
    """Tests for BatchCheckAuthorizationUseCase."""

    @pytest.mark.asyncio
    async def test_execute_batch(
        self,
        mock_authorization_port: MagicMock,
    ):
        """Test batch authorization check."""
        use_case = BatchCheckAuthorizationUseCase(authorization_port=mock_authorization_port)

        checks = [
            ("alice", Action.VIEW, ResourceType.PROJECT, "siopv"),
        ]

        result = await use_case.execute(checks)

        assert isinstance(result, BatchCheckResult)
        assert result.batch_id is not None
        assert result.stats.total_checks == 1
        assert result.stats.allowed_count == 1
        mock_authorization_port.batch_check.assert_called_once()

    @pytest.mark.asyncio
    async def test_execute_batch_multiple_checks(
        self,
        sample_allowed_result: AuthorizationResult,
        sample_denied_result: AuthorizationResult,
    ):
        """Test batch check with multiple items."""
        mock_port = MagicMock(spec=AuthorizationPort)
        mock_port.batch_check = AsyncMock(
            return_value=BatchAuthorizationResult(
                results=[sample_allowed_result, sample_denied_result],
                total_duration_ms=20.0,
            )
        )

        use_case = BatchCheckAuthorizationUseCase(authorization_port=mock_port)

        checks = [
            ("alice", Action.VIEW, ResourceType.PROJECT, "project1"),
            ("bob", Action.EDIT, ResourceType.PROJECT, "project2"),
        ]

        result = await use_case.execute(checks)

        assert result.stats.total_checks == 2
        assert result.stats.allowed_count == 1
        assert result.stats.denied_count == 1
        assert result.any_denied is True
        assert result.all_allowed is False

    @pytest.mark.asyncio
    async def test_execute_batch_empty_raises(
        self,
        mock_authorization_port: MagicMock,
    ):
        """Test that empty batch raises ValueError."""
        use_case = BatchCheckAuthorizationUseCase(authorization_port=mock_authorization_port)

        with pytest.raises(ValueError, match="cannot be empty"):
            await use_case.execute([])

    @pytest.mark.asyncio
    async def test_execute_batch_exceeds_limit_raises(
        self,
        mock_authorization_port: MagicMock,
    ):
        """Test that exceeding batch limit raises ValueError."""
        use_case = BatchCheckAuthorizationUseCase(
            authorization_port=mock_authorization_port,
            max_batch_size=5,
        )

        checks = [("user", Action.VIEW, ResourceType.PROJECT, f"project{i}") for i in range(10)]

        with pytest.raises(ValueError, match="exceeds maximum"):
            await use_case.execute(checks)

    @pytest.mark.asyncio
    async def test_execute_from_contexts(
        self,
        mock_authorization_port: MagicMock,
        sample_authorization_context: AuthorizationContext,
    ):
        """Test batch check with pre-built contexts."""
        use_case = BatchCheckAuthorizationUseCase(authorization_port=mock_authorization_port)

        result = await use_case.execute_from_contexts([sample_authorization_context])

        assert result.stats.total_checks == 1
        mock_authorization_port.batch_check.assert_called_once()

    @pytest.mark.asyncio
    async def test_execute_from_contexts_empty_raises(
        self,
        mock_authorization_port: MagicMock,
    ):
        """Test that empty contexts raises ValueError."""
        use_case = BatchCheckAuthorizationUseCase(authorization_port=mock_authorization_port)

        with pytest.raises(ValueError, match="cannot be empty"):
            await use_case.execute_from_contexts([])

    def test_get_denied_results(
        self,
        sample_allowed_result: AuthorizationResult,
        sample_denied_result: AuthorizationResult,
    ):
        """Test getting denied results from batch."""
        result = BatchCheckResult(
            results=[sample_allowed_result, sample_denied_result],
            batch_id=uuid4(),
            stats=AuthorizationStats(
                total_checks=2,
                allowed_count=1,
                denied_count=1,
                error_count=0,
                avg_duration_ms=5.0,
            ),
        )

        denied = result.get_denied_results()
        assert len(denied) == 1
        assert denied[0].allowed is False


# === ManageRelationshipsUseCase Tests ===


class TestManageRelationshipsUseCase:
    """Tests for ManageRelationshipsUseCase."""

    @pytest.mark.asyncio
    async def test_grant_permission(
        self,
        mock_store_port: MagicMock,
    ):
        """Test granting a permission."""
        use_case = ManageRelationshipsUseCase(store_port=mock_store_port)

        result = await use_case.grant_permission(
            user_id="alice",
            relation=Relation.VIEWER,
            resource_type=ResourceType.PROJECT,
            resource_id="siopv",
        )

        assert result.success is True
        assert result.operation == "grant"
        assert result.error is None
        mock_store_port.write_tuple.assert_called_once()

    @pytest.mark.asyncio
    async def test_grant_permission_failure(self):
        """Test grant permission failure."""
        mock_port = MagicMock(spec=AuthorizationStorePort)
        mock_port.write_tuple = AsyncMock(side_effect=RuntimeError("Write failed"))

        use_case = ManageRelationshipsUseCase(store_port=mock_port)

        result = await use_case.grant_permission(
            user_id="alice",
            relation=Relation.VIEWER,
            resource_type=ResourceType.PROJECT,
            resource_id="siopv",
        )

        assert result.success is False
        assert result.error is not None
        assert "Write failed" in result.error

    @pytest.mark.asyncio
    async def test_revoke_permission(
        self,
        mock_store_port: MagicMock,
    ):
        """Test revoking a permission."""
        use_case = ManageRelationshipsUseCase(store_port=mock_store_port)

        result = await use_case.revoke_permission(
            user_id="alice",
            relation=Relation.VIEWER,
            resource_type=ResourceType.PROJECT,
            resource_id="siopv",
        )

        assert result.success is True
        assert result.operation == "revoke"
        mock_store_port.delete_tuple.assert_called_once()

    @pytest.mark.asyncio
    async def test_revoke_permission_failure(self):
        """Test revoke permission failure."""
        mock_port = MagicMock(spec=AuthorizationStorePort)
        mock_port.delete_tuple = AsyncMock(side_effect=RuntimeError("Delete failed"))

        use_case = ManageRelationshipsUseCase(store_port=mock_port)

        result = await use_case.revoke_permission(
            user_id="alice",
            relation=Relation.VIEWER,
            resource_type=ResourceType.PROJECT,
            resource_id="siopv",
        )

        assert result.success is False
        assert "Delete failed" in result.error

    @pytest.mark.asyncio
    async def test_grant_permissions_batch(
        self,
        mock_store_port: MagicMock,
    ):
        """Test batch grant permissions."""
        use_case = ManageRelationshipsUseCase(store_port=mock_store_port)

        grants = [
            ("alice", Relation.VIEWER, ResourceType.PROJECT, "project1"),
            ("bob", Relation.ANALYST, ResourceType.PROJECT, "project2"),
        ]

        results = await use_case.grant_permissions_batch(grants)

        assert len(results) == 2
        assert all(r.success for r in results)
        assert all(r.operation == "grant" for r in results)
        mock_store_port.write_tuples.assert_called_once()

    @pytest.mark.asyncio
    async def test_grant_permissions_batch_empty_raises(
        self,
        mock_store_port: MagicMock,
    ):
        """Test that empty batch raises ValueError."""
        use_case = ManageRelationshipsUseCase(store_port=mock_store_port)

        with pytest.raises(ValueError, match="cannot be empty"):
            await use_case.grant_permissions_batch([])

    @pytest.mark.asyncio
    async def test_grant_permissions_batch_exceeds_limit_raises(
        self,
        mock_store_port: MagicMock,
    ):
        """Test that exceeding batch limit raises ValueError."""
        use_case = ManageRelationshipsUseCase(store_port=mock_store_port)

        grants = [
            ("user", Relation.VIEWER, ResourceType.PROJECT, f"project{i}") for i in range(101)
        ]

        with pytest.raises(ValueError, match="exceeds maximum"):
            await use_case.grant_permissions_batch(grants)

    @pytest.mark.asyncio
    async def test_revoke_permissions_batch(
        self,
        mock_store_port: MagicMock,
    ):
        """Test batch revoke permissions."""
        use_case = ManageRelationshipsUseCase(store_port=mock_store_port)

        revocations = [
            ("alice", Relation.VIEWER, ResourceType.PROJECT, "project1"),
            ("bob", Relation.ANALYST, ResourceType.PROJECT, "project2"),
        ]

        results = await use_case.revoke_permissions_batch(revocations)

        assert len(results) == 2
        assert all(r.success for r in results)
        assert all(r.operation == "revoke" for r in results)
        mock_store_port.delete_tuples.assert_called_once()

    @pytest.mark.asyncio
    async def test_list_user_permissions(
        self,
        mock_store_port: MagicMock,
    ):
        """Test listing user permissions."""
        sample_tuple = RelationshipTuple.create(
            user_id="alice",
            relation=Relation.VIEWER,
            resource_type=ResourceType.PROJECT,
            resource_id="siopv",
        )
        mock_store_port.read_tuples_for_user = AsyncMock(return_value=[sample_tuple])

        use_case = ManageRelationshipsUseCase(store_port=mock_store_port)

        tuples = await use_case.list_user_permissions("alice")

        assert len(tuples) == 1
        assert tuples[0].user.value == "alice"
        mock_store_port.read_tuples_for_user.assert_called_once()

    @pytest.mark.asyncio
    async def test_list_resource_permissions(
        self,
        mock_store_port: MagicMock,
    ):
        """Test listing resource permissions."""
        sample_tuple = RelationshipTuple.create(
            user_id="alice",
            relation=Relation.OWNER,
            resource_type=ResourceType.PROJECT,
            resource_id="siopv",
        )
        mock_store_port.read_tuples_for_resource = AsyncMock(return_value=[sample_tuple])

        use_case = ManageRelationshipsUseCase(store_port=mock_store_port)

        tuples = await use_case.list_resource_permissions(ResourceType.PROJECT, "siopv")

        assert len(tuples) == 1
        assert tuples[0].relation == Relation.OWNER
        mock_store_port.read_tuples_for_resource.assert_called_once()

    @pytest.mark.asyncio
    async def test_check_tuple_exists(
        self,
        mock_store_port: MagicMock,
    ):
        """Test checking if tuple exists."""
        use_case = ManageRelationshipsUseCase(store_port=mock_store_port)

        exists = await use_case.check_tuple_exists(
            user_id="alice",
            relation=Relation.VIEWER,
            resource_type=ResourceType.PROJECT,
            resource_id="siopv",
        )

        assert exists is True
        mock_store_port.tuple_exists.assert_called_once()


# === Result Dataclass Tests ===


class TestCheckAuthorizationResult:
    """Tests for CheckAuthorizationResult dataclass."""

    def test_allowed_property(self, sample_allowed_result: AuthorizationResult):
        """Test allowed property."""
        result = CheckAuthorizationResult(result=sample_allowed_result)
        assert result.allowed is True

    def test_denied_property(self, sample_denied_result: AuthorizationResult):
        """Test denied property."""
        result = CheckAuthorizationResult(result=sample_denied_result)
        assert result.allowed is False

    def test_decision_id_property(self, sample_allowed_result: AuthorizationResult):
        """Test decision_id property."""
        result = CheckAuthorizationResult(result=sample_allowed_result)
        assert result.decision_id == sample_allowed_result.decision_id


class TestBatchCheckResult:
    """Tests for BatchCheckResult dataclass."""

    def test_all_allowed_true(self, sample_allowed_result: AuthorizationResult):
        """Test all_allowed when all are allowed."""
        result = BatchCheckResult(
            results=[sample_allowed_result, sample_allowed_result],
            batch_id=uuid4(),
            stats=AuthorizationStats(
                total_checks=2,
                allowed_count=2,
                denied_count=0,
                error_count=0,
                avg_duration_ms=5.0,
            ),
        )
        assert result.all_allowed is True
        assert result.any_denied is False

    def test_any_denied_true(
        self,
        sample_allowed_result: AuthorizationResult,
        sample_denied_result: AuthorizationResult,
    ):
        """Test any_denied when some are denied."""
        result = BatchCheckResult(
            results=[sample_allowed_result, sample_denied_result],
            batch_id=uuid4(),
            stats=AuthorizationStats(
                total_checks=2,
                allowed_count=1,
                denied_count=1,
                error_count=0,
                avg_duration_ms=5.0,
            ),
        )
        assert result.all_allowed is False
        assert result.any_denied is True


class TestRelationshipWriteResult:
    """Tests for RelationshipWriteResult dataclass."""

    def test_successful_grant(self):
        """Test successful grant result."""
        rel_tuple = RelationshipTuple.create(
            user_id="alice",
            relation=Relation.VIEWER,
            resource_type=ResourceType.PROJECT,
            resource_id="siopv",
        )
        result = RelationshipWriteResult(
            success=True,
            tuple=rel_tuple,
            operation="grant",
        )

        assert result.success is True
        assert result.operation == "grant"
        assert result.error is None

    def test_failed_revoke(self):
        """Test failed revoke result."""
        rel_tuple = RelationshipTuple.create(
            user_id="alice",
            relation=Relation.VIEWER,
            resource_type=ResourceType.PROJECT,
            resource_id="siopv",
        )
        result = RelationshipWriteResult(
            success=False,
            tuple=rel_tuple,
            operation="revoke",
            error="Connection timeout",
        )

        assert result.success is False
        assert result.operation == "revoke"
        assert "timeout" in result.error


class TestAuthorizationStats:
    """Tests for AuthorizationStats dataclass."""

    def test_create_stats(self):
        """Test creating authorization stats."""
        stats = AuthorizationStats(
            total_checks=10,
            allowed_count=7,
            denied_count=3,
            error_count=0,
            avg_duration_ms=5.5,
        )

        assert stats.total_checks == 10
        assert stats.allowed_count == 7
        assert stats.denied_count == 3
        assert stats.avg_duration_ms == 5.5


# === Factory Function Tests ===


class TestFactoryFunctions:
    """Tests for factory functions."""

    def test_create_check_authorization_use_case(
        self,
        mock_authorization_port: MagicMock,
    ):
        """Test factory for CheckAuthorizationUseCase."""
        use_case = create_check_authorization_use_case(mock_authorization_port)
        assert isinstance(use_case, CheckAuthorizationUseCase)

    def test_create_batch_check_authorization_use_case(
        self,
        mock_authorization_port: MagicMock,
    ):
        """Test factory for BatchCheckAuthorizationUseCase."""
        use_case = create_batch_check_authorization_use_case(mock_authorization_port)
        assert isinstance(use_case, BatchCheckAuthorizationUseCase)

    def test_create_batch_check_with_custom_batch_size(
        self,
        mock_authorization_port: MagicMock,
    ):
        """Test factory with custom batch size."""
        use_case = create_batch_check_authorization_use_case(
            mock_authorization_port,
            max_batch_size=50,
        )
        assert use_case._max_batch_size == 50

    def test_create_manage_relationships_use_case(
        self,
        mock_store_port: MagicMock,
    ):
        """Test factory for ManageRelationshipsUseCase."""
        use_case = create_manage_relationships_use_case(mock_store_port)
        assert isinstance(use_case, ManageRelationshipsUseCase)
