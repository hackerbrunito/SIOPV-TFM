"""Unit tests for authorization entities.

Tests the domain entities for OpenFGA authorization:
- RelationshipTuple: OpenFGA relationship tuples
- AuthorizationContext: Context for permission checks
- AuthorizationResult: Results from authorization checks
- BatchAuthorizationResult: Batch authorization results
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

import pytest
from pydantic import ValidationError

from siopv.domain.authorization.entities import (
    AuthorizationContext,
    AuthorizationResult,
    BatchAuthorizationResult,
    RelationshipTuple,
)
from siopv.domain.authorization.value_objects import (
    Action,
    Relation,
    ResourceId,
    ResourceType,
    UserId,
)

# === Fixtures ===


@pytest.fixture
def sample_user() -> UserId:
    """Create sample user identifier."""
    return UserId(value="alice")


@pytest.fixture
def sample_resource() -> ResourceId:
    """Create sample resource identifier."""
    return ResourceId.for_project("siopv")


@pytest.fixture
def sample_tuple(sample_user: UserId, sample_resource: ResourceId) -> RelationshipTuple:
    """Create sample relationship tuple."""
    return RelationshipTuple(
        user=sample_user,
        relation=Relation.OWNER,
        resource=sample_resource,
    )


@pytest.fixture
def sample_context(sample_user: UserId, sample_resource: ResourceId) -> AuthorizationContext:
    """Create sample authorization context."""
    return AuthorizationContext(
        user=sample_user,
        resource=sample_resource,
        action=Action.VIEW,
    )


# === Test RelationshipTuple ===


class TestRelationshipTuple:
    """Tests for RelationshipTuple entity."""

    def test_create_basic_tuple(self, sample_user: UserId, sample_resource: ResourceId) -> None:
        """Test creating a basic relationship tuple."""
        tuple_obj = RelationshipTuple(
            user=sample_user,
            relation=Relation.OWNER,
            resource=sample_resource,
        )

        assert tuple_obj.user == sample_user
        assert tuple_obj.relation == Relation.OWNER
        assert tuple_obj.resource == sample_resource
        assert tuple_obj.condition_context is None

    def test_create_tuple_with_condition_context(
        self, sample_user: UserId, sample_resource: ResourceId
    ) -> None:
        """Test creating tuple with condition context."""
        context = {"ip_address": "192.168.1.1", "time_of_day": "business_hours"}
        tuple_obj = RelationshipTuple(
            user=sample_user,
            relation=Relation.VIEWER,
            resource=sample_resource,
            condition_context=context,
        )

        assert tuple_obj.condition_context == context

    def test_tuple_has_created_at_timestamp(
        self, sample_user: UserId, sample_resource: ResourceId
    ) -> None:
        """Test tuple automatically gets created_at timestamp."""
        before = datetime.now(UTC)
        tuple_obj = RelationshipTuple(
            user=sample_user,
            relation=Relation.OWNER,
            resource=sample_resource,
        )
        after = datetime.now(UTC)

        assert before <= tuple_obj.created_at <= after

    def test_from_openfga_tuple_basic(self) -> None:
        """Test creating tuple from OpenFGA string format."""
        tuple_obj = RelationshipTuple.from_openfga_tuple(
            user="user:alice",
            relation="owner",
            obj="project:siopv",
        )

        assert tuple_obj.user.value == "alice"
        assert tuple_obj.relation == Relation.OWNER
        assert tuple_obj.resource.resource_type == ResourceType.PROJECT
        assert tuple_obj.resource.identifier == "siopv"

    def test_from_openfga_tuple_without_prefix(self) -> None:
        """Test from_openfga_tuple handles user without prefix."""
        tuple_obj = RelationshipTuple.from_openfga_tuple(
            user="alice",
            relation="viewer",
            obj="vulnerability:CVE-2024-1234",
        )

        assert tuple_obj.user.value == "alice"
        assert tuple_obj.relation == Relation.VIEWER

    def test_from_openfga_tuple_with_condition(self) -> None:
        """Test from_openfga_tuple with condition context."""
        context = {"ip_range": "10.0.0.0/8"}
        tuple_obj = RelationshipTuple.from_openfga_tuple(
            user="user:bob",
            relation="analyst",
            obj="project:security",
            condition_context=context,
        )

        assert tuple_obj.condition_context == context

    def test_from_openfga_tuple_invalid_relation(self) -> None:
        """Test from_openfga_tuple with invalid relation raises error."""
        with pytest.raises(ValueError, match="invalid_relation"):
            RelationshipTuple.from_openfga_tuple(
                user="user:alice",
                relation="invalid_relation",
                obj="project:siopv",
            )

    def test_from_openfga_tuple_invalid_resource_format(self) -> None:
        """Test from_openfga_tuple with invalid resource format."""
        with pytest.raises(ValueError, match="Expected '<type>:<id>'"):
            RelationshipTuple.from_openfga_tuple(
                user="user:alice",
                relation="owner",
                obj="invalid_format",
            )

    def test_create_factory_method(self) -> None:
        """Test create factory method with separate components."""
        tuple_obj = RelationshipTuple.create(
            user_id="alice",
            relation=Relation.ANALYST,
            resource_type=ResourceType.VULNERABILITY,
            resource_id="CVE-2024-5678",
        )

        assert tuple_obj.user.value == "alice"
        assert tuple_obj.relation == Relation.ANALYST
        assert tuple_obj.resource.resource_type == ResourceType.VULNERABILITY
        assert tuple_obj.resource.identifier == "CVE-2024-5678"

    def test_to_openfga_dict(self, sample_tuple: RelationshipTuple) -> None:
        """Test conversion to OpenFGA dictionary format."""
        openfga_dict = sample_tuple.to_openfga_dict()

        assert openfga_dict["user"] == "user:alice"
        assert openfga_dict["relation"] == "owner"
        assert openfga_dict["object"] == "project:siopv"
        assert len(openfga_dict) == 3

    def test_str_representation(self, sample_tuple: RelationshipTuple) -> None:
        """Test string representation of tuple."""
        str_repr = str(sample_tuple)
        assert "alice" in str_repr
        assert "owner" in str_repr
        assert "siopv" in str_repr

    def test_tuple_is_frozen(self, sample_tuple: RelationshipTuple) -> None:
        """Test RelationshipTuple is immutable."""
        with pytest.raises(ValidationError):
            sample_tuple.relation = Relation.VIEWER  # type: ignore[misc]

    def test_tuple_hashable(self) -> None:
        """Test RelationshipTuple can be used in sets/dicts."""
        tuple1 = RelationshipTuple.create(
            user_id="alice",
            relation=Relation.OWNER,
            resource_type=ResourceType.PROJECT,
            resource_id="siopv",
        )
        tuple2 = RelationshipTuple.create(
            user_id="alice",
            relation=Relation.OWNER,
            resource_type=ResourceType.PROJECT,
            resource_id="siopv",
        )
        tuple3 = RelationshipTuple.create(
            user_id="bob",
            relation=Relation.OWNER,
            resource_type=ResourceType.PROJECT,
            resource_id="siopv",
        )

        # Note: hash excludes created_at, so same content = same hash
        assert hash(tuple1) == hash(tuple2)  # Same content = same hash
        tuple_set = {tuple1, tuple3}
        assert len(tuple_set) == 2


# === Test AuthorizationContext ===


class TestAuthorizationContext:
    """Tests for AuthorizationContext entity."""

    def test_create_basic_context(self, sample_user: UserId, sample_resource: ResourceId) -> None:
        """Test creating basic authorization context."""
        context = AuthorizationContext(
            user=sample_user,
            resource=sample_resource,
            action=Action.VIEW,
        )

        assert context.user == sample_user
        assert context.resource == sample_resource
        assert context.action == Action.VIEW
        assert context.direct_relation is None
        assert len(context.contextual_tuples) == 0

    def test_context_has_auto_generated_ids(
        self, sample_user: UserId, sample_resource: ResourceId
    ) -> None:
        """Test context has auto-generated request_id."""
        context = AuthorizationContext(
            user=sample_user,
            resource=sample_resource,
            action=Action.EDIT,
        )

        assert isinstance(context.request_id, UUID)
        assert isinstance(context.requested_at, datetime)

    def test_context_with_direct_relation(
        self, sample_user: UserId, sample_resource: ResourceId
    ) -> None:
        """Test context with direct relation check."""
        context = AuthorizationContext(
            user=sample_user,
            resource=sample_resource,
            action=Action.VIEW,
            direct_relation=Relation.OWNER,
        )

        assert context.direct_relation == Relation.OWNER

    def test_context_with_contextual_tuples(
        self, sample_user: UserId, sample_resource: ResourceId
    ) -> None:
        """Test context with contextual tuples."""
        tuple1 = RelationshipTuple.create(
            user_id="bob",
            relation=Relation.VIEWER,
            resource_type=ResourceType.PROJECT,
            resource_id="other",
        )
        context = AuthorizationContext(
            user=sample_user,
            resource=sample_resource,
            action=Action.VIEW,
            contextual_tuples=[tuple1],
        )

        assert len(context.contextual_tuples) == 1
        assert context.contextual_tuples[0] == tuple1

    def test_context_with_authorization_model_id(
        self, sample_user: UserId, sample_resource: ResourceId
    ) -> None:
        """Test context with OpenFGA authorization model ID."""
        model_id = "01HZXY12ABC34DEF56GH"
        context = AuthorizationContext(
            user=sample_user,
            resource=sample_resource,
            action=Action.REMEDIATE,
            authorization_model_id=model_id,
        )

        assert context.authorization_model_id == model_id

    def test_for_action_factory(self, sample_resource: ResourceId) -> None:
        """Test for_action factory method."""
        context = AuthorizationContext.for_action(
            user_id="charlie",
            resource=sample_resource,
            action=Action.EXPORT,
        )

        assert context.user.value == "charlie"
        assert context.resource == sample_resource
        assert context.action == Action.EXPORT

    def test_for_action_with_contextual_tuples(self, sample_resource: ResourceId) -> None:
        """Test for_action with contextual tuples."""
        tuple1 = RelationshipTuple.create(
            user_id="dave",
            relation=Relation.MEMBER,
            resource_type=ResourceType.ORGANIZATION,
            resource_id="acme",
        )
        context = AuthorizationContext.for_action(
            user_id="charlie",
            resource=sample_resource,
            action=Action.VIEW,
            contextual_tuples=[tuple1],
        )

        assert len(context.contextual_tuples) == 1

    def test_for_action_with_model_id(self, sample_resource: ResourceId) -> None:
        """Test for_action with authorization model ID."""
        model_id = "01HZXY12ABC34DEF56GH"
        context = AuthorizationContext.for_action(
            user_id="charlie",
            resource=sample_resource,
            action=Action.VIEW,
            authorization_model_id=model_id,
        )

        assert context.authorization_model_id == model_id

    def test_for_relation_check_factory(self, sample_resource: ResourceId) -> None:
        """Test for_relation_check factory method."""
        context = AuthorizationContext.for_relation_check(
            user_id="eve",
            resource=sample_resource,
            relation=Relation.AUDITOR,
        )

        assert context.user.value == "eve"
        assert context.direct_relation == Relation.AUDITOR
        assert context.action == Action.VIEW  # Placeholder

    def test_for_relation_check_with_model_id(self, sample_resource: ResourceId) -> None:
        """Test for_relation_check with model ID."""
        model_id = "01HZXY12ABC34DEF56GH"
        context = AuthorizationContext.for_relation_check(
            user_id="eve",
            resource=sample_resource,
            relation=Relation.ADMIN,
            authorization_model_id=model_id,
        )

        assert context.authorization_model_id == model_id

    def test_to_openfga_check_request_basic(self, sample_context: AuthorizationContext) -> None:
        """Test conversion to OpenFGA check request format."""
        request = sample_context.to_openfga_check_request()

        assert request["user"] == "user:alice"
        assert request["object"] == "project:siopv"
        assert "relation" not in request  # Determined by action mapping

    def test_to_openfga_check_request_with_contextual_tuples(
        self, sample_user: UserId, sample_resource: ResourceId
    ) -> None:
        """Test OpenFGA request includes contextual tuples."""
        tuple1 = RelationshipTuple.create(
            user_id="bob",
            relation=Relation.MEMBER,
            resource_type=ResourceType.ORGANIZATION,
            resource_id="acme",
        )
        context = AuthorizationContext(
            user=sample_user,
            resource=sample_resource,
            action=Action.VIEW,
            contextual_tuples=[tuple1],
        )

        request = context.to_openfga_check_request()

        assert "contextual_tuples" in request
        assert len(request["contextual_tuples"]) == 1

    def test_str_representation(self, sample_context: AuthorizationContext) -> None:
        """Test string representation of context."""
        str_repr = str(sample_context)
        assert "alice" in str_repr
        assert "view" in str_repr
        assert "siopv" in str_repr

    def test_context_is_frozen(self, sample_context: AuthorizationContext) -> None:
        """Test AuthorizationContext is immutable."""
        with pytest.raises(ValidationError):
            sample_context.action = Action.DELETE  # type: ignore[misc]


# === Test AuthorizationResult ===


class TestAuthorizationResult:
    """Tests for AuthorizationResult entity."""

    def test_create_basic_result(self, sample_context: AuthorizationContext) -> None:
        """Test creating basic authorization result."""
        result = AuthorizationResult(
            allowed=True,
            context=sample_context,
            checked_relation=Relation.VIEWER,
            reason="User has viewer access",
        )

        assert result.allowed is True
        assert result.context == sample_context
        assert result.checked_relation == Relation.VIEWER
        assert result.reason == "User has viewer access"

    def test_result_has_auto_generated_fields(self, sample_context: AuthorizationContext) -> None:
        """Test result has auto-generated decision_id and timestamp."""
        result = AuthorizationResult(
            allowed=False,
            context=sample_context,
            checked_relation=Relation.OWNER,
        )

        assert isinstance(result.decision_id, UUID)
        assert isinstance(result.decided_at, datetime)

    def test_result_with_performance_metadata(self, sample_context: AuthorizationContext) -> None:
        """Test result with check duration."""
        result = AuthorizationResult(
            allowed=True,
            context=sample_context,
            checked_relation=Relation.ANALYST,
            check_duration_ms=25.5,
        )

        assert result.check_duration_ms == 25.5

    def test_result_with_additional_metadata(self, sample_context: AuthorizationContext) -> None:
        """Test result with additional audit metadata."""
        metadata = {"source": "api", "client_ip": "10.0.0.1"}
        result = AuthorizationResult(
            allowed=True,
            context=sample_context,
            checked_relation=Relation.OWNER,
            metadata=metadata,
        )

        assert result.metadata == metadata

    def test_allowed_result_factory(self, sample_context: AuthorizationContext) -> None:
        """Test allowed_result factory method."""
        result = AuthorizationResult.allowed_result(
            context=sample_context,
            checked_relation=Relation.VIEWER,
            reason="Permission granted via viewer role",
            check_duration_ms=10.0,
        )

        assert result.allowed is True
        assert result.reason == "Permission granted via viewer role"
        assert result.check_duration_ms == 10.0

    def test_denied_result_factory(self, sample_context: AuthorizationContext) -> None:
        """Test denied_result factory method."""
        result = AuthorizationResult.denied_result(
            context=sample_context,
            checked_relation=Relation.OWNER,
            reason="User lacks owner relation",
            check_duration_ms=15.0,
        )

        assert result.allowed is False
        assert result.reason == "User lacks owner relation"
        assert result.check_duration_ms == 15.0

    def test_from_openfga_response_allowed(self, sample_context: AuthorizationContext) -> None:
        """Test from_openfga_response with allowed=true."""
        result = AuthorizationResult.from_openfga_response(
            context=sample_context,
            checked_relation=Relation.ANALYST,
            openfga_allowed=True,
            check_duration_ms=20.0,
        )

        assert result.allowed is True
        assert "has analyst relation" in result.reason.lower()

    def test_from_openfga_response_denied(self, sample_context: AuthorizationContext) -> None:
        """Test from_openfga_response with allowed=false."""
        result = AuthorizationResult.from_openfga_response(
            context=sample_context,
            checked_relation=Relation.OWNER,
            openfga_allowed=False,
            check_duration_ms=18.0,
        )

        assert result.allowed is False
        assert "lacks owner relation" in result.reason.lower()

    def test_audit_log_entry_structure(self, sample_context: AuthorizationContext) -> None:
        """Test audit_log_entry computed field with PII redaction."""
        result = AuthorizationResult.allowed_result(
            context=sample_context,
            checked_relation=Relation.VIEWER,
            check_duration_ms=12.5,
        )

        audit_entry = result.audit_log_entry

        assert "decision_id" in audit_entry
        assert audit_entry["allowed"] is True
        # Security: User is pseudonymized (SHA-256 hash)
        assert audit_entry["user"].startswith("user:")
        assert audit_entry["user"] != "user:alice"  # Not the original
        assert len(audit_entry["user"]) == 5 + 16  # "user:" + 16-char hash
        assert audit_entry["action"] == "view"
        # Security: Resource ID is redacted
        assert audit_entry["resource"] == "project:<redacted>"
        assert audit_entry["checked_relation"] == "viewer"
        assert "request_id" in audit_entry
        assert "requested_at" in audit_entry
        assert "decided_at" in audit_entry
        assert audit_entry["check_duration_ms"] == 12.5

    def test_audit_log_includes_custom_metadata(self, sample_context: AuthorizationContext) -> None:
        """Test audit log includes custom metadata."""
        metadata = {"source": "api", "endpoint": "/vulnerabilities"}
        result = AuthorizationResult.allowed_result(
            context=sample_context,
            checked_relation=Relation.VIEWER,
            metadata=metadata,
        )

        audit_entry = result.audit_log_entry

        assert audit_entry["source"] == "api"
        assert audit_entry["endpoint"] == "/vulnerabilities"

    def test_str_representation_allowed(self, sample_context: AuthorizationContext) -> None:
        """Test string representation for allowed result."""
        result = AuthorizationResult.allowed_result(
            context=sample_context,
            checked_relation=Relation.VIEWER,
        )

        str_repr = str(result)
        assert "ALLOWED" in str_repr
        assert "alice" in str_repr
        assert "view" in str_repr

    def test_str_representation_denied(self, sample_context: AuthorizationContext) -> None:
        """Test string representation for denied result."""
        result = AuthorizationResult.denied_result(
            context=sample_context,
            checked_relation=Relation.OWNER,
        )

        str_repr = str(result)
        assert "DENIED" in str_repr

    def test_result_is_frozen(self, sample_context: AuthorizationContext) -> None:
        """Test AuthorizationResult is immutable."""
        result = AuthorizationResult.allowed_result(
            context=sample_context,
            checked_relation=Relation.VIEWER,
        )

        with pytest.raises(ValidationError):
            result.allowed = False  # type: ignore[misc]


# === Test BatchAuthorizationResult ===


class TestBatchAuthorizationResult:
    """Tests for BatchAuthorizationResult entity."""

    @pytest.fixture
    def sample_results(self, sample_context: AuthorizationContext) -> list[AuthorizationResult]:
        """Create sample authorization results."""
        return [
            AuthorizationResult.allowed_result(
                context=sample_context,
                checked_relation=Relation.VIEWER,
            ),
            AuthorizationResult.denied_result(
                context=sample_context,
                checked_relation=Relation.OWNER,
            ),
            AuthorizationResult.allowed_result(
                context=sample_context,
                checked_relation=Relation.ANALYST,
            ),
        ]

    def test_create_batch_result(self, sample_results: list[AuthorizationResult]) -> None:
        """Test creating batch authorization result."""
        batch = BatchAuthorizationResult(
            results=sample_results,
            total_duration_ms=50.0,
        )

        assert len(batch.results) == 3
        assert batch.total_duration_ms == 50.0
        assert isinstance(batch.batch_id, UUID)

    def test_all_allowed_property_true(self, sample_context: AuthorizationContext) -> None:
        """Test all_allowed when all results are allowed."""
        results = [
            AuthorizationResult.allowed_result(
                context=sample_context,
                checked_relation=Relation.VIEWER,
            ),
            AuthorizationResult.allowed_result(
                context=sample_context,
                checked_relation=Relation.ANALYST,
            ),
        ]
        batch = BatchAuthorizationResult(results=results)

        assert batch.all_allowed is True

    def test_all_allowed_property_false(self, sample_results: list[AuthorizationResult]) -> None:
        """Test all_allowed when some results are denied."""
        batch = BatchAuthorizationResult(results=sample_results)

        assert batch.all_allowed is False

    def test_any_denied_property_true(self, sample_results: list[AuthorizationResult]) -> None:
        """Test any_denied when some results are denied."""
        batch = BatchAuthorizationResult(results=sample_results)

        assert batch.any_denied is True

    def test_any_denied_property_false(self, sample_context: AuthorizationContext) -> None:
        """Test any_denied when all results are allowed."""
        results = [
            AuthorizationResult.allowed_result(
                context=sample_context,
                checked_relation=Relation.VIEWER,
            ),
        ]
        batch = BatchAuthorizationResult(results=results)

        assert batch.any_denied is False

    def test_allowed_count(self, sample_results: list[AuthorizationResult]) -> None:
        """Test allowed_count property."""
        batch = BatchAuthorizationResult(results=sample_results)

        assert batch.allowed_count == 2

    def test_denied_count(self, sample_results: list[AuthorizationResult]) -> None:
        """Test denied_count property."""
        batch = BatchAuthorizationResult(results=sample_results)

        assert batch.denied_count == 1

    def test_get_denied_results(self, sample_results: list[AuthorizationResult]) -> None:
        """Test get_denied_results method."""
        batch = BatchAuthorizationResult(results=sample_results)

        denied = batch.get_denied_results()

        assert len(denied) == 1
        assert denied[0].allowed is False

    def test_get_allowed_results(self, sample_results: list[AuthorizationResult]) -> None:
        """Test get_allowed_results method."""
        batch = BatchAuthorizationResult(results=sample_results)

        allowed = batch.get_allowed_results()

        assert len(allowed) == 2
        assert all(r.allowed for r in allowed)

    def test_empty_batch(self) -> None:
        """Test batch with empty results."""
        batch = BatchAuthorizationResult(results=[])

        assert len(batch.results) == 0
        assert batch.all_allowed is True  # Vacuous truth
        assert batch.any_denied is False
        assert batch.allowed_count == 0
        assert batch.denied_count == 0

    def test_str_representation(self, sample_results: list[AuthorizationResult]) -> None:
        """Test string representation of batch result."""
        batch = BatchAuthorizationResult(results=sample_results)

        str_repr = str(batch)
        assert "2 allowed" in str_repr
        assert "1 denied" in str_repr

    def test_batch_is_frozen(self, sample_results: list[AuthorizationResult]) -> None:
        """Test BatchAuthorizationResult is immutable."""
        batch = BatchAuthorizationResult(results=sample_results)

        with pytest.raises(ValidationError):
            batch.total_duration_ms = 100.0  # type: ignore[misc]


# === Test Edge Cases ===


class TestEdgeCases:
    """Tests for edge cases and boundary conditions."""

    def test_tuple_with_very_long_identifier(self) -> None:
        """Test tuple with maximum length identifier."""
        long_id = "a" * 256
        tuple_obj = RelationshipTuple.create(
            user_id=long_id,
            relation=Relation.OWNER,
            resource_type=ResourceType.PROJECT,
            resource_id="test",
        )

        assert len(tuple_obj.user.value) == 256

    def test_context_with_past_timestamp(self) -> None:
        """Test context requested_at is in the past or present."""
        context = AuthorizationContext.for_action(
            user_id="alice",
            resource=ResourceId.for_project("test"),
            action=Action.VIEW,
        )

        assert context.requested_at <= datetime.now(UTC)

    def test_result_check_duration_zero(self) -> None:
        """Test result with zero check duration."""
        context = AuthorizationContext.for_action(
            user_id="alice",
            resource=ResourceId.for_project("test"),
            action=Action.VIEW,
        )
        result = AuthorizationResult.allowed_result(
            context=context,
            checked_relation=Relation.VIEWER,
            check_duration_ms=0.0,
        )

        assert result.check_duration_ms == 0.0

    def test_result_check_duration_negative_rejected(self) -> None:
        """Test result with negative check duration raises error."""
        context = AuthorizationContext.for_action(
            user_id="alice",
            resource=ResourceId.for_project("test"),
            action=Action.VIEW,
        )

        with pytest.raises(ValidationError):
            AuthorizationResult.allowed_result(
                context=context,
                checked_relation=Relation.VIEWER,
                check_duration_ms=-1.0,
            )

    def test_batch_with_large_number_of_results(self) -> None:
        """Test batch with many results."""
        context = AuthorizationContext.for_action(
            user_id="alice",
            resource=ResourceId.for_project("test"),
            action=Action.VIEW,
        )

        results = [
            AuthorizationResult.allowed_result(
                context=context,
                checked_relation=Relation.VIEWER,
            )
            for _ in range(100)
        ]

        batch = BatchAuthorizationResult(results=results)

        assert batch.allowed_count == 100
        assert batch.all_allowed is True

    def test_context_timestamps_ordering(self) -> None:
        """Test context requested_at comes before result decided_at."""
        context = AuthorizationContext.for_action(
            user_id="alice",
            resource=ResourceId.for_project("test"),
            action=Action.VIEW,
        )

        # Small delay to ensure different timestamps
        result = AuthorizationResult.allowed_result(
            context=context,
            checked_relation=Relation.VIEWER,
        )

        assert context.requested_at <= result.decided_at

    def test_build_audit_entry_with_pii_includes_raw_identifiers(self) -> None:
        """Test that _build_audit_entry with include_pii=True returns raw PII."""
        context = AuthorizationContext.for_action(
            user_id="alice@example.com",
            resource=ResourceId.for_project("secret-project"),
            action=Action.VIEW,
        )
        result = AuthorizationResult.allowed_result(
            context=context,
            checked_relation=Relation.VIEWER,
        )

        # Call private method with include_pii=True (for debugging)
        audit_entry = result._build_audit_entry(include_pii=True)

        assert audit_entry["user"] == "user:alice@example.com"
        assert audit_entry["resource"] == "project:secret-project"


__all__ = [
    "TestAuthorizationContext",
    "TestAuthorizationResult",
    "TestBatchAuthorizationResult",
    "TestEdgeCases",
    "TestRelationshipTuple",
]
