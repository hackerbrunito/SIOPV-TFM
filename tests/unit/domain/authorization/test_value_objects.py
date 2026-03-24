"""Unit tests for authorization value objects.

Tests the core value objects for OpenFGA authorization:
- UserId: User identifier validation and formatting
- ResourceId: Resource identifier with type validation
- ResourceType: Enum for resource types
- Relation: Enum for authorization relations
- Action: Enum for actions
- ActionPermissionMapping: Action to relation mappings
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from siopv.domain.authorization.value_objects import (
    Action,
    ActionPermissionMapping,
    Relation,
    ResourceId,
    ResourceType,
    UserId,
)

# === Fixtures ===


@pytest.fixture
def sample_user_id() -> str:
    """Sample user identifier."""
    return "81684243-9356-4421-8fbf-a4f8d36aa31b"


@pytest.fixture
def sample_email_user() -> str:
    """Sample email-based user identifier."""
    return "alice@example.com"


# === Test ResourceType Enum ===


class TestResourceType:
    """Tests for ResourceType enum."""

    def test_resource_type_values(self) -> None:
        """Test all resource type enum values."""
        assert ResourceType.PROJECT.value == "project"
        assert ResourceType.VULNERABILITY.value == "vulnerability"
        assert ResourceType.REPORT.value == "report"
        assert ResourceType.ORGANIZATION.value == "organization"

    def test_resource_type_str_conversion(self) -> None:
        """Test string representation of resource types."""
        assert str(ResourceType.PROJECT) == "project"
        assert str(ResourceType.VULNERABILITY) == "vulnerability"

    def test_resource_type_from_string(self) -> None:
        """Test creating resource type from string."""
        rt = ResourceType("project")
        assert rt == ResourceType.PROJECT

    def test_resource_type_invalid_raises_error(self) -> None:
        """Test invalid resource type raises ValueError."""
        with pytest.raises(ValueError, match="invalid_type"):
            ResourceType("invalid_type")


# === Test Relation Enum ===


class TestRelation:
    """Tests for Relation enum."""

    def test_relation_values(self) -> None:
        """Test all relation enum values."""
        assert Relation.OWNER.value == "owner"
        assert Relation.VIEWER.value == "viewer"
        assert Relation.ANALYST.value == "analyst"
        assert Relation.AUDITOR.value == "auditor"
        assert Relation.MEMBER.value == "member"
        assert Relation.ADMIN.value == "admin"

    def test_relation_str_conversion(self) -> None:
        """Test string representation of relations."""
        assert str(Relation.OWNER) == "owner"
        assert str(Relation.VIEWER) == "viewer"

    def test_relation_from_string(self) -> None:
        """Test creating relation from string."""
        rel = Relation("owner")
        assert rel == Relation.OWNER

    def test_relation_invalid_raises_error(self) -> None:
        """Test invalid relation raises ValueError."""
        with pytest.raises(ValueError, match="invalid_relation"):
            Relation("invalid_relation")


# === Test Action Enum ===


class TestAction:
    """Tests for Action enum."""

    def test_action_values(self) -> None:
        """Test all action enum values."""
        assert Action.VIEW.value == "view"
        assert Action.EDIT.value == "edit"
        assert Action.REMEDIATE.value == "remediate"
        assert Action.EXPORT.value == "export"
        assert Action.DELETE.value == "delete"
        assert Action.CLASSIFY.value == "classify"
        assert Action.ESCALATE.value == "escalate"
        assert Action.APPROVE.value == "approve"

    def test_action_str_conversion(self) -> None:
        """Test string representation of actions."""
        assert str(Action.VIEW) == "view"
        assert str(Action.DELETE) == "delete"

    def test_action_from_string(self) -> None:
        """Test creating action from string."""
        action = Action("view")
        assert action == Action.VIEW

    def test_action_invalid_raises_error(self) -> None:
        """Test invalid action raises ValueError."""
        with pytest.raises(ValueError, match="invalid_action"):
            Action("invalid_action")


# === Test UserId Value Object ===


class TestUserId:
    """Tests for UserId value object."""

    def test_create_with_valid_uuid(self, sample_user_id: str) -> None:
        """Test creation with valid UUID."""
        user_id = UserId(value=sample_user_id)
        assert user_id.value == sample_user_id

    def test_create_with_email(self, sample_email_user: str) -> None:
        """Test creation with email identifier."""
        user_id = UserId(value=sample_email_user)
        assert user_id.value == sample_email_user

    def test_create_with_alphanumeric(self) -> None:
        """Test creation with alphanumeric identifier."""
        user_id = UserId(value="user123")
        assert user_id.value == "user123"

    def test_create_with_underscore_dash(self) -> None:
        """Test creation with underscore and dash."""
        user_id = UserId(value="user_name-123")
        assert user_id.value == "user_name-123"

    def test_create_with_dot(self) -> None:
        """Test creation with dots (email-like)."""
        user_id = UserId(value="user.name@domain.com")
        assert user_id.value == "user.name@domain.com"

    def test_invalid_empty_string(self) -> None:
        """Test empty string raises validation error."""
        with pytest.raises(ValidationError) as exc_info:
            UserId(value="")
        assert "at least 1 character" in str(exc_info.value).lower()

    def test_invalid_special_characters(self) -> None:
        """Test invalid special characters raise error."""
        with pytest.raises(ValidationError) as exc_info:
            UserId(value="user#123")
        assert "Invalid user ID format" in str(exc_info.value)

    def test_invalid_spaces(self) -> None:
        """Test spaces raise validation error."""
        with pytest.raises(ValidationError) as exc_info:
            UserId(value="user name")
        assert "Invalid user ID format" in str(exc_info.value)

    def test_max_length_boundary(self) -> None:
        """Test max length boundary (256 characters)."""
        long_id = "a" * 256
        user_id = UserId(value=long_id)
        assert len(user_id.value) == 256

    def test_exceeds_max_length(self) -> None:
        """Test exceeding max length raises error."""
        too_long = "a" * 257
        with pytest.raises(ValidationError):
            UserId(value=too_long)

    def test_from_string_without_prefix(self, sample_user_id: str) -> None:
        """Test from_string with plain identifier."""
        user_id = UserId.from_string(sample_user_id)
        assert user_id.value == sample_user_id

    def test_from_string_with_user_prefix(self, sample_user_id: str) -> None:
        """Test from_string strips 'user:' prefix."""
        user_id = UserId.from_string(f"user:{sample_user_id}")
        assert user_id.value == sample_user_id

    def test_to_openfga_format(self, sample_user_id: str) -> None:
        """Test conversion to OpenFGA format."""
        user_id = UserId(value=sample_user_id)
        assert user_id.to_openfga_format() == f"user:{sample_user_id}"

    def test_str_representation(self, sample_user_id: str) -> None:
        """Test string representation uses OpenFGA format."""
        user_id = UserId(value=sample_user_id)
        assert str(user_id) == f"user:{sample_user_id}"

    def test_user_id_is_frozen(self, sample_user_id: str) -> None:
        """Test UserId is immutable."""
        user_id = UserId(value=sample_user_id)
        with pytest.raises(ValidationError):
            user_id.value = "different_user"  # type: ignore[misc]

    def test_user_id_hashable(self) -> None:
        """Test UserId can be used in sets/dicts."""
        user1 = UserId(value="alice")
        user2 = UserId(value="alice")
        user3 = UserId(value="bob")

        assert hash(user1) == hash(user2)
        assert hash(user1) != hash(user3)

        user_set = {user1, user2, user3}
        assert len(user_set) == 2

    def test_user_id_equality(self) -> None:
        """Test UserId equality comparison."""
        user1 = UserId(value="alice")
        user2 = UserId(value="alice")
        user3 = UserId(value="bob")

        assert user1 == user2
        assert user1 != user3
        assert user1 != "alice"  # Not equal to string


# === Test ResourceId Value Object ===


class TestResourceId:
    """Tests for ResourceId value object."""

    def test_create_with_valid_components(self) -> None:
        """Test creation with valid resource type and identifier."""
        resource = ResourceId(
            resource_type=ResourceType.PROJECT,
            identifier="siopv",
        )
        assert resource.resource_type == ResourceType.PROJECT
        assert resource.identifier == "siopv"

    def test_create_vulnerability_resource(self) -> None:
        """Test creation of vulnerability resource."""
        resource = ResourceId(
            resource_type=ResourceType.VULNERABILITY,
            identifier="CVE-2024-1234",
        )
        assert resource.resource_type == ResourceType.VULNERABILITY
        assert resource.identifier == "CVE-2024-1234"

    def test_identifier_with_colon(self) -> None:
        """Test identifier can contain colons."""
        resource = ResourceId(
            resource_type=ResourceType.VULNERABILITY,
            identifier="CVE-2024-1234:subpart",
        )
        assert resource.identifier == "CVE-2024-1234:subpart"

    def test_identifier_with_alphanumeric_dash_underscore(self) -> None:
        """Test identifier with valid characters."""
        resource = ResourceId(
            resource_type=ResourceType.PROJECT,
            identifier="project_name-123",
        )
        assert resource.identifier == "project_name-123"

    def test_invalid_empty_identifier(self) -> None:
        """Test empty identifier raises error."""
        with pytest.raises(ValidationError) as exc_info:
            ResourceId(
                resource_type=ResourceType.PROJECT,
                identifier="",
            )
        assert "at least 1 character" in str(exc_info.value).lower()

    def test_invalid_identifier_special_chars(self) -> None:
        """Test identifier with invalid special characters."""
        with pytest.raises(ValidationError) as exc_info:
            ResourceId(
                resource_type=ResourceType.PROJECT,
                identifier="project#name",
            )
        assert "Invalid resource identifier" in str(exc_info.value)

    def test_identifier_max_length(self) -> None:
        """Test identifier max length boundary."""
        long_id = "a" * 256
        resource = ResourceId(
            resource_type=ResourceType.PROJECT,
            identifier=long_id,
        )
        assert len(resource.identifier) == 256

    def test_identifier_exceeds_max_length(self) -> None:
        """Test exceeding max length raises error."""
        too_long = "a" * 257
        with pytest.raises(ValidationError):
            ResourceId(
                resource_type=ResourceType.PROJECT,
                identifier=too_long,
            )

    def test_from_string_valid_format(self) -> None:
        """Test from_string with valid format."""
        resource = ResourceId.from_string("project:siopv")
        assert resource.resource_type == ResourceType.PROJECT
        assert resource.identifier == "siopv"

    def test_from_string_with_colon_in_identifier(self) -> None:
        """Test from_string splits only on first colon."""
        resource = ResourceId.from_string("vulnerability:CVE-2024-1234:extra")
        assert resource.resource_type == ResourceType.VULNERABILITY
        assert resource.identifier == "CVE-2024-1234:extra"

    def test_from_string_missing_colon(self) -> None:
        """Test from_string without colon raises error."""
        with pytest.raises(ValueError, match="Expected '<type>:<id>'"):
            ResourceId.from_string("invalid_format")

    def test_from_string_unknown_type(self) -> None:
        """Test from_string with unknown type raises error."""
        with pytest.raises(ValueError, match="Unknown resource type"):
            ResourceId.from_string("unknown_type:identifier")

    def test_for_project_factory(self) -> None:
        """Test for_project factory method."""
        resource = ResourceId.for_project("my-project")
        assert resource.resource_type == ResourceType.PROJECT
        assert resource.identifier == "my-project"

    def test_for_vulnerability_factory(self) -> None:
        """Test for_vulnerability factory method."""
        resource = ResourceId.for_vulnerability("CVE-2024-5678")
        assert resource.resource_type == ResourceType.VULNERABILITY
        assert resource.identifier == "CVE-2024-5678"

    def test_for_report_factory(self) -> None:
        """Test for_report factory method."""
        resource = ResourceId.for_report("report-123")
        assert resource.resource_type == ResourceType.REPORT
        assert resource.identifier == "report-123"

    def test_to_openfga_format(self) -> None:
        """Test conversion to OpenFGA format."""
        resource = ResourceId(
            resource_type=ResourceType.PROJECT,
            identifier="siopv",
        )
        assert resource.to_openfga_format() == "project:siopv"

    def test_str_representation(self) -> None:
        """Test string representation uses OpenFGA format."""
        resource = ResourceId.for_vulnerability("CVE-2024-1234")
        assert str(resource) == "vulnerability:CVE-2024-1234"

    def test_resource_id_is_frozen(self) -> None:
        """Test ResourceId is immutable."""
        resource = ResourceId.for_project("siopv")
        with pytest.raises(ValidationError):
            resource.identifier = "different"  # type: ignore[misc]

    def test_resource_id_hashable(self) -> None:
        """Test ResourceId can be used in sets/dicts."""
        res1 = ResourceId.for_project("siopv")
        res2 = ResourceId.for_project("siopv")
        res3 = ResourceId.for_project("other")

        assert hash(res1) == hash(res2)
        assert hash(res1) != hash(res3)

        res_set = {res1, res2, res3}
        assert len(res_set) == 2

    def test_resource_id_equality(self) -> None:
        """Test ResourceId equality comparison."""
        res1 = ResourceId.for_project("siopv")
        res2 = ResourceId.for_project("siopv")
        res3 = ResourceId.for_vulnerability("CVE-2024-1234")

        assert res1 == res2
        assert res1 != res3
        assert res1 != "project:siopv"  # Not equal to string

    def test_different_types_same_identifier_not_equal(self) -> None:
        """Test same identifier but different types are not equal."""
        res1 = ResourceId(resource_type=ResourceType.PROJECT, identifier="test")
        res2 = ResourceId(resource_type=ResourceType.REPORT, identifier="test")
        assert res1 != res2


# === Test ActionPermissionMapping ===


class TestActionPermissionMapping:
    """Tests for ActionPermissionMapping value object."""

    def test_create_mapping(self) -> None:
        """Test creating an action permission mapping."""
        mapping = ActionPermissionMapping(
            action=Action.VIEW,
            required_relations=frozenset({Relation.VIEWER, Relation.OWNER}),
        )
        assert mapping.action == Action.VIEW
        assert Relation.VIEWER in mapping.required_relations
        assert Relation.OWNER in mapping.required_relations

    def test_mapping_is_frozen(self) -> None:
        """Test ActionPermissionMapping is immutable."""
        mapping = ActionPermissionMapping(
            action=Action.VIEW,
            required_relations=frozenset({Relation.VIEWER}),
        )
        with pytest.raises(ValidationError):
            mapping.action = Action.EDIT  # type: ignore[misc]

    def test_default_mappings_exist(self) -> None:
        """Test default mappings are available."""
        mappings = ActionPermissionMapping.default_mappings()
        assert len(mappings) == 8
        assert Action.VIEW in mappings
        assert Action.EDIT in mappings
        assert Action.DELETE in mappings

    def test_default_view_mapping(self) -> None:
        """Test VIEW action has correct default relations."""
        mappings = ActionPermissionMapping.default_mappings()
        view_mapping = mappings[Action.VIEW]

        assert view_mapping.action == Action.VIEW
        assert Relation.VIEWER in view_mapping.required_relations
        assert Relation.ANALYST in view_mapping.required_relations
        assert Relation.AUDITOR in view_mapping.required_relations
        assert Relation.OWNER in view_mapping.required_relations
        assert Relation.ADMIN in view_mapping.required_relations

    def test_default_edit_mapping(self) -> None:
        """Test EDIT action has correct default relations."""
        mappings = ActionPermissionMapping.default_mappings()
        edit_mapping = mappings[Action.EDIT]

        assert edit_mapping.action == Action.EDIT
        assert Relation.ANALYST in edit_mapping.required_relations
        assert Relation.OWNER in edit_mapping.required_relations
        assert Relation.ADMIN in edit_mapping.required_relations
        assert Relation.VIEWER not in edit_mapping.required_relations

    def test_default_remediate_mapping(self) -> None:
        """Test REMEDIATE action has correct default relations."""
        mappings = ActionPermissionMapping.default_mappings()
        remediate_mapping = mappings[Action.REMEDIATE]

        assert remediate_mapping.action == Action.REMEDIATE
        assert Relation.ANALYST in remediate_mapping.required_relations
        assert Relation.OWNER in remediate_mapping.required_relations
        assert len(remediate_mapping.required_relations) == 2

    def test_default_export_mapping(self) -> None:
        """Test EXPORT action has correct default relations."""
        mappings = ActionPermissionMapping.default_mappings()
        export_mapping = mappings[Action.EXPORT]

        assert export_mapping.action == Action.EXPORT
        assert Relation.AUDITOR in export_mapping.required_relations
        assert Relation.OWNER in export_mapping.required_relations
        assert Relation.ADMIN in export_mapping.required_relations

    def test_default_delete_mapping_owner_only(self) -> None:
        """Test DELETE action requires only OWNER relation."""
        mappings = ActionPermissionMapping.default_mappings()
        delete_mapping = mappings[Action.DELETE]

        assert delete_mapping.action == Action.DELETE
        assert Relation.OWNER in delete_mapping.required_relations
        assert len(delete_mapping.required_relations) == 1

    def test_default_classify_mapping(self) -> None:
        """Test CLASSIFY action has correct default relations."""
        mappings = ActionPermissionMapping.default_mappings()
        classify_mapping = mappings[Action.CLASSIFY]

        assert classify_mapping.action == Action.CLASSIFY
        assert Relation.ANALYST in classify_mapping.required_relations
        assert Relation.OWNER in classify_mapping.required_relations

    def test_default_escalate_mapping(self) -> None:
        """Test ESCALATE action has correct default relations."""
        mappings = ActionPermissionMapping.default_mappings()
        escalate_mapping = mappings[Action.ESCALATE]

        assert escalate_mapping.action == Action.ESCALATE
        assert Relation.ANALYST in escalate_mapping.required_relations
        assert Relation.OWNER in escalate_mapping.required_relations

    def test_default_approve_mapping(self) -> None:
        """Test APPROVE action has correct default relations."""
        mappings = ActionPermissionMapping.default_mappings()
        approve_mapping = mappings[Action.APPROVE]

        assert approve_mapping.action == Action.APPROVE
        assert Relation.OWNER in approve_mapping.required_relations
        assert Relation.ADMIN in approve_mapping.required_relations

    def test_required_relations_immutable(self) -> None:
        """Test required_relations frozenset is immutable."""
        mapping = ActionPermissionMapping(
            action=Action.VIEW,
            required_relations=frozenset({Relation.VIEWER}),
        )
        # frozenset doesn't have add method
        with pytest.raises(AttributeError):
            mapping.required_relations.add(Relation.OWNER)  # type: ignore[attr-defined]

    def test_custom_mapping_creation(self) -> None:
        """Test creating custom permission mappings."""
        custom_mapping = ActionPermissionMapping(
            action=Action.APPROVE,
            required_relations=frozenset({Relation.ADMIN}),
        )
        assert custom_mapping.action == Action.APPROVE
        assert len(custom_mapping.required_relations) == 1
        assert Relation.ADMIN in custom_mapping.required_relations


# === Test Edge Cases ===


class TestEdgeCases:
    """Tests for edge cases and boundary conditions."""

    def test_user_id_with_at_symbol(self) -> None:
        """Test UserId with @ symbol (email)."""
        user_id = UserId(value="user@example.com")
        assert "@" in user_id.value

    def test_resource_id_cve_with_long_number(self) -> None:
        """Test ResourceId with long CVE number."""
        resource = ResourceId.for_vulnerability("CVE-2024-123456789")
        assert resource.identifier == "CVE-2024-123456789"

    def test_multiple_colons_in_from_string(self) -> None:
        """Test from_string handles multiple colons correctly."""
        resource = ResourceId.from_string("project:namespace:project:identifier")
        assert resource.resource_type == ResourceType.PROJECT
        assert resource.identifier == "namespace:project:identifier"

    def test_user_id_single_character(self) -> None:
        """Test UserId with single character."""
        user_id = UserId(value="a")
        assert user_id.value == "a"

    def test_resource_id_single_character(self) -> None:
        """Test ResourceId with single character identifier."""
        resource = ResourceId.for_project("x")
        assert resource.identifier == "x"


__all__ = [
    "TestAction",
    "TestActionPermissionMapping",
    "TestEdgeCases",
    "TestRelation",
    "TestResourceId",
    "TestResourceType",
    "TestUserId",
]
