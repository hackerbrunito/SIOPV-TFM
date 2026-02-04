"""Unit tests for authorization exceptions.

Tests the authorization-specific exceptions:
- InvalidRelationError
- InvalidResourceFormatError
- InvalidUserFormatError
- TupleValidationError
- AuthorizationCheckError
- AuthorizationModelError
- StoreNotFoundError
- ActionNotMappedError
"""

from __future__ import annotations

import pytest

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
    Relation,
    ResourceId,
    ResourceType,
    UserId,
)
from siopv.domain.exceptions import AuthorizationError

# === Test InvalidRelationError ===


class TestInvalidRelationError:
    """Tests for InvalidRelationError exception."""

    def test_create_with_basic_info(self) -> None:
        """Test creating error with relation and resource type."""
        error = InvalidRelationError(
            relation=Relation.ANALYST,
            resource_type=ResourceType.ORGANIZATION,
        )

        assert error.relation == Relation.ANALYST
        assert error.resource_type == ResourceType.ORGANIZATION
        # Security: Error message should NOT include relation/resource details
        assert "Invalid relation" in str(error)

    def test_create_with_allowed_relations(self) -> None:
        """Test error includes allowed relations in message."""
        error = InvalidRelationError(
            relation=Relation.ANALYST,
            resource_type=ResourceType.ORGANIZATION,
            allowed_relations=[Relation.MEMBER, Relation.ADMIN],
        )

        assert len(error.allowed_relations) == 2
        error_msg = str(error)
        assert "member" in error_msg.lower()
        assert "admin" in error_msg.lower()

    def test_create_with_details(self) -> None:
        """Test error with additional details."""
        details = {"context": "model_validation", "model_id": "01HZXY"}
        error = InvalidRelationError(
            relation=Relation.VIEWER,
            resource_type=ResourceType.VULNERABILITY,
            details=details,
        )

        assert error.details == details

    def test_is_authorization_error(self) -> None:
        """Test InvalidRelationError inherits from AuthorizationError."""
        error = InvalidRelationError(
            relation=Relation.OWNER,
            resource_type=ResourceType.PROJECT,
        )

        assert isinstance(error, AuthorizationError)

    def test_error_message_format(self) -> None:
        """Test error message follows expected format."""
        error = InvalidRelationError(
            relation=Relation.AUDITOR,
            resource_type=ResourceType.VULNERABILITY,
            allowed_relations=[Relation.VIEWER, Relation.ANALYST],
        )

        msg = str(error)
        # Security: Error message should include allowed relations but NOT input details
        assert "Invalid relation" in msg
        assert "viewer" in msg  # Allowed relations are shown
        assert "analyst" in msg


# === Test InvalidResourceFormatError ===


class TestInvalidResourceFormatError:
    """Tests for InvalidResourceFormatError exception."""

    def test_create_with_resource_string(self) -> None:
        """Test creating error with invalid resource string."""
        error = InvalidResourceFormatError(resource_string="invalid_format")

        assert error.resource_string == "invalid_format"
        # Security: Error message should NOT include user input
        assert "Invalid resource format" in str(error)

    def test_create_with_reason(self) -> None:
        """Test error with specific reason."""
        error = InvalidResourceFormatError(
            resource_string="missing:colon",
            reason="Missing type separator",
        )

        assert error.reason == "Missing type separator"
        assert "Missing type separator" in str(error)

    def test_create_with_details(self) -> None:
        """Test error with additional details."""
        details = {"attempted_parse": True, "position": 10}
        error = InvalidResourceFormatError(
            resource_string="project",
            details=details,
        )

        assert error.details == details

    def test_is_authorization_error(self) -> None:
        """Test InvalidResourceFormatError inherits from AuthorizationError."""
        error = InvalidResourceFormatError(resource_string="bad_format")

        assert isinstance(error, AuthorizationError)

    def test_error_message_without_reason(self) -> None:
        """Test error message when no reason provided."""
        error = InvalidResourceFormatError(resource_string="test")

        msg = str(error)
        assert "Invalid resource format" in msg
        # Security: Error message should NOT include user input


# === Test InvalidUserFormatError ===


class TestInvalidUserFormatError:
    """Tests for InvalidUserFormatError exception."""

    def test_create_with_user_string(self) -> None:
        """Test creating error with invalid user string."""
        error = InvalidUserFormatError(user_string="user#invalid")

        assert error.user_string == "user#invalid"
        # Security: Error message should NOT include user input
        assert "Invalid user format" in str(error)

    def test_create_with_reason(self) -> None:
        """Test error with specific reason."""
        error = InvalidUserFormatError(
            user_string="user name",
            reason="Spaces not allowed",
        )

        assert error.reason == "Spaces not allowed"
        assert "Spaces not allowed" in str(error)

    def test_create_with_details(self) -> None:
        """Test error with additional details."""
        details = {"pattern": r"^[a-zA-Z0-9_@.\-]+$"}
        error = InvalidUserFormatError(
            user_string="user!invalid",
            details=details,
        )

        assert error.details == details

    def test_is_authorization_error(self) -> None:
        """Test InvalidUserFormatError inherits from AuthorizationError."""
        error = InvalidUserFormatError(user_string="bad")

        assert isinstance(error, AuthorizationError)

    def test_error_message_without_reason(self) -> None:
        """Test error message when no reason provided."""
        error = InvalidUserFormatError(user_string="user@@@")

        msg = str(error)
        assert "Invalid user format" in msg
        # Security: Error message should NOT include user input


# === Test TupleValidationError ===


class TestTupleValidationError:
    """Tests for TupleValidationError exception."""

    def test_create_with_tuple_components(self) -> None:
        """Test creating error with tuple components."""
        error = TupleValidationError(
            user="user:alice",
            relation="invalid_relation",
            resource="project:test",
            reason="Unknown relation type",
        )

        assert error.user == "user:alice"
        assert error.relation == "invalid_relation"
        assert error.resource == "project:test"
        assert error.reason == "Unknown relation type"

    def test_error_message_format(self) -> None:
        """Test error message includes reason but not tuple components."""
        error = TupleValidationError(
            user="user:bob",
            relation="owner",
            resource="vulnerability:CVE-2024-1234",
            reason="Invalid resource type for relation",
        )

        msg = str(error)
        # Security: Error message should include reason but NOT user/relation/resource
        assert "Invalid tuple" in msg
        assert "Invalid resource type for relation" in msg

    def test_create_with_details(self) -> None:
        """Test error with additional details."""
        details = {"validation_step": "relation_check"}
        error = TupleValidationError(
            user="user:charlie",
            relation="viewer",
            resource="report:123",
            reason="Test reason",
            details=details,
        )

        assert error.details == details

    def test_is_authorization_error(self) -> None:
        """Test TupleValidationError inherits from AuthorizationError."""
        error = TupleValidationError(
            user="user:test",
            relation="test",
            resource="test:test",
            reason="test",
        )

        assert isinstance(error, AuthorizationError)


# === Test AuthorizationCheckError ===


class TestAuthorizationCheckError:
    """Tests for AuthorizationCheckError exception."""

    def test_create_with_string_components(self) -> None:
        """Test creating error with string components."""
        error = AuthorizationCheckError(
            user="user:alice",
            action="view",
            resource="project:siopv",
            reason="OpenFGA unavailable",
        )

        assert error.user_str == "user:alice"
        assert error.action_str == "view"
        assert error.resource_str == "project:siopv"
        assert error.reason == "OpenFGA unavailable"

    def test_create_with_value_objects(self) -> None:
        """Test creating error with value objects."""
        user = UserId(value="bob")
        resource = ResourceId.for_project("test")
        error = AuthorizationCheckError(
            user=user,
            action=Action.EDIT,
            resource=resource,
            reason="Connection timeout",
        )

        assert "bob" in error.user_str
        assert "edit" in error.action_str.lower()
        assert "test" in error.resource_str

    def test_create_with_underlying_error(self) -> None:
        """Test error with underlying exception."""
        underlying = ConnectionError("Failed to connect to OpenFGA")
        error = AuthorizationCheckError(
            user="user:alice",
            action="view",
            resource="project:test",
            reason="Service unavailable",
            underlying_error=underlying,
        )

        assert error.underlying_error == underlying
        assert "ConnectionError" in str(error)

    def test_create_with_details(self) -> None:
        """Test error with additional details."""
        details = {"endpoint": "https://openfga:8080", "attempt": 3}
        error = AuthorizationCheckError(
            user="user:alice",
            action="view",
            resource="project:test",
            reason="Max retries exceeded",
            details=details,
        )

        assert error.details == details

    def test_error_message_format(self) -> None:
        """Test error message format."""
        error = AuthorizationCheckError(
            user="user:dave",
            action="delete",
            resource="vulnerability:CVE-2024-5678",
            reason="Network error",
        )

        msg = str(error)
        # Security: Error message should include reason but NOT user/action/resource identifiers
        assert "Authorization check failed" in msg
        assert "Network error" in msg

    def test_is_authorization_error(self) -> None:
        """Test AuthorizationCheckError inherits from AuthorizationError."""
        error = AuthorizationCheckError(
            user="test",
            action="test",
            resource="test",
            reason="test",
        )

        assert isinstance(error, AuthorizationError)


# === Test AuthorizationModelError ===


class TestAuthorizationModelError:
    """Tests for AuthorizationModelError exception."""

    def test_create_with_model_id(self) -> None:
        """Test creating error with model ID."""
        error = AuthorizationModelError(
            model_id="01HZXY12ABC34DEF56GH",
            reason="Model not found",
        )

        assert error.model_id == "01HZXY12ABC34DEF56GH"
        assert error.reason == "Model not found"
        assert "01HZXY12ABC34DEF56GH" in str(error)

    def test_create_without_model_id(self) -> None:
        """Test creating error without model ID."""
        error = AuthorizationModelError(
            model_id=None,
            reason="No model configured",
        )

        assert error.model_id is None
        msg = str(error)
        assert "Authorization model error" in msg
        assert "No model configured" in msg

    def test_create_with_details(self) -> None:
        """Test error with additional details."""
        details = {"store_id": "store123", "attempted_load": True}
        error = AuthorizationModelError(
            model_id="01HZXY",
            reason="Schema validation failed",
            details=details,
        )

        assert error.details == details

    def test_is_authorization_error(self) -> None:
        """Test AuthorizationModelError inherits from AuthorizationError."""
        error = AuthorizationModelError(
            model_id="test",
            reason="test",
        )

        assert isinstance(error, AuthorizationError)

    def test_error_message_with_model_id(self) -> None:
        """Test error message includes model ID when provided."""
        error = AuthorizationModelError(
            model_id="model-abc-123",
            reason="Version mismatch",
        )

        msg = str(error)
        assert "model-abc-123" in msg
        assert "Version mismatch" in msg


# === Test StoreNotFoundError ===


class TestStoreNotFoundError:
    """Tests for StoreNotFoundError exception."""

    def test_create_with_store_id(self) -> None:
        """Test creating error with store ID."""
        error = StoreNotFoundError(store_id="store_123")

        assert error.store_id == "store_123"
        assert "store_123" in str(error)

    def test_create_without_store_id(self) -> None:
        """Test creating error without store ID."""
        error = StoreNotFoundError()

        assert error.store_id is None
        msg = str(error)
        assert "not configured" in msg.lower()

    def test_create_with_details(self) -> None:
        """Test error with additional details."""
        details = {"config_path": "/etc/openfga/config.yaml"}
        error = StoreNotFoundError(store_id="test_store", details=details)

        assert error.details == details

    def test_is_authorization_error(self) -> None:
        """Test StoreNotFoundError inherits from AuthorizationError."""
        error = StoreNotFoundError(store_id="test")

        assert isinstance(error, AuthorizationError)

    def test_error_message_with_store_id(self) -> None:
        """Test error message when store ID provided."""
        error = StoreNotFoundError(store_id="my_store")

        msg = str(error)
        assert "not found" in msg.lower()
        assert "my_store" in msg

    def test_error_message_without_store_id(self) -> None:
        """Test error message when no store ID provided."""
        error = StoreNotFoundError()

        msg = str(error)
        assert "not configured" in msg.lower()


# === Test ActionNotMappedError ===


class TestActionNotMappedError:
    """Tests for ActionNotMappedError exception."""

    def test_create_with_action(self) -> None:
        """Test creating error with action."""
        error = ActionNotMappedError(action=Action.CLASSIFY)

        assert error.action == Action.CLASSIFY
        assert "classify" in str(error).lower()

    def test_error_message_format(self) -> None:
        """Test error message format."""
        error = ActionNotMappedError(action=Action.ESCALATE)

        msg = str(error)
        assert "no relation mapping" in msg.lower()
        assert "escalate" in msg

    def test_create_with_details(self) -> None:
        """Test error with additional details."""
        details = {"available_actions": ["view", "edit", "delete"]}
        error = ActionNotMappedError(action=Action.APPROVE, details=details)

        assert error.details == details

    def test_is_authorization_error(self) -> None:
        """Test ActionNotMappedError inherits from AuthorizationError."""
        error = ActionNotMappedError(action=Action.VIEW)

        assert isinstance(error, AuthorizationError)

    def test_all_actions_can_be_used(self) -> None:
        """Test error can be created for any action."""
        actions = [
            Action.VIEW,
            Action.EDIT,
            Action.DELETE,
            Action.REMEDIATE,
            Action.EXPORT,
            Action.CLASSIFY,
            Action.ESCALATE,
            Action.APPROVE,
        ]

        for action in actions:
            error = ActionNotMappedError(action=action)
            assert error.action == action
            assert action.value in str(error)


# === Test Exception Hierarchy ===


class TestExceptionHierarchy:
    """Tests for exception hierarchy and inheritance."""

    def test_all_inherit_from_authorization_error(self) -> None:
        """Test all authorization exceptions inherit from AuthorizationError."""
        exceptions = [
            InvalidRelationError(Relation.OWNER, ResourceType.PROJECT),
            InvalidResourceFormatError("test"),
            InvalidUserFormatError("test"),
            TupleValidationError("u", "r", "o", "reason"),
            AuthorizationCheckError("u", "a", "r", "reason"),
            AuthorizationModelError("model", "reason"),
            StoreNotFoundError("store"),
            ActionNotMappedError(Action.VIEW),
        ]

        for exc in exceptions:
            assert isinstance(exc, AuthorizationError)

    def test_exceptions_are_catchable_as_authorization_error(self) -> None:
        """Test exceptions can be caught as AuthorizationError."""
        with pytest.raises(InvalidRelationError) as exc_info:
            raise InvalidRelationError(Relation.OWNER, ResourceType.PROJECT)
        assert isinstance(exc_info.value, AuthorizationError)

    def test_exceptions_are_catchable_as_exception(self) -> None:
        """Test exceptions can be caught as base Exception."""
        with pytest.raises(StoreNotFoundError) as exc_info:
            raise StoreNotFoundError("test")
        assert isinstance(exc_info.value, Exception)


# === Test Edge Cases ===


class TestEdgeCases:
    """Tests for edge cases and boundary conditions."""

    def test_empty_details_dict(self) -> None:
        """Test exceptions with empty details dictionary."""
        error = InvalidRelationError(
            relation=Relation.VIEWER,
            resource_type=ResourceType.PROJECT,
            details={},
        )

        assert error.details == {}

    def test_none_details(self) -> None:
        """Test exceptions with None details."""
        error = InvalidUserFormatError(user_string="test", details=None)

        # Should default to None or empty dict based on base class
        assert error.details is None or error.details == {}

    def test_very_long_error_messages(self) -> None:
        """Test error messages with very long strings."""
        long_string = "a" * 1000
        error = InvalidResourceFormatError(resource_string=long_string)

        msg = str(error)
        assert len(msg) > 0
        assert "Invalid resource format" in msg

    def test_special_characters_in_error_messages(self) -> None:
        """Test error messages handle special characters."""
        error = InvalidUserFormatError(
            user_string="user\"with'quotes<>&",
            reason="Special chars not allowed: <>\"'&",
        )

        msg = str(error)
        assert len(msg) > 0

    def test_error_with_nested_details(self) -> None:
        """Test error with nested details dictionary."""
        details = {
            "level1": {
                "level2": {"level3": "value"},
                "other": [1, 2, 3],
            }
        }
        error = AuthorizationModelError(
            model_id="test",
            reason="Complex details",
            details=details,
        )

        assert error.details == details

    def test_underlying_error_chain(self) -> None:
        """Test underlying error can be another exception."""
        original = ValueError("Original error")
        wrapped = ConnectionError("Wrapped error")
        wrapped.__cause__ = original

        error = AuthorizationCheckError(
            user="test",
            action="test",
            resource="test",
            reason="Multiple failures",
            underlying_error=wrapped,
        )

        assert error.underlying_error == wrapped
        assert error.underlying_error.__cause__ == original


__all__ = [
    "TestActionNotMappedError",
    "TestAuthorizationCheckError",
    "TestAuthorizationModelError",
    "TestEdgeCases",
    "TestExceptionHierarchy",
    "TestInvalidRelationError",
    "TestInvalidResourceFormatError",
    "TestInvalidUserFormatError",
    "TestStoreNotFoundError",
    "TestTupleValidationError",
]
