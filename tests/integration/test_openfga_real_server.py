"""Real-server integration tests for OpenFGA.

Tests that connect to a real OpenFGA server to verify:
- Health check endpoints
- Authorization model retrieval
- Tuple write and read operations

These tests are SKIPPED when no real OpenFGA server is configured.
To run these tests, set environment variables:
- SIOPV_OPENFGA_API_URL
- SIOPV_OPENFGA_STORE_ID
- SIOPV_OPENFGA_API_TOKEN (if using api_token auth)
- SIOPV_OPENFGA_AUTH_METHOD (none, api_token, or client_credentials)

Run with: pytest -m real_openfga tests/integration/test_openfga_real_server.py -v
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator

import pytest

from siopv.adapters.authorization.openfga_adapter import OpenFGAAdapter
from siopv.domain.authorization import Relation, RelationshipTuple, ResourceType, UserId
from siopv.infrastructure.config.settings import Settings

# Auto-skip mechanism when server unavailable
OPENFGA_API_URL = os.getenv("SIOPV_OPENFGA_API_URL")

pytestmark = pytest.mark.skipif(
    not OPENFGA_API_URL,
    reason="SIOPV_OPENFGA_API_URL not set - real OpenFGA server not available",
)


@pytest.fixture
def real_settings() -> Settings:
    """Create Settings instance from environment variables.

    This fixture reads the actual OpenFGA configuration from environment
    variables, allowing integration tests to connect to a real server.

    Returns:
        Settings instance with OpenFGA configuration.

    Raises:
        ValueError: If required environment variables are missing.
    """
    # Verify required environment variables
    if not os.getenv("SIOPV_OPENFGA_API_URL"):
        msg = "SIOPV_OPENFGA_API_URL environment variable is required"
        raise ValueError(msg)

    if not os.getenv("SIOPV_OPENFGA_STORE_ID"):
        msg = "SIOPV_OPENFGA_STORE_ID environment variable is required"
        raise ValueError(msg)

    # Create settings from environment
    # Settings uses pydantic_settings which auto-loads from env vars
    return Settings(
        anthropic_api_key="dummy-key-for-integration-tests",  # Required field
    )


@pytest.fixture
async def real_openfga_adapter(real_settings: Settings) -> AsyncIterator[OpenFGAAdapter]:
    """Create and initialize a real OpenFGA adapter.

    This fixture creates an adapter connected to a real OpenFGA server,
    initializes it, yields it for tests, and cleans up after.

    Args:
        real_settings: Settings fixture with OpenFGA configuration.

    Yields:
        Initialized OpenFGAAdapter instance.
    """
    adapter = OpenFGAAdapter(real_settings)

    try:
        await adapter.initialize()
        yield adapter
    finally:
        await adapter.close()


@pytest.fixture
def test_user() -> UserId:
    """Create a test user ID for integration tests.

    Returns:
        UserId instance for test user.
    """
    return UserId(value="integration-test-user")


@pytest.fixture
def test_tuple(test_user: UserId) -> RelationshipTuple:
    """Create a test relationship tuple.

    Args:
        test_user: User ID fixture.

    Returns:
        RelationshipTuple for integration testing.
    """
    return RelationshipTuple.create(
        user_id=test_user.value,
        relation=Relation.VIEWER,
        resource_type=ResourceType.PROJECT,
        resource_id="integration-test-project",
    )


@pytest.mark.real_openfga
@pytest.mark.asyncio
async def test_health_check(real_openfga_adapter: OpenFGAAdapter) -> None:
    """Verify OpenFGA server responds to health endpoint.

    This test ensures the OpenFGA server is reachable and responding
    to health check requests. A successful health check indicates:
    - Server is running
    - Network connectivity is working
    - Authentication (if configured) is valid

    Args:
        real_openfga_adapter: Initialized adapter fixture.

    Asserts:
        health_check returns True.
    """
    is_healthy = await real_openfga_adapter.health_check()

    assert is_healthy is True, "OpenFGA server health check failed"


@pytest.mark.real_openfga
@pytest.mark.asyncio
async def test_get_model_id(real_openfga_adapter: OpenFGAAdapter) -> None:
    """Verify authorization model can be retrieved.

    This test checks that:
    - The store exists and is accessible
    - At least one authorization model is configured
    - The model ID can be retrieved successfully
    - The model ID is cached after retrieval

    Args:
        real_openfga_adapter: Initialized adapter fixture.

    Asserts:
        - get_model_id returns a non-empty string
        - Model ID is cached in adapter._cached_model_id
    """
    model_id = await real_openfga_adapter.get_model_id()

    assert model_id, "Model ID should not be empty"
    assert isinstance(model_id, str), "Model ID should be a string"
    assert len(model_id) > 0, "Model ID should have non-zero length"

    # Verify model ID was cached
    assert real_openfga_adapter._cached_model_id == model_id, "Model ID should be cached"


@pytest.mark.real_openfga
@pytest.mark.asyncio
async def test_write_and_read_tuple(
    real_openfga_adapter: OpenFGAAdapter,
    test_tuple: RelationshipTuple,
    test_user: UserId,
) -> None:
    """Verify tuples can be written and read.

    This test performs a complete write-read cycle:
    1. Write a test tuple to the store
    2. Read it back using filters
    3. Verify the tuple exists
    4. Clean up by deleting the tuple

    Args:
        real_openfga_adapter: Initialized adapter fixture.
        test_tuple: Test relationship tuple fixture.
        test_user: Test user ID fixture.

    Asserts:
        - Write operation succeeds
        - Tuple can be read back
        - Read tuple matches written tuple
        - Delete operation succeeds
    """
    # Write the test tuple
    try:
        await real_openfga_adapter.write_tuple(test_tuple)

        # Read tuples back with filter
        tuples = await real_openfga_adapter.read_tuples(
            user=test_user,
            relation=Relation.VIEWER,
            resource=test_tuple.resource,
        )

        # Verify tuple exists
        assert len(tuples) > 0, "Should find at least one tuple"

        # Find our specific tuple
        found = False
        for tuple_item in tuples:
            if (
                tuple_item.user == test_user
                and tuple_item.relation == Relation.VIEWER
                and tuple_item.resource == test_tuple.resource
            ):
                found = True
                break

        assert found, "Written tuple should be found in read results"

        # Verify tuple_exists also works
        exists = await real_openfga_adapter.tuple_exists(
            test_user,
            Relation.VIEWER,
            test_tuple.resource,
        )
        assert exists is True, "tuple_exists should return True for written tuple"

    finally:
        # Clean up: delete the test tuple
        try:
            await real_openfga_adapter.delete_tuple(test_tuple)

            # Verify deletion
            exists_after_delete = await real_openfga_adapter.tuple_exists(
                test_user,
                Relation.VIEWER,
                test_tuple.resource,
            )
            assert exists_after_delete is False, "Tuple should not exist after deletion"

        except (ValueError, RuntimeError) as cleanup_error:
            # Log cleanup failure but don't fail the test
            print(f"Warning: Failed to clean up test tuple: {cleanup_error}")
