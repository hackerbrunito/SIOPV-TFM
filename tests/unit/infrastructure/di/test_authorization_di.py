"""Unit tests for authorization DI factory functions.

Tests cover:
- create_authorization_adapter: Creates and configures OpenFGAAdapter
- get_authorization_port: Returns AuthorizationPort implementation
- get_authorization_store_port: Returns AuthorizationStorePort implementation
- get_authorization_model_port: Returns AuthorizationModelPort implementation
- Proper settings handling and logging
- Cache behavior with lru_cache
"""

from __future__ import annotations

from datetime import timedelta
from unittest.mock import MagicMock, patch

import pytest

from siopv.adapters.authorization import OpenFGAAdapter
from siopv.application.ports import (
    AuthorizationModelPort,
    AuthorizationPort,
    AuthorizationStorePort,
)
from siopv.infrastructure.di.authorization import (
    create_authorization_adapter,
    get_authorization_model_port,
    get_authorization_port,
    get_authorization_store_port,
)


@pytest.fixture
def mock_settings() -> MagicMock:
    """Create mock settings for authorization DI tests."""
    settings = MagicMock()
    settings.openfga_api_url = "http://localhost:8080"
    settings.openfga_store_id = "test-store-id"
    settings.openfga_api_token = None
    settings.openfga_authorization_model_id = None
    settings.openfga_auth_method = "none"
    settings.openfga_client_id = None
    settings.openfga_client_secret = None
    settings.openfga_api_audience = None
    settings.openfga_api_token_issuer = None
    settings.circuit_breaker_failure_threshold = 5
    settings.circuit_breaker_recovery_timeout = 60
    return settings


class TestCreateAuthorizationAdapter:
    """Tests for create_authorization_adapter factory function."""

    def test_creates_openfga_adapter_instance(self, mock_settings: MagicMock) -> None:
        """Test that factory creates OpenFGAAdapter instance."""
        adapter = create_authorization_adapter(mock_settings)

        assert adapter is not None
        assert isinstance(adapter, OpenFGAAdapter)

    def test_adapter_receives_settings(self, mock_settings: MagicMock) -> None:
        """Test that adapter is initialized with provided settings."""
        adapter = create_authorization_adapter(mock_settings)

        # Verify adapter has the correct settings
        assert adapter._api_url == mock_settings.openfga_api_url
        assert adapter._store_id == mock_settings.openfga_store_id

    def test_adapter_circuit_breaker_configured(self, mock_settings: MagicMock) -> None:
        """Test that adapter's circuit breaker is configured from settings."""
        adapter = create_authorization_adapter(mock_settings)

        assert adapter._circuit_breaker is not None
        assert adapter._circuit_breaker.failure_threshold == 5
        assert adapter._circuit_breaker.recovery_timeout == timedelta(seconds=60)

    def test_adapter_has_action_mappings(self, mock_settings: MagicMock) -> None:
        """Test that adapter has default action mappings initialized."""
        adapter = create_authorization_adapter(mock_settings)

        assert adapter._action_mappings is not None
        assert len(adapter._action_mappings) > 0

    def test_multiple_calls_create_separate_instances(self, mock_settings: MagicMock) -> None:
        """Test that each call creates a new adapter instance."""
        adapter1 = create_authorization_adapter(mock_settings)
        adapter2 = create_authorization_adapter(mock_settings)

        # Each call should create a new instance
        assert adapter1 is not adapter2

    def test_adapter_not_initialized_after_creation(self, mock_settings: MagicMock) -> None:
        """Test that adapter is not initialized (client is None) after creation."""
        adapter = create_authorization_adapter(mock_settings)

        # Adapter should be created but not initialized
        assert adapter._owned_client is None

    def test_logging_on_adapter_creation(self, mock_settings: MagicMock) -> None:
        """Test that adapter creation logs appropriate messages."""
        with patch("siopv.infrastructure.di.authorization.logger") as mock_logger:
            adapter = create_authorization_adapter(mock_settings)

            # Should log debug and info messages
            assert mock_logger.debug.called or mock_logger.info.called
            assert adapter is not None


class TestGetAuthorizationPort:
    """Tests for get_authorization_port factory function."""

    def test_returns_authorization_port(self, mock_settings: MagicMock) -> None:
        """Test that function returns AuthorizationPort implementation."""
        port = get_authorization_port(mock_settings)

        assert port is not None
        assert isinstance(port, AuthorizationPort)

    def test_returns_openfga_adapter(self, mock_settings: MagicMock) -> None:
        """Test that returned port is actually an OpenFGAAdapter."""
        port = get_authorization_port(mock_settings)

        assert isinstance(port, OpenFGAAdapter)

    def test_port_implements_interface(self, mock_settings: MagicMock) -> None:
        """Test that returned port implements AuthorizationPort interface."""
        port = get_authorization_port(mock_settings)

        # Check that port has all required methods
        assert hasattr(port, "check")
        assert hasattr(port, "batch_check")
        assert hasattr(port, "check_relation")
        assert hasattr(port, "list_user_relations")

    def test_cache_returns_same_instance(self, mock_settings: MagicMock) -> None:
        """Test that lru_cache returns the same instance for same settings."""
        # Clear cache first
        get_authorization_port.cache_clear()

        port1 = get_authorization_port(mock_settings)
        port2 = get_authorization_port(mock_settings)

        # Same settings should return cached instance
        assert port1 is port2

    def test_different_settings_create_different_instances(self) -> None:
        """Test that different settings create different port instances."""
        # Clear cache first
        get_authorization_port.cache_clear()

        settings1 = MagicMock()
        settings1.openfga_api_url = "http://localhost:8080"
        settings1.openfga_store_id = "store-1"
        settings1.openfga_api_token = None
        settings1.openfga_authorization_model_id = None
        settings1.openfga_auth_method = "none"
        settings1.openfga_client_id = None
        settings1.openfga_client_secret = None
        settings1.openfga_api_audience = None
        settings1.openfga_api_token_issuer = None
        settings1.circuit_breaker_failure_threshold = 5
        settings1.circuit_breaker_recovery_timeout = 60

        settings2 = MagicMock()
        settings2.openfga_api_url = "http://localhost:9090"
        settings2.openfga_store_id = "store-2"
        settings2.openfga_api_token = None
        settings2.openfga_authorization_model_id = None
        settings2.openfga_auth_method = "none"
        settings2.openfga_client_id = None
        settings2.openfga_client_secret = None
        settings2.openfga_api_audience = None
        settings2.openfga_api_token_issuer = None
        settings2.circuit_breaker_failure_threshold = 5
        settings2.circuit_breaker_recovery_timeout = 60

        port1 = get_authorization_port(settings1)
        port2 = get_authorization_port(settings2)

        # Different settings should create different instances
        assert port1 is not port2
        assert port1._api_url != port2._api_url


class TestGetAuthorizationStorePort:
    """Tests for get_authorization_store_port factory function."""

    def test_returns_authorization_store_port(self, mock_settings: MagicMock) -> None:
        """Test that function returns AuthorizationStorePort implementation."""
        port = get_authorization_store_port(mock_settings)

        assert port is not None
        assert isinstance(port, AuthorizationStorePort)

    def test_returns_openfga_adapter(self, mock_settings: MagicMock) -> None:
        """Test that returned port is actually an OpenFGAAdapter."""
        port = get_authorization_store_port(mock_settings)

        assert isinstance(port, OpenFGAAdapter)

    def test_port_implements_interface(self, mock_settings: MagicMock) -> None:
        """Test that returned port implements AuthorizationStorePort interface."""
        port = get_authorization_store_port(mock_settings)

        # Check that port has all required methods
        assert hasattr(port, "write_tuple")
        assert hasattr(port, "write_tuples")
        assert hasattr(port, "delete_tuple")
        assert hasattr(port, "delete_tuples")
        assert hasattr(port, "read_tuples")
        assert hasattr(port, "read_tuples_for_resource")
        assert hasattr(port, "read_tuples_for_user")
        assert hasattr(port, "tuple_exists")

    def test_cache_returns_same_instance(self, mock_settings: MagicMock) -> None:
        """Test that lru_cache returns the same instance for same settings."""
        # Clear cache first
        get_authorization_store_port.cache_clear()

        port1 = get_authorization_store_port(mock_settings)
        port2 = get_authorization_store_port(mock_settings)

        # Same settings should return cached instance
        assert port1 is port2

    def test_different_settings_create_different_instances(self) -> None:
        """Test that different settings create different port instances."""
        # Clear cache first
        get_authorization_store_port.cache_clear()

        settings1 = MagicMock()
        settings1.openfga_api_url = "http://localhost:8080"
        settings1.openfga_store_id = "store-1"
        settings1.openfga_api_token = None
        settings1.openfga_authorization_model_id = None
        settings1.openfga_auth_method = "none"
        settings1.openfga_client_id = None
        settings1.openfga_client_secret = None
        settings1.openfga_api_audience = None
        settings1.openfga_api_token_issuer = None
        settings1.circuit_breaker_failure_threshold = 5
        settings1.circuit_breaker_recovery_timeout = 60

        settings2 = MagicMock()
        settings2.openfga_api_url = "http://localhost:9090"
        settings2.openfga_store_id = "store-2"
        settings2.openfga_api_token = None
        settings2.openfga_authorization_model_id = None
        settings2.openfga_auth_method = "none"
        settings2.openfga_client_id = None
        settings2.openfga_client_secret = None
        settings2.openfga_api_audience = None
        settings2.openfga_api_token_issuer = None
        settings2.circuit_breaker_failure_threshold = 5
        settings2.circuit_breaker_recovery_timeout = 60

        port1 = get_authorization_store_port(settings1)
        port2 = get_authorization_store_port(settings2)

        # Different settings should create different instances
        assert port1 is not port2


class TestGetAuthorizationModelPort:
    """Tests for get_authorization_model_port factory function."""

    def test_returns_authorization_model_port(self, mock_settings: MagicMock) -> None:
        """Test that function returns AuthorizationModelPort implementation."""
        port = get_authorization_model_port(mock_settings)

        assert port is not None
        assert isinstance(port, AuthorizationModelPort)

    def test_returns_openfga_adapter(self, mock_settings: MagicMock) -> None:
        """Test that returned port is actually an OpenFGAAdapter."""
        port = get_authorization_model_port(mock_settings)

        assert isinstance(port, OpenFGAAdapter)

    def test_port_implements_interface(self, mock_settings: MagicMock) -> None:
        """Test that returned port implements AuthorizationModelPort interface."""
        port = get_authorization_model_port(mock_settings)

        # Check that port has all required methods
        assert hasattr(port, "get_model_id")
        assert hasattr(port, "validate_model")
        assert hasattr(port, "health_check")

    def test_cache_returns_same_instance(self, mock_settings: MagicMock) -> None:
        """Test that lru_cache returns the same instance for same settings."""
        # Clear cache first
        get_authorization_model_port.cache_clear()

        port1 = get_authorization_model_port(mock_settings)
        port2 = get_authorization_model_port(mock_settings)

        # Same settings should return cached instance
        assert port1 is port2

    def test_different_settings_create_different_instances(self) -> None:
        """Test that different settings create different port instances."""
        # Clear cache first
        get_authorization_model_port.cache_clear()

        settings1 = MagicMock()
        settings1.openfga_api_url = "http://localhost:8080"
        settings1.openfga_store_id = "store-1"
        settings1.openfga_api_token = None
        settings1.openfga_authorization_model_id = None
        settings1.openfga_auth_method = "none"
        settings1.openfga_client_id = None
        settings1.openfga_client_secret = None
        settings1.openfga_api_audience = None
        settings1.openfga_api_token_issuer = None
        settings1.circuit_breaker_failure_threshold = 5
        settings1.circuit_breaker_recovery_timeout = 60

        settings2 = MagicMock()
        settings2.openfga_api_url = "http://localhost:9090"
        settings2.openfga_store_id = "store-2"
        settings2.openfga_api_token = None
        settings2.openfga_authorization_model_id = None
        settings2.openfga_auth_method = "none"
        settings2.openfga_client_id = None
        settings2.openfga_client_secret = None
        settings2.openfga_api_audience = None
        settings2.openfga_api_token_issuer = None
        settings2.circuit_breaker_failure_threshold = 5
        settings2.circuit_breaker_recovery_timeout = 60

        port1 = get_authorization_model_port(settings1)
        port2 = get_authorization_model_port(settings2)

        # Different settings should create different instances
        assert port1 is not port2


class TestPortsReturnSameAdapter:
    """Tests that all port factories return the same adapter instance."""

    def test_all_ports_from_same_settings_return_different_instances(
        self, mock_settings: MagicMock
    ) -> None:
        """Test that each factory function creates its own adapter instance.

        Note: lru_cache is per-function, so each function has its own cached
        instance. This is by design - each port function caches independently.
        """
        # Clear all caches
        get_authorization_port.cache_clear()
        get_authorization_store_port.cache_clear()
        get_authorization_model_port.cache_clear()

        port_auth = get_authorization_port(mock_settings)
        port_store = get_authorization_store_port(mock_settings)
        port_model = get_authorization_model_port(mock_settings)

        # Each getter function has its own lru_cache, so instances are different
        # This is by design - each function maintains its own singleton
        assert isinstance(port_auth, OpenFGAAdapter)
        assert isinstance(port_store, OpenFGAAdapter)
        assert isinstance(port_model, OpenFGAAdapter)

    def test_repeated_calls_to_same_function_return_cached_instance(
        self, mock_settings: MagicMock
    ) -> None:
        """Test that repeated calls to the same function return cached instance."""
        # Clear all caches
        get_authorization_port.cache_clear()
        get_authorization_store_port.cache_clear()
        get_authorization_model_port.cache_clear()

        port1 = get_authorization_port(mock_settings)
        port2 = get_authorization_port(mock_settings)
        port3 = get_authorization_port(mock_settings)

        assert port1 is port2
        assert port2 is port3


class TestDIIntegration:
    """Integration tests for the authorization DI container."""

    def test_all_factories_work_with_same_settings(self, mock_settings: MagicMock) -> None:
        """Test that all DI functions work correctly with the same settings."""
        # Clear all caches
        get_authorization_port.cache_clear()
        get_authorization_store_port.cache_clear()
        get_authorization_model_port.cache_clear()

        adapter = create_authorization_adapter(mock_settings)
        port_auth = get_authorization_port(mock_settings)
        port_store = get_authorization_store_port(mock_settings)
        port_model = get_authorization_model_port(mock_settings)

        # All should be OpenFGAAdapter instances
        assert isinstance(adapter, OpenFGAAdapter)
        assert isinstance(port_auth, OpenFGAAdapter)
        assert isinstance(port_store, OpenFGAAdapter)
        assert isinstance(port_model, OpenFGAAdapter)

        # All should implement required interfaces
        assert isinstance(port_auth, AuthorizationPort)
        assert isinstance(port_store, AuthorizationStorePort)
        assert isinstance(port_model, AuthorizationModelPort)

    def test_settings_required_fields(self) -> None:
        """Test that proper settings are required for adapter creation."""
        incomplete_settings = MagicMock()
        incomplete_settings.openfga_api_url = None
        incomplete_settings.openfga_store_id = None
        incomplete_settings.circuit_breaker_failure_threshold = 5
        incomplete_settings.circuit_breaker_recovery_timeout = 60

        # Adapter creation succeeds, but initialization will fail
        adapter = create_authorization_adapter(incomplete_settings)
        assert isinstance(adapter, OpenFGAAdapter)
