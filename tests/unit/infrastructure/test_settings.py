"""Unit tests for settings configuration."""

import os
from pathlib import Path
from unittest.mock import patch

import pytest
from pydantic import ValidationError

from siopv.infrastructure.config.settings import Settings, get_settings

# === Basic Settings Tests ===


def test_settings_defaults():
    """Test Settings with default values."""
    # Arrange & Act
    with patch.dict(os.environ, {"SIOPV_ANTHROPIC_API_KEY": "test-key"}, clear=True):
        settings = Settings()

    # Assert
    assert settings.app_name == "SIOPV"
    assert settings.environment == "development"
    assert settings.debug is False
    assert settings.log_level == "INFO"


def test_settings_from_env():
    """Test Settings loads from environment variables with SIOPV_ prefix."""
    # Arrange
    env_vars = {
        "SIOPV_ANTHROPIC_API_KEY": "sk-ant-test123",
        "SIOPV_APP_NAME": "CustomSIOPV",
        "SIOPV_ENVIRONMENT": "production",
        "SIOPV_DEBUG": "true",
        "SIOPV_LOG_LEVEL": "DEBUG",
    }

    # Act
    with patch.dict(os.environ, env_vars, clear=True):
        settings = Settings()

    # Assert
    assert settings.app_name == "CustomSIOPV"
    assert settings.environment == "production"
    assert settings.debug is True
    assert settings.log_level == "DEBUG"
    assert settings.anthropic_api_key.get_secret_value() == "sk-ant-test123"


def test_settings_anthropic_api_key_required():
    """Test Settings requires anthropic_api_key."""
    # Arrange & Act & Assert
    with patch.dict(os.environ, {}, clear=True), pytest.raises(ValidationError) as exc_info:
        Settings()

    assert "anthropic_api_key" in str(exc_info.value)


# === API Configuration Tests ===


def test_settings_nvd_defaults():
    """Test NVD API default configuration."""
    # Arrange & Act
    with patch.dict(os.environ, {"SIOPV_ANTHROPIC_API_KEY": "test-key"}, clear=True):
        settings = Settings()

    # Assert
    assert settings.nvd_api_key is None
    assert settings.nvd_base_url == "https://services.nvd.nist.gov/rest/json/cves/2.0"
    assert settings.nvd_rate_limit == 5


def test_settings_nvd_with_api_key():
    """Test NVD configuration with API key."""
    # Arrange
    env_vars = {
        "SIOPV_ANTHROPIC_API_KEY": "test-key",
        "SIOPV_NVD_API_KEY": "nvd-key-123",
        "SIOPV_NVD_RATE_LIMIT": "50",
    }

    # Act
    with patch.dict(os.environ, env_vars, clear=True):
        settings = Settings()

    # Assert
    assert settings.nvd_api_key is not None
    assert settings.nvd_api_key.get_secret_value() == "nvd-key-123"
    assert settings.nvd_rate_limit == 50


def test_settings_github_configuration():
    """Test GitHub configuration."""
    # Arrange
    env_vars = {
        "SIOPV_ANTHROPIC_API_KEY": "test-key",
        "SIOPV_GITHUB_TOKEN": "ghp_token123",
    }

    # Act
    with patch.dict(os.environ, env_vars, clear=True):
        settings = Settings()

    # Assert
    assert settings.github_token is not None
    assert settings.github_token.get_secret_value() == "ghp_token123"
    assert settings.github_graphql_url == "https://api.github.com/graphql"


def test_settings_epss_defaults():
    """Test EPSS API defaults."""
    # Arrange & Act
    with patch.dict(os.environ, {"SIOPV_ANTHROPIC_API_KEY": "test-key"}, clear=True):
        settings = Settings()

    # Assert
    assert settings.epss_base_url == "https://api.first.org/data/v1/epss"


# === Jira Configuration Tests ===


def test_settings_jira_optional():
    """Test Jira configuration is optional."""
    # Arrange & Act
    with patch.dict(os.environ, {"SIOPV_ANTHROPIC_API_KEY": "test-key"}, clear=True):
        settings = Settings()

    # Assert
    assert settings.jira_base_url is None
    assert settings.jira_email is None
    assert settings.jira_api_token is None
    assert settings.jira_project_key is None


def test_settings_jira_full_configuration():
    """Test Jira with all fields configured."""
    # Arrange
    env_vars = {
        "SIOPV_ANTHROPIC_API_KEY": "test-key",
        "SIOPV_JIRA_BASE_URL": "https://company.atlassian.net",
        "SIOPV_JIRA_EMAIL": "user@example.com",
        "SIOPV_JIRA_API_TOKEN": "jira-token-123",
        "SIOPV_JIRA_PROJECT_KEY": "SEC",
    }

    # Act
    with patch.dict(os.environ, env_vars, clear=True):
        settings = Settings()

    # Assert
    assert settings.jira_base_url == "https://company.atlassian.net"
    assert settings.jira_email == "user@example.com"
    assert settings.jira_api_token.get_secret_value() == "jira-token-123"
    assert settings.jira_project_key == "SEC"


# === Database & ChromaDB Tests ===


def test_settings_database_defaults():
    """Test database defaults to SQLite."""
    # Arrange & Act
    with patch.dict(os.environ, {"SIOPV_ANTHROPIC_API_KEY": "test-key"}, clear=True):
        settings = Settings()

    # Assert
    assert settings.database_url == "sqlite+aiosqlite:///./siopv.db"


def test_settings_chroma_defaults():
    """Test ChromaDB default configuration."""
    # Arrange & Act
    with patch.dict(os.environ, {"SIOPV_ANTHROPIC_API_KEY": "test-key"}, clear=True):
        settings = Settings()

    # Assert
    assert settings.chroma_persist_dir == Path("./chroma_data")
    assert settings.chroma_collection_name == "siopv_embeddings"
    assert settings.chroma_cache_size_mb == 4096


def test_settings_chroma_custom_path():
    """Test ChromaDB with custom persist directory."""
    # Arrange
    env_vars = {
        "SIOPV_ANTHROPIC_API_KEY": "test-key",
        "SIOPV_CHROMA_PERSIST_DIR": "/custom/path/chroma",
    }

    # Act
    with patch.dict(os.environ, env_vars, clear=True):
        settings = Settings()

    # Assert
    assert settings.chroma_persist_dir == Path("/custom/path/chroma")


# === ML Model Tests ===


def test_settings_ml_model_defaults():
    """Test ML model default configuration."""
    # Arrange & Act
    with patch.dict(os.environ, {"SIOPV_ANTHROPIC_API_KEY": "test-key"}, clear=True):
        settings = Settings()

    # Assert
    assert settings.model_path == Path("./models/xgboost_risk_model.json")
    assert settings.uncertainty_threshold == 0.3


def test_settings_ml_model_custom():
    """Test ML model with custom path and threshold."""
    # Arrange
    env_vars = {
        "SIOPV_ANTHROPIC_API_KEY": "test-key",
        "SIOPV_MODEL_PATH": "/opt/models/custom_model.json",
        "SIOPV_UNCERTAINTY_THRESHOLD": "0.5",
    }

    # Act
    with patch.dict(os.environ, env_vars, clear=True):
        settings = Settings()

    # Assert
    assert settings.model_path == Path("/opt/models/custom_model.json")
    assert settings.uncertainty_threshold == 0.5


# === Circuit Breaker Tests ===


def test_settings_circuit_breaker_defaults():
    """Test circuit breaker default configuration."""
    # Arrange & Act
    with patch.dict(os.environ, {"SIOPV_ANTHROPIC_API_KEY": "test-key"}, clear=True):
        settings = Settings()

    # Assert
    assert settings.circuit_breaker_failure_threshold == 5
    assert settings.circuit_breaker_recovery_timeout == 60


def test_settings_circuit_breaker_custom():
    """Test circuit breaker with custom values."""
    # Arrange
    env_vars = {
        "SIOPV_ANTHROPIC_API_KEY": "test-key",
        "SIOPV_CIRCUIT_BREAKER_FAILURE_THRESHOLD": "10",
        "SIOPV_CIRCUIT_BREAKER_RECOVERY_TIMEOUT": "120",
    }

    # Act
    with patch.dict(os.environ, env_vars, clear=True):
        settings = Settings()

    # Assert
    assert settings.circuit_breaker_failure_threshold == 10
    assert settings.circuit_breaker_recovery_timeout == 120


# === Human-in-the-Loop Tests ===


def test_settings_hitl_defaults():
    """Test HITL timeout defaults."""
    # Arrange & Act
    with patch.dict(os.environ, {"SIOPV_ANTHROPIC_API_KEY": "test-key"}, clear=True):
        settings = Settings()

    # Assert
    assert settings.hitl_timeout_level1_hours == 4
    assert settings.hitl_timeout_level2_hours == 8
    assert settings.hitl_timeout_level3_hours == 24


def test_settings_hitl_custom():
    """Test HITL timeouts with custom values."""
    # Arrange
    env_vars = {
        "SIOPV_ANTHROPIC_API_KEY": "test-key",
        "SIOPV_HITL_TIMEOUT_LEVEL1_HOURS": "2",
        "SIOPV_HITL_TIMEOUT_LEVEL2_HOURS": "6",
        "SIOPV_HITL_TIMEOUT_LEVEL3_HOURS": "48",
    }

    # Act
    with patch.dict(os.environ, env_vars, clear=True):
        settings = Settings()

    # Assert
    assert settings.hitl_timeout_level1_hours == 2
    assert settings.hitl_timeout_level2_hours == 6
    assert settings.hitl_timeout_level3_hours == 48


# === Claude Model Configuration Tests ===


def test_settings_claude_model_defaults():
    """Test Claude model defaults."""
    # Arrange & Act
    with patch.dict(os.environ, {"SIOPV_ANTHROPIC_API_KEY": "test-key"}, clear=True):
        settings = Settings()

    # Assert
    assert settings.claude_haiku_model == "claude-haiku-4-5-20251001"
    assert settings.claude_sonnet_model == "claude-sonnet-4-5-20250929"


def test_settings_claude_models_custom():
    """Test Claude models with custom values."""
    # Arrange
    env_vars = {
        "SIOPV_ANTHROPIC_API_KEY": "test-key",
        "SIOPV_CLAUDE_HAIKU_MODEL": "claude-3-haiku-20240307",
        "SIOPV_CLAUDE_SONNET_MODEL": "claude-3-sonnet-20240229",
    }

    # Act
    with patch.dict(os.environ, env_vars, clear=True):
        settings = Settings()

    # Assert
    assert settings.claude_haiku_model == "claude-3-haiku-20240307"
    assert settings.claude_sonnet_model == "claude-3-sonnet-20240229"


# === Environment Validation Tests ===


def test_settings_environment_literal_validation():
    """Test environment accepts only valid literals."""
    # Arrange
    env_vars = {
        "SIOPV_ANTHROPIC_API_KEY": "test-key",
        "SIOPV_ENVIRONMENT": "production",
    }

    # Act
    with patch.dict(os.environ, env_vars, clear=True):
        settings = Settings()

    # Assert
    assert settings.environment == "production"


def test_settings_log_level_literal_validation():
    """Test log_level accepts only valid literals."""
    # Arrange
    env_vars = {
        "SIOPV_ANTHROPIC_API_KEY": "test-key",
        "SIOPV_LOG_LEVEL": "ERROR",
    }

    # Act
    with patch.dict(os.environ, env_vars, clear=True):
        settings = Settings()

    # Assert
    assert settings.log_level == "ERROR"


# === OpenFGA Tests ===


def test_settings_openfga_optional():
    """Test OpenFGA configuration is optional."""
    # Arrange & Act
    with patch.dict(os.environ, {"SIOPV_ANTHROPIC_API_KEY": "test-key"}, clear=True):
        settings = Settings()

    # Assert
    assert settings.openfga_api_url is None
    assert settings.openfga_store_id is None


def test_settings_openfga_configured():
    """Test OpenFGA with configuration."""
    # Arrange
    env_vars = {
        "SIOPV_ANTHROPIC_API_KEY": "test-key",
        "SIOPV_OPENFGA_API_URL": "http://localhost:8080",
        "SIOPV_OPENFGA_STORE_ID": "store-123",
    }

    # Act
    with patch.dict(os.environ, env_vars, clear=True):
        settings = Settings()

    # Assert
    assert settings.openfga_api_url == "http://localhost:8080"
    assert settings.openfga_store_id == "store-123"


# === get_settings() Cache Tests ===


def test_get_settings_returns_cached_instance():
    """Test get_settings() returns cached singleton."""
    # Arrange
    with patch.dict(os.environ, {"SIOPV_ANTHROPIC_API_KEY": "test-key"}, clear=True):
        # Act
        settings1 = get_settings()
        settings2 = get_settings()

    # Assert
    assert settings1 is settings2


def test_get_settings_cache_info():
    """Test get_settings() uses lru_cache."""
    # Arrange
    get_settings.cache_clear()

    # Act
    with patch.dict(os.environ, {"SIOPV_ANTHROPIC_API_KEY": "test-key"}, clear=True):
        get_settings()
        cache_info = get_settings.cache_info()

    # Assert
    assert cache_info.hits == 0
    assert cache_info.misses == 1


# === SecretStr Tests ===


def test_settings_secret_str_hidden():
    """Test SecretStr fields don't expose secrets in repr."""
    # Arrange
    env_vars = {
        "SIOPV_ANTHROPIC_API_KEY": "super-secret-key",
        "SIOPV_NVD_API_KEY": "nvd-secret",
    }

    # Act
    with patch.dict(os.environ, env_vars, clear=True):
        settings = Settings()

    # Assert
    settings_repr = repr(settings)
    assert "super-secret-key" not in settings_repr
    assert "nvd-secret" not in settings_repr
    assert "SecretStr" in settings_repr


def test_settings_secret_str_get_secret_value():
    """Test SecretStr.get_secret_value() returns actual value."""
    # Arrange
    env_vars = {
        "SIOPV_ANTHROPIC_API_KEY": "actual-secret",
    }

    # Act
    with patch.dict(os.environ, env_vars, clear=True):
        settings = Settings()

    # Assert
    assert settings.anthropic_api_key.get_secret_value() == "actual-secret"


# === Extra Fields Tests ===


def test_settings_ignores_extra_fields():
    """Test Settings ignores unknown environment variables."""
    # Arrange
    env_vars = {
        "SIOPV_ANTHROPIC_API_KEY": "test-key",
        "SIOPV_UNKNOWN_FIELD": "should-be-ignored",
        "SIOPV_ANOTHER_UNKNOWN": "also-ignored",
    }

    # Act & Assert (should not raise ValidationError)
    with patch.dict(os.environ, env_vars, clear=True):
        settings = Settings()
        assert settings.app_name == "SIOPV"  # Normal field works
