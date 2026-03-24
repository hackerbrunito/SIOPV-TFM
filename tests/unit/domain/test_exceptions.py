"""Unit tests for domain exceptions."""

from siopv.domain.exceptions import (
    APIClientError,
    AuthorizationError,
    CheckpointError,
    CircuitBreakerOpenError,
    ClassificationError,
    EnrichmentError,
    InferenceError,
    IngestionError,
    JiraIntegrationError,
    ModelNotFoundError,
    NodeExecutionError,
    OrchestrationError,
    OutputError,
    PermissionDeniedError,
    PrivacyError,
    RateLimitError,
    ReportGenerationError,
    SensitiveDataDetectedError,
    SIOPVError,
    TrivyParseError,
    ValidationError,
)

# === Base Exception Tests ===


def test_siopv_error_message_only():
    """Test SIOPVError with message only."""
    # Arrange & Act
    error = SIOPVError("Test error")

    # Assert
    assert error.message == "Test error"
    assert error.details == {}
    assert str(error) == "Test error"


def test_siopv_error_with_details():
    """Test SIOPVError with details dict."""
    # Arrange
    details = {"cve_id": "CVE-2024-1234", "severity": "HIGH"}

    # Act
    error = SIOPVError("Vulnerability processing failed", details=details)

    # Assert
    assert error.message == "Vulnerability processing failed"
    assert error.details == details
    assert "Details: " in str(error)
    assert "CVE-2024-1234" in str(error)


def test_siopv_error_empty_details():
    """Test SIOPVError with explicitly empty details."""
    # Arrange & Act
    error = SIOPVError("Test error", details={})

    # Assert
    assert error.details == {}
    assert str(error) == "Test error"


def test_siopv_error_none_details():
    """Test SIOPVError with None details defaults to empty dict."""
    # Arrange & Act
    error = SIOPVError("Test error", details=None)

    # Assert
    assert error.details == {}


# === Ingestion Errors ===


def test_ingestion_error_inheritance():
    """Test IngestionError inherits from SIOPVError."""
    # Arrange & Act
    error = IngestionError("Ingestion failed")

    # Assert
    assert isinstance(error, SIOPVError)
    assert isinstance(error, IngestionError)


def test_trivy_parse_error():
    """Test TrivyParseError with malformed JSON."""
    # Arrange & Act
    error = TrivyParseError(
        "Invalid JSON in Trivy report",
        details={"file": "report.json", "line": 42},
    )

    # Assert
    assert isinstance(error, IngestionError)
    assert "Invalid JSON" in error.message


def test_validation_error():
    """Test ValidationError for Pydantic validation failure."""
    # Arrange & Act
    error = ValidationError(
        "Pydantic validation failed",
        details={"field": "cve_id", "error": "invalid format"},
    )

    # Assert
    assert isinstance(error, IngestionError)


# === Enrichment Errors ===


def test_api_client_error_basic():
    """Test APIClientError with basic parameters."""
    # Arrange & Act
    error = APIClientError(
        message="API request failed",
        api_name="NVD",
        status_code=500,
    )

    # Assert
    assert error.api_name == "NVD"
    assert error.status_code == 500
    assert isinstance(error, EnrichmentError)


def test_api_client_error_without_status():
    """Test APIClientError without status code."""
    # Arrange & Act
    error = APIClientError(
        message="Connection timeout",
        api_name="GitHub",
    )

    # Assert
    assert error.api_name == "GitHub"
    assert error.status_code is None


def test_api_client_error_with_details():
    """Test APIClientError with additional details."""
    # Arrange
    details = {"endpoint": "/cves/CVE-2024-1234", "timeout": 30}

    # Act
    error = APIClientError(
        message="Request timeout",
        api_name="NVD",
        details=details,
    )

    # Assert
    assert error.details == details


def test_rate_limit_error_default():
    """Test RateLimitError with default message."""
    # Arrange & Act
    error = RateLimitError(api_name="NVD")

    # Assert
    assert error.api_name == "NVD"
    assert error.status_code == 429
    assert error.retry_after is None
    assert "Rate limit exceeded for NVD" in error.message


def test_rate_limit_error_with_retry_after():
    """Test RateLimitError with retry_after header."""
    # Arrange & Act
    error = RateLimitError(
        api_name="GitHub",
        retry_after=60,
        details={"limit": 5000, "remaining": 0},
    )

    # Assert
    assert error.retry_after == 60
    assert error.api_name == "GitHub"
    assert isinstance(error, APIClientError)


def test_circuit_breaker_open_error():
    """Test CircuitBreakerOpenError."""
    # Arrange & Act
    error = CircuitBreakerOpenError(
        "Circuit breaker open for NVD API",
        details={"failures": 5, "threshold": 5},
    )

    # Assert
    assert isinstance(error, EnrichmentError)


# === Classification Errors ===


def test_classification_error():
    """Test ClassificationError base."""
    # Arrange & Act
    error = ClassificationError("ML classification failed")

    # Assert
    assert isinstance(error, SIOPVError)


def test_model_not_found_error():
    """Test ModelNotFoundError for missing trained model."""
    # Arrange & Act
    error = ModelNotFoundError(
        "XGBoost model not found",
        details={"path": "./models/xgboost_risk_model.json"},
    )

    # Assert
    assert isinstance(error, ClassificationError)


def test_inference_error():
    """Test InferenceError for ML inference failure."""
    # Arrange & Act
    error = InferenceError(
        "Feature extraction failed",
        details={"missing_features": ["cvss_score", "epss_percentile"]},
    )

    # Assert
    assert isinstance(error, ClassificationError)


# === Orchestration Errors ===


def test_orchestration_error():
    """Test OrchestrationError base."""
    # Arrange & Act
    error = OrchestrationError("LangGraph execution failed")

    # Assert
    assert isinstance(error, SIOPVError)


def test_checkpoint_error():
    """Test CheckpointError for checkpoint save/restore failure."""
    # Arrange & Act
    error = CheckpointError(
        "Failed to save checkpoint",
        details={"thread_id": "thread-123", "step": 5},
    )

    # Assert
    assert isinstance(error, OrchestrationError)


def test_node_execution_error():
    """Test NodeExecutionError for graph node failure."""
    # Arrange & Act
    error = NodeExecutionError(
        "Node 'enrich_context' failed",
        details={"node": "enrich_context", "error": "timeout"},
    )

    # Assert
    assert isinstance(error, OrchestrationError)


# === Authorization Errors ===


def test_authorization_error():
    """Test AuthorizationError base."""
    # Arrange & Act
    error = AuthorizationError("Authorization check failed")

    # Assert
    assert isinstance(error, SIOPVError)


def test_permission_denied_error():
    """Test PermissionDeniedError with user/resource/action."""
    # Arrange & Act
    error = PermissionDeniedError(
        user="analyst1",
        resource="vulnerability:CVE-2024-1234",
        action="approve",
    )

    # Assert
    assert error.user == "analyst1"
    assert error.resource == "vulnerability:CVE-2024-1234"
    assert error.action == "approve"
    assert "Permission denied" in error.message
    assert "analyst1" in error.message
    assert "approve" in error.message
    assert isinstance(error, AuthorizationError)


def test_permission_denied_error_with_details():
    """Test PermissionDeniedError with additional details."""
    # Arrange
    details = {"required_role": "senior_analyst", "user_role": "analyst"}

    # Act
    error = PermissionDeniedError(
        user="junior_analyst",
        resource="report:confidential",
        action="view",
        details=details,
    )

    # Assert
    assert error.details == details


# === Privacy/DLP Errors ===


def test_privacy_error():
    """Test PrivacyError base."""
    # Arrange & Act
    error = PrivacyError("DLP sanitization failed")

    # Assert
    assert isinstance(error, SIOPVError)


def test_sensitive_data_detected_error():
    """Test SensitiveDataDetectedError."""
    # Arrange & Act
    error = SensitiveDataDetectedError(
        "Sensitive data detected in CVE description",
        details={"patterns": ["email", "api_key"], "field": "description"},
    )

    # Assert
    assert isinstance(error, PrivacyError)


# === Output Errors ===


def test_output_error():
    """Test OutputError base."""
    # Arrange & Act
    error = OutputError("Output generation failed")

    # Assert
    assert isinstance(error, SIOPVError)


def test_jira_integration_error():
    """Test JiraIntegrationError."""
    # Arrange & Act
    error = JiraIntegrationError(
        "Failed to create Jira ticket",
        details={"project": "SEC", "error": "authentication failed"},
    )

    # Assert
    assert isinstance(error, OutputError)


def test_report_generation_error():
    """Test ReportGenerationError."""
    # Arrange & Act
    error = ReportGenerationError(
        "PDF generation failed",
        details={"template": "vulnerability_report.html", "error": "missing font"},
    )

    # Assert
    assert isinstance(error, OutputError)


# === Edge Cases ===


def test_exception_chain():
    """Test exception chaining through inheritance."""
    # Arrange & Act
    error = RateLimitError(api_name="NVD")

    # Assert
    assert isinstance(error, APIClientError)
    assert isinstance(error, EnrichmentError)
    assert isinstance(error, SIOPVError)
    assert isinstance(error, Exception)


def test_error_str_with_special_characters():
    """Test error string formatting with special characters."""
    # Arrange
    details = {"message": "Error: 'value' contains \"quotes\""}

    # Act
    error = SIOPVError("Test error", details=details)

    # Assert
    assert "Details: " in str(error)


def test_multiple_inheritance_paths():
    """Test that error classes maintain correct inheritance."""
    # Arrange
    errors = [
        TrivyParseError("test"),
        ValidationError("test"),
        RateLimitError("API"),
        PermissionDeniedError("user", "resource", "action"),
    ]

    # Act & Assert
    for error in errors:
        assert isinstance(error, SIOPVError)
        assert isinstance(error, Exception)
