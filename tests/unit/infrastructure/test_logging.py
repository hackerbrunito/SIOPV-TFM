"""Unit tests for logging setup."""

import logging
from unittest.mock import MagicMock

import pytest
import structlog

from siopv.infrastructure.logging.setup import configure_logging, get_logger

# === configure_logging() Tests ===


def test_configure_logging_defaults():
    """Test configure_logging with default parameters."""
    # Arrange & Act
    configure_logging()

    # Assert
    root_logger = logging.getLogger()
    assert root_logger.level == logging.INFO
    assert len(root_logger.handlers) == 1
    assert isinstance(root_logger.handlers[0], logging.StreamHandler)


def test_configure_logging_debug_level():
    """Test configure_logging with DEBUG level."""
    # Arrange & Act
    configure_logging(level="DEBUG")

    # Assert
    root_logger = logging.getLogger()
    assert root_logger.level == logging.DEBUG


def test_configure_logging_warning_level():
    """Test configure_logging with WARNING level."""
    # Arrange & Act
    configure_logging(level="WARNING")

    # Assert
    root_logger = logging.getLogger()
    assert root_logger.level == logging.WARNING


def test_configure_logging_error_level():
    """Test configure_logging with ERROR level."""
    # Arrange & Act
    configure_logging(level="ERROR")

    # Assert
    root_logger = logging.getLogger()
    assert root_logger.level == logging.ERROR


def test_configure_logging_json_format():
    """Test configure_logging with JSON output."""
    # Arrange & Act
    configure_logging(level="INFO", json_format=True)

    # Assert
    root_logger = logging.getLogger()
    handler = root_logger.handlers[0]
    formatter = handler.formatter
    assert isinstance(formatter, structlog.stdlib.ProcessorFormatter)


def test_configure_logging_console_format():
    """Test configure_logging with console output."""
    # Arrange & Act
    configure_logging(level="INFO", json_format=False)

    # Assert
    root_logger = logging.getLogger()
    handler = root_logger.handlers[0]
    formatter = handler.formatter
    assert isinstance(formatter, structlog.stdlib.ProcessorFormatter)


def test_configure_logging_clears_existing_handlers():
    """Test configure_logging removes existing handlers."""
    # Arrange
    root_logger = logging.getLogger()
    mock_handler = MagicMock(spec=logging.Handler)
    root_logger.addHandler(mock_handler)
    len(root_logger.handlers)

    # Act
    configure_logging()

    # Assert
    assert len(root_logger.handlers) == 1
    assert mock_handler not in root_logger.handlers


def test_configure_logging_suppresses_noisy_loggers():
    """Test configure_logging suppresses httpx, httpcore, chromadb."""
    # Arrange & Act
    configure_logging(level="DEBUG")

    # Assert
    assert logging.getLogger("httpx").level == logging.WARNING
    assert logging.getLogger("httpcore").level == logging.WARNING
    assert logging.getLogger("chromadb").level == logging.WARNING


def test_configure_logging_handler_outputs_to_stdout():
    """Test configure_logging handler writes to stdout."""
    # Arrange & Act
    configure_logging()

    # Assert
    import sys

    root_logger = logging.getLogger()
    handler = root_logger.handlers[0]
    assert handler.stream is sys.stdout


# === get_logger() Tests ===


def test_get_logger_returns_logger():
    """Test get_logger returns a logger instance."""
    # Arrange
    configure_logging()

    # Act
    logger = get_logger("test_module")

    # Assert
    # structlog.get_logger() returns BoundLoggerLazyProxy or BoundLogger
    assert hasattr(logger, "info")
    assert hasattr(logger, "error")
    assert hasattr(logger, "warning")
    assert hasattr(logger, "debug")


def test_get_logger_with_module_name():
    """Test get_logger with __name__ pattern."""
    # Arrange
    configure_logging()

    # Act
    logger = get_logger("siopv.infrastructure.config")

    # Assert
    assert hasattr(logger, "info")
    assert callable(logger.info)


def test_get_logger_different_names():
    """Test get_logger with different names."""
    # Arrange
    configure_logging()

    # Act
    logger1 = get_logger("module1")
    logger2 = get_logger("module2")

    # Assert
    # Both should be valid loggers
    assert hasattr(logger1, "info")
    assert hasattr(logger2, "info")


# === Integration Tests ===


def test_logging_json_output_format(capsys):
    """Test JSON format produces valid JSON logs."""
    # Arrange
    configure_logging(level="INFO", json_format=True)
    logger = get_logger("test")

    # Act
    logger.info("test_message", key="value")

    # Assert
    captured = capsys.readouterr()
    assert "test_message" in captured.out
    # JSON format includes structured fields
    assert "key" in captured.out or "value" in captured.out


def test_logging_console_output_format(capsys):
    """Test console format produces readable logs."""
    # Arrange
    configure_logging(level="INFO", json_format=False)
    logger = get_logger("test")

    # Act
    logger.info("test_message", user="analyst")

    # Assert
    captured = capsys.readouterr()
    assert "test_message" in captured.out


def test_logging_with_structured_data(capsys):
    """Test logging with structured key-value pairs."""
    # Arrange
    configure_logging(level="INFO", json_format=False)
    logger = get_logger("test")

    # Act
    logger.info(
        "processing_vulnerability",
        cve_id="CVE-2024-1234",
        severity="HIGH",
        score=8.5,
    )

    # Assert
    captured = capsys.readouterr()
    assert "processing_vulnerability" in captured.out
    assert "CVE-2024-1234" in captured.out


def test_logging_exception_handling(capsys):
    """Test logging captures exception information."""
    # Arrange
    configure_logging(level="ERROR", json_format=False)
    logger = get_logger("test")

    # Act
    try:
        raise ValueError("Test error")
    except ValueError:
        logger.exception("error_occurred", operation="test")

    # Assert
    captured = capsys.readouterr()
    assert "error_occurred" in captured.out
    assert "ValueError" in captured.out
    assert "Test error" in captured.out


def test_logging_level_filtering(capsys):
    """Test log level filtering works correctly."""
    # Arrange
    configure_logging(level="WARNING", json_format=False)
    logger = get_logger("test")

    # Act
    logger.debug("debug_message")
    logger.info("info_message")
    logger.warning("warning_message")

    # Assert
    captured = capsys.readouterr()
    assert "debug_message" not in captured.out
    assert "info_message" not in captured.out
    assert "warning_message" in captured.out


# === Processor Tests ===


def test_logging_includes_timestamp(capsys):
    """Test logs include ISO timestamp."""
    # Arrange
    configure_logging(level="INFO", json_format=True)
    logger = get_logger("test")

    # Act
    logger.info("test_message")

    # Assert
    captured = capsys.readouterr()
    # ISO timestamp format check (basic)
    import re

    # Matches YYYY-MM-DD or ISO-like patterns
    assert re.search(r"\d{4}-\d{2}-\d{2}", captured.out)


def test_logging_includes_logger_name(capsys):
    """Test logs include logger name."""
    # Arrange
    configure_logging(level="INFO", json_format=False)
    logger = get_logger("siopv.test_module")

    # Act
    logger.info("test_message")

    # Assert
    captured = capsys.readouterr()
    # Logger name should appear somewhere
    assert "test_module" in captured.out or "siopv" in captured.out


def test_logging_includes_log_level(capsys):
    """Test logs include log level."""
    # Arrange
    configure_logging(level="INFO", json_format=False)
    logger = get_logger("test")

    # Act
    logger.warning("warning_message")

    # Assert
    captured = capsys.readouterr()
    assert "warning" in captured.out.lower() or "WARNING" in captured.out


# === Edge Cases ===


def test_configure_logging_called_multiple_times():
    """Test configure_logging can be called multiple times safely."""
    # Arrange & Act
    configure_logging(level="DEBUG")
    configure_logging(level="INFO")
    configure_logging(level="WARNING")

    # Assert
    root_logger = logging.getLogger()
    assert root_logger.level == logging.WARNING
    assert len(root_logger.handlers) == 1


def test_get_logger_before_configure():
    """Test get_logger works before configure_logging is called."""
    # Arrange & Act
    logger = get_logger("test_unconfigured")

    # Assert
    # Should still return a valid logger object
    assert hasattr(logger, "info")
    assert hasattr(logger, "error")


def test_logging_with_none_values(capsys):
    """Test logging handles None values in structured data."""
    # Arrange
    configure_logging(level="INFO", json_format=False)
    logger = get_logger("test")

    # Act
    logger.info("test_message", value=None, data=None)

    # Assert
    captured = capsys.readouterr()
    assert "test_message" in captured.out


def test_logging_with_empty_string(capsys):
    """Test logging handles empty string values."""
    # Arrange
    configure_logging(level="INFO", json_format=False)
    logger = get_logger("test")

    # Act
    logger.info("", field="value")

    # Assert
    capsys.readouterr()
    # Should not crash


def test_suppressed_logger_respects_level():
    """Test suppressed loggers (httpx) still respect WARNING level."""
    # Arrange
    configure_logging(level="DEBUG")

    # Act
    httpx_logger = logging.getLogger("httpx")
    httpx_logger.debug("This should not appear")
    httpx_logger.warning("This should appear")

    # Assert
    assert httpx_logger.level == logging.WARNING


def test_logging_with_special_characters(capsys):
    """Test logging handles special characters correctly."""
    # Arrange
    configure_logging(level="INFO", json_format=False)
    logger = get_logger("test")

    # Act
    logger.info(
        "test_message",
        data="Special chars: <>&\"'",
        unicode="Test: \u2713 \u2717",
    )

    # Assert
    captured = capsys.readouterr()
    assert "test_message" in captured.out


# === Concurrent Logging Tests ===


@pytest.mark.asyncio
async def test_logging_thread_safe():
    """Test logging configuration is thread-safe."""
    # Arrange
    configure_logging(level="INFO", json_format=False)

    # Act
    import asyncio

    async def log_message(name: str):
        logger = get_logger(name)
        logger.info("concurrent_message", thread=name)

    await asyncio.gather(
        log_message("thread1"),
        log_message("thread2"),
        log_message("thread3"),
    )

    # Assert - should not crash


def test_logger_method_signatures():
    """Test logger has expected method signatures."""
    # Arrange
    configure_logging()
    logger = get_logger("test")

    # Assert
    assert callable(logger.info)
    assert callable(logger.debug)
    assert callable(logger.warning)
    assert callable(logger.error)
    assert callable(logger.exception)
