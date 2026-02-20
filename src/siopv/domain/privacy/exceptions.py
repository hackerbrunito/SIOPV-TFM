"""Exceptions for the privacy/DLP domain.

Defines the exception hierarchy for DLP operations.
"""

from __future__ import annotations


class DLPError(Exception):
    """Base exception for all DLP-related errors."""


class SanitizationError(DLPError):
    """Raised when text sanitization fails unexpectedly."""


class PresidioUnavailableError(DLPError):
    """Raised when Presidio services are unavailable or fail to initialize."""


class SemanticValidationError(DLPError):
    """Raised when the semantic validator (Haiku) encounters a critical error."""


__all__ = [
    "DLPError",
    "PresidioUnavailableError",
    "SanitizationError",
    "SemanticValidationError",
]
