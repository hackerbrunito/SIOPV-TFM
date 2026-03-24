"""Port interfaces for DLP (Data Loss Prevention) in SIOPV.

Defines the contracts for DLP service implementations following hexagonal
architecture. These ports define WHAT the application needs for privacy
protection, while adapters provide HOW it is implemented using Presidio
and Claude Haiku.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from siopv.domain.privacy.entities import DLPResult, SanitizationContext
    from siopv.domain.privacy.value_objects import PIIDetection


@runtime_checkable
class DLPPort(Protocol):
    """Port interface for DLP sanitization operations.

    Implementations accept a SanitizationContext describing the text and
    detection parameters, and return a DLPResult with the sanitized output
    and all detected PII entities.
    """

    async def sanitize(self, context: SanitizationContext) -> DLPResult:
        """Sanitize text by detecting and redacting PII.

        Args:
            context: SanitizationContext with text, language, and thresholds.

        Returns:
            DLPResult with sanitized text and detection metadata.

        Raises:
            SanitizationError: If the sanitization operation fails.
            PresidioUnavailableError: If Presidio engine is unavailable.
        """
        ...


@runtime_checkable
class SemanticValidatorPort(Protocol):
    """Port interface for semantic PII validation using an LLM.

    Provides a second-pass validation after Presidio sanitization to catch
    any PII that rule-based approaches may have missed. Returns True when
    the text is considered safe (fail-open: errors return True).
    """

    async def validate(self, text: str, detections: list[PIIDetection]) -> bool:
        """Validate that sanitized text contains no remaining PII.

        Args:
            text: The already-sanitized text to validate.
            detections: PII detections from the first-pass Presidio scan
                (provided as context for the validator).

        Returns:
            True if text is safe (no remaining PII detected).
            False if the validator found remaining sensitive information.
            True on validator errors (fail-open — Presidio already ran).
        """
        ...


__all__ = [
    "DLPPort",
    "SemanticValidatorPort",
]
