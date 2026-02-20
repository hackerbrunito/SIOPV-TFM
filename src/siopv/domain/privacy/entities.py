"""Domain entities for the privacy/DLP domain.

Defines SanitizationContext (input) and DLPResult (output) as immutable
Pydantic v2 models following the hexagonal architecture pattern.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, computed_field

from siopv.domain.privacy.value_objects import PIIDetection


class SanitizationContext(BaseModel):
    """Input context for a DLP sanitization request.

    Encapsulates the text to be sanitized along with configuration
    controlling what entities to detect and at what confidence threshold.
    """

    model_config = ConfigDict(frozen=True)

    text: str = Field(
        ...,
        description="Text to sanitize for PII",
    )
    language: str = Field(
        default="en",
        description="Language of the text (ISO 639-1 code)",
    )
    entities_to_detect: list[str] | None = Field(
        default=None,
        description="Specific entity types to detect; None means detect all",
    )
    score_threshold: float = Field(
        default=0.5,
        ge=0.0,
        le=1.0,
        description="Minimum confidence score for a detection to be reported",
    )


class DLPResult(BaseModel):
    """Result of a DLP sanitization operation.

    Contains the sanitized text, individual detections, and validation
    outcomes from both the Presidio engine and optional Haiku semantic
    validator.
    """

    model_config = ConfigDict(frozen=True)

    original_text: str = Field(
        ...,
        description="The original unsanitized text",
    )
    sanitized_text: str = Field(
        ...,
        description="Text with PII replaced by placeholder tokens",
    )
    detections: list[PIIDetection] = Field(
        default_factory=list,
        description="All PII detections found in the original text",
    )
    presidio_passed: bool = Field(
        ...,
        description="True if Presidio found no PII (or all PII was redacted)",
    )
    semantic_passed: bool = Field(
        default=True,
        description="True if Haiku semantic validation confirmed text is safe",
    )

    # Pydantic @computed_field + @property known mypy incompatibility
    @computed_field  # type: ignore[prop-decorator]
    @property
    def total_redactions(self) -> int:
        """Total number of PII entities redacted."""
        return len(self.detections)

    # Pydantic @computed_field + @property known mypy incompatibility
    @computed_field  # type: ignore[prop-decorator]
    @property
    def contains_pii(self) -> bool:
        """True if any PII was detected in the original text."""
        return len(self.detections) > 0

    @classmethod
    def safe_text(cls, text: str) -> DLPResult:
        """Create a DLPResult for text confirmed to contain no PII.

        Convenience factory for the common case where no PII is found,
        so original and sanitized text are identical.

        Args:
            text: Clean text with no PII

        Returns:
            DLPResult with empty detections and all passed flags True
        """
        return cls(
            original_text=text,
            sanitized_text=text,
            detections=[],
            presidio_passed=True,
            semantic_passed=True,
        )


__all__ = [
    "DLPResult",
    "SanitizationContext",
]
