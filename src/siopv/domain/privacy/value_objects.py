"""Value objects for the privacy/DLP domain.

Defines PII entity types and detection results as immutable value objects.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class PIIEntityType(StrEnum):
    """Types of PII entities that can be detected.

    Covers standard Presidio entities plus custom security-relevant ones.
    """

    PERSON = "PERSON"
    EMAIL_ADDRESS = "EMAIL_ADDRESS"
    PHONE_NUMBER = "PHONE_NUMBER"
    CREDIT_CARD = "CREDIT_CARD"
    IP_ADDRESS = "IP_ADDRESS"
    URL = "URL"
    CRYPTO = "CRYPTO"
    API_KEY = "API_KEY"
    SECRET_TOKEN = "SECRET_TOKEN"
    PASSWORD = "PASSWORD"
    NRP = "NRP"  # National Registration/ID number


class PIIDetection(BaseModel):
    """Immutable value object representing a single PII detection.

    Captures the location, type, and confidence of a detected PII entity,
    along with the replacement text used during sanitization.
    """

    model_config = ConfigDict(frozen=True)

    entity_type: PIIEntityType = Field(
        ...,
        description="Type of PII entity detected",
    )
    start: int = Field(
        ...,
        ge=0,
        description="Start character offset in original text",
    )
    end: int = Field(
        ...,
        ge=0,
        description="End character offset in original text (exclusive)",
    )
    score: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Confidence score from 0.0 to 1.0",
    )
    text: str = Field(
        ...,
        description="The original text that was detected as PII",
    )
    replacement: str = Field(
        ...,
        description="The redacted replacement text (e.g., '<API_KEY>')",
    )

    @classmethod
    def from_presidio(
        cls,
        entity_type: str,
        start: int,
        end: int,
        score: float,
        original_text: str,
    ) -> PIIDetection:
        """Create a PIIDetection from a Presidio RecognizerResult.

        Attempts to map the Presidio entity type to a PIIEntityType enum.
        Unknown entity types default to SECRET_TOKEN.

        Args:
            entity_type: Presidio entity type string
            start: Start character offset
            end: End character offset
            score: Confidence score
            original_text: The full original text (used to extract detected span)

        Returns:
            PIIDetection instance
        """
        # Map Presidio entity types to our enum
        type_map: dict[str, PIIEntityType] = {
            "PERSON": PIIEntityType.PERSON,
            "EMAIL_ADDRESS": PIIEntityType.EMAIL_ADDRESS,
            "PHONE_NUMBER": PIIEntityType.PHONE_NUMBER,
            "CREDIT_CARD": PIIEntityType.CREDIT_CARD,
            "IP_ADDRESS": PIIEntityType.IP_ADDRESS,
            "URL": PIIEntityType.URL,
            "CRYPTO": PIIEntityType.CRYPTO,
            "API_KEY": PIIEntityType.API_KEY,
            "SECRET_TOKEN": PIIEntityType.SECRET_TOKEN,
            "PASSWORD": PIIEntityType.PASSWORD,
            "NRP": PIIEntityType.NRP,
            "US_SSN": PIIEntityType.NRP,
            "US_DRIVER_LICENSE": PIIEntityType.NRP,
            "US_PASSPORT": PIIEntityType.NRP,
            "US_BANK_NUMBER": PIIEntityType.CREDIT_CARD,
            "IBAN_CODE": PIIEntityType.CREDIT_CARD,
            "MEDICAL_LICENSE": PIIEntityType.NRP,
            "DATE_TIME": PIIEntityType.NRP,
            "LOCATION": PIIEntityType.NRP,
            "ORGANIZATION": PIIEntityType.PERSON,
        }

        pii_type = type_map.get(entity_type, PIIEntityType.SECRET_TOKEN)
        detected_text = original_text[start:end] if start < len(original_text) else ""

        return cls(
            entity_type=pii_type,
            start=start,
            end=end,
            score=score,
            text=detected_text,
            replacement=f"<{pii_type.value}>",
        )


__all__ = [
    "PIIDetection",
    "PIIEntityType",
]
