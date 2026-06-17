"""Dependency injection factory functions for ML and ingestion components.

Factory functions for creating ML classification adapters that implement
MLClassifierPort, and the TrivyParser adapter that implements TrivyParserPort.
Supports graceful degradation when model files are missing.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import structlog

from siopv.adapters.external_apis.trivy_parser import TrivyParser
from siopv.adapters.ml.xgboost_classifier import XGBoostClassifier
from siopv.application.ports.feature_engineering import FeatureEngineerPort
from siopv.application.ports.ml_classifier import MLClassifierPort
from siopv.application.ports.parsing import TrivyParserPort
from siopv.domain.exceptions import IntegrityError, PathTraversalError
from siopv.infrastructure.ml.model_persistence import ModelPersistence

if TYPE_CHECKING:
    from siopv.infrastructure.config import Settings

logger = structlog.get_logger(__name__)


def build_trivy_parser() -> TrivyParserPort:
    """Create a TrivyParser adapter instance.

    Returns:
        TrivyParserPort implementation for parsing Trivy JSON reports
    """
    parser = TrivyParser()
    logger.info("trivy_parser_created")
    return parser


def build_classifier(settings: Settings) -> MLClassifierPort | None:
    """Create a configured XGBoost classifier from application settings.

    Args:
        settings: Application settings with model path configuration

    Returns:
        MLClassifierPort implementation, or None if model file does not exist
    """
    model_path = settings.model_path

    if not model_path.exists():
        logger.warning(
            "classifier_skipped",
            reason="model file not found",
            model_path=str(model_path),
        )
        return None

    # Integrity gate (S9 / M-01): verify the model artifact — size, SHA-256 hash,
    # and HMAC signature (when SIOPV_MODEL_SIGNING_KEY is set) — before loading it.
    # A tampered/oversized artifact fails closed: the classifier is skipped and
    # the pipeline degrades to its no-ML fallback rather than trusting a poisoned model.
    signing_key = (
        settings.model_signing_key.get_secret_value() if settings.model_signing_key else None
    )
    persistence = ModelPersistence(
        base_path=settings.model_base_path,
        signing_key=signing_key,
        max_model_size=settings.model_max_size_bytes,
    )
    try:
        persistence.verify_model_file(model_path)
    except (IntegrityError, PathTraversalError) as exc:
        logger.exception(
            "classifier_skipped",
            reason="model integrity verification failed",
            model_path=str(model_path),
            error=str(exc),
        )
        return None

    adapter = XGBoostClassifier(model_path=model_path, environment=settings.environment)
    logger.info("classifier_created", model_path=str(model_path))
    return adapter


def build_feature_engineer() -> FeatureEngineerPort:
    """Create a FeatureEngineer adapter instance.

    Returns:
        FeatureEngineerPort implementation for extracting ML feature vectors.
    """
    from siopv.adapters.ml.feature_engineer import FeatureEngineer  # noqa: PLC0415

    engineer = FeatureEngineer()
    logger.info("feature_engineer_created")
    return engineer


__all__ = [
    "build_classifier",
    "build_feature_engineer",
    "build_trivy_parser",
]
