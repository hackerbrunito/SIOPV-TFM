"""Dependency injection factory functions for DLP components.

Factory functions for creating and configuring DLP components that implement
the DLPPort. Follows the same lru_cache singleton pattern used in the
authorization DI module.
"""

from __future__ import annotations

from functools import lru_cache
from typing import TYPE_CHECKING

import structlog

from siopv.adapters.dlp.dual_layer_adapter import DualLayerDLPAdapter, create_dual_layer_adapter
from siopv.adapters.dlp.presidio_adapter import PresidioAdapter
from siopv.application.ports.dlp import DLPPort

if TYPE_CHECKING:
    from siopv.infrastructure.config.settings import Settings

logger = structlog.get_logger(__name__)


def create_presidio_adapter(settings: Settings) -> PresidioAdapter:
    """Create a configured PresidioAdapter from application settings.

    Args:
        settings: Application settings providing the Anthropic API key
            and optional Haiku model override.

    Returns:
        PresidioAdapter with Presidio engines initialized and optional
        Haiku semantic validator configured.
    """
    api_key = settings.anthropic_api_key.get_secret_value()
    haiku_model = settings.claude_haiku_model

    logger.debug(
        "creating_presidio_adapter",
        haiku_model=haiku_model,
        semantic_validation=bool(api_key),
    )

    adapter = PresidioAdapter(
        api_key=api_key,
        haiku_model=haiku_model,
        enable_semantic_validation=bool(api_key),
    )

    logger.info("presidio_adapter_created", adapter_class="PresidioAdapter")
    return adapter


@lru_cache(maxsize=1)
def get_dlp_port(settings: Settings) -> DLPPort:
    """Get the singleton DLP port implementation backed by PresidioAdapter.

    Uses lru_cache to ensure only one PresidioAdapter (with its Presidio
    engines) is created per settings object.

    Args:
        settings: Application settings instance.

    Returns:
        DLPPort implementation backed by PresidioAdapter.
    """
    adapter = create_presidio_adapter(settings)
    logger.debug("dlp_port_created", port_type="DLPPort")
    # PresidioAdapter satisfies DLPPort via structural subtyping (Protocol)
    return adapter


def create_dual_layer_dlp_adapter(settings: Settings) -> DualLayerDLPAdapter:
    """Create a DualLayerDLPAdapter from application settings.

    The DualLayerDLPAdapter runs Presidio (Layer 1) and invokes Haiku
    only when Presidio finds zero entities (Layer 2 semantic fallback).

    Args:
        settings: Application settings providing the Anthropic API key
            and optional Haiku model override.

    Returns:
        DualLayerDLPAdapter with Presidio and Haiku configured.
    """
    api_key = settings.anthropic_api_key.get_secret_value()
    haiku_model = settings.claude_haiku_model

    logger.debug(
        "creating_dual_layer_dlp_adapter",
        haiku_model=haiku_model,
    )

    adapter = create_dual_layer_adapter(
        api_key=api_key,
        haiku_model=haiku_model,
    )

    logger.info("dual_layer_dlp_adapter_created", adapter_class="DualLayerDLPAdapter")
    return adapter


@lru_cache(maxsize=1)
def get_dual_layer_dlp_port(settings: Settings) -> DLPPort:
    """Get the singleton DualLayerDLPAdapter DLP port.

    Preferred over get_dlp_port() for production use — adds a Haiku
    semantic fallback pass for texts that Presidio finds clean.

    Args:
        settings: Application settings instance.

    Returns:
        DLPPort backed by DualLayerDLPAdapter (Presidio + Haiku).
    """
    adapter = create_dual_layer_dlp_adapter(settings)
    logger.debug("dual_layer_dlp_port_created", port_type="DualLayerDLPAdapter")
    # DualLayerDLPAdapter satisfies DLPPort via structural subtyping (Protocol)
    return adapter


__all__ = [
    "create_dual_layer_dlp_adapter",
    "create_presidio_adapter",
    "get_dlp_port",
    "get_dual_layer_dlp_port",
]
