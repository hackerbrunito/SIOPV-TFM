"""Enrich node for LangGraph pipeline.

Handles Phase 2: Context enrichment using CRAG pattern.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

import structlog

if TYPE_CHECKING:
    from siopv.application.orchestration.state import PipelineState
    from siopv.application.ports import (
        EPSSClientPort,
        GitHubAdvisoryClientPort,
        NVDClientPort,
        OSINTSearchClientPort,
        VectorStorePort,
    )

logger = structlog.get_logger(__name__)


def enrich_node(
    state: PipelineState,
    *,
    nvd_client: NVDClientPort | None = None,
    epss_client: EPSSClientPort | None = None,
    github_client: GitHubAdvisoryClientPort | None = None,
    osint_client: OSINTSearchClientPort | None = None,
    vector_store: VectorStorePort | None = None,
    max_concurrent: int = 5,
) -> dict:
    """Execute enrichment phase as a LangGraph node.

    This node wraps the EnrichContextUseCase to integrate with
    the LangGraph orchestration pipeline.

    Args:
        state: Current pipeline state with vulnerabilities
        nvd_client: NVD API client (optional, uses default if None)
        epss_client: EPSS API client (optional, uses default if None)
        github_client: GitHub Advisory client (optional, uses default if None)
        osint_client: OSINT search client (optional, uses default if None)
        vector_store: Vector store adapter (optional, uses default if None)
        max_concurrent: Maximum concurrent enrichment requests

    Returns:
        State updates with enrichments dict
    """
    logger.info(
        "enrich_node_started",
        thread_id=state.get("thread_id"),
        vulnerability_count=len(state.get("vulnerabilities", [])),
    )

    vulnerabilities = state.get("vulnerabilities", [])

    if not vulnerabilities:
        logger.warning("enrich_node_skipped", reason="no_vulnerabilities")
        return {
            "enrichments": {},
            "current_node": "enrich",
        }

    try:
        # Run async enrichment in sync context
        enrichments = asyncio.run(
            _run_enrichment(
                vulnerabilities=vulnerabilities,
                nvd_client=nvd_client,
                epss_client=epss_client,
                github_client=github_client,
                osint_client=osint_client,
                vector_store=vector_store,
                max_concurrent=max_concurrent,
            )
        )

        logger.info(
            "enrich_node_complete",
            enriched_count=len(enrichments),
            total_vulnerabilities=len(vulnerabilities),
        )

        return {
            "enrichments": enrichments,
            "current_node": "enrich",
        }

    except Exception as e:
        error_msg = f"Enrichment failed: {e}"
        logger.error("enrich_node_failed", error=error_msg, exception=str(e))
        return {
            "enrichments": {},
            "errors": [error_msg],
            "current_node": "enrich",
        }


async def _run_enrichment(
    vulnerabilities: list,
    nvd_client: NVDClientPort | None,
    epss_client: EPSSClientPort | None,
    github_client: GitHubAdvisoryClientPort | None,
    osint_client: OSINTSearchClientPort | None,
    vector_store: VectorStorePort | None,
    max_concurrent: int,
) -> dict:
    """Run async enrichment using EnrichContextUseCase.

    Args:
        vulnerabilities: List of VulnerabilityRecord to enrich
        nvd_client: NVD API client
        epss_client: EPSS API client
        github_client: GitHub Advisory client
        osint_client: OSINT search client
        vector_store: Vector store adapter
        max_concurrent: Maximum concurrent requests

    Returns:
        Dictionary mapping CVE ID to EnrichmentData
    """
    from siopv.application.use_cases.enrich_context import EnrichContextUseCase
    from siopv.domain.value_objects import EnrichmentData

    # If clients are not provided, return minimal enrichments
    # This allows the node to work in test/mock scenarios
    if any(
        client is None
        for client in [nvd_client, epss_client, github_client, osint_client, vector_store]
    ):
        logger.warning(
            "enrich_node_using_minimal_enrichment",
            reason="missing_clients",
        )
        return _create_minimal_enrichments(vulnerabilities)

    use_case = EnrichContextUseCase(
        nvd_client=nvd_client,
        epss_client=epss_client,
        github_client=github_client,
        osint_client=osint_client,
        vector_store=vector_store,
    )

    result = await use_case.execute_batch(
        vulnerabilities,
        max_concurrent=max_concurrent,
    )

    # Convert results to dictionary
    enrichments: dict[str, EnrichmentData] = {}
    for enrichment_result in result.results:
        if enrichment_result.enrichment is not None:
            enrichments[enrichment_result.cve_id] = enrichment_result.enrichment

    return enrichments


def _create_minimal_enrichments(vulnerabilities: list) -> dict:
    """Create minimal enrichment data when clients are unavailable.

    This provides basic enrichment structure for testing or
    when external APIs are not configured.

    Args:
        vulnerabilities: List of VulnerabilityRecord

    Returns:
        Dictionary mapping CVE ID to minimal EnrichmentData
    """
    from siopv.domain.value_objects import EnrichmentData

    enrichments = {}
    for vuln in vulnerabilities:
        cve_id = vuln.cve_id.value
        enrichments[cve_id] = EnrichmentData(
            cve_id=cve_id,
            relevance_score=0.5,  # Default relevance
        )

    return enrichments


async def enrich_node_async(
    state: PipelineState,
    *,
    nvd_client: NVDClientPort | None = None,
    epss_client: EPSSClientPort | None = None,
    github_client: GitHubAdvisoryClientPort | None = None,
    osint_client: OSINTSearchClientPort | None = None,
    vector_store: VectorStorePort | None = None,
    max_concurrent: int = 5,
) -> dict:
    """Async version of enrich_node for use in async contexts.

    Args:
        state: Current pipeline state with vulnerabilities
        nvd_client: NVD API client
        epss_client: EPSS API client
        github_client: GitHub Advisory client
        osint_client: OSINT search client
        vector_store: Vector store adapter
        max_concurrent: Maximum concurrent requests

    Returns:
        State updates with enrichments dict
    """
    logger.info(
        "enrich_node_async_started",
        thread_id=state.get("thread_id"),
        vulnerability_count=len(state.get("vulnerabilities", [])),
    )

    vulnerabilities = state.get("vulnerabilities", [])

    if not vulnerabilities:
        logger.warning("enrich_node_async_skipped", reason="no_vulnerabilities")
        return {
            "enrichments": {},
            "current_node": "enrich",
        }

    try:
        enrichments = await _run_enrichment(
            vulnerabilities=vulnerabilities,
            nvd_client=nvd_client,
            epss_client=epss_client,
            github_client=github_client,
            osint_client=osint_client,
            vector_store=vector_store,
            max_concurrent=max_concurrent,
        )

        logger.info(
            "enrich_node_async_complete",
            enriched_count=len(enrichments),
        )

        return {
            "enrichments": enrichments,
            "current_node": "enrich",
        }

    except Exception as e:
        error_msg = f"Async enrichment failed: {e}"
        logger.error("enrich_node_async_failed", error=error_msg)
        return {
            "enrichments": {},
            "errors": [error_msg],
            "current_node": "enrich",
        }


__all__ = [
    "enrich_node",
    "enrich_node_async",
]
