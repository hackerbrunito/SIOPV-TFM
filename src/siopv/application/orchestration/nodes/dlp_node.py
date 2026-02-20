"""DLP guardrail node for LangGraph pipeline.

Sanitizes vulnerability descriptions before they proceed to the enrichment
node. Implements Phase 6: Privacy/DLP guardrail layer.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

import structlog

from siopv.domain.privacy.entities import SanitizationContext

if TYPE_CHECKING:
    from siopv.application.orchestration.state import PipelineState
    from siopv.application.ports.dlp import DLPPort

logger = structlog.get_logger(__name__)


def dlp_node(
    state: PipelineState,
    *,
    dlp_port: DLPPort | None = None,
) -> dict[str, object]:
    """DLP guardrail node — sanitizes vulnerability descriptions before enrichment.

    Reads vulnerabilities from state, runs each description through the DLP
    port (Presidio + optional Haiku validation), and returns a summary of
    redactions. Does NOT modify the vulnerability records themselves; the
    sanitized text is recorded in dlp_result for audit purposes.

    Skips gracefully if no DLP port is configured (logs a warning).

    Args:
        state: Current pipeline state containing the ingested vulnerabilities.
        dlp_port: DLP port implementation (PresidioAdapter). If None, node
            is skipped with a warning.

    Returns:
        State update dict with ``current_node`` and ``dlp_result`` fields.
    """
    vulnerabilities = state.get("vulnerabilities", [])

    if dlp_port is None:
        logger.warning(
            "dlp_node_skipped",
            reason="No DLP port configured",
            vulnerability_count=len(vulnerabilities),
        )
        return {
            "current_node": "dlp",
            "dlp_result": {"skipped": True, "reason": "no_dlp_port"},
        }

    if not vulnerabilities:
        logger.info("dlp_node_no_vulnerabilities")
        return {
            "current_node": "dlp",
            "dlp_result": {
                "skipped": False,
                "processed": 0,
                "total_redactions": 0,
                "per_cve": {},
            },
        }

    total_redactions = 0
    per_cve: dict[str, object] = {}

    for vuln in vulnerabilities:
        cve_id = vuln.cve_id.value
        description = vuln.description or ""

        ctx = SanitizationContext(text=description)
        result = asyncio.run(dlp_port.sanitize(ctx))

        per_cve[cve_id] = {
            "redactions": result.total_redactions,
            "presidio_passed": result.presidio_passed,
            "semantic_passed": result.semantic_passed,
            "contains_pii": result.contains_pii,
        }
        total_redactions += result.total_redactions

    logger.info(
        "dlp_node_complete",
        vulnerability_count=len(vulnerabilities),
        total_redactions=total_redactions,
        vulnerabilities_with_pii=sum(
            1 for v in per_cve.values() if isinstance(v, dict) and v.get("redactions", 0) > 0
        ),
    )

    return {
        "current_node": "dlp",
        "dlp_result": {
            "skipped": False,
            "processed": len(vulnerabilities),
            "total_redactions": total_redactions,
            "per_cve": per_cve,
        },
    }


__all__ = ["dlp_node"]
