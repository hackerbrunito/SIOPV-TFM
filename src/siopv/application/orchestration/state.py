"""Pipeline State schema for LangGraph orchestration.

Defines the TypedDict state schema for the SIOPV vulnerability processing
pipeline. LangGraph requires TypedDict (not Pydantic BaseModel) for state.

Based on specification section 3.4.
"""

from __future__ import annotations

import operator
from dataclasses import dataclass, field
from typing import Annotated, TypedDict

from siopv.application.use_cases.classify_risk import ClassificationResult
from siopv.domain.entities import VulnerabilityRecord
from siopv.domain.value_objects import EnrichmentData


class PipelineState(TypedDict, total=False):
    """LangGraph state schema for the SIOPV pipeline.

    Uses TypedDict as required by LangGraph StateGraph.
    Fields marked with Annotated[..., operator.add] are append-only.

    Attributes:
        vulnerabilities: List of parsed VulnerabilityRecord from Phase 1
        enrichments: Dict mapping CVE ID to EnrichmentData from Phase 2
        classifications: Dict mapping CVE ID to ClassificationResult from Phase 3
        escalated_cves: List of CVE IDs requiring human review
        llm_confidence: Dict mapping CVE ID to LLM confidence score (0.0-1.0)
        processed_count: Number of vulnerabilities processed
        errors: List of error messages encountered during processing
        report_path: Path to the input Trivy report (optional, for file-based ingestion)
        thread_id: Unique identifier for this pipeline execution
        current_node: Name of the currently executing node
    """

    # Phase 1 - Ingestion
    vulnerabilities: list[VulnerabilityRecord]
    report_path: str | None

    # Phase 2 - Enrichment
    enrichments: dict[str, EnrichmentData]

    # Phase 3 - Classification
    classifications: dict[str, ClassificationResult]

    # Phase 4 - Orchestration state
    escalated_cves: Annotated[list[str], operator.add]
    llm_confidence: dict[str, float]
    processed_count: int
    errors: Annotated[list[str], operator.add]

    # Metadata
    thread_id: str
    current_node: str


@dataclass(frozen=True)
class DiscrepancyResult:
    """Result of discrepancy calculation between ML and LLM scores.

    Attributes:
        cve_id: CVE identifier
        ml_score: ML model risk probability (0.0-1.0)
        llm_confidence: LLM confidence score (0.0-1.0)
        discrepancy: Absolute difference |ml_score - llm_confidence|
        should_escalate: Whether this CVE should be escalated to human review
    """

    cve_id: str
    ml_score: float
    llm_confidence: float
    discrepancy: float
    should_escalate: bool


@dataclass
class ThresholdConfig:
    """Configuration for the adaptive uncertainty threshold.

    Attributes:
        base_threshold: Base discrepancy threshold (default 0.3 from spec)
        confidence_floor: LLM confidence below this triggers escalation (default 0.7)
        percentile: Percentile for adaptive threshold calculation (default 90)
        history_size: Number of historical discrepancies to track (default 500)
    """

    base_threshold: float = 0.3
    confidence_floor: float = 0.7
    percentile: int = 90
    history_size: int = 500


@dataclass
class DiscrepancyHistory:
    """Tracks historical discrepancies for adaptive threshold calculation.

    Maintains a rolling window of discrepancies from past evaluations
    to compute the adaptive percentile-based threshold.
    """

    values: list[float] = field(default_factory=list)
    max_size: int = 500

    def add(self, discrepancy: float) -> None:
        """Add a discrepancy value to history.

        Args:
            discrepancy: The discrepancy value to add
        """
        self.values.append(discrepancy)
        if len(self.values) > self.max_size:
            self.values = self.values[-self.max_size :]

    def get_percentile(self, percentile: int) -> float:
        """Calculate the specified percentile of historical discrepancies.

        Args:
            percentile: The percentile to calculate (0-100)

        Returns:
            The percentile value, or 0.3 (base threshold) if no history
        """
        if not self.values:
            return 0.3  # Default base threshold

        sorted_values = sorted(self.values)
        index = int(len(sorted_values) * percentile / 100)
        index = min(index, len(sorted_values) - 1)
        return sorted_values[index]


def create_initial_state(
    *,
    report_path: str | None = None,
    thread_id: str | None = None,
) -> PipelineState:
    """Create initial pipeline state with default values.

    Args:
        report_path: Optional path to Trivy report file
        thread_id: Optional thread ID for checkpointing

    Returns:
        PipelineState with initialized fields
    """
    import uuid

    return PipelineState(
        vulnerabilities=[],
        report_path=report_path,
        enrichments={},
        classifications={},
        escalated_cves=[],
        llm_confidence={},
        processed_count=0,
        errors=[],
        thread_id=thread_id or str(uuid.uuid4()),
        current_node="start",
    )


__all__ = [
    "DiscrepancyHistory",
    "DiscrepancyResult",
    "PipelineState",
    "ThresholdConfig",
    "create_initial_state",
]
