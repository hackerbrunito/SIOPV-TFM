"""LangGraph orchestration for SIOPV pipeline.

Phase 4 implementation: Orchestration and Uncertainty Management.
Provides the StateGraph-based workflow with conditional routing
based on ML/LLM confidence discrepancy.

Based on specification section 3.4.
"""

from __future__ import annotations

from siopv.application.orchestration.edges import (
    RouteType,
    calculate_batch_discrepancies,
    calculate_discrepancy,
    route_after_classify,
    route_after_escalate,
    should_escalate_route,
)
from siopv.application.orchestration.graph import (
    DEFAULT_CHECKPOINT_DB,
    PipelineGraphBuilder,
    create_pipeline_graph,
    run_pipeline,
)
from siopv.application.orchestration.nodes import (
    classify_node,
    enrich_node,
    escalate_node,
    ingest_node,
)
from siopv.application.orchestration.state import (
    DiscrepancyHistory,
    DiscrepancyResult,
    PipelineState,
    ThresholdConfig,
    create_initial_state,
)
from siopv.application.orchestration.utils import (
    calculate_escalation_candidates,
    check_any_escalation_needed,
    should_escalate_cve,
)

__all__ = [
    # State
    "DiscrepancyHistory",
    "DiscrepancyResult",
    "PipelineState",
    "ThresholdConfig",
    "create_initial_state",
    # Nodes
    "classify_node",
    "enrich_node",
    "escalate_node",
    "ingest_node",
    # Edges
    "RouteType",
    "calculate_batch_discrepancies",
    "calculate_discrepancy",
    "route_after_classify",
    "route_after_escalate",
    "should_escalate_route",
    # Graph
    "DEFAULT_CHECKPOINT_DB",
    "PipelineGraphBuilder",
    "create_pipeline_graph",
    "run_pipeline",
    # Utils
    "calculate_escalation_candidates",
    "check_any_escalation_needed",
    "should_escalate_cve",
]
