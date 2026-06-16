"""Tests for escalate_node (non-blocking HITL flagging).

The node tags uncertain CVEs for human review and returns state updates; it does
NOT call interrupt() and never blocks the pipeline. Human decisions are applied
out-of-band (Streamlit dashboard / webhook).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from unittest.mock import patch

import pytest

from siopv.application.orchestration.nodes.escalate_node import (
    _build_escalation_summary,
    _calculate_escalation_level,
    escalate_node,
    get_escalation_summary,
)
from siopv.application.orchestration.state import create_initial_state
from siopv.application.use_cases.classify_risk import ClassificationResult
from siopv.domain.value_objects.discrepancy import ThresholdConfig
from siopv.domain.value_objects.risk_score import RiskScore

_DEFAULT_THRESHOLD_CONFIG = ThresholdConfig(
    base_threshold=0.3,
    confidence_floor=0.7,
    percentile=90,
    history_size=500,
    default_confidence=0.5,
)
_DEFAULT_LEVEL_THRESHOLDS: tuple[tuple[int, int], ...] = ((24, 3), (8, 2), (4, 1))
_DEFAULT_REVIEW_DEADLINE_HOURS = 24


class TestEscalateNode:
    """Tests for escalate_node function."""

    @pytest.fixture
    def mock_classification_high_confidence(self) -> ClassificationResult:
        """Create classification with high confidence (no escalation needed)."""
        return ClassificationResult(
            cve_id="CVE-2024-1111",
            risk_score=RiskScore.from_prediction(
                cve_id="CVE-2024-1111",
                probability=0.8,
            ),
        )

    @pytest.fixture
    def mock_classification_low_confidence(self) -> ClassificationResult:
        """Create classification that should trigger escalation."""
        return ClassificationResult(
            cve_id="CVE-2024-2222",
            risk_score=RiskScore.from_prediction(
                cve_id="CVE-2024-2222",
                probability=0.9,
            ),
        )

    @pytest.fixture
    def mock_classification_no_score(self) -> ClassificationResult:
        """Create classification with no risk score."""
        return ClassificationResult(
            cve_id="CVE-2024-3333",
            risk_score=None,
        )

    def test_escalate_node_no_classifications(self) -> None:
        """Test escalate node with no classifications returns escalation_required=False."""
        state = create_initial_state()

        result = escalate_node(
            state,
            level_thresholds=_DEFAULT_LEVEL_THRESHOLDS,
            review_deadline_hours=_DEFAULT_REVIEW_DEADLINE_HOURS,
            threshold_config=_DEFAULT_THRESHOLD_CONFIG,
        )

        assert result["escalated_cves"] == []
        assert result["escalation_required"] is False
        assert result["current_node"] == "escalate"

    def test_escalate_node_no_escalation_needed(
        self, mock_classification_high_confidence: ClassificationResult
    ) -> None:
        """Test escalate node when no escalation needed (no interrupt called)."""
        state = {
            **create_initial_state(),
            "classifications": {"CVE-2024-1111": mock_classification_high_confidence},
            "llm_confidence": {"CVE-2024-1111": 0.85},
        }

        result = escalate_node(
            state,
            level_thresholds=_DEFAULT_LEVEL_THRESHOLDS,
            review_deadline_hours=_DEFAULT_REVIEW_DEADLINE_HOURS,
            threshold_config=_DEFAULT_THRESHOLD_CONFIG,
        )

        assert result["current_node"] == "escalate"
        assert result["escalation_required"] is False
        assert len(result["escalated_cves"]) == 0

    def test_escalate_node_flags_candidates_without_interrupt(
        self,
        mock_classification_low_confidence: ClassificationResult,
    ) -> None:
        """Candidates are flagged for review and the pipeline continues (no interrupt).

        Phase B redesign: escalate_node is non-blocking — it tags CVEs and returns
        state updates. Human review happens out-of-band (dashboard/webhook), so the
        node never calls ``interrupt()`` and never blocks the CI/CD pipeline.
        """
        state = {
            **create_initial_state(),
            "classifications": {"CVE-2024-2222": mock_classification_low_confidence},
            "llm_confidence": {"CVE-2024-2222": 0.4},
        }

        result = escalate_node(
            state,
            level_thresholds=_DEFAULT_LEVEL_THRESHOLDS,
            review_deadline_hours=_DEFAULT_REVIEW_DEADLINE_HOURS,
            threshold_config=_DEFAULT_THRESHOLD_CONFIG,
        )

        assert result["escalation_required"] is True
        assert "CVE-2024-2222" in result["escalated_cves"]
        assert result["current_node"] == "escalate"

    def test_escalate_node_returns_review_metadata(
        self,
        mock_classification_low_confidence: ClassificationResult,
    ) -> None:
        """The returned state carries the review-tracking metadata used downstream."""
        state = {
            **create_initial_state(),
            "classifications": {"CVE-2024-2222": mock_classification_low_confidence},
            "llm_confidence": {"CVE-2024-2222": 0.4},
        }

        result = escalate_node(
            state,
            level_thresholds=_DEFAULT_LEVEL_THRESHOLDS,
            review_deadline_hours=_DEFAULT_REVIEW_DEADLINE_HOURS,
            threshold_config=_DEFAULT_THRESHOLD_CONFIG,
        )

        assert "CVE-2024-2222" in result["escalated_cves"]
        assert result["escalation_timestamp"] is not None
        assert result["review_deadline"] is not None
        assert result["escalation_level"] in (0, 1, 2, 3)

    def test_escalate_node_leaves_human_decision_unset(
        self,
        mock_classification_low_confidence: ClassificationResult,
    ) -> None:
        """Human decisions are applied out-of-band; the node initializes them to None."""
        state = {
            **create_initial_state(),
            "classifications": {"CVE-2024-2222": mock_classification_low_confidence},
            "llm_confidence": {"CVE-2024-2222": 0.4},
        }

        result = escalate_node(
            state,
            level_thresholds=_DEFAULT_LEVEL_THRESHOLDS,
            review_deadline_hours=_DEFAULT_REVIEW_DEADLINE_HOURS,
            threshold_config=_DEFAULT_THRESHOLD_CONFIG,
        )

        assert result["human_decision"] is None
        assert result["human_modified_score"] is None
        assert result["human_modified_recommendation"] is None

    def test_escalation_timestamp_and_deadline_set(
        self,
        mock_classification_low_confidence: ClassificationResult,
    ) -> None:
        """Test that escalation_timestamp and review_deadline are set correctly."""
        state = {
            **create_initial_state(),
            "classifications": {"CVE-2024-2222": mock_classification_low_confidence},
            "llm_confidence": {"CVE-2024-2222": 0.4},
        }

        result = escalate_node(
            state,
            level_thresholds=_DEFAULT_LEVEL_THRESHOLDS,
            review_deadline_hours=_DEFAULT_REVIEW_DEADLINE_HOURS,
            threshold_config=_DEFAULT_THRESHOLD_CONFIG,
        )

        assert result["escalation_timestamp"] is not None
        assert result["review_deadline"] is not None

        # Verify deadline is ~24h after timestamp
        ts = datetime.fromisoformat(result["escalation_timestamp"])
        dl = datetime.fromisoformat(result["review_deadline"])
        delta = dl - ts
        assert timedelta(hours=23, minutes=59) <= delta <= timedelta(hours=24, minutes=1)

    def test_escalate_node_missing_risk_score_escalates(
        self,
        mock_classification_no_score: ClassificationResult,
    ) -> None:
        """Test escalate node escalates CVE with missing risk score."""
        state = {
            **create_initial_state(),
            "classifications": {"CVE-2024-3333": mock_classification_no_score},
            "llm_confidence": {"CVE-2024-3333": 0.8},
        }

        result = escalate_node(
            state,
            level_thresholds=_DEFAULT_LEVEL_THRESHOLDS,
            review_deadline_hours=_DEFAULT_REVIEW_DEADLINE_HOURS,
            threshold_config=_DEFAULT_THRESHOLD_CONFIG,
        )

        assert result["escalation_required"] is True
        assert "CVE-2024-3333" in result["escalated_cves"]


class TestCalculateEscalationLevel:
    """Tests for _calculate_escalation_level function."""

    def test_level_0_no_elapsed_time(self) -> None:
        """Test level 0 when virtually no time has elapsed."""
        now = datetime.now(UTC)
        timestamp = now.isoformat()

        level = _calculate_escalation_level(timestamp, level_thresholds=_DEFAULT_LEVEL_THRESHOLDS)

        assert level == 0

    def test_level_0_under_4_hours(self) -> None:
        """Test level 0 when under 4 hours have elapsed."""
        now = datetime.now(UTC)
        timestamp = (now - timedelta(hours=3, minutes=59)).isoformat()

        level = _calculate_escalation_level(timestamp, level_thresholds=_DEFAULT_LEVEL_THRESHOLDS)

        assert level == 0

    def test_level_1_over_4_hours(self) -> None:
        """Test level 1 (analyst notified) when >4h elapsed."""
        now = datetime.now(UTC)
        timestamp = (now - timedelta(hours=5)).isoformat()

        level = _calculate_escalation_level(timestamp, level_thresholds=_DEFAULT_LEVEL_THRESHOLDS)

        assert level == 1

    def test_level_2_over_8_hours(self) -> None:
        """Test level 2 (lead escalated) when >8h elapsed."""
        now = datetime.now(UTC)
        timestamp = (now - timedelta(hours=9)).isoformat()

        level = _calculate_escalation_level(timestamp, level_thresholds=_DEFAULT_LEVEL_THRESHOLDS)

        assert level == 2

    def test_level_3_over_24_hours(self) -> None:
        """Test level 3 (auto-approved) when >24h elapsed."""
        now = datetime.now(UTC)
        timestamp = (now - timedelta(hours=25)).isoformat()

        level = _calculate_escalation_level(timestamp, level_thresholds=_DEFAULT_LEVEL_THRESHOLDS)

        assert level == 3

    def test_level_boundary_exactly_4_hours(self) -> None:
        """Test boundary: exactly 4h should be level 0 (need >4h)."""
        now = datetime.now(UTC)
        # Slightly under 4h to stay at level 0
        timestamp = (now - timedelta(hours=4, seconds=-1)).isoformat()

        level = _calculate_escalation_level(timestamp, level_thresholds=_DEFAULT_LEVEL_THRESHOLDS)

        assert level == 0

    def test_level_boundary_just_over_24_hours(self) -> None:
        """Test boundary: just over 24h should be level 3."""
        now = datetime.now(UTC)
        timestamp = (now - timedelta(hours=24, seconds=1)).isoformat()

        level = _calculate_escalation_level(timestamp, level_thresholds=_DEFAULT_LEVEL_THRESHOLDS)

        assert level == 3


class TestGetEscalationSummary:
    """Tests for get_escalation_summary function."""

    @pytest.fixture
    def mock_classification(self) -> ClassificationResult:
        """Create mock classification for summary."""
        return ClassificationResult(
            cve_id="CVE-2024-1234",
            risk_score=RiskScore.from_prediction(
                cve_id="CVE-2024-1234",
                probability=0.85,
            ),
        )

    def test_get_escalation_summary_empty(self) -> None:
        """Test escalation summary with no escalations."""
        state = {
            **create_initial_state(),
            "escalated_cves": [],
            "classifications": {},
            "llm_confidence": {},
        }

        summary = get_escalation_summary(state)

        assert summary["total_escalated"] == 0
        assert summary["total_processed"] == 0
        assert summary["escalation_rate"] == 0
        assert summary["escalated_details"] == []

    def test_get_escalation_summary_with_escalations(
        self, mock_classification: ClassificationResult
    ) -> None:
        """Test escalation summary with escalated CVEs."""
        state = {
            **create_initial_state(),
            "escalated_cves": ["CVE-2024-1234"],
            "classifications": {"CVE-2024-1234": mock_classification},
            "llm_confidence": {"CVE-2024-1234": 0.5},
        }

        summary = get_escalation_summary(state)

        assert summary["total_escalated"] == 1
        assert summary["total_processed"] == 1
        assert summary["escalation_rate"] == 100.0
        assert len(summary["escalated_details"]) == 1

        detail = summary["escalated_details"][0]
        assert detail["cve_id"] == "CVE-2024-1234"
        assert detail["llm_confidence"] == 0.5
        assert detail["ml_score"] == 0.85
        assert detail["discrepancy"] == pytest.approx(0.35, rel=0.01)

    def test_get_escalation_summary_sorts_by_discrepancy(self) -> None:
        """Test escalation summary sorts by discrepancy (highest first)."""
        classification1 = ClassificationResult(
            cve_id="CVE-2024-1111",
            risk_score=RiskScore.from_prediction(
                cve_id="CVE-2024-1111",
                probability=0.9,
            ),
        )
        classification2 = ClassificationResult(
            cve_id="CVE-2024-2222",
            risk_score=RiskScore.from_prediction(
                cve_id="CVE-2024-2222",
                probability=0.5,
            ),
        )

        state = {
            **create_initial_state(),
            "escalated_cves": ["CVE-2024-1111", "CVE-2024-2222"],
            "classifications": {
                "CVE-2024-1111": classification1,
                "CVE-2024-2222": classification2,
            },
            "llm_confidence": {
                "CVE-2024-1111": 0.5,  # discrepancy = 0.4
                "CVE-2024-2222": 0.45,  # discrepancy = 0.05
            },
        }

        summary = get_escalation_summary(state)

        assert summary["escalated_details"][0]["cve_id"] == "CVE-2024-1111"
        assert summary["escalated_details"][1]["cve_id"] == "CVE-2024-2222"

    def test_get_escalation_summary_handles_missing_risk_score(self) -> None:
        """Test escalation summary handles CVE with missing risk score."""
        classification = ClassificationResult(
            cve_id="CVE-2024-9999",
            risk_score=None,
        )

        state = {
            **create_initial_state(),
            "escalated_cves": ["CVE-2024-9999"],
            "classifications": {"CVE-2024-9999": classification},
            "llm_confidence": {"CVE-2024-9999": 0.6},
        }

        summary = get_escalation_summary(state)

        assert len(summary["escalated_details"]) == 1
        detail = summary["escalated_details"][0]
        assert detail["cve_id"] == "CVE-2024-9999"
        assert detail["ml_score"] is None
        assert detail["discrepancy"] is None


class TestEscalateNodeErrorBranches:
    """Tests for uncovered error branches in escalate_node."""

    def test_level_thresholds_none_raises_value_error(self) -> None:
        """Test _calculate_escalation_level raises when level_thresholds is None."""
        now = datetime.now(UTC)
        with pytest.raises(ValueError, match="level_thresholds must be provided"):
            _calculate_escalation_level(now.isoformat(), level_thresholds=None)

    def test_review_deadline_hours_none_yields_null_deadline(self) -> None:
        """review_deadline_hours=None yields a null deadline; escalation still proceeds.

        The non-blocking redesign no longer raises when the deadline is unset — the
        review_deadline is simply omitted (None) while the CVE is still flagged.
        """
        classification = ClassificationResult(
            cve_id="CVE-2024-2222",
            risk_score=RiskScore.from_prediction(cve_id="CVE-2024-2222", probability=0.9),
        )
        state = {
            **create_initial_state(),
            "classifications": {"CVE-2024-2222": classification},
            "llm_confidence": {"CVE-2024-2222": 0.4},
        }

        result = escalate_node(
            state,
            level_thresholds=_DEFAULT_LEVEL_THRESHOLDS,
            review_deadline_hours=None,
            threshold_config=_DEFAULT_THRESHOLD_CONFIG,
        )

        assert result["escalation_required"] is True
        assert result["review_deadline"] is None
        assert result["escalation_timestamp"] is not None

    def test_identify_candidates_exception_returns_empty(self) -> None:
        """Test escalate_node returns empty escalation on internal exception."""
        classification = ClassificationResult(
            cve_id="CVE-2024-2222",
            risk_score=RiskScore.from_prediction(cve_id="CVE-2024-2222", probability=0.9),
        )
        state = {
            **create_initial_state(),
            "classifications": {"CVE-2024-2222": classification},
            "llm_confidence": {"CVE-2024-2222": 0.4},
        }

        with patch(
            "siopv.application.orchestration.nodes.escalate_node._identify_escalation_candidates",
            side_effect=RuntimeError("boom"),
        ):
            result = escalate_node(
                state,
                level_thresholds=_DEFAULT_LEVEL_THRESHOLDS,
                review_deadline_hours=_DEFAULT_REVIEW_DEADLINE_HOURS,
                threshold_config=_DEFAULT_THRESHOLD_CONFIG,
            )

        assert result["escalated_cves"] == []
        assert result["escalation_required"] is False
        assert any("Escalation analysis failed" in e for e in result["errors"])


class TestBuildEscalationSummary:
    """Tests for the _build_escalation_summary helper.

    Retained from the original interrupt-payload design; still present in the
    module (see project rule: orphaned-but-implemented code is investigated, not
    deleted) and exercised here so its behavior stays covered and documented.
    """

    def test_summary_with_risk_score(self) -> None:
        """A classified CVE yields ml_score, confidence and their discrepancy."""
        classification = ClassificationResult(
            cve_id="CVE-2024-2222",
            risk_score=RiskScore.from_prediction(cve_id="CVE-2024-2222", probability=0.9),
        )
        summaries = _build_escalation_summary(
            ["CVE-2024-2222"],
            {"CVE-2024-2222": classification},
            {"CVE-2024-2222": 0.4},
        )

        assert len(summaries) == 1
        entry = summaries[0]
        assert entry["cve_id"] == "CVE-2024-2222"
        assert entry["ml_score"] == pytest.approx(0.9)
        assert entry["llm_confidence"] == pytest.approx(0.4)
        assert entry["discrepancy"] == pytest.approx(0.5)

    def test_summary_missing_classification_defaults_to_zero(self) -> None:
        """An escalated CVE absent from classifications defaults ml_score to 0.0."""
        summaries = _build_escalation_summary(["CVE-2024-9999"], {}, {})

        assert len(summaries) == 1
        entry = summaries[0]
        assert entry["cve_id"] == "CVE-2024-9999"
        assert entry["ml_score"] == 0.0
        assert entry["llm_confidence"] == 0.0
        assert entry["discrepancy"] == 0.0
