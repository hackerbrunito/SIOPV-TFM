"""Tests for escalate_node."""

from __future__ import annotations

import pytest

from siopv.application.orchestration.nodes.escalate_node import (
    escalate_node,
    get_escalation_summary,
)
from siopv.application.orchestration.state import create_initial_state
from siopv.application.use_cases.classify_risk import ClassificationResult
from siopv.domain.value_objects.risk_score import RiskScore


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

    def test_escalate_node_no_classifications(self):
        """Test escalate node with no classifications."""
        state = create_initial_state()

        result = escalate_node(state)

        assert result["escalated_cves"] == []
        assert result["current_node"] == "escalate"

    def test_escalate_node_no_escalation_needed(
        self, mock_classification_high_confidence: ClassificationResult
    ):
        """Test escalate node when no escalation needed."""
        state = {
            **create_initial_state(),
            "classifications": {"CVE-2024-1111": mock_classification_high_confidence},
            "llm_confidence": {"CVE-2024-1111": 0.85},  # High confidence, low discrepancy
        }

        result = escalate_node(state)

        assert result["current_node"] == "escalate"
        # With high confidence and low discrepancy, no escalation
        assert len(result["escalated_cves"]) == 0

    def test_escalate_node_all_escalate_high_discrepancy(
        self, mock_classification_low_confidence: ClassificationResult
    ):
        """Test escalate node when high discrepancy triggers escalation."""
        state = {
            **create_initial_state(),
            "classifications": {"CVE-2024-2222": mock_classification_low_confidence},
            "llm_confidence": {"CVE-2024-2222": 0.4},  # High discrepancy (0.9 - 0.4 = 0.5)
        }

        result = escalate_node(state)

        assert result["current_node"] == "escalate"
        assert "CVE-2024-2222" in result["escalated_cves"]

    def test_escalate_node_escalate_low_confidence(
        self, mock_classification_high_confidence: ClassificationResult
    ):
        """Test escalate node when low LLM confidence triggers escalation."""
        state = {
            **create_initial_state(),
            "classifications": {"CVE-2024-1111": mock_classification_high_confidence},
            "llm_confidence": {"CVE-2024-1111": 0.5},  # Below 0.7 threshold
        }

        result = escalate_node(state)

        assert result["current_node"] == "escalate"
        assert "CVE-2024-1111" in result["escalated_cves"]

    def test_escalate_node_missing_risk_score_escalates(
        self, mock_classification_no_score: ClassificationResult
    ):
        """Test escalate node escalates CVE with missing risk score."""
        state = {
            **create_initial_state(),
            "classifications": {"CVE-2024-3333": mock_classification_no_score},
            "llm_confidence": {"CVE-2024-3333": 0.8},
        }

        result = escalate_node(state)

        assert result["current_node"] == "escalate"
        # Missing risk score should trigger escalation
        assert "CVE-2024-3333" in result["escalated_cves"]

    def test_escalate_node_mixed_escalation(
        self,
        mock_classification_high_confidence: ClassificationResult,
        mock_classification_low_confidence: ClassificationResult,
    ):
        """Test escalate node with mixed escalation scenarios."""
        state = {
            **create_initial_state(),
            "classifications": {
                "CVE-2024-1111": mock_classification_high_confidence,
                "CVE-2024-2222": mock_classification_low_confidence,
            },
            "llm_confidence": {
                "CVE-2024-1111": 0.85,  # No escalation (high confidence, low discrepancy)
                "CVE-2024-2222": 0.5,  # Escalate (low confidence)
            },
        }

        result = escalate_node(state)

        assert result["current_node"] == "escalate"
        # Only CVE-2024-2222 should be escalated
        assert "CVE-2024-2222" in result["escalated_cves"]


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

    def test_get_escalation_summary_empty(self):
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
    ):
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

    def test_get_escalation_summary_sorts_by_discrepancy(self):
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

        # Should be sorted by discrepancy, highest first
        assert summary["escalated_details"][0]["cve_id"] == "CVE-2024-1111"
        assert summary["escalated_details"][1]["cve_id"] == "CVE-2024-2222"

    def test_get_escalation_summary_handles_missing_risk_score(self):
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
