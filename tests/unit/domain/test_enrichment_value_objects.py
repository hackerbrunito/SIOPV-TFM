"""Tests for enrichment domain value objects."""

import pytest
from pydantic import ValidationError

from siopv.domain.value_objects import (
    CVSSVector,
    EnrichmentData,
    EPSSScore,
    GitHubAdvisory,
    NVDEnrichment,
    OSINTResult,
)


class TestEPSSScore:
    """Tests for EPSSScore value object."""

    def test_valid_epss_score(self) -> None:
        """Test creation with valid EPSS score."""
        epss = EPSSScore(score=0.05, percentile=0.75)
        assert epss.score == 0.05
        assert epss.percentile == 0.75

    def test_score_at_boundaries(self) -> None:
        """Test EPSS score at min and max boundaries."""
        min_epss = EPSSScore(score=0.0, percentile=0.0)
        assert min_epss.score == 0.0

        max_epss = EPSSScore(score=1.0, percentile=1.0)
        assert max_epss.score == 1.0

    def test_score_below_minimum(self) -> None:
        """Test that score below 0 raises error."""
        with pytest.raises(ValidationError):
            EPSSScore(score=-0.1, percentile=0.5)

    def test_score_above_maximum(self) -> None:
        """Test that score above 1 raises error."""
        with pytest.raises(ValidationError):
            EPSSScore(score=1.1, percentile=0.5)

    def test_from_api_response(self) -> None:
        """Test factory method from API response."""
        api_data = {"epss": "0.123", "percentile": "0.85"}
        epss = EPSSScore.from_api_response(api_data)
        assert epss.score == 0.123
        assert epss.percentile == 0.85

    def test_is_high_risk(self) -> None:
        """Test high risk detection (>0.1)."""
        low_risk = EPSSScore(score=0.05, percentile=0.5)
        assert not low_risk.is_high_risk

        high_risk = EPSSScore(score=0.15, percentile=0.9)
        assert high_risk.is_high_risk

    def test_str_representation(self) -> None:
        """Test string representation."""
        epss = EPSSScore(score=0.0567, percentile=0.75)
        assert "0.0567" in str(epss)

    def test_is_frozen(self) -> None:
        """Test that EPSSScore is immutable."""
        epss = EPSSScore(score=0.5, percentile=0.5)
        with pytest.raises(ValidationError):
            epss.score = 0.9  # type: ignore[misc]


class TestCVSSVector:
    """Tests for CVSSVector value object."""

    def test_valid_cvss_vector(self) -> None:
        """Test creation with valid CVSS vector."""
        vector = CVSSVector(
            attack_vector="N",
            attack_complexity="L",
            privileges_required="N",
            user_interaction="N",
            scope="U",
            confidentiality_impact="H",
            integrity_impact="H",
            availability_impact="H",
        )
        assert vector.attack_vector == "N"
        assert vector.attack_complexity == "L"

    def test_from_vector_string_valid(self) -> None:
        """Test parsing valid CVSS vector string."""
        vector_str = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        vector = CVSSVector.from_vector_string(vector_str)

        assert vector is not None
        assert vector.attack_vector == "N"
        assert vector.attack_complexity == "L"
        assert vector.privileges_required == "N"
        assert vector.user_interaction == "N"
        assert vector.scope == "U"
        assert vector.confidentiality_impact == "H"
        assert vector.integrity_impact == "H"
        assert vector.availability_impact == "H"

    def test_from_vector_string_invalid(self) -> None:
        """Test parsing invalid vector string returns None."""
        assert CVSSVector.from_vector_string("") is None
        assert CVSSVector.from_vector_string("invalid") is None
        assert CVSSVector.from_vector_string("CVSS:2.0/AV:N") is None

    def test_from_vector_string_incomplete(self) -> None:
        """Test parsing incomplete vector string returns None."""
        vector_str = "CVSS:3.1/AV:N/AC:L"  # Missing required metrics
        assert CVSSVector.from_vector_string(vector_str) is None

    def test_to_feature_dict(self) -> None:
        """Test conversion to ML feature dictionary."""
        vector = CVSSVector(
            attack_vector="N",
            attack_complexity="L",
            privileges_required="N",
            user_interaction="N",
            scope="C",
            confidentiality_impact="H",
            integrity_impact="L",
            availability_impact="N",
        )
        features = vector.to_feature_dict()

        assert features["attack_vector"] == 3  # N = Network = 3
        assert features["attack_complexity"] == 1  # L = Low = 1
        assert features["privileges_required"] == 2  # N = None = 2
        assert features["scope"] == 1  # C = Changed = 1
        assert features["confidentiality_impact"] == 2  # H = High = 2
        assert features["integrity_impact"] == 1  # L = Low = 1
        assert features["availability_impact"] == 0  # N = None = 0

    def test_normalize_to_uppercase(self) -> None:
        """Test that values are normalized to uppercase."""
        vector = CVSSVector(
            attack_vector="n",
            attack_complexity="l",
            privileges_required="n",
            user_interaction="n",
            scope="u",
            confidentiality_impact="h",
            integrity_impact="h",
            availability_impact="h",
        )
        assert vector.attack_vector == "N"
        assert vector.attack_complexity == "L"


class TestNVDEnrichment:
    """Tests for NVDEnrichment value object."""

    def test_valid_nvd_enrichment(self) -> None:
        """Test creation with valid NVD data."""
        nvd = NVDEnrichment(
            cve_id="CVE-2021-44228",
            description="Log4j vulnerability",
            cvss_v3_score=10.0,
            has_exploit_ref=True,
        )
        assert nvd.cve_id == "CVE-2021-44228"
        assert nvd.description == "Log4j vulnerability"
        assert nvd.cvss_v3_score == 10.0
        assert nvd.has_exploit_ref is True

    def test_from_nvd_response(self) -> None:
        """Test factory method from NVD API response."""
        api_data = {
            "cve": {
                "id": "CVE-2021-44228",
                "descriptions": [
                    {"lang": "en", "value": "Apache Log4j2 vulnerability"},
                ],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "cvssData": {
                                "baseScore": 10.0,
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                            }
                        }
                    ]
                },
                "references": [
                    {"url": "https://example.com", "tags": ["Exploit"]},
                ],
                "weaknesses": [
                    {"description": [{"value": "CWE-502"}]},
                ],
                "published": "2021-12-10T10:15:00Z",
                "lastModified": "2024-01-01T00:00:00Z",
            }
        }
        nvd = NVDEnrichment.from_nvd_response(api_data)

        assert nvd.cve_id == "CVE-2021-44228"
        assert nvd.description == "Apache Log4j2 vulnerability"
        assert nvd.cvss_v3_score == 10.0
        assert nvd.cvss_v3_vector is not None
        assert nvd.has_exploit_ref is True
        assert "CWE-502" in nvd.cwe_ids
        assert len(nvd.references) == 1

    def test_days_since_publication(self) -> None:
        """Test days since publication calculation."""
        from datetime import UTC, datetime, timedelta

        past_date = datetime.now(UTC) - timedelta(days=30)
        nvd = NVDEnrichment(
            cve_id="CVE-2024-0001",
            published_date=past_date,
        )
        days = nvd.days_since_publication
        assert days is not None
        assert days >= 30

    def test_days_since_publication_none(self) -> None:
        """Test days since publication when no date."""
        nvd = NVDEnrichment(cve_id="CVE-2024-0001")
        assert nvd.days_since_publication is None


class TestGitHubAdvisory:
    """Tests for GitHubAdvisory value object."""

    def test_valid_github_advisory(self) -> None:
        """Test creation with valid GitHub advisory data."""
        advisory = GitHubAdvisory(
            ghsa_id="GHSA-jfh8-c2jp-5v3q",
            cve_id="CVE-2021-44228",
            summary="Log4j RCE vulnerability",
            severity="CRITICAL",
        )
        assert advisory.ghsa_id == "GHSA-jfh8-c2jp-5v3q"
        assert advisory.cve_id == "CVE-2021-44228"
        assert advisory.severity == "CRITICAL"

    def test_from_graphql_response(self) -> None:
        """Test factory method from GraphQL response."""
        graphql_data = {
            "ghsaId": "GHSA-jfh8-c2jp-5v3q",
            "summary": "Log4j vulnerability",
            "severity": "CRITICAL",
            "publishedAt": "2021-12-10T00:00:00Z",
            "updatedAt": "2024-01-01T00:00:00Z",
            "identifiers": [
                {"type": "CVE", "value": "CVE-2021-44228"},
                {"type": "GHSA", "value": "GHSA-jfh8-c2jp-5v3q"},
            ],
            "vulnerabilities": {
                "nodes": [
                    {
                        "package": {"ecosystem": "MAVEN", "name": "log4j-core"},
                        "vulnerableVersionRange": "< 2.17.0",
                        "firstPatchedVersion": {"identifier": "2.17.0"},
                    }
                ]
            },
        }
        advisory = GitHubAdvisory.from_graphql_response(graphql_data)

        assert advisory.ghsa_id == "GHSA-jfh8-c2jp-5v3q"
        assert advisory.cve_id == "CVE-2021-44228"
        assert advisory.summary == "Log4j vulnerability"
        assert advisory.severity == "CRITICAL"
        assert advisory.package_ecosystem == "MAVEN"
        assert advisory.package_name == "log4j-core"
        assert "2.17.0" in advisory.patched_versions


class TestOSINTResult:
    """Tests for OSINTResult value object."""

    def test_valid_osint_result(self) -> None:
        """Test creation with valid OSINT result."""
        result = OSINTResult(
            title="CVE-2021-44228 Exploit",
            url="https://example.com/exploit",
            content="Proof of concept for Log4j...",
            score=0.85,
        )
        assert result.title == "CVE-2021-44228 Exploit"
        assert result.score == 0.85

    def test_from_tavily_result(self) -> None:
        """Test factory method from Tavily API response."""
        tavily_data = {
            "title": "Log4j Exploit Analysis",
            "url": "https://security.example.com/log4j",
            "content": "Detailed analysis of the Log4j vulnerability...",
            "score": 0.92,
            "published_date": "2021-12-15",
        }
        result = OSINTResult.from_tavily_result(tavily_data)

        assert result.title == "Log4j Exploit Analysis"
        assert result.url == "https://security.example.com/log4j"
        assert result.score == 0.92
        assert result.published_date == "2021-12-15"

    def test_score_validation(self) -> None:
        """Test that score must be between 0 and 1."""
        with pytest.raises(ValidationError):
            OSINTResult(title="Test", url="http://test.com", content="", score=1.5)


class TestEnrichmentData:
    """Tests for EnrichmentData aggregate value object."""

    def test_valid_enrichment_data(self) -> None:
        """Test creation with valid enrichment data."""
        enrichment = EnrichmentData(
            cve_id="CVE-2021-44228",
            relevance_score=0.8,
        )
        assert enrichment.cve_id == "CVE-2021-44228"
        assert enrichment.relevance_score == 0.8

    def test_is_enriched(self) -> None:
        """Test is_enriched property."""
        # Not enriched (no data)
        empty = EnrichmentData(cve_id="CVE-2024-0001")
        assert not empty.is_enriched

        # Enriched with NVD
        with_nvd = EnrichmentData(
            cve_id="CVE-2024-0001",
            nvd=NVDEnrichment(cve_id="CVE-2024-0001"),
        )
        assert with_nvd.is_enriched

        # Enriched with EPSS
        with_epss = EnrichmentData(
            cve_id="CVE-2024-0001",
            epss=EPSSScore(score=0.5, percentile=0.9),
        )
        assert with_epss.is_enriched

    def test_needs_osint_fallback(self) -> None:
        """Test OSINT fallback threshold."""
        # Below threshold - needs fallback
        low_relevance = EnrichmentData(cve_id="CVE-2024-0001", relevance_score=0.5)
        assert low_relevance.needs_osint_fallback

        # At threshold - needs fallback
        at_threshold = EnrichmentData(cve_id="CVE-2024-0001", relevance_score=0.59)
        assert at_threshold.needs_osint_fallback

        # Above threshold - no fallback needed
        high_relevance = EnrichmentData(cve_id="CVE-2024-0001", relevance_score=0.6)
        assert not high_relevance.needs_osint_fallback

    def test_to_embedding_text(self) -> None:
        """Test embedding text generation."""
        enrichment = EnrichmentData(
            cve_id="CVE-2021-44228",
            nvd=NVDEnrichment(
                cve_id="CVE-2021-44228",
                description="Apache Log4j vulnerability",
                cwe_ids=["CWE-502"],
            ),
            epss=EPSSScore(score=0.9, percentile=0.99),
        )
        text = enrichment.to_embedding_text()

        assert "CVE-2021-44228" in text
        assert "Apache Log4j vulnerability" in text
        assert "CWE-502" in text
        assert "0.9" in text

    def test_full_enrichment(self) -> None:
        """Test fully enriched data."""
        enrichment = EnrichmentData(
            cve_id="CVE-2021-44228",
            nvd=NVDEnrichment(cve_id="CVE-2021-44228", description="Test"),
            epss=EPSSScore(score=0.9, percentile=0.99),
            github_advisory=GitHubAdvisory(ghsa_id="GHSA-test", cve_id="CVE-2021-44228"),
            osint_results=[
                OSINTResult(title="Test", url="http://test.com", content="", score=0.8),
            ],
            relevance_score=0.95,
        )

        assert enrichment.is_enriched
        assert not enrichment.needs_osint_fallback
        assert enrichment.nvd is not None
        assert enrichment.epss is not None
        assert enrichment.github_advisory is not None
        assert len(enrichment.osint_results) == 1
