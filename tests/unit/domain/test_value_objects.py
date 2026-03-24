"""Tests for domain value objects."""

import pytest
from pydantic import ValidationError

from siopv.domain.value_objects import (
    CVEId,
    CVSSScore,
    LayerInfo,
    PackageVersion,
)


class TestCVEId:
    """Tests for CVEId value object."""

    def test_valid_cve_id(self) -> None:
        """Test creation with valid CVE ID format."""
        cve = CVEId(value="CVE-2024-12345")
        assert cve.value == "CVE-2024-12345"
        assert str(cve) == "CVE-2024-12345"

    def test_valid_cve_id_long_number(self) -> None:
        """Test CVE ID with longer numeric suffix."""
        cve = CVEId(value="CVE-2026-1234567")
        assert cve.value == "CVE-2026-1234567"

    def test_invalid_cve_id_format(self) -> None:
        """Test that invalid CVE ID format raises error."""
        with pytest.raises(ValidationError) as exc_info:
            CVEId(value="INVALID-2024-12345")
        assert "Invalid CVE ID format" in str(exc_info.value)

    def test_invalid_cve_id_missing_prefix(self) -> None:
        """Test CVE ID without CVE prefix."""
        with pytest.raises(ValidationError):
            CVEId(value="2024-12345")

    def test_invalid_cve_id_wrong_separator(self) -> None:
        """Test CVE ID with wrong separator."""
        with pytest.raises(ValidationError):
            CVEId(value="CVE_2024_12345")

    def test_cve_id_is_frozen(self) -> None:
        """Test that CVEId is immutable."""
        cve = CVEId(value="CVE-2024-12345")
        with pytest.raises(ValidationError):
            cve.value = "CVE-2024-99999"  # type: ignore[misc]

    def test_cve_id_hashable(self) -> None:
        """Test that CVEId can be used in sets/dicts."""
        cve1 = CVEId(value="CVE-2024-12345")
        cve2 = CVEId(value="CVE-2024-12345")
        cve3 = CVEId(value="CVE-2024-99999")

        assert hash(cve1) == hash(cve2)
        assert hash(cve1) != hash(cve3)

        cve_set = {cve1, cve2, cve3}
        assert len(cve_set) == 2


class TestCVSSScore:
    """Tests for CVSSScore value object."""

    def test_valid_score(self) -> None:
        """Test creation with valid CVSS score."""
        score = CVSSScore(value=7.5)
        assert score.value == 7.5
        assert str(score) == "7.5"
        assert float(score) == 7.5

    def test_score_at_boundaries(self) -> None:
        """Test CVSS score at min and max boundaries."""
        min_score = CVSSScore(value=0.0)
        assert min_score.value == 0.0

        max_score = CVSSScore(value=10.0)
        assert max_score.value == 10.0

    def test_score_below_minimum(self) -> None:
        """Test that score below 0 raises error."""
        with pytest.raises(ValidationError):
            CVSSScore(value=-0.1)

    def test_score_above_maximum(self) -> None:
        """Test that score above 10 raises error."""
        with pytest.raises(ValidationError):
            CVSSScore(value=10.1)

    def test_from_float_with_value(self) -> None:
        """Test factory method with valid value."""
        score = CVSSScore.from_float(8.5)
        assert score is not None
        assert score.value == 8.5

    def test_from_float_with_none(self) -> None:
        """Test factory method with None returns None."""
        score = CVSSScore.from_float(None)
        assert score is None

    def test_score_is_frozen(self) -> None:
        """Test that CVSSScore is immutable."""
        score = CVSSScore(value=5.0)
        with pytest.raises(ValidationError):
            score.value = 9.0  # type: ignore[misc]


class TestPackageVersion:
    """Tests for PackageVersion value object."""

    def test_valid_version(self) -> None:
        """Test creation with valid version string."""
        version = PackageVersion(value="1.2.3")
        assert version.value == "1.2.3"
        assert str(version) == "1.2.3"

    def test_complex_version_string(self) -> None:
        """Test complex version strings."""
        version = PackageVersion(value="3.0.3-r1")
        assert version.value == "3.0.3-r1"

    def test_empty_version_raises_error(self) -> None:
        """Test that empty version string raises error."""
        with pytest.raises(ValidationError):
            PackageVersion(value="")

    def test_version_is_frozen(self) -> None:
        """Test that PackageVersion is immutable."""
        version = PackageVersion(value="1.0.0")
        with pytest.raises(ValidationError):
            version.value = "2.0.0"  # type: ignore[misc]


class TestLayerInfo:
    """Tests for LayerInfo value object."""

    def test_valid_layer_info(self) -> None:
        """Test creation with valid layer info."""
        layer = LayerInfo(
            digest="sha256:abc123",
            diff_id="sha256:def456",
        )
        assert layer.digest == "sha256:abc123"
        assert layer.diff_id == "sha256:def456"

    def test_layer_info_with_none_values(self) -> None:
        """Test layer info with None values."""
        layer = LayerInfo(digest=None, diff_id=None)
        assert layer.digest is None
        assert layer.diff_id is None

    def test_from_trivy_with_data(self) -> None:
        """Test factory method with Trivy layer data."""
        trivy_data = {
            "Digest": "sha256:abc123",
            "DiffID": "sha256:def456",
        }
        layer = LayerInfo.from_trivy(trivy_data)
        assert layer is not None
        assert layer.digest == "sha256:abc123"
        assert layer.diff_id == "sha256:def456"

    def test_from_trivy_with_none(self) -> None:
        """Test factory method with None returns None."""
        layer = LayerInfo.from_trivy(None)
        assert layer is None

    def test_from_trivy_with_empty_dict(self) -> None:
        """Test factory method with empty dict returns None (no useful data)."""
        layer = LayerInfo.from_trivy({})
        # Empty dict has no layer info, so returns None
        assert layer is None

    def test_layer_info_is_frozen(self) -> None:
        """Test that LayerInfo is immutable."""
        layer = LayerInfo(digest="sha256:abc")
        with pytest.raises(ValidationError):
            layer.digest = "sha256:xyz"  # type: ignore[misc]
