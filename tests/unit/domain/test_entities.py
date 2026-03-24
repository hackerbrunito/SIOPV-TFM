"""Tests for domain entities."""

import pytest
from pydantic import ValidationError

from siopv.domain.entities import VulnerabilityRecord
from siopv.domain.value_objects import CVEId, CVSSScore, PackageVersion


class TestVulnerabilityRecord:
    """Tests for VulnerabilityRecord entity."""

    def test_create_minimal_record(self) -> None:
        """Test creation with minimal required fields."""
        record = VulnerabilityRecord(
            cve_id=CVEId(value="CVE-2024-12345"),
            package_name="test-package",
            installed_version=PackageVersion(value="1.0.0"),
            severity="HIGH",
        )

        assert record.cve_id.value == "CVE-2024-12345"
        assert record.package_name == "test-package"
        assert record.installed_version.value == "1.0.0"
        assert record.severity == "HIGH"
        assert record.fixed_version is None
        assert record.cvss_v3_score is None

    def test_create_full_record(self) -> None:
        """Test creation with all fields."""
        record = VulnerabilityRecord(
            cve_id=CVEId(value="CVE-2024-12345"),
            package_name="test-package",
            installed_version=PackageVersion(value="1.0.0"),
            fixed_version=PackageVersion(value="1.0.1"),
            severity="CRITICAL",
            cvss_v3_score=CVSSScore(value=9.8),
            title="Test vulnerability",
            description="A test vulnerability description",
            primary_url="https://example.com/cve",
            target="alpine:latest",
            locations=["path/to/file"],
        )

        assert record.fixed_version is not None
        assert record.fixed_version.value == "1.0.1"
        assert record.cvss_v3_score is not None
        assert record.cvss_v3_score.value == 9.8
        assert record.title == "Test vulnerability"
        assert record.target == "alpine:latest"
        assert "path/to/file" in record.locations

    def test_severity_normalization_lowercase(self) -> None:
        """Test that severity is normalized to uppercase."""
        record = VulnerabilityRecord(
            cve_id=CVEId(value="CVE-2024-12345"),
            package_name="test-package",
            installed_version=PackageVersion(value="1.0.0"),
            severity="high",  # lowercase
        )
        assert record.severity == "HIGH"

    def test_severity_normalization_mixed_case(self) -> None:
        """Test severity normalization with mixed case."""
        record = VulnerabilityRecord(
            cve_id=CVEId(value="CVE-2024-12345"),
            package_name="test-package",
            installed_version=PackageVersion(value="1.0.0"),
            severity="CrItIcAl",  # mixed case
        )
        assert record.severity == "CRITICAL"

    def test_invalid_severity_becomes_unknown(self) -> None:
        """Test that invalid severity becomes UNKNOWN."""
        record = VulnerabilityRecord(
            cve_id=CVEId(value="CVE-2024-12345"),
            package_name="test-package",
            installed_version=PackageVersion(value="1.0.0"),
            severity="INVALID",
        )
        assert record.severity == "UNKNOWN"

    def test_dedup_key(self) -> None:
        """Test deduplication key generation."""
        record = VulnerabilityRecord(
            cve_id=CVEId(value="CVE-2024-12345"),
            package_name="test-package",
            installed_version=PackageVersion(value="1.0.0"),
            severity="HIGH",
        )

        key = record.dedup_key
        assert key == ("CVE-2024-12345", "test-package", "1.0.0")

    def test_merge_location(self) -> None:
        """Test merging additional location."""
        record = VulnerabilityRecord(
            cve_id=CVEId(value="CVE-2024-12345"),
            package_name="test-package",
            installed_version=PackageVersion(value="1.0.0"),
            severity="HIGH",
            locations=["location1"],
        )

        merged = record.merge_location("location2")

        # Original unchanged (frozen)
        assert record.locations == ["location1"]

        # New record has both locations
        assert "location1" in merged.locations
        assert "location2" in merged.locations

    def test_merge_location_no_duplicate(self) -> None:
        """Test that merging same location doesn't duplicate."""
        record = VulnerabilityRecord(
            cve_id=CVEId(value="CVE-2024-12345"),
            package_name="test-package",
            installed_version=PackageVersion(value="1.0.0"),
            severity="HIGH",
            locations=["location1"],
        )

        merged = record.merge_location("location1")

        # Same object returned when location already exists
        assert merged is record

    def test_from_trivy_basic(self) -> None:
        """Test creation from Trivy vulnerability data."""
        trivy_data = {
            "VulnerabilityID": "CVE-2024-12345",
            "PkgName": "openssl",
            "InstalledVersion": "1.1.1",
            "FixedVersion": "1.1.2",
            "Severity": "HIGH",
            "Title": "OpenSSL vulnerability",
            "Description": "A vulnerability in OpenSSL",
            "PrimaryURL": "https://nvd.nist.gov/vuln/detail/CVE-2024-12345",
            "CVSS": {
                "nvd": {
                    "V3Score": 7.5,
                },
            },
        }

        record = VulnerabilityRecord.from_trivy(trivy_data, target="debian:latest")

        assert record.cve_id.value == "CVE-2024-12345"
        assert record.package_name == "openssl"
        assert record.installed_version.value == "1.1.1"
        assert record.fixed_version is not None
        assert record.fixed_version.value == "1.1.2"
        assert record.severity == "HIGH"
        assert record.cvss_v3_score is not None
        assert record.cvss_v3_score.value == 7.5
        assert record.target == "debian:latest"

    def test_from_trivy_ghsa_cvss(self) -> None:
        """Test CVSS extraction from GHSA source."""
        trivy_data = {
            "VulnerabilityID": "CVE-2026-12345",
            "PkgName": "requests",
            "InstalledVersion": "2.25.0",
            "Severity": "CRITICAL",
            "CVSS": {
                "ghsa": {
                    "V3Score": 9.1,
                },
            },
        }

        record = VulnerabilityRecord.from_trivy(trivy_data)

        assert record.cvss_v3_score is not None
        assert record.cvss_v3_score.value == 9.1

    def test_from_trivy_no_cvss(self) -> None:
        """Test creation when no CVSS score available."""
        trivy_data = {
            "VulnerabilityID": "CVE-2024-12345",
            "PkgName": "test-pkg",
            "InstalledVersion": "1.0.0",
            "Severity": "MEDIUM",
        }

        record = VulnerabilityRecord.from_trivy(trivy_data)

        assert record.cvss_v3_score is None

    def test_from_trivy_no_fixed_version(self) -> None:
        """Test creation when no fixed version available."""
        trivy_data = {
            "VulnerabilityID": "CVE-2024-12345",
            "PkgName": "test-pkg",
            "InstalledVersion": "1.0.0",
            "Severity": "LOW",
        }

        record = VulnerabilityRecord.from_trivy(trivy_data)

        assert record.fixed_version is None

    def test_from_trivy_with_layer(self) -> None:
        """Test creation with Docker layer info."""
        trivy_data = {
            "VulnerabilityID": "CVE-2024-12345",
            "PkgName": "test-pkg",
            "InstalledVersion": "1.0.0",
            "Severity": "HIGH",
            "Layer": {
                "Digest": "sha256:abc123",
                "DiffID": "sha256:def456",
            },
        }

        record = VulnerabilityRecord.from_trivy(trivy_data)

        assert record.layer is not None
        assert record.layer.digest == "sha256:abc123"
        assert record.layer.diff_id == "sha256:def456"

    def test_from_trivy_with_pkg_path(self) -> None:
        """Test location tracking with package path."""
        trivy_data = {
            "VulnerabilityID": "CVE-2024-12345",
            "PkgName": "requests",
            "InstalledVersion": "2.25.0",
            "Severity": "HIGH",
            "PkgPath": "usr/local/lib/python3.9/site-packages/requests-2.25.0.dist-info",
        }

        record = VulnerabilityRecord.from_trivy(trivy_data)

        assert len(record.locations) == 1
        assert "usr/local/lib/python3.9" in record.locations[0]

    def test_record_is_frozen(self) -> None:
        """Test that VulnerabilityRecord is immutable."""
        record = VulnerabilityRecord(
            cve_id=CVEId(value="CVE-2024-12345"),
            package_name="test-package",
            installed_version=PackageVersion(value="1.0.0"),
            severity="HIGH",
        )

        with pytest.raises(ValidationError):
            record.severity = "LOW"  # type: ignore[misc]

    def test_empty_package_name_fails(self) -> None:
        """Test that empty package name raises error."""
        with pytest.raises(ValidationError):
            VulnerabilityRecord(
                cve_id=CVEId(value="CVE-2024-12345"),
                package_name="",
                installed_version=PackageVersion(value="1.0.0"),
                severity="HIGH",
            )
