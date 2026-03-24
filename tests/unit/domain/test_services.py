"""Tests for domain services."""

from siopv.domain.entities import VulnerabilityRecord
from siopv.domain.services import (
    deduplicate_vulnerabilities,
    group_by_package,
    group_by_severity,
    sort_by_severity,
)
from siopv.domain.value_objects import CVEId, PackageVersion


def create_test_record(
    cve_id: str = "CVE-2024-12345",
    package_name: str = "test-pkg",
    version: str = "1.0.0",
    severity: str = "HIGH",
    locations: list[str] | None = None,
) -> VulnerabilityRecord:
    """Helper to create test records."""
    return VulnerabilityRecord(
        cve_id=CVEId(value=cve_id),
        package_name=package_name,
        installed_version=PackageVersion(value=version),
        severity=severity,
        locations=locations or [],
    )


class TestDeduplicateVulnerabilities:
    """Tests for deduplicate_vulnerabilities service."""

    def test_no_duplicates(self) -> None:
        """Test with no duplicates."""
        records = [
            create_test_record(cve_id="CVE-2024-0001"),
            create_test_record(cve_id="CVE-2024-0002"),
            create_test_record(cve_id="CVE-2024-0003"),
        ]

        result = deduplicate_vulnerabilities(records)

        assert len(result) == 3

    def test_exact_duplicates_merged(self) -> None:
        """Test that exact duplicates are merged."""
        records = [
            create_test_record(cve_id="CVE-2024-0001", locations=["loc1"]),
            create_test_record(cve_id="CVE-2024-0001", locations=["loc2"]),
            create_test_record(cve_id="CVE-2024-0001", locations=["loc3"]),
        ]

        result = deduplicate_vulnerabilities(records)

        assert len(result) == 1
        assert "loc1" in result[0].locations
        assert "loc2" in result[0].locations
        assert "loc3" in result[0].locations

    def test_same_cve_different_packages(self) -> None:
        """Test same CVE in different packages stays separate."""
        records = [
            create_test_record(cve_id="CVE-2024-0001", package_name="pkg-a"),
            create_test_record(cve_id="CVE-2024-0001", package_name="pkg-b"),
        ]

        result = deduplicate_vulnerabilities(records)

        assert len(result) == 2

    def test_same_cve_same_package_different_versions(self) -> None:
        """Test same CVE/package with different versions stays separate."""
        records = [
            create_test_record(cve_id="CVE-2024-0001", package_name="pkg", version="1.0.0"),
            create_test_record(cve_id="CVE-2024-0001", package_name="pkg", version="2.0.0"),
        ]

        result = deduplicate_vulnerabilities(records)

        assert len(result) == 2

    def test_empty_list(self) -> None:
        """Test with empty list."""
        result = deduplicate_vulnerabilities([])

        assert result == []

    def test_preserves_order_first_occurrence(self) -> None:
        """Test that first occurrence is kept."""
        records = [
            create_test_record(cve_id="CVE-2024-0001", severity="HIGH"),
            create_test_record(cve_id="CVE-2024-0001", severity="CRITICAL"),  # Duplicate
        ]

        result = deduplicate_vulnerabilities(records)

        assert len(result) == 1
        # First occurrence (HIGH) should be kept
        assert result[0].severity == "HIGH"


class TestGroupByPackage:
    """Tests for group_by_package service."""

    def test_groups_correctly(self) -> None:
        """Test grouping by package name."""
        records = [
            create_test_record(cve_id="CVE-2024-0001", package_name="openssl"),
            create_test_record(cve_id="CVE-2024-0002", package_name="openssl"),
            create_test_record(cve_id="CVE-2024-0003", package_name="curl"),
            create_test_record(cve_id="CVE-2024-0004", package_name="python"),
        ]

        result = group_by_package(records)

        assert len(result) == 3
        assert len(result["openssl"]) == 2
        assert len(result["curl"]) == 1
        assert len(result["python"]) == 1

    def test_empty_list(self) -> None:
        """Test with empty list."""
        result = group_by_package([])

        assert result == {}

    def test_single_package(self) -> None:
        """Test with all vulns in same package."""
        records = [
            create_test_record(cve_id="CVE-2024-0001", package_name="openssl"),
            create_test_record(cve_id="CVE-2024-0002", package_name="openssl"),
        ]

        result = group_by_package(records)

        assert len(result) == 1
        assert "openssl" in result
        assert len(result["openssl"]) == 2


class TestGroupBySeverity:
    """Tests for group_by_severity service."""

    def test_groups_correctly(self) -> None:
        """Test grouping by severity."""
        records = [
            create_test_record(cve_id="CVE-2024-0001", severity="CRITICAL"),
            create_test_record(cve_id="CVE-2024-0002", severity="CRITICAL"),
            create_test_record(cve_id="CVE-2024-0003", severity="HIGH"),
            create_test_record(cve_id="CVE-2024-0004", severity="LOW"),
        ]

        result = group_by_severity(records)

        assert len(result) == 3
        assert len(result["CRITICAL"]) == 2
        assert len(result["HIGH"]) == 1
        assert len(result["LOW"]) == 1

    def test_empty_list(self) -> None:
        """Test with empty list."""
        result = group_by_severity([])

        assert result == {}


class TestSortBySeverity:
    """Tests for sort_by_severity service."""

    def test_sort_descending(self) -> None:
        """Test sorting by severity (most critical first)."""
        records = [
            create_test_record(cve_id="CVE-2024-0001", severity="LOW"),
            create_test_record(cve_id="CVE-2024-0002", severity="CRITICAL"),
            create_test_record(cve_id="CVE-2024-0003", severity="MEDIUM"),
            create_test_record(cve_id="CVE-2024-0004", severity="HIGH"),
        ]

        result = sort_by_severity(records, descending=True)

        assert result[0].severity == "CRITICAL"
        assert result[1].severity == "HIGH"
        assert result[2].severity == "MEDIUM"
        assert result[3].severity == "LOW"

    def test_sort_ascending(self) -> None:
        """Test sorting by severity (least critical first)."""
        records = [
            create_test_record(cve_id="CVE-2024-0001", severity="CRITICAL"),
            create_test_record(cve_id="CVE-2024-0002", severity="LOW"),
        ]

        result = sort_by_severity(records, descending=False)

        # Ascending = least severe first
        assert result[0].severity == "LOW"
        assert result[1].severity == "CRITICAL"

    def test_unknown_severity_last(self) -> None:
        """Test that UNKNOWN severity is sorted last."""
        records = [
            create_test_record(cve_id="CVE-2024-0001", severity="UNKNOWN"),
            create_test_record(cve_id="CVE-2024-0002", severity="LOW"),
            create_test_record(cve_id="CVE-2024-0003", severity="CRITICAL"),
        ]

        result = sort_by_severity(records, descending=True)

        assert result[0].severity == "CRITICAL"
        assert result[1].severity == "LOW"
        assert result[2].severity == "UNKNOWN"

    def test_empty_list(self) -> None:
        """Test with empty list."""
        result = sort_by_severity([])

        assert result == []

    def test_all_same_severity(self) -> None:
        """Test with all same severity preserves order."""
        records = [
            create_test_record(cve_id="CVE-2024-0001", severity="HIGH"),
            create_test_record(cve_id="CVE-2024-0002", severity="HIGH"),
            create_test_record(cve_id="CVE-2024-0003", severity="HIGH"),
        ]

        result = sort_by_severity(records)

        assert len(result) == 3
        # Order should be preserved for same severity
        assert result[0].cve_id.value == "CVE-2024-0001"
        assert result[1].cve_id.value == "CVE-2024-0002"
        assert result[2].cve_id.value == "CVE-2024-0003"
