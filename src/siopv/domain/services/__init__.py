"""Domain services for SIOPV.

Pure business logic functions with no external dependencies.
"""

from __future__ import annotations

from collections import defaultdict
from typing import TYPE_CHECKING

import structlog

if TYPE_CHECKING:
    from siopv.domain.entities import VulnerabilityRecord

logger = structlog.get_logger(__name__)


def deduplicate_vulnerabilities(
    records: list[VulnerabilityRecord],
) -> list[VulnerabilityRecord]:
    """Deduplicate vulnerability records by (cve_id, package_name, installed_version).

    When duplicates are found, the first occurrence is kept and additional
    locations are merged into it.

    Args:
        records: List of VulnerabilityRecord entities (possibly with duplicates)

    Returns:
        List of deduplicated VulnerabilityRecord entities with merged locations
    """
    seen: dict[tuple[str, str, str], VulnerabilityRecord] = {}
    duplicates_count = 0

    for record in records:
        key = record.dedup_key

        if key in seen:
            # Merge locations from duplicate
            existing = seen[key]
            for location in record.locations:
                existing = existing.merge_location(location)
            seen[key] = existing
            duplicates_count += 1
        else:
            seen[key] = record

    if duplicates_count > 0:
        logger.info(
            "deduplication_complete",
            original_count=len(records),
            deduplicated_count=len(seen),
            duplicates_removed=duplicates_count,
        )

    return list(seen.values())


def group_by_package(
    records: list[VulnerabilityRecord],
) -> dict[str, list[VulnerabilityRecord]]:
    """Group vulnerability records by package name.

    This optimization allows batch processing of vulnerabilities
    per package, reducing LLM API calls in later pipeline stages.

    Args:
        records: List of VulnerabilityRecord entities

    Returns:
        Dictionary mapping package_name to list of vulnerabilities for that package
    """
    groups: dict[str, list[VulnerabilityRecord]] = defaultdict(list)

    for record in records:
        groups[record.package_name].append(record)

    logger.debug(
        "grouped_by_package",
        total_records=len(records),
        unique_packages=len(groups),
    )

    return dict(groups)


def group_by_severity(
    records: list[VulnerabilityRecord],
) -> dict[str, list[VulnerabilityRecord]]:
    """Group vulnerability records by severity level.

    Useful for prioritization and reporting.

    Args:
        records: List of VulnerabilityRecord entities

    Returns:
        Dictionary mapping severity level to list of vulnerabilities
    """
    groups: dict[str, list[VulnerabilityRecord]] = defaultdict(list)

    for record in records:
        groups[record.severity].append(record)

    return dict(groups)


def sort_by_severity(
    records: list[VulnerabilityRecord],
    descending: bool = True,
) -> list[VulnerabilityRecord]:
    """Sort vulnerability records by severity.

    Order: CRITICAL > HIGH > MEDIUM > LOW > UNKNOWN

    Args:
        records: List of VulnerabilityRecord entities
        descending: If True, most severe first (default)

    Returns:
        Sorted list of VulnerabilityRecord entities
    """
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}

    return sorted(
        records,
        key=lambda r: severity_order.get(r.severity, 5),
        reverse=not descending,
    )


__all__ = [
    "deduplicate_vulnerabilities",
    "group_by_package",
    "group_by_severity",
    "sort_by_severity",
]
