"""Port interfaces for enrichment data clients.

These abstract base classes define contracts for external API adapters.
Implementations live in adapters/external_apis/.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from siopv.domain.value_objects import (
        EPSSScore,
        GitHubAdvisory,
        NVDEnrichment,
        OSINTResult,
    )


class NVDClientPort(ABC):
    """Port interface for NVD (National Vulnerability Database) API client.

    Implementations must handle:
    - Rate limiting (5 req/30s without key, 50 req/30s with key)
    - Circuit breaker for API failures
    - Response caching
    """

    @abstractmethod
    async def get_cve(self, cve_id: str) -> NVDEnrichment | None:
        """Fetch CVE details from NVD API.

        Args:
            cve_id: CVE identifier (e.g., "CVE-2021-44228")

        Returns:
            NVDEnrichment with CVE details, or None if not found

        Raises:
            NVDClientError: On API errors after retries exhausted
        """
        ...

    @abstractmethod
    async def get_cves_batch(
        self, cve_ids: list[str], *, max_concurrent: int = 5
    ) -> dict[str, NVDEnrichment | None]:
        """Fetch multiple CVEs with rate limiting.

        Args:
            cve_ids: List of CVE identifiers
            max_concurrent: Maximum concurrent requests

        Returns:
            Dictionary mapping cve_id to NVDEnrichment or None
        """
        ...

    @abstractmethod
    async def health_check(self) -> bool:
        """Check if NVD API is reachable.

        Returns:
            True if API responds, False otherwise
        """
        ...


class EPSSClientPort(ABC):
    """Port interface for FIRST EPSS API client.

    EPSS provides exploit prediction scores updated daily.
    No authentication required.
    """

    @abstractmethod
    async def get_score(self, cve_id: str) -> EPSSScore | None:
        """Fetch EPSS score for a CVE.

        Args:
            cve_id: CVE identifier

        Returns:
            EPSSScore with probability and percentile, or None if not found
        """
        ...

    @abstractmethod
    async def get_scores_batch(self, cve_ids: list[str]) -> dict[str, EPSSScore | None]:
        """Fetch EPSS scores for multiple CVEs.

        The EPSS API supports batch queries more efficiently.

        Args:
            cve_ids: List of CVE identifiers

        Returns:
            Dictionary mapping cve_id to EPSSScore or None
        """
        ...


class GitHubAdvisoryClientPort(ABC):
    """Port interface for GitHub Security Advisories GraphQL API.

    Implementations must handle:
    - Personal Access Token authentication
    - Rate limiting (60 req/h without auth, 5000 req/h with auth)
    - GraphQL query construction
    """

    @abstractmethod
    async def get_advisory_by_cve(self, cve_id: str) -> GitHubAdvisory | None:
        """Fetch GitHub Security Advisory for a CVE.

        Args:
            cve_id: CVE identifier

        Returns:
            GitHubAdvisory with package-specific info, or None if not found
        """
        ...

    @abstractmethod
    async def get_advisories_for_package(
        self,
        package_name: str,
        ecosystem: str | None = None,
    ) -> list[GitHubAdvisory]:
        """Fetch all advisories affecting a package.

        Args:
            package_name: Package name to search
            ecosystem: Optional ecosystem filter (npm, pip, maven, etc.)

        Returns:
            List of GitHubAdvisory objects
        """
        ...


class OSINTSearchClientPort(ABC):
    """Port interface for OSINT search (Tavily API).

    Used as fallback when NVD/GitHub don't provide sufficient context.
    Activated by CRAG pattern when relevance < 0.6.
    """

    @abstractmethod
    async def search(
        self,
        query: str,
        *,
        max_results: int = 5,
        search_depth: str = "basic",
    ) -> list[OSINTResult]:
        """Search for vulnerability information.

        Args:
            query: Search query (typically CVE ID + context)
            max_results: Maximum results to return
            search_depth: "basic" or "advanced" search

        Returns:
            List of OSINTResult objects with search results
        """
        ...

    @abstractmethod
    async def search_exploit_info(self, cve_id: str) -> list[OSINTResult]:
        """Search specifically for exploit information.

        Constructs targeted query for PoC, exploits, and attack vectors.

        Args:
            cve_id: CVE identifier

        Returns:
            List of OSINTResult objects
        """
        ...


__all__ = [
    "EPSSClientPort",
    "GitHubAdvisoryClientPort",
    "NVDClientPort",
    "OSINTSearchClientPort",
]
