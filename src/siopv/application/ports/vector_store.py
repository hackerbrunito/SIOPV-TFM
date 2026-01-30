"""Port interface for vector store operations.

Defines the contract for vector database adapters (ChromaDB).
Used for storing and retrieving enrichment embeddings.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from siopv.domain.value_objects import EnrichmentData


class VectorStorePort(ABC):
    """Port interface for vector store operations.

    Implementations must handle:
    - Persistent storage (SQLite backend for ChromaDB)
    - LRU cache management (max 4GB as per spec)
    - Embedding generation
    """

    @abstractmethod
    async def store_enrichment(self, enrichment: EnrichmentData) -> str:
        """Store enrichment data with generated embedding.

        Args:
            enrichment: EnrichmentData to store

        Returns:
            Document ID for stored enrichment
        """
        ...

    @abstractmethod
    async def store_enrichments_batch(self, enrichments: list[EnrichmentData]) -> list[str]:
        """Store multiple enrichments efficiently.

        Args:
            enrichments: List of EnrichmentData to store

        Returns:
            List of document IDs
        """
        ...

    @abstractmethod
    async def query_similar(
        self,
        query_text: str,
        *,
        n_results: int = 5,
        min_relevance: float = 0.0,
    ) -> list[tuple[EnrichmentData, float]]:
        """Query for similar enrichment documents.

        Args:
            query_text: Text to find similar documents for
            n_results: Maximum results to return
            min_relevance: Minimum similarity score (0-1)

        Returns:
            List of (EnrichmentData, similarity_score) tuples
        """
        ...

    @abstractmethod
    async def get_by_cve_id(self, cve_id: str) -> EnrichmentData | None:
        """Retrieve stored enrichment by CVE ID.

        Args:
            cve_id: CVE identifier

        Returns:
            EnrichmentData if found, None otherwise
        """
        ...

    @abstractmethod
    async def exists(self, cve_id: str) -> bool:
        """Check if enrichment exists for CVE.

        Args:
            cve_id: CVE identifier

        Returns:
            True if enrichment exists
        """
        ...

    @abstractmethod
    async def delete(self, cve_id: str) -> bool:
        """Delete enrichment by CVE ID.

        Args:
            cve_id: CVE identifier

        Returns:
            True if deleted, False if not found
        """
        ...

    @abstractmethod
    async def count(self) -> int:
        """Get total count of stored enrichments.

        Returns:
            Number of stored documents
        """
        ...

    @abstractmethod
    async def clear(self) -> None:
        """Clear all stored enrichments.

        Use with caution - primarily for testing.
        """
        ...


__all__ = ["VectorStorePort"]
