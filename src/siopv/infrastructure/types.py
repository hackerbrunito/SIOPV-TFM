"""Shared type definitions for SIOPV infrastructure.

Centralizes common type aliases to maintain DRY principle.
"""

from typing import Any

# Type alias for JSON response data from external APIs
# Used across all API client adapters (NVD, EPSS, GitHub, Tavily)
JsonDict = dict[str, Any]

__all__ = [
    "JsonDict",
]
