"""Authorization adapters for SIOPV Phase 5 (OpenFGA).

Provides adapter implementations for the authorization port interfaces.
The OpenFGAAdapter implements all three authorization ports:
- AuthorizationPort: Check permissions
- AuthorizationStorePort: Manage tuples
- AuthorizationModelPort: Model management

Usage:
    from siopv.adapters.authorization import OpenFGAAdapter

    adapter = OpenFGAAdapter(settings)
    await adapter.initialize()

    # Check permission
    result = await adapter.check(context)

    # Write tuple
    await adapter.write_tuple(relationship)

    # Cleanup
    await adapter.close()
"""

from siopv.adapters.authorization.openfga_adapter import (
    OpenFGAAdapter,
    OpenFGAAdapterError,
)

__all__ = [
    "OpenFGAAdapter",
    "OpenFGAAdapterError",
]
