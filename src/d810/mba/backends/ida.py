"""Compatibility shim for ``d810.backends.mba.ida``.

The canonical implementation lives in :mod:`d810.backends.mba.ida`. This
module re-exports its public surface so external scripts, tests, and
persisted plugin code that import the legacy path keep working.

Do not add new logic here. New code must import from
``d810.backends.mba.ida`` directly.
"""
from __future__ import annotations

from d810.backends.mba.ida import (  # noqa: F401
    IDANodeVisitor,
    IDAPatternAdapter,
    adapt_rules,
)

__all__ = [
    "IDANodeVisitor",
    "IDAPatternAdapter",
    "adapt_rules",
]