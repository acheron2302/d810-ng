"""Compatibility shim for ``d810.hexrays.hooks.ctree_hooks``.

The canonical implementation lives in :mod:`d810.hexrays.hooks.ctree_hooks`.
This module re-exports its public surface so external scripts, tests,
and persisted plugin code that import the legacy path keep working.

Do not add new logic here. New code must import from
``d810.hexrays.hooks.ctree_hooks`` directly.
"""
from __future__ import annotations

from d810.hexrays.hooks.ctree_hooks import (  # noqa: F401
    CtreeOptimizationRule,
    CtreeOptimizerManager,
)

__all__ = [
    "CtreeOptimizationRule",
    "CtreeOptimizerManager",
]