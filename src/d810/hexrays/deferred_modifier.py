"""Compatibility shim for ``d810.hexrays.deferred_modifier``.

The canonical implementation lives in
:mod:`d810.hexrays.mutation.deferred_modifier`. This module re-exports its
public surface so external scripts, tests, and persisted plugin code that
import the legacy path keep working.

Do not add new logic here. New code must import from
``d810.hexrays.mutation.deferred_modifier`` directly.
"""
from __future__ import annotations

from d810.hexrays.mutation.deferred_modifier import (  # noqa: F401
    DeferredGraphModifier,
    GraphModification,
    ImmediateGraphModifier,
    ModificationType,
)

__all__ = [
    "DeferredGraphModifier",
    "GraphModification",
    "ImmediateGraphModifier",
    "ModificationType",
]