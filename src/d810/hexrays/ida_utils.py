"""Compatibility shim for ``d810.hexrays.utils.ida_utils``.

The canonical implementation lives in :mod:`d810.hexrays.utils.ida_utils`.
This module re-exports its public surface so external scripts, tests,
and persisted plugin code that import the legacy path keep working.

Do not add new logic here. New code must import from
``d810.hexrays.utils.ida_utils`` directly.
"""
from __future__ import annotations

from d810.hexrays.utils.ida_utils import (  # noqa: F401
    fetch_idb_value,
    is_never_written_var,
    is_read_only_inited_var,
    segment_is_read_only,
)

__all__ = [
    "fetch_idb_value",
    "is_never_written_var",
    "is_read_only_inited_var",
    "segment_is_read_only",
]