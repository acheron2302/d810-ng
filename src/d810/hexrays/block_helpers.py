"""Compatibility shim for ``d810.hexrays.block_helpers``.

The canonical implementation lives in :mod:`d810.hexrays.ir.block_helpers`.
This module re-exports its public surface so external scripts, tests,
and persisted plugin code that import the legacy path keep working.

Do not add new logic here. New code must import from
``d810.hexrays.ir.block_helpers`` directly.
"""
from __future__ import annotations

from d810.hexrays.ir.block_helpers import (  # noqa: F401
    block_has_predecessor,
    block_has_successor,
    get_block_info,
    get_block_serial,
    get_pred_serial_set,
    get_pred_serials,
    get_succ_serial_set,
    get_succ_serials,
)

__all__ = [
    "block_has_predecessor",
    "block_has_successor",
    "get_block_info",
    "get_block_serial",
    "get_pred_serial_set",
    "get_pred_serials",
    "get_succ_serial_set",
    "get_succ_serials",
    "is_cython_available",
]


def is_cython_available() -> bool:
    """Deprecated compatibility helper.

    The legacy module exposed a ``is_cython_available`` flag; the canonical
    ``d810.hexrays.ir.block_helpers`` resolves its Cython backend at import
    time and exposes the implementation directly. Use
    :func:`d810.core.cymode.CythonMode.is_enabled` to detect Cython mode.
    """
    from d810.core.cymode import CythonMode

    return bool(CythonMode().is_enabled())