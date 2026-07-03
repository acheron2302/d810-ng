"""Compatibility shim for ``d810.hexrays.mop_snapshot``.

The canonical implementation lives in :mod:`d810.hexrays.ir.mop_snapshot`.
This module re-exports its public surface so external scripts, tests,
and persisted plugin code that import the legacy path keep working.

Do not add new logic here. New code must import from
``d810.hexrays.ir.mop_snapshot`` directly.

Note: MopSnapshot supports both a pure-Python and a Cython-backed
implementation that is selected at module-import time based on
``CythonMode``. Both this shim and the canonical module defer that
selection to the canonical import; loading this shim therefore installs
the same backend selection in ``sys.modules`` as loading the canonical
module directly.
"""
from __future__ import annotations

from d810.hexrays.ir.mop_snapshot import (  # noqa: F401
    MopSnapshot,
)

__all__ = [
    "MopSnapshot",
]