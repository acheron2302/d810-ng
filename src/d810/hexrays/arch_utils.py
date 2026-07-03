"""Compatibility shim for ``d810.hexrays.arch_utils``.

The canonical implementation lives in :mod:`d810.hexrays.utils.arch_utils`.
This module re-exports its public surface so external scripts, tests,
and persisted plugin code that import the legacy path keep working.

Do not add new logic here. New code must import from
``d810.hexrays.utils.arch_utils`` directly.
"""
from __future__ import annotations

from d810.hexrays.utils.arch_utils import (  # noqa: F401
    ArchType,
    clear_caches,
    get_arch,
    get_first_arg_reg,
    get_return_reg,
    is_identity_function,
    resolve_global_pointer,
    resolve_trampoline_chain,
    is_trampoline_code,
)

__all__ = [
    "ArchType",
    "clear_caches",
    "get_arch",
    "get_first_arg_reg",
    "get_return_reg",
    "is_identity_function",
    "resolve_global_pointer",
    "resolve_trampoline_chain",
    "is_trampoline_code",
]