"""Compatibility shim for ``d810.hexrays.utils.table_utils``.

The canonical implementation lives in :mod:`d810.hexrays.utils.table_utils`.
This module re-exports its public surface so external scripts, tests,
and persisted plugin code that import the legacy path keep working.

Do not add new logic here. New code must import from
``d810.hexrays.utils.table_utils`` directly.
"""
from __future__ import annotations

from d810.hexrays.utils.table_utils import (  # noqa: F401
    BADADDR,
    TableEncoding,
    XorKeyInfo,
    analyze_table_encoding,
    decode_table_entry,
    find_table_reference,
    find_xor_with_globals,
    get_flags_safe,
    get_func_safe,
    is_code_ea,
    is_valid_database_ea,
    read_global_value,
    read_table_entries,
    validate_code_target,
)

__all__ = [
    "BADADDR",
    "TableEncoding",
    "XorKeyInfo",
    "analyze_table_encoding",
    "decode_table_entry",
    "find_table_reference",
    "find_xor_with_globals",
    "get_flags_safe",
    "get_func_safe",
    "is_code_ea",
    "is_valid_database_ea",
    "read_global_value",
    "read_table_entries",
    "validate_code_target",
]