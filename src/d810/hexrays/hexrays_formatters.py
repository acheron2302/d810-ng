"""Compatibility shim for ``d810.hexrays.utils.hexrays_formatters``.

The canonical implementation lives in
:mod:`d810.hexrays.utils.hexrays_formatters`. This module re-exports its
public surface so external scripts, tests, and persisted plugin code that
import the legacy path keep working.

Do not add new logic here. New code must import from
``d810.hexrays.utils.hexrays_formatters`` directly.
"""
from __future__ import annotations

from d810.hexrays.utils.hexrays_formatters import (  # noqa: F401
    MopTreeLogger,
    block_printer,
    count_minsn_nodes,
    dump_microcode_for_debug,
    format_minsn_t,
    format_mop_list,
    format_mop_t,
    mba_printer,
    maturity_to_string,
    mop_tree,
    mop_type_to_string,
    opcode_to_string,
    sanitize_ea,
    string_to_maturity,
    write_mc_to_file,
)

__all__ = [
    "MopTreeLogger",
    "block_printer",
    "count_minsn_nodes",
    "dump_microcode_for_debug",
    "format_minsn_t",
    "format_mop_list",
    "format_mop_t",
    "mba_printer",
    "maturity_to_string",
    "mop_tree",
    "mop_type_to_string",
    "opcode_to_string",
    "sanitize_ea",
    "string_to_maturity",
    "write_mc_to_file",
]