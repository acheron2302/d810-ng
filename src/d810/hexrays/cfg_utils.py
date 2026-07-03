"""Compatibility shim for ``d810.hexrays.cfg_utils``.

The canonical implementation is split across three modules:

- :mod:`d810.hexrays.ir.cfg_queries` for CFG read-only queries.
- :mod:`d810.hexrays.mutation.cfg_mutations` for CFG mutation primitives.
- :mod:`d810.hexrays.mutation.cfg_verify` for safe verification helpers.
- :mod:`d810.hexrays.ir.mop_utils` for stack-var helper functions.

This module re-exports the legacy symbols so external scripts, tests,
and persisted plugin code that import the legacy path keep working.

Do not add new logic here. New code must import from the canonical
modules directly.
"""
from __future__ import annotations

from d810.hexrays.ir.cfg_queries import (  # noqa: F401
    _serial_in_predset,
    get_block_serials_by_address,
    get_block_serials_by_address_range,
    is_conditional_jump,
    is_indirect_jump,
)
from d810.hexrays.ir.mop_utils import (  # noqa: F401
    extract_base_and_offset,
    get_stack_var_name,
)
from d810.hexrays.mutation.cfg_mutations import (  # noqa: F401
    change_0way_block_successor,
    change_1way_block_successor,
    change_1way_call_block_successor,
    change_2way_block_conditional_successor,
    change_block_address,
    create_block,
    duplicate_block,
    ensure_child_has_an_unconditional_father,
    ensure_last_block_is_goto,
    insert_goto_instruction,
    insert_nop_blk,
    make_2way_block_goto,
    mba_deep_cleaning,
    mba_remove_simple_goto_blocks,
    update_blk_successor,
    update_block_successors,
)
from d810.hexrays.mutation.cfg_verify import (  # noqa: F401
    log_block_info,
    safe_verify,
)

__all__ = [
    # cfg_queries
    "_serial_in_predset",
    "get_block_serials_by_address",
    "get_block_serials_by_address_range",
    "is_conditional_jump",
    "is_indirect_jump",
    # mop_utils
    "extract_base_and_offset",
    "get_stack_var_name",
    # cfg_mutations
    "change_0way_block_successor",
    "change_1way_block_successor",
    "change_1way_call_block_successor",
    "change_2way_block_conditional_successor",
    "change_block_address",
    "create_block",
    "duplicate_block",
    "ensure_child_has_an_unconditional_father",
    "ensure_last_block_is_goto",
    "insert_goto_instruction",
    "insert_nop_blk",
    "make_2way_block_goto",
    "mba_deep_cleaning",
    "mba_remove_simple_goto_blocks",
    "update_blk_successor",
    "update_block_successors",
    # cfg_verify
    "log_block_info",
    "safe_verify",
]