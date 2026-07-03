"""Legacy compatibility shim for ``d810.expr.ast``.

The canonical AST dispatcher now lives in :mod:`d810.hexrays.expr.ast` and the
canonical IR builder helpers live in :mod:`d810.hexrays.ir.minsn_utils` and
:mod:`d810.hexrays.ir.mop_utils`. This module re-exports those symbols so that
older imports such as ``from d810.expr.ast import AstLeaf`` keep resolving to
the exact same class objects that the canonical dispatcher provides.

The module deliberately implements **no** class logic of its own; any drift
from the canonical module would defeat the purpose of the shim and re-introduce
the mixed-class identity crash seen during IDA reloads.

Only ``clear_mop_to_ast_cache`` is provided as a thin compatibility helper
because external callers historically used it to flush the shared cache.
"""

from __future__ import annotations

from d810.core import MOP_TO_AST_CACHE
from d810.hexrays.expr.ast import (
    AstBase,
    AstBaseProtocol,
    AstConstant,
    AstConstantProtocol,
    AstLeaf,
    AstLeafProtocol,
    AstNode,
    AstNodeProtocol,
    AstProxy,
    get_constant_mop,
    get_mop_key,
)
from d810.hexrays.ir.minsn_utils import minsn_to_ast
from d810.hexrays.ir.mop_utils import mop_to_ast


def clear_mop_to_ast_cache() -> None:
    """Clear the shared ``MOP_TO_AST_CACHE`` (compatibility helper).

    This is a tiny compatibility helper preserved around the shared
    :data:`d810.core.MOP_TO_AST_CACHE` so that legacy callers continue to
    work without having to reach into :mod:`d810.core` directly.
    """
    MOP_TO_AST_CACHE.clear()


__all__ = [
    # Canonical AST classes (re-exported, identical objects)
    "AstBase",
    "AstConstant",
    "AstLeaf",
    "AstNode",
    "AstProxy",
    # Protocols for hot-reload-safe isinstance() checks
    "AstBaseProtocol",
    "AstConstantProtocol",
    "AstLeafProtocol",
    "AstNodeProtocol",
    # Builders
    "get_constant_mop",
    "get_mop_key",
    "mop_to_ast",
    "minsn_to_ast",
    # Compatibility helper
    "clear_mop_to_ast_cache",
]