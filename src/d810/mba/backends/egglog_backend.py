"""Compatibility shim for ``d810.mba.backends.egglog_backend``.

The canonical implementation lives in
:mod:`d810.backends.mba.egglog_backend`. This module re-exports its
public surface so external scripts, tests, and persisted plugin code
that import the legacy path keep working.

Do not add new logic here. New code must import from
``d810.backends.mba.egglog_backend`` directly.
"""
from __future__ import annotations

from d810.backends.mba.egglog_backend import (  # noqa: F401
    EGGLOG_AVAILABLE,
    AstToBitExprConverter,
    BitExpr,
    EGraphOptimizer,
    MBAEGraph,
    PatternExpr,
    check_egglog_available,
    generate_equivalent_patterns,
    requires_egglog,
    verify_pattern_equivalence,
)

__all__ = [
    "EGGLOG_AVAILABLE",
    "AstToBitExprConverter",
    "BitExpr",
    "EGraphOptimizer",
    "MBAEGraph",
    "PatternExpr",
    "check_egglog_available",
    "generate_equivalent_patterns",
    "requires_egglog",
    "verify_pattern_equivalence",
]