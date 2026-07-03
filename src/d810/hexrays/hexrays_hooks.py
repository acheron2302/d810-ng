"""Compatibility shim for ``d810.hexrays.hooks.hexrays_hooks``.

The canonical implementation lives in :mod:`d810.hexrays.hooks.hexrays_hooks`.
This module re-exports its public surface so external scripts, tests,
and persisted plugin code that import the legacy path keep working.

Do not add new logic here. New code must import from
``d810.hexrays.hooks.hexrays_hooks`` directly.
"""
from __future__ import annotations

from d810.hexrays.hooks.hexrays_hooks import (  # noqa: F401
    DEFAULT_ANALYZER_MATURITIES,
    DEFAULT_OPTIMIZATION_CHAIN_MATURITIES,
    DEFAULT_OPTIMIZATION_EARLY_MATURITIES,
    DEFAULT_OPTIMIZATION_PATTERN_MATURITIES,
    DEFAULT_OPTIMIZATION_PEEPHOLE_MATURITIES,
    DEFAULT_OPTIMIZATION_Z3_MATURITIES,
    BlockOptimizerManager,
    DecompilationEvent,
    HexraysDecompilationHook,
    InstructionOptimizerManager,
    InstructionVisitorManager,
    hash_minsn,
)

__all__ = [
    "DEFAULT_ANALYZER_MATURITIES",
    "DEFAULT_OPTIMIZATION_CHAIN_MATURITIES",
    "DEFAULT_OPTIMIZATION_EARLY_MATURITIES",
    "DEFAULT_OPTIMIZATION_PATTERN_MATURITIES",
    "DEFAULT_OPTIMIZATION_PEEPHOLE_MATURITIES",
    "DEFAULT_OPTIMIZATION_Z3_MATURITIES",
    "BlockOptimizerManager",
    "DecompilationEvent",
    "HexraysDecompilationHook",
    "InstructionOptimizerManager",
    "InstructionVisitorManager",
    "hash_minsn",
]