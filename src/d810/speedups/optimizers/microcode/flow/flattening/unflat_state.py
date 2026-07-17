"""Read-only unflattening hot-path helpers (Python wrapper with fallback).

Phase 6: thin Python wrappers that mirror the planned Cython interface
in ``c_mop_state.pyx``.  When the Cython extension is built (see
``setup.py``), this module re-exports its functions; otherwise the
pure-Python fallbacks are used so the rest of d810 keeps working.

All helpers in this module are **read-only**: they never mutate the
MBA, the CFG, or any microcode instruction.  Mutation continues to
live in the central CFG mutation gateway.

Exposed interface
-----------------

``hash_unresolved_state(unresolved_mops, memory_unresolved_mops, func_ea)``
    Compute a single 64-bit hash for an unresolved mop list, used as a
    key in ``SearchContext.result_cache``/``visited_states``.

``batch_hash_mops(mops, func_ea)``
    Hash a list of mops in one call.  Returns a ``list[int]`` parallel
    to the input.

``jtbl_case_target_serials(entry_blk)``
    For an mblock ending in m_jtbl, return the (case_value, target_serial)
    pairs as a list of 2-tuples of ints.  Returns an empty list if the
    block is not a jtbl or the case list is not accessible.

``block_serial_set(blk, kind)``
    Return a Python ``set[int]`` of the block's predecessor or
    successor serials.  ``kind`` is ``"pred"`` or ``"succ"``.

The Cython implementations (when present) accelerate the per-mop and
per-block traversals by avoiding Python-level loops and by batching
SWIG attribute access.
"""
from __future__ import annotations

from typing import Iterable

# ---------------------------------------------------------------------------
# Cython fast-path import (optional, fails closed to Python).
# ---------------------------------------------------------------------------

_c_module = None
_c_import_error: Exception | None = None
try:
    from d810.speedups.optimizers.microcode.flow.flattening import (  # type: ignore
        c_mop_state as _c_module,
    )
except Exception as _exc:  # pragma: no cover - exercised only on builds
    _c_import_error = _exc
    _c_module = None


def _try_call_c(name, *args, **kwargs):
    """Call a Cython function by name, falling back to None on absence.

    Used by the wrapper functions below to short-circuit to the C
    implementation when available.
    """
    if _c_module is None:
        return None
    fn = getattr(_c_module, name, None)
    if fn is None:
        return None
    try:
        return fn(*args, **kwargs)
    except Exception:
        # Never let a Cython helper failure propagate -- Python
        # fallback is the canonical behavior.
        return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def hash_unresolved_state(
    unresolved_mops,
    memory_unresolved_mops,
    func_ea: int = 0,
) -> int:
    """Return a 64-bit hash for an (unresolved, memory-unresolved) pair.

    Tries the Cython implementation first, then falls back to a pure
    Python hash that mirrors :class:`SearchContext.make_state_hash`.
    """
    out = _try_call_c(
        "hash_unresolved_state",
        list(unresolved_mops),
        list(memory_unresolved_mops),
        int(func_ea),
    )
    if out is not None:
        try:
            return int(out)
        except Exception:
            pass
    # Pure-Python fallback mirrors tracker.SearchContext.make_state_hash.
    try:
        from d810.hexrays.utils.hexrays_helpers import structural_mop_hash

        non_memory_parts = []
        for mop in unresolved_mops:
            try:
                non_memory_parts.append(
                    (0, int(mop.t), int(structural_mop_hash(mop, int(func_ea))))
                )
            except Exception:
                # Single-mop fallback to id() so we never lose correctness.
                non_memory_parts.append((0, int(getattr(mop, "t", 0)), id(mop)))
        memory_parts = []
        for mop in memory_unresolved_mops:
            try:
                memory_parts.append(
                    (1, int(mop.t), int(structural_mop_hash(mop, int(func_ea))))
                )
            except Exception:
                memory_parts.append((1, int(getattr(mop, "t", 0)), id(mop)))
        return hash(tuple(sorted(non_memory_parts + memory_parts)))
    except Exception:
        return 0


def batch_hash_mops(mops, func_ea: int = 0) -> list[int]:
    """Hash a list of mops in one call, returning a parallel list[int]."""
    out = _try_call_c("batch_hash_mops", list(mops), int(func_ea))
    if out is not None:
        try:
            return [int(x) for x in out]
        except Exception:
            pass
    result: list[int] = []
    try:
        from d810.hexrays.utils.hexrays_helpers import structural_mop_hash

        for mop in mops:
            try:
                result.append(int(structural_mop_hash(mop, int(func_ea))))
            except Exception:
                result.append(id(mop))
    except Exception:
        for mop in mops:
            result.append(id(mop))
    return result


def jtbl_case_target_serials(entry_blk) -> list[tuple[int, int]]:
    """Return ``(case_value, target_serial)`` pairs for an m_jtbl block.

    Empty list if the block is not a jtbl or the case list is not
    accessible.  The result is suitable for direct dict construction.
    """
    out = _try_call_c("jtbl_case_target_serials", entry_blk)
    if out is not None:
        try:
            return [(int(a), int(b)) for a, b in out]
        except Exception:
            pass
    result: list[tuple[int, int]] = []
    try:
        import ida_hexrays

        if entry_blk is None:
            return result
        tail = getattr(entry_blk, "tail", None)
        if tail is None or tail.opcode != ida_hexrays.m_jtbl:
            return result
        r = tail.r
        if r is None or getattr(r, "t", None) != ida_hexrays.mop_c or r.c is None:
            return result
        mcases = r.c
        try:
            size = mcases.targets.size()
        except Exception:
            return result
        try:
            values_size = mcases.values.size()
        except Exception:
            values_size = size
        for i in range(size):
            try:
                target_serial = int(mcases.targets[i])
            except Exception:
                return []
            if i >= values_size:
                continue
            try:
                case_values = mcases.values[i]
            except Exception:
                continue
            if case_values is None or len(case_values) == 0:
                continue
            try:
                result.append((int(case_values[0]), target_serial))
            except Exception:
                continue
    except Exception:
        return []
    return result


def block_serial_set(blk, kind: str = "pred") -> set[int]:
    """Return a Python set[int] of predecessor or successor serials.

    ``kind`` is ``"pred"`` or ``"succ"``.  Pure-Python fallback; the
    Cython implementation (when available) batches the SWIG calls.
    """
    out = _try_call_c("block_serial_set", blk, str(kind))
    if out is not None:
        try:
            return {int(x) for x in out}
        except Exception:
            pass
    result: set[int] = set()
    if blk is None:
        return result
    try:
        if kind == "pred":
            for s in blk.predset:
                try:
                    result.add(int(s))
                except Exception:
                    pass
        elif kind == "succ":
            for s in blk.succset:
                try:
                    result.add(int(s))
                except Exception:
                    pass
    except Exception:
        return set()
    return result


__all__ = [
    "hash_unresolved_state",
    "batch_hash_mops",
    "jtbl_case_target_serials",
    "block_serial_set",
]
