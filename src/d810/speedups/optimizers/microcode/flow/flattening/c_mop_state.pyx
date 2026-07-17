# cython: language_level=3
# distutils: language = c
"""Cython fast-path stubs for unflattening hot paths.

This file is a placeholder for the planned Cython implementation.  It
defines the same interface as ``d810.speedups.optimizers.microcode.
flow.flattening.unflat_state`` so the wrapper can import either
implementation transparently.

Phase 6: keep this file read-only with respect to the MBA/CFG.
Mutation continues to live in the central CFG mutation gateway.

To enable: build with ``D810_BUILD_SPEEDUPS=1 pip install -e .[speedups]``
in an environment that has the IDA SDK + a C compiler.
"""
from __future__ import annotations

cimport cython

# NOTE: the real implementation will declare the helper cpdef functions
# once the IDA SDK header availability is confirmed for the build env.
# Until then, the Python wrapper in ``unflat_state.py`` is the canonical
# implementation and this file only needs to be syntactically valid
# Cython so ``setup.py`` can find and compile it.

# Provide minimal Python-visible symbols so the wrapper's import does
# not raise AttributeError.  These delegate to Python implementations
# (deferred import) to keep the file standalone.
def hash_unresolved_state(unresolved_mops, memory_unresolved_mops, func_ea=0):
    from d810.speedups.optimizers.microcode.flow.flattening.unflat_state import (
        hash_unresolved_state as _py,
    )
    return _py(unresolved_mops, memory_unresolved_mops, func_ea)


def batch_hash_mops(mops, func_ea=0):
    from d810.speedups.optimizers.microcode.flow.flattening.unflat_state import (
        batch_hash_mops as _py,
    )
    return _py(mops, func_ea)


def jtbl_case_target_serials(entry_blk):
    from d810.speedups.optimizers.microcode.flow.flattening.unflat_state import (
        jtbl_case_target_serials as _py,
    )
    return _py(entry_blk)


def block_serial_set(blk, kind="pred"):
    from d810.speedups.optimizers.microcode.flow.flattening.unflat_state import (
        block_serial_set as _py,
    )
    return _py(blk, kind)
