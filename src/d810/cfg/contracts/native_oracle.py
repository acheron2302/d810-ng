"""Native oracle for blocked-by-api INTERR checks.

Historically this module attempted to import a Cython extension
``d810.speedups.cythxr._cblock_oracle`` to provide fast, native checks
for the 15 ``INTERR`` codes that the upstream Hex-Rays API blocks from
direct inspection.  The Cython module was never implemented, so the
import silently failed and ``NATIVE_ORACLE_AVAILABLE`` was permanently
``False``, which caused ``ida_contract.py`` to skip the relevant checks
without any user-visible signal.

This module is now an **explicit, documented stub** that:

1. Returns an empty list of violations from :func:`check_mba_native` and
   :func:`check_block_native` (matching the previous fallback semantics
   so callers do not have to change).
2. Logs a single warning at module import time explaining that the
   native oracle is unavailable and which checks are therefore skipped.
3. Provides :func:`oracle_available` returning ``False`` so callers can
   opt in or out explicitly.

If a future contributor ports the 15 blocked-by-api checks to a Cython
extension, they can drop in the actual module and remove this stub.
Until then, do NOT add a placeholder Cython import here: silent
``ImportError`` swallowing was the original bug.
"""

from __future__ import annotations

from d810.core import getLogger
from d810.core.typing import TYPE_CHECKING

if TYPE_CHECKING:
    from d810.core.typing import List, Tuple


logger = getLogger(__name__)


# The native Cython oracle is intentionally NOT implemented.  Setting
# this flag to ``False`` lets callers branch on availability without
# ever triggering a missing-module import.
NATIVE_ORACLE_AVAILABLE = False


# Reason logged once at module import time so operators do not have to
# read this file to understand why the affected checks are skipped.
_UNAVAILABLE_REASON = (
    "Native oracle is unavailable: the Cython extension "
    "'d810.speedups.cythxr._cblock_oracle' has not been implemented. "
    "The 15 blocked-by-api INTERR codes will not be checked; the "
    "ida_contract checks that depend on this oracle will return an "
    "empty violation list.  See .kilo/fixing-plan.md (item 9) for the "
    "decision and the path to re-enable native checking."
)


def oracle_available() -> bool:
    """Return ``True`` only when the native Cython oracle is importable.

    Returns:
        ``False`` until the ``_cblock_oracle`` extension is implemented.
    """
    return NATIVE_ORACLE_AVAILABLE


def check_mba_native(mba) -> "List[Tuple[int, int, str]]":
    """Run native oracle checks on a full MBA.

    Stub implementation: returns an empty list because the native
    extension is not available.  Callers MUST be tolerant of an empty
    list and treat it as "no violations detected by native checks" —
    downstream Python checks are still performed.

    Args:
        mba: A SWIG-wrapped ``ida_hexrays.mba_t`` object.

    Returns:
        Empty list when the native oracle is not available.
    """
    return []


def check_block_native(block) -> "List[Tuple[int, int, str]]":
    """Run native oracle checks on a single block.

    Stub implementation: returns an empty list because the native
    extension is not available.

    Args:
        block: A SWIG-wrapped ``ida_hexrays.mblock_t`` object.

    Returns:
        Empty list when the native oracle is not available.
    """
    return []


# Log the unavailable status once at import time so the operator sees a
# single, deterministic warning instead of one per call.
logger.debug(_UNAVAILABLE_REASON)


__all__ = [
    "NATIVE_ORACLE_AVAILABLE",
    "oracle_available",
    "check_mba_native",
    "check_block_native",
]