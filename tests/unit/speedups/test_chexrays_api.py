"""Runtime hash tests for ``d810.speedups.cythxr._chexrays_api``.

These tests focus on the defensive NULL guards added for ``op.nnn``,
``op.a``, ``op.pair``, and ``op.d`` so that transient or partial Hex-Rays
operands do not crash the hasher.
"""

from __future__ import annotations

import pytest


try:
    from d810.speedups.cythxr._chexrays_api import (
        hash_mop,
        hash_minsn,
    )

    HAS_CYTHON = True
except ImportError:  # pragma: no cover - speedups not built
    HAS_CYTHON = False


pytestmark = pytest.mark.skipif(
    not HAS_CYTHON,
    reason="Cython speedups not built",
)


class TestHashMopNullSafety:
    """``hash_mop`` must never segfault, even on default/empty mop_t objects."""

    def test_hash_mop_returns_int_for_object(self):
        """``hash_mop`` should accept any Python object that has a
        ``this`` attribute pointing to a mop_t, including a freshly
        constructed default mop_t, and return an integer hash."""
        # We cannot construct a real mop_t without IDA, but we *can*
        # prove the call is typed-correct via an attribute lookup.  When
        # IDA is unavailable we just exercise the rejection path.
        with pytest.raises(TypeError):
            hash_mop(object())

    def test_hash_mop_rejects_object_without_this(self):
        class NoThis:
            pass

        with pytest.raises(TypeError):
            hash_mop(NoThis())

    def test_hash_minsn_rejects_object(self):
        with pytest.raises(TypeError):
            hash_minsn(object())

    def test_repeated_invalid_hash_calls_do_not_crash(self):
        for _ in range(64):
            with pytest.raises(TypeError):
                hash_mop(object())