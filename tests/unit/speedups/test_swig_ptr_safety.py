"""Regression tests for the ``_swig_ptr`` helper and friends in
``d810.speedups.cythxr._chexrays`` and ``_chexrays_api``.

The ``_swig_ptr`` helper used to dereference a ``PyObject*`` obtained via
``PyObject_GetAttrString`` without NULL checks and without ``Py_DECREF``,
which leaked a reference and crashed hard whenever the ``obj`` did not
expose a usable ``this`` SWIG pointer.  These tests ensure that invalid
input now raises ``TypeError`` instead of segfaulting.
"""

from __future__ import annotations

import pytest


# Import the Cython wrappers we exercise.  These tests skip gracefully if
# the speedups are not built for this interpreter (matches the pattern in
# ``test_simd.py``).
try:
    from d810.speedups.cythxr._chexrays_api import (
        hash_mop,
        hash_minsn,
        get_stack_or_reg_name,
    )

    HAS_CYTHON = True
except ImportError:  # pragma: no cover - speedups not built
    HAS_CYTHON = False
except OSError:  # pragma: no cover - DLL load failed (missing ida dll)
    HAS_CYTHON = False


pytestmark = pytest.mark.skipif(
    not HAS_CYTHON,
    reason="Cython speedups not built",
)


class TestSwigPtrSafety:
    """Passing non-SWIG objects to ``_swig_ptr`` consumers must raise cleanly."""

    def test_hash_mop_rejects_plain_object(self):
        with pytest.raises(TypeError):
            hash_mop(object())

    def test_hash_minsn_rejects_plain_object(self):
        with pytest.raises(TypeError):
            hash_minsn(object())

    def test_hash_mop_rejects_object_without_this(self):
        class NoThis:
            pass

        with pytest.raises(TypeError):
            hash_mop(NoThis())

    def test_hash_mop_rejects_object_with_null_this(self):
        """If ``this`` is present but is a NULL pointer, raise instead of crashing."""

        class _SwigWithNullPtr:
            class _SwigThis:
                ptr = None

            this = _SwigThis()

        with pytest.raises(TypeError):
            hash_mop(_SwigWithNullPtr())

    def test_get_stack_or_reg_name_rejects_plain_object(self):
        with pytest.raises(TypeError):
            get_stack_or_reg_name(object())

    def test_hash_mop_repeated_invalid_calls_do_not_crash(self):
        """Repeated invalid calls must never segfault the process."""
        for _ in range(64):
            with pytest.raises(TypeError):
                hash_mop(object())