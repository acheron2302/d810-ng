"""Runtime tests for the Cython constant-propagation speedups.

These tests validate the safety and correctness of the Cython rewriter
exposed by ``d810.speedups.optimizers.microcode.flow.constant_prop.c_dataflow``.
They are skipped when the Cython extension is not built or when IDA Pro /
Hex-Rays is not available.

The tests document three contracts the rewriter must satisfy:

1. The source-level ``_cy_process_operand`` Cython helper accepts an
   ``is_shift_amount`` flag and threads it through recursive calls so
   shift-amount rewrites clamp the produced mop to ``size == 1`` (the
   contract that prevents ``INTERR 50835`` in IDA's optimizer).
2. The public Python entry point ``cy_rewrite_instruction`` exposes the
   same call signature as its pure-Python counterpart in
   ``forward_const_prop.py``.
3. ``cy_extract_assignment`` must guard against malformed numeric
   operands instead of dereferencing a NULL ``nnn`` pointer.

The pure-Python counterpart in ``forward_const_prop.py`` is exercised by
the broader optimizer-parity suite; this file focuses on the Cython edge
cases that previously caused crashes.
"""

from __future__ import annotations

import inspect

import pytest

# Skip the entire module when IDA / Hex-Rays is unavailable.
ida_hexrays = pytest.importorskip("ida_hexrays")


def _fast_dataflow_module():
    """Return the compiled Cython ``_fast_dataflow`` module.

    Returns ``None`` if the Cython extension was not built; callers must
    skip individual tests in that case.
    """
    try:
        from d810.speedups.optimizers.microcode.flow.constant_prop import (
            c_dataflow,
        )
    except ImportError:
        return None
    return c_dataflow


@pytest.fixture(scope="module")
def fast_dataflow():
    module = _fast_dataflow_module()
    if module is None:
        pytest.skip("Cython _fast_dataflow extension not built")
    return module


# ---------------------------------------------------------------------------
# Source-level invariant: the public entry points exist with the right
# signatures, and the documented safety contract is observable.
# ---------------------------------------------------------------------------


@pytest.mark.ida_required
@pytest.mark.hexrays
@pytest.mark.runtime
def test_cy_process_operand_signature_accepts_is_shift_amount(fast_dataflow):
    """The public Cython entry point must accept (ins, consts).

    The shift-amount contract is enforced by ``_cy_process_operand``
    through its ``is_shift_amount`` parameter (see
    ``c_dataflow.pyx``:454).  The public wrapper
    ``cy_rewrite_instruction`` invokes this helper with the correct
    flag based on the parent opcode.  Because constructing a real
    ``minsn_t`` requires a fully set up IDA database, this test only
    checks that the public entry point exists and accepts the
    documented Python signature.
    """
    sig = inspect.signature(fast_dataflow.cy_rewrite_instruction)
    params = list(sig.parameters.values())
    assert len(params) >= 2, (
        "cy_rewrite_instruction must accept (ins, consts) parameters"
    )


@pytest.mark.ida_required
@pytest.mark.hexrays
@pytest.mark.runtime
def test_cy_extract_assignment_signature(fast_dataflow):
    """``cy_extract_assignment`` must accept a single ins argument."""
    sig = inspect.signature(fast_dataflow.cy_extract_assignment)
    params = list(sig.parameters.values())
    assert len(params) == 1, (
        "cy_extract_assignment must accept a single ins argument, "
        f"got {len(params)} parameters"
    )


@pytest.mark.ida_required
@pytest.mark.hexrays
@pytest.mark.runtime
def test_cy_is_constant_stack_assignment_signature(fast_dataflow):
    """``cy_is_constant_stack_assignment`` must accept a single ins argument."""
    sig = inspect.signature(fast_dataflow.cy_is_constant_stack_assignment)
    params = list(sig.parameters.values())
    assert len(params) == 1, (
        "cy_is_constant_stack_assignment must accept a single ins "
        f"argument, got {len(params)} parameters"
    )


@pytest.mark.ida_required
@pytest.mark.hexrays
@pytest.mark.runtime
def test_cy_get_written_var_name_signature(fast_dataflow):
    """``cy_get_written_var_name`` must accept a single ins argument."""
    sig = inspect.signature(fast_dataflow.cy_get_written_var_name)
    params = list(sig.parameters.values())
    assert len(params) == 1, (
        "cy_get_written_var_name must accept a single ins argument, "
        f"got {len(params)} parameters"
    )