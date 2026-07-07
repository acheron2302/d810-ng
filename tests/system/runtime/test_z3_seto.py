"""Targeted regression test for Z3 AST support of ``m_seto``.

These tests pin down the signed-subtraction-overflow semantics of the
``m_seto`` opcode as expressed by :class:`AstNodeZ3Visitor`. Before this
fix, the Z3 visitor raised ``D810Z3Exception: Unknown opcode seto`` for any
expression rooted at ``seto(...)``, blocking ``Z3ConstantOptimization``
from proving and folding such constants.

Markers (auto-applied by ``tests/system/runtime/conftest.py``):
``ida_required``, ``hexrays``, ``runtime``.
"""

from __future__ import annotations

import pytest

try:
    import z3  # noqa: F401  (presence check)

    HAS_Z3 = True
except ImportError:  # pragma: no cover - Z3 not installed
    HAS_Z3 = False


pytestmark = pytest.mark.skipif(
    not HAS_Z3,
    reason="Z3 python bindings are required for the m_seto Z3 tests",
)


def _build_seto(z3_mod, ida_hexrays, left_val: int, right_val: int):
    """Build a concrete ``m_seto(left, right)`` AST and convert it via Z3.

    Returns the resulting Z3 BitVec expression (32-bit, ``1`` if overflow
    is set, ``0`` otherwise).
    """
    from d810.backends.ast.z3 import AstNodeZ3Visitor
    from d810.hexrays.expr.p_ast import AstConstant, AstNode

    left = AstConstant(name="L", expected_value=left_val)
    left.dest_size = 4
    right = AstConstant(name="R", expected_value=right_val)
    right.dest_size = 4
    node = AstNode(opcode=ida_hexrays.m_seto, left=left, right=right)
    node.dest_size = 4

    return AstNodeZ3Visitor().visit(node)


def _eval_z3(z3_mod, expr) -> int:
    """Evaluate a 32-bit Z3 BitVec expression with a fresh solver."""
    solver = z3_mod.Solver()
    solver.add(expr != z3_mod.BitVecVal(0, 32))
    solver.add(expr != z3_mod.BitVecVal(1, 32))
    if solver.check() == z3_mod.sat:
        # Non-constant: dump a model and fail loudly with diagnostics.
        model = solver.model()
        pytest.fail(f"m_seto expression is not constant; model: {model}")
    # Now it's proven constant; ask whether it equals 0 or 1.
    is_zero = z3_mod.Solver()
    is_zero.add(expr != z3_mod.BitVecVal(0, 32))
    return 0 if is_zero.check() == z3_mod.sat else 1


class TestSetoZ3Conversion:
    """``AstNodeZ3Visitor`` must support ``m_seto`` with the same signed
    subtraction overflow semantics as the concrete evaluators."""

    # Case matrix from the implementation plan, 32-bit subtraction overflow.
    OVERFLOW_CASES = [
        (0x7FFFFFFF, 0xFFFFFFFF, 1),  # INT_MAX - (-1) -> overflow
        (0x80000000, 0x00000001, 1),  # INT_MIN - 1 -> overflow
        (0x00000005, 0x00000003, 0),  # small positive diff -> no overflow
        (0xFFFFFFFF, 0x00000001, 0),  # -1 - 1 -> no overflow (wraps to -2)
    ]

    @pytest.mark.parametrize(
        ("left_val", "right_val", "expected"),
        OVERFLOW_CASES,
        ids=[
            "INT_MAX_minus_neg1",
            "INT_MIN_minus_1",
            "5_minus_3",
            "neg1_minus_1",
        ],
    )
    def test_m_seto_overflow_semantics(
        self, ida_hexrays, left_val, right_val, expected
    ):
        """The Z3 expression must match the concrete signed-overflow bit."""
        import z3 as z3_mod

        expr = _build_seto(z3_mod, ida_hexrays, left_val, right_val)
        assert expr.size() == 32
        assert _eval_z3(z3_mod, expr) == expected

    def test_m_seto_does_not_raise_unknown_opcode(self, ida_hexrays):
        """Regression: visiting ``m_seto`` must not raise
        ``D810Z3Exception(Unknown opcode seto)``."""
        from d810.backends.ast.z3 import AstNodeZ3Visitor
        from d810.errors import D810Z3Exception
        from d810.hexrays.expr.p_ast import AstConstant, AstNode

        left = AstConstant(name="L", expected_value=1)
        left.dest_size = 4
        right = AstConstant(name="R", expected_value=2)
        right.dest_size = 4
        node = AstNode(opcode=ida_hexrays.m_seto, left=left, right=right)
        node.dest_size = 4

        # The visitor must complete without D810Z3Exception. We don't
        # care which exact 32-bit BitVec it returns beyond it being a
        # valid Z3 expression that does not raise.
        AstNodeZ3Visitor().visit(node)

    def test_m_seto_legacy_helpers_consistent(self, ida_hexrays):
        """The legacy ``expr.z3_utils.ast_to_z3_expression`` must accept
        ``m_seto`` too, mirroring the primary backend."""
        import z3 as z3_mod

        from d810.expr.z3_utils import ast_to_z3_expression
        from d810.hexrays.expr.p_ast import AstConstant, AstNode

        left = AstConstant(name="L", expected_value=0x7FFFFFFF)
        left.dest_size = 4
        right = AstConstant(name="R", expected_value=0xFFFFFFFF)
        right.dest_size = 4
        node = AstNode(opcode=ida_hexrays.m_seto, left=left, right=right)
        node.dest_size = 4

        expr = ast_to_z3_expression(node)
        assert expr.size() == 32
        assert _eval_z3(z3_mod, expr) == 1