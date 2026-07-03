"""Runtime parity tests for ``CythonConcreteEvaluator`` vs ``ConcreteEvaluator``.

These tests require IDA Pro and the Cython speedup module.  When the
Cython ``c_concrete`` module is not available, the parity assertions
still run against the Python fallback so that the contract is exercised
at least once.

Markers: ``ida_required``, ``hexrays``, ``runtime``.
"""

from __future__ import annotations

import pytest


try:
    from d810.speedups.evaluator.c_concrete import (
        CythonConcreteEvaluator as _CythonCls,
    )

    HAS_CYTHON_EVALUATOR = True
except ImportError:  # pragma: no cover - speedups not built
    HAS_CYTHON_EVALUATOR = False


from d810.evaluator.concrete import ConcreteEvaluator
from d810.errors import AstEvaluationException


def _require_ida_and_speedups():
    if not HAS_CYTHON_EVALUATOR:
        pytest.skip("Cython evaluator not built")


class TestMissingLeafBindingParity:
    """Both evaluators must return ``None`` for an unbound leaf."""

    def test_python_returns_none(self, ida_hexrays):
        from d810.hexrays.expr.p_ast import AstLeaf

        leaf = AstLeaf(name="x")
        leaf.ast_index = 1
        assert ConcreteEvaluator().evaluate(leaf, {}) is None

    @pytest.mark.skipif(
        not HAS_CYTHON_EVALUATOR,
        reason="Cython evaluator not built",
    )
    def test_cython_returns_none(self, ida_hexrays):
        from d810.hexrays.expr.p_ast import AstLeaf

        leaf = AstLeaf(name="x")
        leaf.ast_index = 1
        assert _CythonCls().evaluate(leaf, {}) is None


class TestMLnotParity:
    """``m_lnot`` parity: both must return the same masked integer."""

    def _build(self, ida_hexrays, value):
        from d810.hexrays.expr.p_ast import AstConstant, AstNode

        constant = AstConstant(name="k", expected_value=value)
        node = AstNode(opcode=ida_hexrays.m_lnot, left=constant)
        node.dest_size = 4
        constant.dest_size = 4
        return node

    def test_python_lnot_zero(self, ida_hexrays):
        node = self._build(ida_hexrays, 0)
        assert ConcreteEvaluator().evaluate(node, {}) == 1

    @pytest.mark.skipif(
        not HAS_CYTHON_EVALUATOR,
        reason="Cython evaluator not built",
    )
    def test_cython_lnot_zero(self, ida_hexrays):
        node = self._build(ida_hexrays, 0)
        assert _CythonCls().evaluate(node, {}) == 1

    def test_python_lnot_nonzero(self, ida_hexrays):
        node = self._build(ida_hexrays, 5)
        assert ConcreteEvaluator().evaluate(node, {}) == 0

    @pytest.mark.skipif(
        not HAS_CYTHON_EVALUATOR,
        reason="Cython evaluator not built",
    )
    def test_cython_lnot_nonzero(self, ida_hexrays):
        node = self._build(ida_hexrays, 5)
        assert _CythonCls().evaluate(node, {}) == 0


class TestDivModByZeroParity:
    """``m_udiv`` / ``m_sdiv`` / ``m_umod`` / ``m_smod`` by zero → ``None``."""

    @pytest.mark.parametrize(
        "opcode_name",
        ["m_udiv", "m_sdiv", "m_umod", "m_smod"],
    )
    def test_python_divmod_by_zero(self, ida_hexrays, opcode_name):
        from d810.hexrays.expr.p_ast import AstConstant, AstNode

        left = AstConstant(name="a", expected_value=10)
        right = AstConstant(name="b", expected_value=0)
        left.dest_size = 4
        right.dest_size = 4
        node = AstNode(opcode=getattr(ida_hexrays, opcode_name), left=left, right=right)
        node.dest_size = 4
        assert ConcreteEvaluator().evaluate(node, {}) is None

    @pytest.mark.parametrize(
        "opcode_name",
        ["m_udiv", "m_sdiv", "m_umod", "m_smod"],
    )
    @pytest.mark.skipif(
        not HAS_CYTHON_EVALUATOR,
        reason="Cython evaluator not built",
    )
    def test_cython_divmod_by_zero(self, ida_hexrays, opcode_name):
        from d810.hexrays.expr.p_ast import AstConstant, AstNode

        left = AstConstant(name="a", expected_value=10)
        right = AstConstant(name="b", expected_value=0)
        left.dest_size = 4
        right.dest_size = 4
        node = AstNode(opcode=getattr(ida_hexrays, opcode_name), left=left, right=right)
        node.dest_size = 4
        assert _CythonCls().evaluate(node, {}) is None


class TestAddSubMulParity:
    """Basic arithmetic parity between the two evaluators."""

    def test_python_add(self, ida_hexrays):
        from d810.hexrays.expr.p_ast import AstConstant, AstNode

        left = AstConstant(name="a", expected_value=3)
        right = AstConstant(name="b", expected_value=4)
        left.dest_size = 4
        right.dest_size = 4
        node = AstNode(opcode=ida_hexrays.m_add, left=left, right=right)
        node.dest_size = 4
        assert ConcreteEvaluator().evaluate(node, {}) == 7

    @pytest.mark.skipif(
        not HAS_CYTHON_EVALUATOR,
        reason="Cython evaluator not built",
    )
    def test_cython_add(self, ida_hexrays):
        from d810.hexrays.expr.p_ast import AstConstant, AstNode

        left = AstConstant(name="a", expected_value=3)
        right = AstConstant(name="b", expected_value=4)
        left.dest_size = 4
        right.dest_size = 4
        node = AstNode(opcode=ida_hexrays.m_add, left=left, right=right)
        node.dest_size = 4
        assert _CythonCls().evaluate(node, {}) == 7