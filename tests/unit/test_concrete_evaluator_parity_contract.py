"""Pure-Python unit tests for the canonical ``ConcreteEvaluator`` parity
behaviors that the Cython fast path must also implement.

These tests pin down the contract that the Cython
:class:`d810.speedups.evaluator.c_concrete.CythonConcreteEvaluator` must
honor.  They exercise the Python reference implementation directly so the
suite runs even when the Cython extension or IDA itself is unavailable.

The Cython fast path is tested separately under
``tests/system/runtime/test_concrete_evaluator_parity.py``.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest


# Try to import the Python evaluator lazily so this test module can be
# collected even when ida_hexrays is not available.
try:
    from d810.evaluator.concrete import ConcreteEvaluator
    from d810.errors import AstEvaluationException
    HAS_CONCRETE = True
except ImportError:  # pragma: no cover - requires IDA
    HAS_CONCRETE = False


pytestmark = pytest.mark.skipif(
    not HAS_CONCRETE,
    reason="ida_hexrays is required for the ConcreteEvaluator parity tests",
)


# Use the opcode integer values from ida_hexrays directly if available,
# otherwise the parity tests still verify the structural Python
# behaviour.  ``ida_hexrays`` is only imported lazily so the file can be
# collected without the IDA plugin.
def _try_import_ida_opcodes():
    try:
        import ida_hexrays

        return {
            "m_mov": ida_hexrays.m_mov,
            "m_neg": ida_hexrays.m_neg,
            "m_lnot": ida_hexrays.m_lnot,
            "m_bnot": ida_hexrays.m_bnot,
            "m_add": ida_hexrays.m_add,
            "m_sub": ida_hexrays.m_sub,
            "m_mul": ida_hexrays.m_mul,
            "m_udiv": ida_hexrays.m_udiv,
            "m_sdiv": ida_hexrays.m_sdiv,
            "m_umod": ida_hexrays.m_umod,
            "m_smod": ida_hexrays.m_smod,
            "m_or": ida_hexrays.m_or,
            "m_and": ida_hexrays.m_and,
            "m_xor": ida_hexrays.m_xor,
            "m_shl": ida_hexrays.m_shl,
            "m_shr": ida_hexrays.m_shr,
            "m_sar": ida_hexrays.m_sar,
            "mop_n": ida_hexrays.mop_n,
            "m_call": ida_hexrays.m_call,
        }
    except ImportError:
        return None


OPCODES = _try_import_ida_opcodes()
NEEDS_IDA = pytest.mark.skipif(
    OPCODES is None,
    reason="ida_hexrays not importable",
)


# ---------------------------------------------------------------------------
# Mock AST classes that satisfy the duck-typed protocol used by the
# Python evaluator.
# ---------------------------------------------------------------------------


class MockMop:
    def __init__(self, value=None, kind="unknown"):
        self.value = value
        self.t = OPCODES["mop_n"] if kind == "number" and OPCODES else 0


class MockLeaf:
    """Stand-in for ``AstLeaf`` for ``ConcreteEvaluator._eval_leaf``."""

    def __init__(self, ast_index=None, mop=None, is_constant=False,
                 expected_value=None, dest_size=None):
        self.ast_index = ast_index
        self.mop = mop
        self._is_constant = is_constant
        self.expected_value = expected_value
        self.dest_size = dest_size

    def is_leaf(self):
        return True

    def is_node(self):
        return False

    def is_constant(self):
        return self._is_constant


class MockNode:
    """Stand-in for ``AstNode`` for ``ConcreteEvaluator._eval_node``."""

    def __init__(self, opcode, left, right=None, dest_size=4, ast_index=None,
                 func_name=""):
        self.opcode = opcode
        self.left = left
        self.right = right
        self.dest_size = dest_size
        self.ast_index = ast_index
        self.func_name = func_name

    def is_leaf(self):
        return False

    def is_node(self):
        return True

    def is_constant(self):
        return False


# ---------------------------------------------------------------------------
# Tests for the parity contract.
# ---------------------------------------------------------------------------


class TestMissingLeafBindingReturnsNone:
    """A leaf whose ``ast_index`` is absent from the env must yield ``None``."""

    @NEEDS_IDA
    def test_missing_binding_returns_none(self):
        leaf = MockLeaf(ast_index=42, is_constant=False)
        env = {}  # ast_index=42 not present
        ev = ConcreteEvaluator()
        assert ev.evaluate(leaf, env) is None


class TestMLnotReturnsMaskedInteger:
    """``m_lnot`` returns ``int(lv == 0) & res_mask`` (not a Python bool)."""

    @NEEDS_IDA
    def test_mlnot_zero_returns_one(self):
        leaf = MockLeaf(ast_index=0, is_constant=True, expected_value=0)
        node = MockNode(OPCODES["m_lnot"], leaf, dest_size=4)
        ev = ConcreteEvaluator()
        result = ev.evaluate(node, {})
        # res_mask for 4 bytes == 0xFFFFFFFF; 1 & mask == 1
        assert result == 1
        assert isinstance(result, int)
        assert not isinstance(result, bool)

    @NEEDS_IDA
    def test_mlnot_nonzero_returns_zero(self):
        leaf = MockLeaf(ast_index=0, is_constant=True, expected_value=5)
        node = MockNode(OPCODES["m_lnot"], leaf, dest_size=4)
        ev = ConcreteEvaluator()
        result = ev.evaluate(node, {})
        assert result == 0
        assert isinstance(result, int)


class TestDivModByZeroReturnsNone:
    """Division and modulo with a zero divisor must return ``None``."""

    @pytest.mark.parametrize("opcode_name", ["m_udiv", "m_sdiv", "m_umod", "m_smod"])
    @NEEDS_IDA
    def test_divmod_by_zero_returns_none(self, opcode_name):
        left = MockLeaf(ast_index=0, is_constant=True, expected_value=10, dest_size=4)
        right = MockLeaf(ast_index=1, is_constant=True, expected_value=0, dest_size=4)
        node = MockNode(OPCODES[opcode_name], left, right, dest_size=4)
        ev = ConcreteEvaluator()
        assert ev.evaluate(node, {}) is None

    @NEEDS_IDA
    def test_udiv_nonzero_returns_quotient(self):
        left = MockLeaf(ast_index=0, is_constant=True, expected_value=20)
        right = MockLeaf(ast_index=1, is_constant=True, expected_value=4)
        node = MockNode(OPCODES["m_udiv"], left, right, dest_size=4)
        ev = ConcreteEvaluator()
        assert ev.evaluate(node, {}) == 5

    @NEEDS_IDA
    def test_umod_nonzero_returns_remainder(self):
        left = MockLeaf(ast_index=0, is_constant=True, expected_value=20)
        right = MockLeaf(ast_index=1, is_constant=True, expected_value=3)
        node = MockNode(OPCODES["m_umod"], left, right, dest_size=4)
        ev = ConcreteEvaluator()
        assert ev.evaluate(node, {}) == 2


class TestArithmeticMasking:
    """Arithmetic results are masked to ``dest_size`` bits."""

    @NEEDS_IDA
    def test_add_overflows_are_masked(self):
        left = MockLeaf(ast_index=0, is_constant=True, expected_value=0xFFFFFFFF)
        right = MockLeaf(ast_index=1, is_constant=True, expected_value=1)
        node = MockNode(OPCODES["m_add"], left, right, dest_size=4)
        ev = ConcreteEvaluator()
        assert ev.evaluate(node, {}) == 0

    @NEEDS_IDA
    def test_or_masked(self):
        left = MockLeaf(ast_index=0, is_constant=True, expected_value=0xF0)
        right = MockLeaf(ast_index=1, is_constant=True, expected_value=0x0F)
        node = MockNode(OPCODES["m_or"], left, right, dest_size=1)
        ev = ConcreteEvaluator()
        # dest_size=1 mask == 0xFF; 0xF0 | 0x0F = 0xFF
        assert ev.evaluate(node, {}) == 0xFF


class TestNullPropagation:
    """``None`` operands must propagate through the result."""

    @NEEDS_IDA
    def test_add_with_none_left_propagates(self):
        right = MockLeaf(ast_index=1, is_constant=True, expected_value=2)
        # Left leaf has ast_index=0 which is not bound
        left = MockLeaf(ast_index=0, is_constant=False)
        node = MockNode(OPCODES["m_add"], left, right, dest_size=4)
        ev = ConcreteEvaluator()
        assert ev.evaluate(node, {}) is None


class TestUnknownOpcodeRaises:
    """Unsupported opcodes still raise ``AstEvaluationException``."""

    @NEEDS_IDA
    def test_unknown_opcode_raises(self):
        # opcode 0xFFFF is not in the dispatch table
        node = MockNode(0xFFFF,
                        MockLeaf(ast_index=0, is_constant=True, expected_value=1),
                        dest_size=4)
        ev = ConcreteEvaluator()
        with pytest.raises(AstEvaluationException):
            ev.evaluate(node, {})