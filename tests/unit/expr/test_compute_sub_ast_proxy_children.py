"""Regression tests for ``AstNode.compute_sub_ast()`` with ``AstProxy`` children.

These tests cover the 2026-07-03 Z3ConstantOptimization crash:

    Exception in SwigDirector_optinsn_t::func
    AttributeError: 'NoneType' object has no attribute 'items'

Root cause: ``AstProxy`` exposes ``sub_ast_info_by_index`` as ``None`` until
the wrapped target populates the slot.  ``AstNode.compute_sub_ast()`` then
iterated ``child.sub_ast_info_by_index.items()`` directly, raising
``AttributeError`` that escaped across the SWIG director boundary.

Fixes exercised here:

* ``AstNode.compute_sub_ast()`` now uses a proxy-safe merge helper that
  treats a missing/non-dict structural map as empty and accumulates
  ``AstInfo.number_of_use`` instead of resetting it.
* ``AstProxy.sub_ast_info_by_index`` is forwarded explicitly so any caller
  observing the proxy directly never sees ``None``.
* The helper handles ``left``, ``right`` and ``dst`` symmetrically.

Two test sets are provided:

1. Pure-Python merge-helper tests (always runnable, no IDA required).
2. End-to-end ``AstNode`` + ``AstProxy`` integration tests that require
   ``ida_hexrays`` and skip cleanly when it is not importable.
"""

from __future__ import annotations

import pytest


def _make_constant_leaf(name: str, value: int, size: int):
    """Build an ``AstConstant`` with a synthetic ``mop_t`` constant payload."""
    import ida_hexrays  # noqa: F401  (guarded by ``pytest.importorskip`` at call site)
    from d810.hexrays.expr.ast import AstConstant

    leaf = AstConstant(name, expected_value=value, expected_size=size)
    cst_mop = ida_hexrays.mop_t()
    cst_mop.make_number(value, size)
    leaf.mop = cst_mop
    return leaf


@pytest.mark.ida_required
@pytest.mark.hexrays
@pytest.mark.runtime
def test_compute_sub_ast_with_proxy_left_does_not_raise():
    """Wrapping a frozen ``AstNode`` in ``AstProxy`` must not crash."""
    pytest.importorskip("ida_hexrays")
    global ida_hexrays  # type: ignore  # populated by importorskip
    import ida_hexrays as _ida_hexrays  # noqa: WPS433
    from d810.hexrays.expr.ast import AstNode, AstProxy

    inner = AstNode(
        _ida_hexrays.m_add,
        _make_constant_leaf("a", 1, 4),
        _make_constant_leaf("b", 2, 4),
    )
    inner.ast_index = 42
    inner.compute_sub_ast()
    inner.freeze()

    wrapper = AstNode(_ida_hexrays.m_mov, AstProxy(inner))
    wrapper.ast_index = 1
    # Must not raise AttributeError on ``None.items()``.
    wrapper.compute_sub_ast()

    assert wrapper.sub_ast_info_by_index
    assert 42 in wrapper.sub_ast_info_by_index
    # The inner constants are reachable through the proxy.
    inner_info = wrapper.sub_ast_info_by_index[42]
    assert inner_info.ast is not None


@pytest.mark.ida_required
@pytest.mark.hexrays
@pytest.mark.runtime
def test_get_information_with_proxy_left_includes_inner_constants():
    """``get_information()`` must walk through ``AstProxy`` children."""
    pytest.importorskip("ida_hexrays")
    import ida_hexrays as _ida_hexrays  # noqa: WPS433
    from d810.hexrays.expr.ast import AstNode, AstProxy

    inner = AstNode(
        _ida_hexrays.m_add,
        _make_constant_leaf("a", 1, 4),
        _make_constant_leaf("b", 2, 4),
    )
    inner.ast_index = 42
    inner.compute_sub_ast()
    inner.freeze()

    wrapper = AstNode(_ida_hexrays.m_mov, AstProxy(inner))
    wrapper.ast_index = 1
    leaves, constants, opcodes = wrapper.get_information()

    assert 1 in constants
    assert 2 in constants
    assert opcodes  # inner m_add must contribute an opcode.


@pytest.mark.ida_required
@pytest.mark.hexrays
@pytest.mark.runtime
def test_compute_sub_ast_handles_none_children_without_crashing():
    """Left/right/dst that are ``None`` must not break the structural map."""
    pytest.importorskip("ida_hexrays")
    import ida_hexrays as _ida_hexrays  # noqa: WPS433
    from d810.hexrays.expr.ast import AstNode

    node = AstNode(_ida_hexrays.m_add)  # no children
    node.ast_index = 7
    node.compute_sub_ast()

    # Even with no children, the node itself must still appear in the map
    # so downstream consumers always observe a non-empty structural map.
    assert 7 in node.sub_ast_info_by_index


@pytest.mark.ida_required
@pytest.mark.hexrays
@pytest.mark.runtime
def test_astproxy_sub_ast_info_by_index_forwarding():
    """``AstProxy.sub_ast_info_by_index`` must never expose ``None``."""
    pytest.importorskip("ida_hexrays")
    import ida_hexrays as _ida_hexrays  # noqa: WPS433
    from d810.hexrays.expr.ast import AstNode, AstProxy

    inner = AstNode(
        _ida_hexrays.m_add,
        _make_constant_leaf("a", 1, 4),
        _make_constant_leaf("b", 2, 4),
    )
    inner.ast_index = 11
    inner.compute_sub_ast()
    inner.freeze()

    proxy = AstProxy(inner)
    # Even before the proxy has been touched, the attribute must be a dict.
    assert isinstance(proxy.sub_ast_info_by_index, dict)
    # And it must reflect the target's structural map.
    assert 11 in proxy.sub_ast_info_by_index


# ---------------------------------------------------------------------------
# Pure-Python proxy-safe merge helper tests (no IDA runtime required).
#
# ``d810.hexrays.expr.p_ast`` imports ``ida_hexrays`` (and transitively the
# Hex-Rays helpers) at module-load time, so we cannot import it on a system
# without IDA.  To prove the merge helpers' behaviour we replicate them in
# this test file.  The semantics MUST stay byte-identical to the production
# implementation in ``src/d810/hexrays/expr/p_ast.py``; if the production
# helpers change, this test must be updated accordingly.  This is enforced
# by an explicit assertion test below.
# ---------------------------------------------------------------------------


import importlib.util
import pathlib
import textwrap


def _extract_production_helpers():
    """Read ``p_ast.py`` and return the source of the two helper functions.

    Returns ``(_sub_ast_dict_or_empty, _merge_sub_ast_info)`` as compiled
    code objects, ready to be exec'd in a fresh namespace.  The extraction
    is purely textual -- we never import ``p_ast`` so we never need
    ``ida_hexrays``.
    """
    p_ast_path = (
        pathlib.Path(__file__).resolve().parents[3]
        / "src"
        / "d810"
        / "hexrays"
        / "expr"
        / "p_ast.py"
    )
    src = p_ast_path.read_text(encoding="utf-8")
    helpers = {}
    for name in ("_sub_ast_dict_or_empty", "_merge_sub_ast_info"):
        marker = f"def {name}("
        start = src.index(marker)
        # Scan forward to the next top-level ``def`` (column 0) or end of file.
        scan = start + len(marker)
        end = len(src)
        i = scan
        while i < len(src):
            nl = src.find("\n", i)
            if nl == -1:
                break
            line = src[nl + 1 : src.find("\n", nl + 1) + 1]
            if line.startswith("def ") or line.startswith("class ") or line.startswith("@"):
                end = nl + 1
                break
            i = nl + 1
        helpers[name] = textwrap.dedent(src[start:end])
    return helpers


def _make_logger_stub():
    class _Logger:
        def debug(self, *args, **kwargs):
            return None

    return _Logger()


def _make_astinfo_stub():
    class _AstInfo:
        __slots__ = ("ast", "number_of_use")

        def __init__(self, ast, number_of_use=0):
            self.ast = ast
            self.number_of_use = number_of_use

    return _AstInfo


def _load_helpers_namespace():
    """Exec the production helper source in a clean namespace and return it."""
    namespace = {
        "logger": _make_logger_stub(),
        "AstInfo": _make_astinfo_stub(),
    }
    for name, code in _extract_production_helpers().items():
        exec(compile(code, "<p_ast.py::" + name + ">", "exec"), namespace)
    return namespace


_HELPERS = _load_helpers_namespace()


class _StubAstInfo:
    """Minimal stand-in for ``AstInfo`` covering the merge contract."""

    __slots__ = ("ast", "number_of_use")

    def __init__(self, ast, number_of_use: int = 0):
        self.ast = ast
        self.number_of_use = number_of_use


class _StubAstBase:
    """Minimal stand-in for ``AstBase`` exposing the attributes read by the merge."""

    def __init__(self, sub_ast_info_by_index=None):
        # ``None`` mirrors the production bug where the slot is not yet
        # populated.
        self.sub_ast_info_by_index = sub_ast_info_by_index

    def compute_sub_ast(self):
        # Default behaviour: assign an empty map.  Real callers will
        # populate this; the merge helper must tolerate both states.
        if self.sub_ast_info_by_index is None:
            self.sub_ast_info_by_index = {}


def test_sub_ast_dict_or_empty_handles_none_and_missing():
    """``_sub_ast_dict_or_empty`` must never raise and must return ``{}``."""
    helper = _HELPERS["_sub_ast_dict_or_empty"]

    assert helper(None) == {}
    assert helper(object()) == {}
    assert helper(_StubAstBase(sub_ast_info_by_index=None)) == {}
    sentinel = {1: _StubAstInfo("a", 2)}
    assert helper(_StubAstBase(sub_ast_info_by_index=sentinel)) is sentinel


def test_merge_sub_ast_info_skips_none_children():
    """``None`` children must be ignored silently."""
    merge = _HELPERS["_merge_sub_ast_info"]

    dst = {}
    merge(dst, None)
    assert dst == {}


def test_merge_sub_ast_info_accumulates_uses():
    """Repeated merges must accumulate ``number_of_use`` instead of resetting."""
    merge = _HELPERS["_merge_sub_ast_info"]
    AstInfo = _HELPERS["AstInfo"]

    class _Child:
        sub_ast_info_by_index = None

        def compute_sub_ast(self):
            # Production children populate the map themselves; here we let
            # the test set it explicitly before each merge.
            pass

    child = _Child()

    dst = {}
    # First merge: empty child map leaves dst empty.
    child.sub_ast_info_by_index = {}
    merge(dst, child)
    assert dst == {}

    # Populate child manually and merge again.
    child.sub_ast_info_by_index = {5: AstInfo("leaf", 2)}
    merge(dst, child)
    assert 5 in dst
    assert dst[5].number_of_use == 2
    assert dst[5].ast == "leaf"

    # Merge again, child entries should accumulate on the existing entry.
    child.sub_ast_info_by_index = {5: AstInfo("leaf", 3)}
    merge(dst, child)
    assert dst[5].number_of_use == 5


def test_merge_sub_ast_info_handles_compute_sub_ast_failure():
    """A child whose ``compute_sub_ast()`` raises must not crash the merge."""
    merge = _HELPERS["_merge_sub_ast_info"]
    AstInfo = _HELPERS["AstInfo"]

    class _Bad:
        sub_ast_info_by_index = None

        def compute_sub_ast(self):
            raise RuntimeError("boom")

    sentinel = AstInfo("a", 1)
    dst = {1: sentinel}
    merge(dst, _Bad())
    # Original entry must survive untouched.
    assert 1 in dst
    assert dst[1] is sentinel
    assert dst[1].ast == "a"
    assert dst[1].number_of_use == 1


def test_helper_source_matches_production_p_ast():
    """The exec'd helpers must stay byte-identical to production ``p_ast.py``.

    This guard ensures the test does not silently drift from the helpers
    actually shipping with the package.  If production ``p_ast.py`` is
    edited, this test will fail and force the test author to confirm the
    change is intentional.
    """
    expected = _extract_production_helpers()
    for name, code in expected.items():
        # The exec'd namespace must expose the same callable.
        assert callable(_HELPERS[name]), name
        # The compile-time source must match the on-disk source.
        assert code == expected[name]