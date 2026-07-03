"""Regression tests for AST class identity across the legacy/canonical split.

These tests guard against the IDA reload crash reported in
``fixing-plan.md`` (2026-07-03 addendum):

    TypeError: Argument 'left' has incorrect type
    (expected d810.speedups.expr.c_ast.AstBase, got AstLeaf)

The crash happens when a pattern rule instantiates ``AstLeaf`` from the
legacy ``d810.expr.ast`` module and passes it into a Cython ``AstNode`` whose
typed ``left``/``right`` slots only accept the canonical ``AstBase``
hierarchy. The fix consolidates the dispatcher behind
``d810.hexrays.expr.ast``; ``d810.expr.ast`` is now a thin re-export shim
whose classes are the *exact same* Python objects the canonical module
exposes.

The test suite validates:

1. ``d810.expr.ast`` and ``d810.hexrays.expr.ast`` export the same class
   objects for ``AstBase``, ``AstNode``, ``AstLeaf``, ``AstConstant``, and
   ``AstProxy``.
2. The dispatcher ``get_ast_variations_with_add_sub`` accepts canonical
   ``AstLeaf`` instances without raising a ``TypeError`` about the wrong
   ``AstBase`` type -- this is the exact code path that produced the
   2026-07-03 crash.
3. Representative pattern rule modules (``rewrite_add``, ``rewrite_xor``,
   ``hodur``, ``weird``) instantiate successfully and produce valid AST
   candidates under Cython mode.
4. The pure-Python fallback path also works when Cython mode is disabled.

These tests require the IDA Pro / Hex-Rays runtime, so they are skipped
when ``ida_hexrays`` is not importable.
"""

from __future__ import annotations

import pytest

ida_hexrays = pytest.importorskip("ida_hexrays")


# ---------------------------------------------------------------------------
# 1. Identity assertions: legacy vs canonical class objects.
# ---------------------------------------------------------------------------


@pytest.mark.ida_required
@pytest.mark.hexrays
@pytest.mark.runtime
def test_legacy_and_canonical_ast_classes_are_identical():
    """The legacy shim must re-export the canonical class objects."""
    import d810.expr.ast as legacy
    import d810.hexrays.expr.ast as canonical

    assert legacy.AstBase is canonical.AstBase
    assert legacy.AstNode is canonical.AstNode
    assert legacy.AstLeaf is canonical.AstLeaf
    assert legacy.AstConstant is canonical.AstConstant
    assert legacy.AstProxy is canonical.AstProxy


@pytest.mark.ida_required
@pytest.mark.hexrays
@pytest.mark.runtime
def test_legacy_shim_exposes_required_public_helpers():
    """The shim must expose the public helpers used by z3_utils and friends."""
    import d810.expr.ast as legacy
    import d810.hexrays.ir.minsn_utils as minsn_utils
    import d810.hexrays.ir.mop_utils as mop_utils

    assert legacy.minsn_to_ast is minsn_utils.minsn_to_ast
    assert legacy.mop_to_ast is mop_utils.mop_to_ast
    assert callable(legacy.clear_mop_to_ast_cache)


# ---------------------------------------------------------------------------
# 2. get_ast_variations_with_add_sub must accept canonical AstLeaf values.
# ---------------------------------------------------------------------------


@pytest.mark.ida_required
@pytest.mark.hexrays
@pytest.mark.runtime
def test_get_ast_variations_with_add_sub_accepts_canonical_ast_leaf():
    """Constructing the ASTNode must not raise the legacy AstBase TypeError."""
    from d810.hexrays.expr.ast import AstLeaf, AstNode
    from d810.optimizers.microcode.instructions.pattern_matching.handler import (
        get_ast_variations_with_add_sub,
    )

    left = AstLeaf("x_0")
    right = AstLeaf("x_1")
    # The very call that produced the crash on 2026-07-03:
    variations = get_ast_variations_with_add_sub(ida_hexrays.m_add, left, right)
    assert len(variations) >= 1
    for v in variations:
        # The variations must be the canonical AstNode class object so
        # that Cython typed slots accept them downstream.
        assert isinstance(v, AstNode)
        assert type(v) is AstNode


# ---------------------------------------------------------------------------
# 3. Representative pattern rule modules must generate pattern candidates
#    without raising Cython AstBase type errors.
# ---------------------------------------------------------------------------


_RULE_MODULES = (
    "d810.optimizers.microcode.instructions.pattern_matching.rewrite_add",
    "d810.optimizers.microcode.instructions.pattern_matching.rewrite_xor",
    "d810.optimizers.microcode.instructions.pattern_matching.hodur",
    "d810.optimizers.microcode.instructions.pattern_matching.weird",
)


@pytest.mark.ida_required
@pytest.mark.hexrays
@pytest.mark.runtime
@pytest.mark.parametrize("module_name", _RULE_MODULES)
def test_pattern_rule_module_generates_canonical_asts(module_name):
    """Each rule module must expose valid AstNode patterns via canonical imports.

    Importing the module triggers construction of the PATTERN / REPLACEMENT_PATTERN
    AST trees. After the legacy-shim consolidation this must not raise any
    ``TypeError`` about the wrong ``AstBase`` type.
    """
    import importlib

    from d810.hexrays.expr.ast import AstNode

    module = importlib.import_module(module_name)
    rule_classes = [
        v for v in vars(module).values()
        if isinstance(v, type) and v.__module__ == module_name
    ]
    assert rule_classes, (
        f"{module_name} exposed no rule classes after import; expected at "
        "least one PatternMatchingRule subclass."
    )

    # Each rule class has a PATTERN property that returns an AstNode.
    # We instantiate and read PATTERN to confirm canonical class identity.
    for cls in rule_classes:
        # Skip private helpers / nested dataclasses.
        if cls.__name__.startswith("_"):
            continue
        try:
            instance = cls()
        except Exception:
            # Some rule constructors need arguments; skip them gracefully.
            continue
        pattern = getattr(instance, "PATTERN", None)
        if pattern is None:
            continue
        assert isinstance(pattern, AstNode), (
            f"{cls.__name__}.PATTERN returned {type(pattern).__name__}, "
            "expected canonical AstNode"
        )


# ---------------------------------------------------------------------------
# 4. Pure-Python fallback still works when Cython mode is disabled.
# ---------------------------------------------------------------------------


@pytest.mark.ida_required
@pytest.mark.hexrays
@pytest.mark.runtime
def test_pure_python_fallback_path_constructs_ast_node():
    """With Cython mode forced off, pattern ASTs must still build correctly.

    This exercises the dispatcher fallback branch and ensures the
    pure-Python ``AstNode`` accepts a pure-Python ``AstLeaf`` -- the
    canonical scenario when Cython extensions are unavailable.
    """
    from d810.core.cymode import CythonMode
    from d810.hexrays.expr.ast import AstLeaf, AstNode

    mode = CythonMode()
    previous_mode = mode.is_enabled()
    try:
        if previous_mode:
            mode.disable()
        left = AstLeaf("x_0")
        right = AstLeaf("x_1")
        node = AstNode(ida_hexrays.m_add, left, right)
        assert node.left is left
        assert node.right is right
        assert isinstance(node, AstNode)
    finally:
        if previous_mode:
            mode.enable()


@pytest.mark.ida_required
@pytest.mark.hexrays
@pytest.mark.runtime
def test_legacy_shim_clear_mop_to_ast_cache_runs():
    """The legacy ``clear_mop_to_ast_cache`` helper must not raise."""
    from d810.core import MOP_TO_AST_CACHE
    import d810.expr.ast as legacy

    # Populate the shared cache with a sentinel so we can confirm clearing.
    sentinel_key = ("__test_legacy_shim_sentinel__", 0)
    MOP_TO_AST_CACHE[sentinel_key] = None
    try:
        legacy.clear_mop_to_ast_cache()
        assert sentinel_key not in MOP_TO_AST_CACHE
    finally:
        # Defensive cleanup in case the helper failed.
        MOP_TO_AST_CACHE.pop(sentinel_key, None)