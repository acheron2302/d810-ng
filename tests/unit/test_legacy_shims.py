"""Compatibility shims: assert that legacy modules only re-export.

The architecture consolidation plan designates canonical locations for
several d810 modules and turns the legacy duplicate modules into thin
re-export shims. These tests guard against accidental divergence by
asserting that the legacy modules contain only re-export statements and
no implementation logic.

Allowed content in each shim:
- module docstring
- ``from __future__ import annotations``
- ``from <canonical_module> import (...)`` re-exports
- ``__all__ = [...]`` declaration

If a new helper, constant, or function appears in a shim, the shim has
drifted from its purpose and should either be moved to the canonical
location or be added to ``ignore_extras`` in this test with a written
justification.

These tests are pure-Python (no IDA import) because they only parse the
shim source files.
"""

from __future__ import annotations

import ast
import pathlib
import textwrap


REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
SHIM_DIR = REPO_ROOT / "src" / "d810" / "hexrays"


SHIM_MODULES = {
    "arch_utils": "d810.hexrays.utils.arch_utils",
    "hexrays_formatters": "d810.hexrays.utils.hexrays_formatters",
    "hexrays_helpers": "d810.hexrays.utils.hexrays_helpers",
    "ida_utils": "d810.hexrays.utils.ida_utils",
    "table_utils": "d810.hexrays.utils.table_utils",
    "hexrays_hooks": "d810.hexrays.hooks.hexrays_hooks",
    "ctree_hooks": "d810.hexrays.hooks.ctree_hooks",
    "mop_snapshot": "d810.hexrays.ir.mop_snapshot",
    "block_helpers": "d810.hexrays.ir.block_helpers",
    "deferred_modifier": "d810.hexrays.mutation.deferred_modifier",
}


def _parse_shim(shim_filename: str) -> ast.Module:
    path = SHIM_DIR / f"{shim_filename}.py"
    source = path.read_text(encoding="utf-8")
    return ast.parse(source, filename=str(path))


def _is_re_export_import(node: ast.stmt, canonical_module: str) -> bool:
    """Return True if `node` is ``from <canonical_module> import ...``."""
    if not isinstance(node, ast.ImportFrom):
        return False
    return node.module == canonical_module


def _is_annotations_future(node: ast.stmt) -> bool:
    return (
        isinstance(node, ast.ImportFrom)
        and node.module == "__future__"
        and any(alias.name == "annotations" for alias in node.names)
    )


def _is_all_declaration(node: ast.stmt) -> bool:
    return isinstance(node, ast.Assign) and any(
        isinstance(target, ast.Name) and target.id == "__all__" for target in node.targets
    )


def _is_compatibility_helper(node: ast.stmt) -> bool:
    """Allow deprecated compatibility helpers that document the shim drift.

    A compatibility helper must:
      * be a module-level ``def`` whose docstring contains
        ``"Deprecated compatibility helper"`` or
        ``"compatibility helper"``;
      * not contain implementation logic that duplicates the canonical module.
    """
    if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return False
    doc = ast.get_docstring(node) or ""
    return "compatibility helper" in doc.lower()


def test_legacy_hexrays_shims_only_reexport():
    """Legacy d810.hexrays modules must only re-export canonical symbols.

    A shim may contain:
      * a module docstring,
      * ``from __future__ import annotations``,
      * one or more ``from <canonical_module> import (...)`` blocks,
      * an ``__all__ = [...]`` declaration.
    Anything else (functions, classes, constants) signals drift.
    """
    for shim_filename, canonical_module in SHIM_MODULES.items():
        tree = _parse_shim(shim_filename)
        offenders: list[str] = []
        for node in tree.body:
            if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant):
                # docstring
                continue
            if _is_annotations_future(node):
                continue
            if _is_re_export_import(node, canonical_module):
                continue
            if _is_all_declaration(node):
                continue
            if _is_compatibility_helper(node):
                continue
            offenders.append(
                f"{ast.unparse(node).splitlines()[0]} ({type(node).__name__})"
            )
        assert not offenders, textwrap.dedent(
            f"""
            Legacy shim d810.hexrays.{shim_filename} contains content
            beyond re-exports; move the new logic to its canonical
            location ({canonical_module}) or update the test.

            Offending statements:
              {chr(10).join('  - ' + o for o in offenders)}
            """
        )


def test_legacy_hexrays_shims_have_all_declaration():
    """Each shim must declare __all__ so import * surfaces stay explicit."""
    for shim_filename in SHIM_MODULES:
        tree = _parse_shim(shim_filename)
        all_nodes = [n for n in tree.body if _is_all_declaration(n)]
        assert all_nodes, (
            f"d810.hexrays.{shim_filename} is missing an __all__ declaration; "
            "shims must advertise their public surface explicitly."
        )


def _legacy_hexrays_helpers_imported_names(shim_filename: str) -> set[str]:
    """Return the set of names imported by the canonical re-export blocks."""
    tree = _parse_shim(shim_filename)
    names: set[str] = set()
    for node in tree.body:
        if isinstance(node, ast.ImportFrom) and node.module == (
            "d810.hexrays.utils.hexrays_helpers"
        ):
            for alias in node.names:
                names.add(alias.asname or alias.name)
    return names


def _legacy_hexrays_helpers_all(shim_filename: str) -> set[str]:
    """Return the set of names declared in the legacy shim's __all__."""
    tree = _parse_shim(shim_filename)
    for node in tree.body:
        if not _is_all_declaration(node):
            continue
        value = node.value
        if not isinstance(value, (ast.List, ast.Tuple)):
            continue
        return {
            elt.value
            for elt in value.elts
            if isinstance(elt, ast.Constant) and isinstance(elt.value, str)
        }
    return set()


def test_legacy_hexrays_helpers_shim_reexports_and_table():
    """``AND_TABLE`` must be re-exported by the legacy shim.

    Stale C++ extensions generated against ``d810.hexrays.hexrays_helpers``
    can still attempt to resolve ``AND_TABLE`` through that legacy path,
    so the shim must advertise it both via the import block and in
    ``__all__``. The canonical definition lives in ``d810.core.bits``.
    """
    shim = "hexrays_helpers"
    imported = _legacy_hexrays_helpers_imported_names(shim)
    assert "AND_TABLE" in imported, (
        "Legacy shim d810.hexrays.hexrays_helpers must re-export AND_TABLE "
        "from d810.hexrays.utils.hexrays_helpers so that stale extensions "
        "generated against the legacy helper path can resolve it."
    )

    advertised = _legacy_hexrays_helpers_all(shim)
    assert "AND_TABLE" in advertised, (
        "Legacy shim d810.hexrays.hexrays_helpers must list AND_TABLE in "
        "__all__ to keep the re-export surface internally consistent."
    )