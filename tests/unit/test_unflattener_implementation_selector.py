"""Unit tests for the Unflattener ``implementation`` config field.

The composition-based OLLVM unflattener lives behind an opt-in selector.
These tests exercise only the pure-Python selector logic; runtime tests in
``tests/system/runtime/optimizers/microcode/flow/flattening/`` cover the
end-to-end behavior in a real IDA environment.

The tests avoid importing :mod:`d810.optimizers.microcode.flow.flattening.unflattener`
directly because that module pulls in ``ida_hexrays``. Instead they extract
the :func:`Unflattener.select_implementation` static method from the source
file via AST and re-execute it in a stripped-down namespace.
"""

from __future__ import annotations

import ast
import logging
import pathlib
import textwrap


THIS_DIR = pathlib.Path(__file__).resolve().parent
REPO_ROOT = THIS_DIR
while REPO_ROOT != REPO_ROOT.parent:
    if (REPO_ROOT / "pyproject.toml").is_file():
        break
    REPO_ROOT = REPO_ROOT.parent

UNFLATTENER_PATH = (
    REPO_ROOT
    / "src"
    / "d810"
    / "optimizers"
    / "microcode"
    / "flow"
    / "flattening"
    / "unflattener.py"
)
assert UNFLATTENER_PATH.is_file(), (
    f"Could not find unflattener.py at {UNFLATTENER_PATH!r}; "
    "test_unflattener_implementation_selector.py must live in tests/unit/."
)


def _extract_selector():
    """Return a standalone callable mirroring Unflattener.select_implementation.

    We do not import the module (which requires IDA). Instead we read the
    source file, lift the constants and the static method into a tiny
    namespace, and exec them.
    """
    src = UNFLATTENER_PATH.read_text(encoding="utf-8")
    tree = ast.parse(src)

    class_node = next(
        node for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == "Unflattener"
    )

    constants: dict = {}
    for member in class_node.body:
        if isinstance(member, ast.Assign):
            for target in member.targets:
                if isinstance(target, ast.Name) and target.id in {
                    "IMPLEMENTATION_LEGACY",
                    "IMPLEMENTATION_SERVICES",
                }:
                    try:
                        constants[target.id] = ast.literal_eval(member.value)
                    except (ValueError, SyntaxError):
                        pass

    select_method = next(
        member for member in class_node.body
        if isinstance(member, ast.FunctionDef) and member.name == "select_implementation"
    )
    method_src = ast.get_source_segment(src, select_method)
    assert method_src is not None, "could not extract select_implementation source"

    # Bind the constants as module-level names so the lifted source can
    # reference ``Unflattener.IMPLEMENTATION_LEGACY`` and friends.
    class _Stub:
        pass

    stub = _Stub()
    for k, v in constants.items():
        setattr(stub, k, v)

    # Also bind the logger used inside the method body.
    unflat_logger = logging.getLogger("test.unflattener.selector")

    # Provide a no-op implementation of the per-process dedupe helper
    # so the lifted source resolves the name without doing real work.
    def _warn_invalid_implementation_once(_value):
        return None

    namespace: dict = {
        "Unflattener": stub,
        "unflat_logger": unflat_logger,
        "_warn_invalid_implementation_once": _warn_invalid_implementation_once,
        "__name__": "test_unflattener_selector",
    }
    exec(compile(method_src, str(UNFLATTENER_PATH), "exec"), namespace)
    return namespace["select_implementation"]


select_implementation = _extract_selector()


def test_default_is_legacy():
    assert select_implementation(None, None) == "legacy"
    assert select_implementation("", None) == "legacy"


def test_config_value_legacy():
    assert select_implementation("legacy", None) == "legacy"


def test_config_value_services():
    assert select_implementation("services", None) == "services"


def test_config_value_case_insensitive():
    assert select_implementation("LEGACY", None) == "legacy"
    assert select_implementation("Services", None) == "services"


def test_env_value_overrides_config():
    """Environment override must take precedence over project config."""
    assert select_implementation("legacy", "services") == "services"
    assert select_implementation("services", "legacy") == "legacy"


def test_invalid_config_falls_back_to_legacy():
    """Unknown implementation values must fail closed to legacy."""
    assert select_implementation("garbage", None) == "legacy"


def test_invalid_env_falls_back_to_next_valid_source():
    """Invalid env var must fall back to the next valid source (config)."""
    assert select_implementation("services", "garbage") == "services"
    assert select_implementation("legacy", "garbage") == "legacy"


def test_services_valid_value():
    assert select_implementation("services") == "services"
    assert select_implementation("services", None) == "services"


def test_whitespace_handling():
    assert select_implementation("  legacy  ", None) == "legacy"
    assert select_implementation("\tservices\n", None) == "services"