"""Config-to-registry coverage test.

Every active ``blk_rules[].name`` in :mod:`d810.conf` must bind to a
concrete, registered :class:`FlowOptimizationRule` subclass.  A rule
that is named in a config but never registered is silently dropped by
``D810State.load`` (``manager.py`` does strict name matching), so a
missing registration is invisible to the user and the rule simply never
runs.

The explicit ``_ALLOWED_MISSING`` set lists rule names that are
intentionally hidden or dead.  New entries must come with a one-line
rationale so the next reader can audit them.
"""
from __future__ import annotations

import json
import pathlib

import pytest


pytestmark = pytest.mark.runtime

REPO_ROOT = pathlib.Path(__file__).resolve().parent
while REPO_ROOT != REPO_ROOT.parent:
    if (REPO_ROOT / "pyproject.toml").is_file():
        break
    REPO_ROOT = REPO_ROOT.parent

CONF_DIR = REPO_ROOT / "src" / "d810" / "conf"

#: Names that may appear in active blk_rules but are not (yet) registered.
#: Each entry MUST carry a one-line rationale.  Keep this list small:
#: every entry is a future TODO.
_ALLOWED_MISSING: dict[str, str] = {
    "SimplifiedLoopUnflattener": (
        "Dead config reference in flatfold_no_predicate_loop_fix.json: "
        "no implementation exists in src/.  The rule is silently dropped "
        "by D810State.load because its module is never imported.  TODO: "
        "either implement the rule or remove the config entry."
    ),
    "BlockLevelEgglogOptimizer": (
        "Dead config reference in example_libobfuscated.json: "
        "no implementation exists in src/.  The example config demonstrates "
        "the egglog pipeline but the rule itself is not shipped.  TODO: "
        "either implement the rule or remove the config entry."
    ),
    "StateMachineLoopUnroller": (
        "Dead config reference in state_machine_loops.json: "
        "no implementation exists in src/.  TODO: either implement the "
        "rule or remove the config entry."
    ),
}


def _load_active_block_rule_names() -> list[tuple[pathlib.Path, str]]:
    """Return (config_path, rule_name) for every active blk_rules entry."""
    results: list[tuple[pathlib.Path, str]] = []
    for path in sorted(CONF_DIR.glob("*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
        for rule in data.get("blk_rules", []):
            if not rule.get("is_activated"):
                continue
            name = rule.get("name")
            if not name:
                continue
            results.append((path, name))
    return results


def test_all_active_block_rules_bind_to_registered_flow_rule():
    import inspect

    import d810.optimizers.microcode.flow  # noqa: F401
    from d810.optimizers.microcode.flow.handler import FlowOptimizationRule

    known = {
        cls().name
        for cls in FlowOptimizationRule.registry.values()
        if not inspect.isabstract(cls)
    }
    print(
        f"\n[config coverage] {len(known)} registered blk-rule names: "
        f"{sorted(known)}"
    )

    missing: list[tuple[pathlib.Path, str]] = []
    for path, name in _load_active_block_rule_names():
        if name in known:
            continue
        if name in _ALLOWED_MISSING:
            continue
        missing.append((path, name))

    if missing:
        lines = [
            f"  {p.relative_to(REPO_ROOT)}::{n}" for p, n in missing
        ]
        pytest.fail(
            "Active block rule names not bound to any registered "
            "FlowOptimizationRule.  These will be silently dropped by "
            "D810State.load.  Either implement the rule or document it "
            "in _ALLOWED_MISSING with a one-line rationale.\n"
            + "\n".join(lines)
        )


def test_no_unjustified_allowed_missing_entries():
    """Sanity check: every entry in _ALLOWED_MISSING has a rationale.

    Entries without rationale (or with an empty string) silently let
    dead config references slip through the regression test, which is
    exactly the failure mode this test exists to prevent.
    """
    for name, rationale in _ALLOWED_MISSING.items():
        assert rationale and rationale.strip(), (
            f"_ALLOWED_MISSING[{name!r}] has no rationale; "
            "add a one-line explanation or remove the entry."
        )