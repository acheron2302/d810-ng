"""Regression tests for deterministic rule registration of the OLLVM and
Hodur unflattener rules.

These tests assert that ``import d810.optimizers.microcode.flow`` is, on
its own, sufficient to make ``Unflattener`` and ``HodurUnflattener``
visible in ``FlowOptimizationRule.registry`` and in
``D810State.known_blk_rules``.

Without deterministic registration the rules are silently absent from the
UI even though their modules exist in the source tree, because class
registration is a Python import-side-effect of
``Registrant.__init_subclass__``.
"""
from __future__ import annotations

import pytest


pytestmark = pytest.mark.runtime


def test_importing_flow_package_registers_unflattener():
    import d810.optimizers.microcode.flow  # noqa: F401
    from d810.optimizers.microcode.flow.handler import FlowOptimizationRule

    registry = FlowOptimizationRule.registry
    assert "unflattener" in registry, (
        "Unflattener is not registered after importing "
        "d810.optimizers.microcode.flow; the flow package __init__ "
        "must import d810.optimizers.microcode.flow.flattening for "
        "deterministic registration."
    )
    assert registry["unflattener"].__name__ == "Unflattener"


def test_importing_flow_package_registers_hodur_unflattener():
    import d810.optimizers.microcode.flow  # noqa: F401
    from d810.optimizers.microcode.flow.handler import FlowOptimizationRule

    registry = FlowOptimizationRule.registry
    assert "hodurunflattener" in registry, (
        "HodurUnflattener is not registered after importing "
        "d810.optimizers.microcode.flow; the flow package __init__ "
        "must import d810.optimizers.microcode.flow.flattening for "
        "deterministic registration."
    )
    assert registry["hodurunflattener"].__name__ == "HodurUnflattener"


def test_unflat_classes_visible_in_registry():
    """Print the registry contents to give explicit log evidence."""
    import d810.optimizers.microcode.flow  # noqa: F401
    from d810.optimizers.microcode.flow.handler import FlowOptimizationRule

    unflat_names = sorted(
        cls.__name__
        for cls in FlowOptimizationRule.registry.values()
        if "Unflat" in cls.__name__
    )
    print("\n[unflat registry]", unflat_names)
    assert "Unflattener" in unflat_names
    assert "HodurUnflattener" in unflat_names


def test_d810_state_load_exposes_unflattener_in_known_blk_rules():
    """D810State.load(gui=False) must list both unflatteners in known_blk_rules."""
    from d810.manager import D810State

    state = D810State()
    state.load(gui=False)
    names = {rule.name for rule in state.known_blk_rules}
    print("\n[known_blk_rules Unflat]", sorted(n for n in names if "Unflat" in n))
    assert "Unflattener" in names, (
        f"Unflattener missing from D810State.known_blk_rules. "
        f"Found {sorted(names)}."
    )
    assert "HodurUnflattener" in names, (
        f"HodurUnflattener missing from D810State.known_blk_rules. "
        f"Found {sorted(names)}."
    )


def test_unflattener_config_schema_has_implementation_selector():
    """CONFIG_SCHEMA must contain ``implementation`` with choices
    exactly (``"legacy"``, ``"services"``).  This is what the UI uses to
    render the selector combo box.
    """
    import d810.optimizers.microcode.flow  # noqa: F401
    from d810.optimizers.microcode.flow.handler import FlowOptimizationRule

    rule_cls = FlowOptimizationRule.registry["unflattener"]
    params = {param.name: param for param in rule_cls.CONFIG_SCHEMA}
    assert "implementation" in params, (
        f"Unflattener.CONFIG_SCHEMA is missing 'implementation'. "
        f"Got: {list(params)}"
    )
    assert params["implementation"].choices == ("legacy", "services"), (
        f"Unflattener.CONFIG_SCHEMA 'implementation' choices drifted. "
        f"Got: {params['implementation'].choices!r}"
    )