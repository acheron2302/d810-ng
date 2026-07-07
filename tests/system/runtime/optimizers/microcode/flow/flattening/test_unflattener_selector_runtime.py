"""Runtime tests for the ``Unflattener`` ``implementation`` selector and
services coordinator fallback behavior.

The pure-Python selector logic is covered by
``tests/unit/test_unflattener_implementation_selector.py`` (AST-extracted);
this module exercises real ``Unflattener`` instances in the IDA runtime.
"""
from __future__ import annotations

import pytest


pytestmark = pytest.mark.runtime


def test_selected_implementation_normalizes_env_whitespace(monkeypatch):
    """``D810_UNFLATTENER_IMPL`` must be normalized through
    :meth:`Unflattener.select_implementation`.  Mixed-case and whitespace
    values must resolve to ``"services"`` rather than silently falling
    back to legacy.
    """
    import d810.optimizers.microcode.flow  # noqa: F401
    from d810.optimizers.microcode.flow.handler import FlowOptimizationRule

    rule_cls = FlowOptimizationRule.registry["unflattener"]
    rule = rule_cls()
    rule.configure({"implementation": "legacy"})
    # Sanity: baseline.
    assert rule._selected_implementation == "legacy"
    monkeypatch.setenv("D810_UNFLATTENER_IMPL", " Services ")
    try:
        assert rule.selected_implementation == "services", (
            "Env override was not normalized through select_implementation()."
        )
    finally:
        monkeypatch.delenv("D810_UNFLATTENER_IMPL", raising=False)


def test_selected_implementation_invalid_env_falls_back(monkeypatch):
    """Invalid env values must fall back to the next valid source
    (the config value).  Mirrors the static helper contract.
    """
    import d810.optimizers.microcode.flow  # noqa: F401
    from d810.optimizers.microcode.flow.handler import FlowOptimizationRule

    rule_cls = FlowOptimizationRule.registry["unflattener"]
    rule = rule_cls()
    rule.configure({"implementation": "services"})
    monkeypatch.setenv("D810_UNFLATTENER_IMPL", "garbage")
    try:
        assert rule.selected_implementation == "services"
    finally:
        monkeypatch.delenv("D810_UNFLATTENER_IMPL", raising=False)


def test_configure_normalizes_implementation_via_selector():
    """``configure()`` must funnel the ``implementation`` config value
    through the same normalization as the env override so the two
    cannot drift apart.
    """
    import d810.optimizers.microcode.flow  # noqa: F401
    from d810.optimizers.microcode.flow.handler import FlowOptimizationRule

    rule_cls = FlowOptimizationRule.registry["unflattener"]
    rule = rule_cls()

    rule.configure({"implementation": "SERVICES"})
    assert rule._selected_implementation == "services"

    rule.configure({"implementation": " legacy "})
    assert rule._selected_implementation == "legacy"

    rule.configure({"implementation": "garbage"})
    assert rule._selected_implementation == "legacy"


def test_services_coordinator_unavailable_falls_back_to_legacy(monkeypatch):
    """When services mode is selected but the coordinator cannot be
    built (forced import failure), :meth:`optimize` must fall back to
    the legacy path BEFORE any CFG mutation.

    We force the failure by patching the lazy-import targets used by
    :attr:`Unflattener.services_coordinator` so the constructor raises.
    """
    import d810.optimizers.microcode.flow  # noqa: F401
    from d810.optimizers.microcode.flow.flattening import services as _services_mod
    from d810.optimizers.microcode.flow.flattening import (
        unflattener_refactored as _refactored_mod,
    )
    from d810.optimizers.microcode.flow.flattening.unflattener import Unflattener
    from d810.optimizers.microcode.flow.flattening.generic import (
        GenericDispatcherUnflatteningRule,
    )

    # Pre-import so monkeypatch can find the attribute to replace.
    _ = _services_mod.OLLVMDispatcherFinder
    _ = _refactored_mod.UnflattenerRule

    rule = Unflattener()
    rule._selected_implementation = Unflattener.IMPLEMENTATION_SERVICES
    rule._services_coordinator = None
    monkeypatch.delenv("D810_UNFLATTENER_IMPL", raising=False)

    class _Boom(Exception):
        pass

    class _FakeFinder:
        def __init__(self):
            raise _Boom("finder init failed")

    def _fake_unflattener_rule(*_a, **_kw):
        raise _Boom("UnflattenerRule build failed")

    monkeypatch.setattr(_services_mod, "OLLVMDispatcherFinder", _FakeFinder)
    monkeypatch.setattr(_refactored_mod, "UnflattenerRule", _fake_unflattener_rule)

    legacy_calls = []

    def _legacy(self, blk):
        legacy_calls.append(blk)
        return 0

    monkeypatch.setattr(GenericDispatcherUnflatteningRule, "optimize", _legacy)

    class _Blk:
        pass

    # Provide the minimum attributes optimize()/optimize fallback path needs.
    rule.mba = object()
    rule.cur_maturity = 0

    result = rule.optimize(_Blk())
    assert result == 0
    assert legacy_calls, (
        "services_unavailable path did not fall back to legacy; "
        "the rule would silently do nothing instead of running legacy."
    )


def test_optimize_dispatches_to_services_when_coordinator_present(monkeypatch):
    """When the services coordinator IS available, ``optimize`` must
    call ``coordinator.apply`` rather than the legacy path.  This guards
    against the previous behaviour where a missing coordinator silently
    no-op'd the rule.
    """
    import d810.optimizers.microcode.flow  # noqa: F401
    from d810.optimizers.microcode.flow.flattening.unflattener import Unflattener

    rule = Unflattener()
    rule._selected_implementation = Unflattener.IMPLEMENTATION_SERVICES
    monkeypatch.delenv("D810_UNFLATTENER_IMPL", raising=False)

    class _FakeCoordinator:
        def __init__(self):
            self.apply_calls = []

        def apply(self, context, blk):
            self.apply_calls.append((context, blk))
            return 7

    coordinator = _FakeCoordinator()
    rule._services_coordinator = coordinator

    rule.mba = object()
    rule.cur_maturity = 0

    class _Blk:
        pass

    result = rule.optimize(_Blk())
    assert result == 7
    assert len(coordinator.apply_calls) == 1


def test_invalid_implementation_warning_is_deduped():
    """A permanently invalid ``implementation`` value must not flood the
    log on every property access.  ``select_implementation`` is invoked
    once per ``Unflattener.selected_implementation`` read; an
    implementation that always picks an invalid value would emit one
    WARNING per call without dedup, which would be thousands of lines
    on a real decompilation.

    We verify the dedupe by checking that the dedupe set only ever
    grows by one entry per unique invalid value across many calls.
    """
    import d810.optimizers.microcode.flow  # noqa: F401
    from d810.optimizers.microcode.flow.flattening import unflattener as _mod

    _mod._reset_invalid_implementation_warn_cache()

    # Simulate the hot path: select_implementation() called many times
    # with the same invalid env value.
    for _ in range(100):
        assert _mod.Unflattener.select_implementation("garbage", None) == "legacy"

    # Only "garbage" should have been recorded in the dedupe set.
    assert _mod._INVALID_IMPLEMENTATION_WARNED == {"garbage"}, (
        f"Dedupe set should contain only 'garbage' after 100 identical "
        f"invalid calls, got {_mod._INVALID_IMPLEMENTATION_WARNED!r}."
    )

    # A different invalid value should add a second entry.
    _mod.Unflattener.select_implementation("also_bad", None)
    assert _mod._INVALID_IMPLEMENTATION_WARNED == {"garbage", "also_bad"}

    # Sanity: valid values never touch the dedupe set.
    _mod.Unflattener.select_implementation("services", None)
    _mod.Unflattener.select_implementation("legacy", None)
    assert _mod._INVALID_IMPLEMENTATION_WARNED == {"garbage", "also_bad"}

    _mod._reset_invalid_implementation_warn_cache()