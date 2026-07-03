"""Unit tests for the composition-based unflattening coordinator.

The :class:`UnflattenerRule` (in :mod:`d810.optimizers.microcode.flow.flattening.unflattener_refactored`)
is a thin coordinator that delegates to :class:`DispatcherFinder`,
:class:`PathEmulator`, and :class:`CFGPatcher` services. The coordinator
itself can be exercised without IDA by mocking those dependencies,
which is the whole point of the composition refactor.

These tests are pure-Python and do not require IDA Pro.

Test coverage:
- No dispatchers found -> returns 0 changes.
- Non-entry block -> returns 0 changes without consulting the finder.
- Single dispatcher, single predecessor -> unflattened.
- Single dispatcher, multiple predecessors -> all unflattened.
- Unresolvable predecessor -> skipped gracefully.
- Missing predecessor block -> skipped gracefully.
- Patch failure -> skipped without crashing the rule.
- Exception in emulator -> skipped, other predecessors still processed.
- Count of changes reflects successful redirects only.
"""

from __future__ import annotations

import ast
import pathlib
import sys
import types

import pytest


THIS_FILE = pathlib.Path(__file__).resolve()
REPO_ROOT = THIS_FILE
while REPO_ROOT != REPO_ROOT.parent:
    if (REPO_ROOT / "pyproject.toml").is_file():
        break
    REPO_ROOT = REPO_ROOT.parent
UNFLATTENER_REFACTORED_PATH = (
    REPO_ROOT
    / "src"
    / "d810"
    / "optimizers"
    / "microcode"
    / "flow"
    / "flattening"
    / "unflattener_refactored.py"
)
SERVICES_PATH = (
    REPO_ROOT
    / "src"
    / "d810"
    / "optimizers"
    / "microcode"
    / "flow"
    / "flattening"
    / "services.py"
)
assert UNFLATTENER_REFACTORED_PATH.is_file(), UNFLATTENER_REFACTORED_PATH
assert SERVICES_PATH.is_file(), SERVICES_PATH


class _StubBlock:
    """Lightweight stand-in for ida_hexrays.mblock_t.

    The coordinator only needs ``blk.serial`` and ``blk.predset``; tests
    populate other attributes when needed.
    """

    def __init__(self, serial, predset=None):
        self.serial = serial
        self.predset = set(predset or ())


class _StubMop:
    def __init__(self, value=0):
        self.value = value


@pytest.fixture
def coordinator_classes():
    """Build a minimal namespace exposing Dispatcher, UnflattenerRule, etc.

    We extract the lightweight :class:`Dispatcher` dataclass from
    ``services.py`` via AST so the test never imports modules that pull
    in IDA at module load time.
    """
    # Stub ida_hexrays so dataclass type-hints resolve when services.py
    # is exec'd in a clean namespace.
    stub_ida = types.ModuleType("ida_hexrays")

    class _Stub:
        pass

    stub_ida.mblock_t = _Stub
    stub_ida.mop_t = _Stub
    stub_ida.minsn_t = _Stub
    stub_ida.mbl_array_t = _Stub
    sys.modules.setdefault("ida_hexrays", stub_ida)

    services_src = SERVICES_PATH.read_text(encoding="utf-8")
    services_mod = types.ModuleType("_services_test")
    sys.modules["_services_test"] = services_mod
    services_ns = services_mod.__dict__
    exec(compile(services_src, str(SERVICES_PATH), "exec"), services_ns)
    Dispatcher = services_ns["Dispatcher"]
    DispatcherFinder = services_ns["DispatcherFinder"]
    PathEmulator = services_ns["PathEmulator"]
    CFGPatcher = services_ns["CFGPatcher"]

    # Lift only the UnflattenerRule class via AST; this avoids executing
    # the module-level ``from d810.optimizers...`` imports that pull in
    # the wider optimizer package (and IDA dependencies).
    ur_src = UNFLATTENER_REFACTORED_PATH.read_text(encoding="utf-8")
    ur_tree = ast.parse(ur_src)
    class_node = next(
        node for node in ur_tree.body
        if isinstance(node, ast.ClassDef) and node.name == "UnflattenerRule"
    )
    # Build a tiny module with the lifted class plus the imports it needs.
    ur_mod = types.ModuleType("_unflattener_refactored_test")
    sys.modules["_unflattener_refactored_test"] = ur_mod
    ur_ns = ur_mod.__dict__

    class _OptimizationContextStub:
        def __init__(self, **kwargs):
            for k, v in kwargs.items():
                setattr(self, k, v)

    class _OptimizationRuleStub:
        pass

    ur_ns.update(
        {
            "Dispatcher": Dispatcher,
            "DispatcherFinder": DispatcherFinder,
            "PathEmulator": PathEmulator,
            "CFGPatcher": CFGPatcher,
            "logger": _FakeLogger(),
            # Annotations referenced by the class definition
            "OptimizationContext": _OptimizationContextStub,
            "OptimizationRule": _OptimizationRuleStub,
            "ida_hexrays": stub_ida,
        }
    )
    # Compile and exec just the class definition in our namespace.
    class_src = ast.get_source_segment(ur_src, class_node)
    assert class_src is not None, "could not lift UnflattenerRule source"
    # Ensure the class methods that reference module-level imports resolve
    # through our namespace.
    exec(compile(class_src, str(UNFLATTENER_REFACTORED_PATH), "exec"), ur_ns)
    return ur_ns


class _FakeLogger:
    """Stub logger matching the small surface UnflattenerRule touches."""

    def __init__(self):
        self.infos: list[str] = []
        self.warnings: list[str] = []
        self.debugs: list[str] = []

    def info(self, msg, *args, **kwargs):
        self.infos.append(msg % args if args else msg)

    def warning(self, msg, *args, **kwargs):
        self.warnings.append(msg % args if args else msg)

    def debug(self, msg, *args, **kwargs):
        self.debugs.append(msg % args if args else msg)


class _MockFinder:
    """Mock DispatcherFinder for tests."""

    def __init__(self, dispatchers=None):
        self._dispatchers = list(dispatchers or [])
        self.calls = 0

    def find(self, context):
        self.calls += 1
        return list(self._dispatchers)


class _MockEmulator:
    """Mock PathEmulator for tests."""

    def __init__(self, targets):
        # targets: callable mapping (pred_serial, dispatcher) -> mblock_t or None
        self._targets = targets
        self.calls: list[tuple] = []

    def resolve_target(self, context, from_block, dispatcher):
        self.calls.append((from_block.serial, dispatcher.entry_block.serial))
        return self._targets(from_block.serial, dispatcher)


class _MockPatcher:
    """Mock CFGPatcher for tests."""

    def __init__(self, ensure_return=0, redirect_returns=None):
        self._ensure_return = ensure_return
        self._redirect_returns = redirect_returns
        self.ensure_calls: list = []
        self.redirect_calls: list = []
        self.raise_on_redirect = False

    def ensure_unconditional_predecessor(self, context, father, child, verify=True):
        self.ensure_calls.append((father.serial, child.serial))
        if father is None:
            return 0
        return self._ensure_return

    def redirect_edge(self, context, from_block, to_block, verify=True):
        self.redirect_calls.append((from_block.serial, to_block.serial))
        if self.raise_on_redirect:
            raise RuntimeError("simulated patch failure")
        if self._redirect_returns is None:
            return 1
        return self._redirect_returns


class _MockContext:
    """Stand-in for OptimizationContext.

    The coordinator only reads ``context.mba`` and a logger. Provide
    both via attributes.
    """

    def __init__(self, mba):
        self.mba = mba
        self.logger = _FakeLogger()


class _MockMba:
    """Stand-in for mba_t returning predefined predecessor blocks."""

    def __init__(self, blocks):
        # blocks: dict serial -> mblock_t
        self._blocks = blocks

    def get_mblock(self, serial):
        return self._blocks.get(serial)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_no_dispatchers_returns_zero(coordinator_classes):
    UnflattenerRule = coordinator_classes["UnflattenerRule"]
    Dispatcher = coordinator_classes["Dispatcher"]

    finder = _MockFinder([])
    rule = UnflattenerRule(finder)

    mba = _MockMba({0: _StubBlock(0)})
    context = _MockContext(mba)

    changes = rule.apply(context, _StubBlock(0))
    assert changes == 0
    assert finder.calls == 1


def test_non_entry_block_returns_zero_without_finder(coordinator_classes):
    UnflattenerRule = coordinator_classes["UnflattenerRule"]

    finder = _MockFinder()
    rule = UnflattenerRule(finder)

    mba = _MockMba({5: _StubBlock(5)})
    context = _MockContext(mba)

    changes = rule.apply(context, _StubBlock(5))
    assert changes == 0
    assert finder.calls == 0  # must NOT consult finder


def test_single_dispatcher_single_predecessor(coordinator_classes):
    UnflattenerRule = coordinator_classes["UnflattenerRule"]
    Dispatcher = coordinator_classes["Dispatcher"]

    dispatcher_entry = _StubBlock(10, predset=[5])
    state_var = _StubMop(value=42)
    dispatcher = Dispatcher(entry_block=dispatcher_entry, state_variable=state_var)

    finder = _MockFinder([dispatcher])

    pred_block = _StubBlock(5)
    target_block = _StubBlock(20)

    def target_for(pred_serial, _disp):
        assert pred_serial == 5
        return target_block

    emulator = _MockEmulator(target_for)
    patcher = _MockPatcher(ensure_return=0, redirect_returns=1)

    rule = UnflattenerRule(finder, emulator, patcher)

    mba = _MockMba({0: _StubBlock(0), 5: pred_block, 10: dispatcher_entry, 20: target_block})
    context = _MockContext(mba)

    changes = rule.apply(context, _StubBlock(0))
    assert changes == 1
    assert patcher.redirect_calls == [(5, 20)]
    assert emulator.calls == [(5, 10)]


def test_multiple_predecessors_all_resolved(coordinator_classes):
    UnflattenerRule = coordinator_classes["UnflattenerRule"]
    Dispatcher = coordinator_classes["Dispatcher"]

    dispatcher_entry = _StubBlock(10, predset=[5, 6, 7])
    state_var = _StubMop(value=42)
    dispatcher = Dispatcher(entry_block=dispatcher_entry, state_variable=state_var)

    finder = _MockFinder([dispatcher])
    pred_blocks = {s: _StubBlock(s) for s in (5, 6, 7)}
    # Use distinct key namespaces for pred_blocks and targets in the mba
    # dict so the **-spread does not silently overwrite the predecessor
    # entries with the target blocks.
    target_blocks = {20: _StubBlock(20), 21: _StubBlock(21), 22: _StubBlock(22)}
    targets_by_pred = {5: target_blocks[20], 6: target_blocks[21], 7: target_blocks[22]}

    def target_for(pred_serial, _disp):
        return targets_by_pred[pred_serial]

    emulator = _MockEmulator(target_for)
    patcher = _MockPatcher(ensure_return=0, redirect_returns=1)

    rule = UnflattenerRule(finder, emulator, patcher)
    mba = _MockMba(
        {0: _StubBlock(0), 10: dispatcher_entry, **pred_blocks, **target_blocks}
    )
    context = _MockContext(mba)

    changes = rule.apply(context, _StubBlock(0))
    assert changes == 3, (
        f"Expected 3 changes, got {changes}. "
        f"redirect_calls={patcher.redirect_calls}, "
        f"emulator_calls={emulator.calls}"
    )
    assert len(patcher.redirect_calls) == 3


def test_unresolvable_predecessor_is_skipped(coordinator_classes):
    UnflattenerRule = coordinator_classes["UnflattenerRule"]
    Dispatcher = coordinator_classes["Dispatcher"]

    dispatcher_entry = _StubBlock(10, predset=[5, 6])
    state_var = _StubMop(value=42)
    dispatcher = Dispatcher(entry_block=dispatcher_entry, state_variable=state_var)

    finder = _MockFinder([dispatcher])

    targets_iter = iter([_StubBlock(20), None])

    def target_for(pred_serial, _disp):
        return next(targets_iter)

    emulator = _MockEmulator(target_for)
    patcher = _MockPatcher(ensure_return=0, redirect_returns=1)

    rule = UnflattenerRule(finder, emulator, patcher)
    mba = _MockMba(
        {
            0: _StubBlock(0),
            5: _StubBlock(5),
            6: _StubBlock(6),
            10: dispatcher_entry,
            20: _StubBlock(20),
        }
    )
    context = _MockContext(mba)

    changes = rule.apply(context, _StubBlock(0))
    # Only the first predecessor was resolved -> one redirect.
    assert changes == 1
    assert len(patcher.redirect_calls) == 1


def test_missing_predecessor_block_is_skipped(coordinator_classes):
    UnflattenerRule = coordinator_classes["UnflattenerRule"]
    Dispatcher = coordinator_classes["Dispatcher"]

    # Dispatcher claims predecessor 99, but mba has no block 99.
    dispatcher_entry = _StubBlock(10, predset=[99])
    state_var = _StubMop(value=42)
    dispatcher = Dispatcher(entry_block=dispatcher_entry, state_variable=state_var)

    finder = _MockFinder([dispatcher])
    emulator = _MockEmulator(lambda *_args, **_kw: None)
    patcher = _MockPatcher(ensure_return=0, redirect_returns=1)
    rule = UnflattenerRule(finder, emulator, patcher)

    mba = _MockMba({0: _StubBlock(0), 10: dispatcher_entry})
    context = _MockContext(mba)

    changes = rule.apply(context, _StubBlock(0))
    assert changes == 0
    assert patcher.redirect_calls == []
    assert emulator.calls == []  # must not emulate with a None pred_block


def test_emulator_exception_isolated(coordinator_classes):
    UnflattenerRule = coordinator_classes["UnflattenerRule"]
    Dispatcher = coordinator_classes["Dispatcher"]

    dispatcher_entry = _StubBlock(10, predset=[5, 6])
    state_var = _StubMop(value=42)
    dispatcher = Dispatcher(entry_block=dispatcher_entry, state_variable=state_var)

    finder = _MockFinder([dispatcher])

    call_count = {"n": 0}

    def target_for(pred_serial, _disp):
        call_count["n"] += 1
        if pred_serial == 5:
            raise RuntimeError("simulated emulator crash")
        return _StubBlock(20)

    emulator = _MockEmulator(target_for)
    patcher = _MockPatcher(ensure_return=0, redirect_returns=1)

    rule = UnflattenerRule(finder, emulator, patcher)
    mba = _MockMba(
        {
            0: _StubBlock(0),
            5: _StubBlock(5),
            6: _StubBlock(6),
            10: dispatcher_entry,
            20: _StubBlock(20),
        }
    )
    context = _MockContext(mba)

    changes = rule.apply(context, _StubBlock(0))
    # Emulator exception for pred 5 -> skipped, pred 6 still redirected.
    assert changes == 1
    assert len(patcher.redirect_calls) == 1
    assert patcher.redirect_calls[0][0] == 6


def test_redirect_failure_isolated(coordinator_classes):
    UnflattenerRule = coordinator_classes["UnflattenerRule"]
    Dispatcher = coordinator_classes["Dispatcher"]

    dispatcher_entry = _StubBlock(10, predset=[5, 6])
    state_var = _StubMop(value=42)
    dispatcher = Dispatcher(entry_block=dispatcher_entry, state_variable=state_var)

    finder = _MockFinder([dispatcher])
    targets = {5: _StubBlock(20), 6: _StubBlock(21)}

    emulator = _MockEmulator(lambda s, _d: targets[s])
    patcher = _MockPatcher(ensure_return=0, redirect_returns=1)

    # Make the first redirect fail.
    original_redirect = patcher.redirect_edge

    def flaky_redirect(context, from_block, to_block, verify=True):
        if from_block.serial == 5:
            raise RuntimeError("simulated patch failure")
        return original_redirect(context, from_block, to_block, verify)

    patcher.redirect_edge = flaky_redirect  # type: ignore[assignment]

    rule = UnflattenerRule(finder, emulator, patcher)
    mba = _MockMba(
        {0: _StubBlock(0), 5: _StubBlock(5), 6: _StubBlock(6), 10: dispatcher_entry, 20: _StubBlock(20), 21: _StubBlock(21)}
    )
    context = _MockContext(mba)

    changes = rule.apply(context, _StubBlock(0))
    # First predecessor fails -> only second one contributes.
    assert changes == 1


def test_multiple_dispatchers_processed(coordinator_classes):
    UnflattenerRule = coordinator_classes["UnflattenerRule"]
    Dispatcher = coordinator_classes["Dispatcher"]

    d1_entry = _StubBlock(10, predset=[5])
    d2_entry = _StubBlock(20, predset=[15])
    state_var = _StubMop(value=1)

    dispatchers = [
        Dispatcher(entry_block=d1_entry, state_variable=state_var),
        Dispatcher(entry_block=d2_entry, state_variable=state_var),
    ]
    finder = _MockFinder(dispatchers)

    targets = {5: _StubBlock(100), 15: _StubBlock(200)}
    emulator = _MockEmulator(lambda s, _d: targets[s])
    patcher = _MockPatcher(ensure_return=0, redirect_returns=1)

    rule = UnflattenerRule(finder, emulator, patcher)
    mba = _MockMba(
        {
            0: _StubBlock(0),
            5: _StubBlock(5),
            10: d1_entry,
            15: _StubBlock(15),
            20: d2_entry,
            100: _StubBlock(100),
            200: _StubBlock(200),
        }
    )
    context = _MockContext(mba)

    changes = rule.apply(context, _StubBlock(0))
    assert changes == 2
    assert sorted(call[0] for call in patcher.redirect_calls) == [5, 15]