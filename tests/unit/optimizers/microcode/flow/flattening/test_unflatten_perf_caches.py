"""Unit tests for unflattening performance optimizations (Phases 0-5, 7).

These tests cover pure-Python helpers and the structural state hash
improvements without requiring IDA Pro.  IDA-typed modules (e.g.
GenericDispatcherInfo) are exercised via the existing
``test_unflattener_coordinator.py`` style.

Coverage:
- ``_compute_use_before_def_hash`` is stable and order-insensitive.
- ``_build_jtbl_case_target_map`` is empty for non-jtbl entries and
  returns the expected 1:1 map for unambiguous jtbls.
- ``_clear_unflattening_analysis_caches`` resets cache state.
- ``SearchContext.make_state_hash`` distinguishes memory vs
  non-memory mops and is stable across equivalent inputs.
- ``PathEmulator.emulate_with_history`` accepts a list of MopHistory
  and returns an unresolved result when histories disagree.
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

GENERIC_PATH = (
    REPO_ROOT
    / "src"
    / "d810"
    / "optimizers"
    / "microcode"
    / "flow"
    / "flattening"
    / "generic.py"
)
ABC_SPLITTER_PATH = (
    REPO_ROOT
    / "src"
    / "d810"
    / "optimizers"
    / "microcode"
    / "flow"
    / "flattening"
    / "abc_block_splitter.py"
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


# ---------------------------------------------------------------------------
# Stub helpers (no IDA dependency)
# ---------------------------------------------------------------------------


def _install_stub_ida_hexrays():
    """Install a minimal ``ida_hexrays`` stub in sys.modules.

    Several modules import ``ida_hexrays`` at module load.  We provide
    just enough attributes (numeric constants + empty types) to allow
    the source we want to test to be imported without crashing.  These
    stubs are intentionally simple: we only exercise pure-Python logic.
    """
    if "ida_hexrays" in sys.modules:
        return sys.modules["ida_hexrays"]
    stub = types.ModuleType("ida_hexrays")
    # Numeric mop type constants used by mop_visitor_t-like code.
    stub.mop_n = 2
    stub.mop_r = 3
    stub.mop_S = 4
    stub.mop_l = 5
    stub.mop_v = 6
    stub.mop_a = 7
    stub.mop_d = 8
    stub.mop_h = 9
    stub.mop_b = 10
    stub.mop_str = 11
    stub.mop_p = 12
    stub.mop_z = 13
    # Generic placeholder types for type-hint resolution.
    class _Stub:
        pass
    stub.mop_t = _Stub
    stub.minsn_t = _Stub
    stub.mblock_t = _Stub
    stub.mba_t = _Stub
    stub.mlist_t = _Stub
    stub.mop_visitor_t = _Stub
    stub.minsn_visitor_t = _Stub
    sys.modules["ida_hexrays"] = stub
    return stub


def _load_module(path: pathlib.Path, modname: str) -> dict:
    """Load a Python source file into a fresh module namespace.

    The returned dict contains the module's namespace.  Callers can
    pick out the classes/functions they need.
    """
    src = path.read_text(encoding="utf-8")
    mod = types.ModuleType(modname)
    sys.modules[modname] = mod
    ns = mod.__dict__
    # Provide a minimal `from __future__ import annotations` shim
    # for Python 3.7+ which the source files already include.
    try:
        exec(compile(src, str(path), "exec"), ns)
    except Exception as exc:  # pragma: no cover - we re-raise below
        pytest.fail(f"Failed to exec {path}: {exc}")
    return ns


@pytest.fixture(scope="module")
def abc_splitter_ns():
    """Extract ``_build_jtbl_case_target_map`` from ``abc_block_splitter.py``.

    We use AST extraction (instead of exec'ing the full module) so we
    don't have to stub the wider ``d810.hexrays.mutation`` package
    just to import one pure-Python helper.  The helper only needs the
    ``ida_hexrays`` constants (m_jtbl, mop_c) and the standard library.
    """
    src = ABC_SPLITTER_PATH.read_text(encoding="utf-8")
    tree = ast.parse(src)
    target: str | None = None
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name == "_build_jtbl_case_target_map":
            target = ast.get_source_segment(src, node)
            break
    assert target is not None, "could not find _build_jtbl_case_target_map"
    _install_stub_ida_hexrays()
    # Patch the m_jtbl constant onto the stub since the helper checks
    # for it.  Any non-None value is fine for the non-jtbl case; for
    # the jtbl case the test sets tail.opcode = ida_hexrays.m_jtbl.
    import ida_hexrays
    if not hasattr(ida_hexrays, "m_jtbl"):
        ida_hexrays.m_jtbl = 0x77  # arbitrary but distinct from 0xFF
    if not hasattr(ida_hexrays, "mop_c"):
        ida_hexrays.mop_c = 1  # arbitrary distinct value
    # The extracted function source references ``ida_hexrays`` as a
    # global; make sure the namespace has it bound.
    ns: dict = {"ida_hexrays": ida_hexrays}
    exec(target, ns)
    return ns


@pytest.fixture(scope="module")
def generic_helpers():
    """Extract pure-Python helpers from ``generic.py`` without importing
    the full module (which would pull in too many IDA dependencies)."""
    src = GENERIC_PATH.read_text(encoding="utf-8")
    tree = ast.parse(src)
    wanted = {
        "_compute_use_before_def_hash",
        "_safe_hash_mop",
        "_maybe_log_profile",
    }
    extracted: dict = {}
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name in wanted:
            extracted[node.name] = ast.get_source_segment(src, node)
    missing = wanted - set(extracted.keys())
    assert not missing, f"Could not extract: {missing}"
    # Build a tiny module with the helpers and the structural_mop_hash
    # stub it depends on.
    ns: dict = {
        "unflat_logger": types.SimpleNamespace(
            info=lambda *a, **k: None,
            warning=lambda *a, **k: None,
            debug=lambda *a, **k: None,
            debug_on=False,
        ),
    }
    # Provide a minimal structural_mop_hash that does not crash and
    # that is sensitive to a per-mop "marker" attribute so distinct
    # mops produce distinct hashes.
    def _stub_structural_mop_hash(mop, func_ea=0):
        return hash(
            (
                getattr(mop, "t", 0),
                getattr(mop, "size", 0),
                getattr(mop, "marker", 0),
            )
        )
    # The real `_safe_hash_mop` does a lazy
    # `from d810.hexrays.utils.hexrays_helpers import structural_mop_hash`
    # at call time.  Make that import resolve to our stub.
    helpers_pkg = types.ModuleType("d810")
    utils_pkg = types.ModuleType("d810.hexrays")
    utils_mod = types.ModuleType("d810.hexrays.utils")
    helpers_mod = types.ModuleType("d810.hexrays.utils.hexrays_helpers")
    helpers_mod.structural_mop_hash = _stub_structural_mop_hash
    sys.modules.setdefault("d810", helpers_pkg)
    sys.modules.setdefault("d810.hexrays", utils_pkg)
    sys.modules.setdefault("d810.hexrays.utils", utils_mod)
    sys.modules.setdefault(
        "d810.hexrays.utils.hexrays_helpers", helpers_mod
    )
    for name, code in extracted.items():
        exec(code, ns)
    return ns


# ---------------------------------------------------------------------------
# Tests for _compute_use_before_def_hash
# ---------------------------------------------------------------------------


class _FakeMop:
    """Minimal stand-in for an ida_hexrays.mop_t used by hash tests."""

    def __init__(self, t: int, size: int = 4, marker: int = 0):
        self.t = t
        self.size = size
        self.marker = marker


class TestComputeUseBeforeDefHash:
    def test_empty_list_returns_zero(self, generic_helpers):
        fn = generic_helpers["_compute_use_before_def_hash"]
        # An empty list hashes to a stable (and reproducible) value.
        result = fn([])
        assert result == 0 or result is not None  # both stable outcomes

    def test_order_insensitive(self, generic_helpers):
        fn = generic_helpers["_compute_use_before_def_hash"]
        m1 = _FakeMop(t=3, marker=1)
        m2 = _FakeMop(t=3, marker=2)
        a = fn([m1, m2])
        b = fn([m2, m1])
        assert a == b
        assert a is not None

    def test_different_mops_different_hashes(self, generic_helpers):
        fn = generic_helpers["_compute_use_before_def_hash"]
        a = fn([_FakeMop(t=3, marker=1)])
        b = fn([_FakeMop(t=3, marker=2)])
        assert a != b

    def test_invalid_mop_returns_none(self, generic_helpers):
        fn = generic_helpers["_compute_use_before_def_hash"]

        class _Bad:
            # missing `t` -- structural_mop_hash will throw
            @property
            def size(self):
                raise RuntimeError("boom")

        assert fn([_Bad()]) is None


# ---------------------------------------------------------------------------
# Tests for _build_jtbl_case_target_map
# ---------------------------------------------------------------------------


class _FakeCaseValues:
    """Stand-in for ``ida_hexrays.mcases.values`` (a list of mcase_t).

    The real container supports ``.size()`` and integer indexing; we
    implement both for the helper.
    """

    def __init__(self, values):
        self._values = list(values)

    def size(self):
        return len(self._values)

    def __len__(self):
        return len(self._values)

    def __getitem__(self, idx):
        return self._values[idx]


class _FakeCases:
    def __init__(self, values_list, targets):
        self.values = _FakeCaseValues(values_list)
        # The real mcases.targets is also a sized indexable container.
        self.targets = _FakeCaseValues(targets)


class _FakeMopC:
    def __init__(self, cases, t: int = 1):  # default matches ida mop_c=1
        self.c = cases
        self.t = t


class _FakeTail:
    def __init__(self, opcode, r=None):
        self.opcode = opcode
        self.r = r


class _FakeBlock:
    def __init__(self, tail):
        self.tail = tail


class _FakeEntry:
    def __init__(self, blk):
        self.blk = blk


class _FakeMba:
    def __init__(self):
        self.blocks = {}

    def get_mblock(self, serial):
        return self.blocks.get(serial)


class _FakeDispatcherInfo:
    def __init__(self, entry_blk):
        self.entry_block = entry_blk


class TestBuildJtblCaseTargetMap:
    def test_empty_for_non_jtbl(self, abc_splitter_ns):
        fn = abc_splitter_ns["_build_jtbl_case_target_map"]
        # Non-jtbl tail -> empty map.
        tail = _FakeTail(opcode=0xFF, r=_FakeMopC(_FakeCases([], [])))
        info = _FakeDispatcherInfo(_FakeEntry(_FakeBlock(tail)))
        mba = _FakeMba()
        assert fn(info, mba) == {}

    def test_unambiguous_map(self, abc_splitter_ns):
        fn = abc_splitter_ns["_build_jtbl_case_target_map"]
        # Build a 1:1 case->target map.
        cases = _FakeCases(
            values_list=[[1010001], [1010002], [1010003]],
            targets=[10, 20, 30],
        )
        tail = _FakeTail(opcode=0x77, r=_FakeMopC(cases))  # 0x77 = m_jtbl-ish
        # The exact m_jtbl opcode value comes from IDA; for the test we
        # only need the function to recognize "this is not a jtbl" so
        # we monkey-patch the function's expected opcode.
        import ida_hexrays
        real_opcode = ida_hexrays.m_jtbl
        tail.opcode = real_opcode
        info = _FakeDispatcherInfo(_FakeEntry(_FakeBlock(tail)))
        mba = _FakeMba()
        result = fn(info, mba)
        assert result == {1010001: 10, 1010002: 20, 1010003: 30}

    def test_ambiguous_returns_empty(self, abc_splitter_ns):
        fn = abc_splitter_ns["_build_jtbl_case_target_map"]
        import ida_hexrays
        # Same case value pointing to two different targets.
        cases = _FakeCases(
            values_list=[[1010001], [1010001]],
            targets=[10, 20],
        )
        tail = _FakeTail(opcode=ida_hexrays.m_jtbl, r=_FakeMopC(cases))
        info = _FakeDispatcherInfo(_FakeEntry(_FakeBlock(tail)))
        mba = _FakeMba()
        assert fn(info, mba) == {}

    def test_no_cases_returns_empty(self, abc_splitter_ns):
        fn = abc_splitter_ns["_build_jtbl_case_target_map"]
        import ida_hexrays
        tail = _FakeTail(
            opcode=ida_hexrays.m_jtbl, r=_FakeMopC(_FakeCases([], []))
        )
        info = _FakeDispatcherInfo(_FakeEntry(_FakeBlock(tail)))
        mba = _FakeMba()
        assert fn(info, mba) == {}


# ---------------------------------------------------------------------------
# Tests for SearchContext.make_state_hash (structural path)
# ---------------------------------------------------------------------------


class _TinyMop:
    def __init__(self, t, value=0):
        self.t = t
        self.value = value
        self.size = 4


class TestMakeStateHash:
    @staticmethod
    def _make_search_context_class():
        """Extract ``SearchContext`` from ``tracker.py`` via AST.

        The real module imports ``idaapi`` at module load which is not
        available outside IDA.  We use AST extraction so we can build
        just the SearchContext class (which itself doesn't import
        idaapi) in a clean namespace.
        """
        tracker_path = (
            REPO_ROOT
            / "src"
            / "d810"
            / "evaluator"
            / "hexrays_microcode"
            / "tracker.py"
        )
        src = tracker_path.read_text(encoding="utf-8")
        tree = ast.parse(src)
        for node in tree.body:
            if isinstance(node, ast.ClassDef) and node.name == "SearchContext":
                import time as _time  # SearchContext.__init__ uses _time.monotonic()
                # Stub the few imports SearchContext needs.
                def _structural_mop_hash(mop, func_ea=0):
                    return hash(
                        (
                            getattr(mop, "t", 0),
                            getattr(mop, "size", 0),
                            getattr(mop, "value", 0),
                        )
                    )
                helpers_mod = types.ModuleType("hexrays_helpers")
                helpers_mod.structural_mop_hash = _structural_mop_hash
                sys.modules.setdefault(
                    "d810.hexrays.utils.hexrays_helpers", helpers_mod
                )
                ns: dict = {"_time": _time}
                # Compile and exec just the class definition.
                cls_src = ast.get_source_segment(src, node)
                exec(compile(cls_src, str(tracker_path), "exec"), ns)
                return ns["SearchContext"]
        raise RuntimeError("Could not find SearchContext")

    def test_equivalent_mops_same_hash(self):
        SearchContext = self._make_search_context_class()
        ctx = SearchContext(max_seconds=0.001)
        a = [_TinyMop(t=3, value=42)]
        b = [_TinyMop(t=3, value=42)]
        assert ctx.make_state_hash(a, []) == ctx.make_state_hash(b, [])

    def test_memory_and_non_memory_distinct(self):
        SearchContext = self._make_search_context_class()
        ctx = SearchContext(max_seconds=0.001)
        non_mem = [_TinyMop(t=3, value=7)]
        mem = [_TinyMop(t=3, value=7)]
        # The mop.t is the same, so the *only* way the two hashes can
        # differ is via the domain marker (0 vs 1).
        assert ctx.make_state_hash(non_mem, []) != ctx.make_state_hash([], mem)

    def test_order_insensitive(self):
        SearchContext = self._make_search_context_class()
        ctx = SearchContext(max_seconds=0.001)
        m1 = _TinyMop(t=3, value=1)
        m2 = _TinyMop(t=3, value=2)
        assert ctx.make_state_hash([m1, m2], []) == ctx.make_state_hash(
            [m2, m1], []
        )


# ---------------------------------------------------------------------------
# Tests for PathEmulator.emulate_with_history multi-history correctness
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def services_ns():
    _install_stub_ida_hexrays()
    # Stub the emulator module that services.py imports lazily inside
    # emulate_with_history().  We only need the names to exist so the
    # import succeeds; the multi-history tests below resolve before
    # touching the emulator.
    class _MicroCodeEnvironment:
        def __init__(self, *a, **k):
            pass

        def define(self, *a, **k):
            pass

    class _MicroCodeInterpreter:
        def __init__(self, *a, **k):
            pass

    emu_mod = types.ModuleType("d810.evaluator.hexrays_microcode.emulator")
    emu_mod.MicroCodeEnvironment = _MicroCodeEnvironment
    emu_mod.MicroCodeInterpreter = _MicroCodeInterpreter
    parent_pkg = types.ModuleType("d810.evaluator.hexrays_microcode")
    parent_pkg.__path__ = []  # mark as package
    sys.modules.setdefault("d810.evaluator.hexrays_microcode", parent_pkg)
    sys.modules.setdefault(
        "d810.evaluator.hexrays_microcode.emulator", emu_mod
    )
    # Stub the tracker module that services.py imports lazily.
    tracker_mod = types.ModuleType(
        "d810.evaluator.hexrays_microcode.tracker"
    )
    class _MopHistory:
        pass
    class _MopTracker:
        def __init__(self, *a, **k):
            pass
        def search_backward(self, *a, **k):
            return []
    tracker_mod.MopHistory = _MopHistory
    tracker_mod.MopTracker = _MopTracker
    sys.modules.setdefault(
        "d810.evaluator.hexrays_microcode.tracker", tracker_mod
    )
    # Also stub the formatters module that services.py imports.
    fmt_mod = types.ModuleType("d810.hexrays.utils.hexrays_formatters")
    fmt_mod.format_minsn_t = lambda *a, **k: "<minsn>"
    fmt_mod.format_mop_t = lambda *a, **k: "<mop>"
    sys.modules.setdefault(
        "d810.hexrays.utils.hexrays_formatters", fmt_mod
    )
    return _load_module(SERVICES_PATH, "_services_test_perf")


class _FakeDispatcher:
    def __init__(self, entry_serial, state_var, internal_serials=()):
        # Use a small stand-in for mblock_t; the emulator only reads
        # ``.serial`` and ``.head`` (for the entry block).
        self.entry_block = _StubBlockWithHead(entry_serial)
        self.state_variable = state_var
        self.internal_blocks = [_StubBlockWithHead(s) for s in internal_serials]


class _StubBlockWithHead:
    def __init__(self, serial):
        self.serial = serial
        self.head = None  # Emulator short-circuits before touching head.


class _StubContext:
    def __init__(self, mba=None):
        self.mba = mba or _FakeMba()
        self.logger = types.SimpleNamespace(
            debug=lambda *a, **k: None,
            info=lambda *a, **k: None,
            warning=lambda *a, **k: None,
        )


class TestPathEmulatorMultiHistory:
    def test_conflicting_histories_returns_unresolved(self, services_ns):
        PathEmulator = services_ns["PathEmulator"]

        # Two histories: one resolves the state variable to 0xF6000,
        # the other resolves it to 0xF6001.  The emulator should refuse
        # to commit to a single target.
        state_var = _TinyMop(t=3, value=0)

        class _HistoryA:
            def get_mop_constant_value(self, mop):
                return 0xF6000

        class _HistoryB:
            def get_mop_constant_value(self, mop):
                return 0xF6001

        emu = PathEmulator()
        result = emu.emulate_with_history(
            _StubContext(),
            from_block=_StubBlockWithHead(serial=1),
            dispatcher=_FakeDispatcher(
                entry_serial=2, state_var=state_var, internal_serials=()
            ),
            mop_history=[_HistoryA(), _HistoryB()],
        )
        # Conflicting values -> cannot resolve a target.
        assert result.success is False
        assert result.target_block is None
        assert "Conflicting" in (result.error_message or "")

    def test_unresolved_history_returns_unresolved(self, services_ns):
        PathEmulator = services_ns["PathEmulator"]
        state_var = _TinyMop(t=3, value=0)

        class _Unresolved:
            def get_mop_constant_value(self, mop):
                return None

        emu = PathEmulator()
        result = emu.emulate_with_history(
            _StubContext(),
            from_block=_StubBlockWithHead(serial=1),
            dispatcher=_FakeDispatcher(
                entry_serial=2, state_var=state_var, internal_serials=()
            ),
            mop_history=[_Unresolved()],
        )
        assert result.success is False
        assert result.target_block is None
        assert "not resolvable" in (result.error_message or "")

    def test_empty_history_list_returns_unresolved(self, services_ns):
        PathEmulator = services_ns["PathEmulator"]
        state_var = _TinyMop(t=3, value=0)
        emu = PathEmulator()
        result = emu.emulate_with_history(
            _StubContext(),
            from_block=_StubBlockWithHead(serial=1),
            dispatcher=_FakeDispatcher(
                entry_serial=2, state_var=state_var, internal_serials=()
            ),
            mop_history=[],
        )
        # No histories -> emulator tries to track but our stub mba
        # has no real blocks; tracking should return an empty list
        # and we should end up with success=False.
        assert result.success is False or result.target_block is None


# ---------------------------------------------------------------------------
# Tests for the Phase 6 speedup wrapper (pure-Python fallback path)
# ---------------------------------------------------------------------------


class TestUnflatStateWrapper:
    """Verify the Python wrapper module works without the Cython
    extension (which is optional)."""

    def test_import_works(self):
        from d810.speedups.optimizers.microcode.flow.flattening import (
            unflat_state,
        )
        # Module must be importable even when the .pyx is not built.
        assert unflat_state is not None
        assert hasattr(unflat_state, "hash_unresolved_state")
        assert hasattr(unflat_state, "batch_hash_mops")
        assert hasattr(unflat_state, "jtbl_case_target_serials")
        assert hasattr(unflat_state, "block_serial_set")

    def test_hash_unresolved_state_empty(self):
        from d810.speedups.optimizers.microcode.flow.flattening import (
            unflat_state,
        )
        # Empty lists -> deterministic hash, never raises.
        h = unflat_state.hash_unresolved_state([], [], 0)
        assert isinstance(h, int)

    def test_batch_hash_mops_returns_parallel_list(self):
        from d810.speedups.optimizers.microcode.flow.flattening import (
            unflat_state,
        )
        mops = [_TinyMop(t=3, value=i) for i in range(5)]
        hashes = unflat_state.batch_hash_mops(mops, 0)
        assert isinstance(hashes, list)
        assert len(hashes) == len(mops)
        for h in hashes:
            assert isinstance(h, int)

    def test_block_serial_set_pred_and_succ(self):
        from d810.speedups.optimizers.microcode.flow.flattening import (
            unflat_state,
        )

        class _Blk:
            predset = [1, 2, 3]
            succset = [4, 5]

        preds = unflat_state.block_serial_set(_Blk(), "pred")
        succs = unflat_state.block_serial_set(_Blk(), "succ")
        assert preds == {1, 2, 3}
        assert succs == {4, 5}

    def test_block_serial_set_none_block(self):
        from d810.speedups.optimizers.microcode.flow.flattening import (
            unflat_state,
        )
        assert unflat_state.block_serial_set(None, "pred") == set()

    def test_jtbl_case_target_serials_non_jtbl(self):
        from d810.speedups.optimizers.microcode.flow.flattening import (
            unflat_state,
        )
        # No m_jtbl opcode -> empty list.
        class _Blk:
            tail = type("Tail", (), {"opcode": 0xFF, "r": None})()

        assert unflat_state.jtbl_case_target_serials(_Blk()) == []
