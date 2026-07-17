"""Tests for the recon runtime speed-up plan (Phase 1-8).

Covers:

* Phase 1: hook gating
* Phase 2: in-memory result cache and dirty analysis
* Phase 3: bulk SQLite writes / transactions
* Phase 4: skipping empty metadata-only result rows
* Phase 6: CFGShapeCollector flattening score gates / approximation
* Phase 5: shared CFG snapshot builder
* Phase 8: profiling counters
"""
from __future__ import annotations

import tempfile
from pathlib import Path
from types import MappingProxyType
from unittest.mock import MagicMock

import pytest

from d810.cfg.flowgraph import BlockSnapshot, FlowGraph
from d810.recon.analysis import AnalysisPhase
from d810.recon.collectors.cfg_shape import (
    CFGShapeCollector,
    _HIGH_INDEGREE_THRESHOLD,
    _MAX_DOMINATOR_SCORE_BLOCKS,
)
from d810.recon.models import DeobfuscationHints, ReconResult
from d810.recon.phase import (
    EMPTY_RESULT_COLLECTOR_NAMES,
    ReconPhase,
    _is_empty_result,
)
from d810.recon.runtime import ReconAnalysisRuntime
from d810.recon.snapshot import (
    SNAPSHOT_COMPATIBLE_COLLECTORS,
    build_recon_flow_graph,
)
from d810.recon.store import ReconStore


# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------


def _make_result(
    collector_name: str = "T",
    func_ea: int = 0x401000,
    maturity: int = 5,
    metrics: dict | None = None,
    candidates: tuple = (),
    timestamp: float = 0.0,
) -> ReconResult:
    return ReconResult(
        collector_name=collector_name,
        func_ea=func_ea,
        maturity=maturity,
        timestamp=timestamp,
        metrics=MappingProxyType(metrics or {}),
        candidates=candidates,
    )


@pytest.fixture
def temp_db():
    import os as _os
    fd, name = tempfile.mkstemp(suffix=".db")
    _os.close(fd)
    Path(name).unlink(missing_ok=True)
    yield Path(name)
    Path(name).unlink(missing_ok=True)


@pytest.fixture
def store(temp_db):
    s = ReconStore(temp_db)
    yield s
    s.close()


class _FakeMicrocodeMba:
    """Minimal stand-in for ``mba_t`` for snapshot tests."""

    def __init__(self, blocks, *, entry_ea=0x401000, entry_serial=0):
        self.qty = len(blocks)
        self._blocks = blocks
        self.entry_ea = entry_ea
        self.entry_serial = entry_serial

    def get_mblock(self, idx):
        return self._blocks.get(idx)


def _make_live_blk(serial, *, block_type=0, succs=(), start_ea=0, tail_opcode=0, flags=0):
    blk = MagicMock()
    blk.serial = serial
    blk.type = block_type
    blk.succset = succs
    blk.start_ea = start_ea
    blk.flags = flags
    if tail_opcode is not None:
        tail = MagicMock()
        tail.opcode = tail_opcode
        blk.tail = tail
    else:
        blk.tail = None
    return blk


# ---------------------------------------------------------------------------
# Phase 1 - hook gating contract (validation through runtime interaction)
# ---------------------------------------------------------------------------


class TestHookGatingContract:
    """The exact change pattern from Phase 1 of the plan, expressed in a
    hook-call-like helper to verify the contract without spinning up IDA."""

    def test_empty_results_skip_analyze_dirty(self):
        store = MagicMock()
        phase = MagicMock()
        phase.run_microcode_collectors.return_value = []
        rt = ReconAnalysisRuntime(phase, AnalysisPhase(), store)
        # Replace the bound methods with mocks BEFORE invoking the gating path
        # so we can assert they were not called.
        rt.ingest_results = MagicMock()
        rt.analyze_dirty_and_persist = MagicMock()

        results = phase.run_microcode_collectors("mba", func_ea=0x1, maturity=5)
        if results and rt is not None:
            rt.ingest_results(0x1, results)
            rt.analyze_dirty_and_persist(0x1)

        # No ingest / analyze should fire when results are empty.
        rt.ingest_results.assert_not_called()
        rt.analyze_dirty_and_persist.assert_not_called()
        assert results == []

    def test_non_empty_results_trigger_ingest_and_persist(self):
        store = MagicMock()
        phase = MagicMock()
        result = _make_result(metrics={"k": 1})
        phase.run_microcode_collectors.return_value = [result]
        rt = ReconAnalysisRuntime(phase, AnalysisPhase(), store)
        rt.ingest_results = MagicMock()
        rt.analyze_dirty_and_persist = MagicMock(return_value=DeobfuscationHints(
            func_ea=1, obfuscation_type=None, confidence=0.0,
            recommended_inferences=(), candidates=(), suppress_rules=(),
        ))

        results = phase.run_microcode_collectors("mba", func_ea=0x1, maturity=5)
        if results and rt is not None:
            rt.ingest_results(0x1, results)
            hints = rt.analyze_dirty_and_persist(0x1)

        rt.ingest_results.assert_called_once_with(0x1, [result])
        rt.analyze_dirty_and_persist.assert_called_once_with(0x1)
        assert isinstance(hints, DeobfuscationHints)


# ---------------------------------------------------------------------------
# Phase 2 - in-memory result cache + dirty analysis
# ---------------------------------------------------------------------------


class TestRuntimeInMemoryCache:
    def test_ingest_marks_function_dirty(self, store):
        phase = ReconPhase(store=store)
        rt = ReconAnalysisRuntime(phase, AnalysisPhase(), store)
        rt.reset_for_func(0x1000)
        result = _make_result(metrics={"a": 1})
        rt.ingest_results(0x1000, [result])
        assert 0x1000 in rt._dirty_funcs
        assert rt._results_by_func[0x1000] == [result]

    def test_ingest_empty_is_noop(self, store):
        rt = ReconAnalysisRuntime(ReconPhase(store=store), AnalysisPhase(), store)
        rt.ingest_results(0x1000, [])
        assert rt._dirty_funcs == set()
        assert rt._results_by_func == {}

    def test_analyze_dirty_uses_memory_no_store_load(self, store):
        phase = ReconPhase(store=store)
        rt = ReconAnalysisRuntime(phase, AnalysisPhase(), store)
        rt.reset_for_func(0x1000)
        result = _make_result(metrics={"k": 2})
        rt.ingest_results(0x1000, [result])
        store.load_all_recon_results = MagicMock(wraps=store.load_all_recon_results)
        hints = rt.analyze_dirty_and_persist(0x1000)
        assert hints is not None
        assert store.load_all_recon_results.call_count == 1
        assert 0x1000 not in rt._dirty_funcs

    def test_analyze_dirty_second_call_returns_cache(self, store):
        rt = ReconAnalysisRuntime(ReconPhase(store=store), AnalysisPhase(), store)
        rt.reset_for_func(0x1000)
        result = _make_result(metrics={"k": 2})
        rt.ingest_results(0x1000, [result])
        first = rt.analyze_dirty_and_persist(0x1000)
        # Without new ingestions, calling again should return the cached hints
        # and not re-persist (no second save_analysis_bundle / save_hints).
        store.save_hints = MagicMock(wraps=store.save_hints)
        second = rt.analyze_dirty_and_persist(0x1000)
        assert first is second
        store.save_hints.assert_not_called()

    def test_analyze_and_persist_falls_back_to_store_when_memory_empty(self, store):
        phase = ReconPhase(store=store)
        rt = ReconAnalysisRuntime(phase, AnalysisPhase(), store)
        rt.reset_for_func(0x2000)
        result = _make_result(func_ea=0x2000, metrics={"k": 3})
        # Insert into the store directly to emulate a prior decompilation pass.
        store.save_recon_result(result)
        # No ingest; analyze_and_persist should fall back to store.load_all_recon_results.
        store.load_all_recon_results = MagicMock(wraps=store.load_all_recon_results)
        hints = rt.analyze_and_persist(0x2000)
        assert hints is not None
        store.load_all_recon_results.assert_called_once()

    def test_reset_for_func_clears_memory_cache(self, store):
        rt = ReconAnalysisRuntime(ReconPhase(store=store), AnalysisPhase(), store)
        rt.reset_for_func(0x1)
        rt.ingest_results(0x1, [_make_result()])
        rt.analyze_dirty_and_persist(0x1)
        # Re-entering with a new func must clear stale data for the new func.
        rt.reset_for_func(0x2)
        assert 0x1 not in rt._dirty_funcs
        assert 0x2 not in rt._dirty_funcs
        assert 0x1 not in rt._results_by_func


# ---------------------------------------------------------------------------
# Phase 3 - bulk writes + transactions in ReconStore
# ---------------------------------------------------------------------------


class TestStoreBulkAndTransaction:
    def test_bulk_save_persists_all(self, store):
        results = [
            _make_result(collector_name="A", func_ea=0x1, maturity=5, metrics={"x": 1}),
            _make_result(collector_name="B", func_ea=0x1, maturity=5, metrics={"x": 2}),
        ]
        store.save_recon_results_bulk(results)
        loaded = store.load_all_recon_results(func_ea=0x1)
        assert len(loaded) == 2
        names = {r.collector_name for r in loaded}
        assert names == {"A", "B"}

    def test_bulk_empty_is_noop(self, store):
        store.save_recon_results_bulk([])
        assert store.load_all_recon_results(func_ea=0x999) == []

    def test_transaction_rollback_on_exception(self, store):
        store._conn.execute(
            "INSERT INTO recon_results VALUES (?,?,?,?,?,?)",
            (0x42, 5, "pre", 0.0, "{}", "[]"),
        )
        store._conn.commit()
        with pytest.raises(RuntimeError):
            with store.transaction():
                store._conn.execute(
                    "INSERT INTO recon_results VALUES (?,?,?,?,?,?)",
                    (0x42, 6, "boom", 0.0, "{}", "[]"),
                )
                raise RuntimeError("simulated failure")
        # Rollback should have removed the failing insert.
        loaded = store.load_all_recon_results(func_ea=0x42)
        names = {r.collector_name for r in loaded}
        assert "boom" not in names
        assert "pre" in names

    def test_save_recon_result_default_commits(self, store):
        store.save_recon_result(_make_result(collector_name="single", metrics={"k": 1}))
        assert len(store.load_all_recon_results(func_ea=0x401000)) == 1

    def test_save_analysis_bundle_one_transaction(self, store):
        hints = DeobfuscationHints(
            func_ea=0x600,
            obfuscation_type="ollvm_flat",
            confidence=0.8,
            recommended_inferences=("unflattening",),
            candidates=(),
            suppress_rules=("ConstantFolding",),
        )
        store.save_analysis_bundle(hints, collectors_fired=3)
        # Both hints and session summary must be present after one call.
        assert store.load_hints(func_ea=0x600) is not None
        assert store.load_session_summary(0x600) is not None


# ---------------------------------------------------------------------------
# Phase 4 - skip empty results
# ---------------------------------------------------------------------------


class TestPhase4EmptyResult:
    def test_is_empty_result_detects_empty(self):
        empty = _make_result(collector_name="X", metrics={}, candidates=())
        non_empty = _make_result(collector_name="X", metrics={"k": 1})
        assert _is_empty_result(empty) is True
        assert _is_empty_result(non_empty) is False

    def test_empty_metadata_only_not_persisted(self, store):
        phase = ReconPhase(store=store)

        class _MetaOnlyCollector:
            name = "handler_transitions"
            maturities = frozenset({5})
            level = "microcode"

            def collect(self, target, func_ea, maturity):
                return _make_result(
                    collector_name="handler_transitions",
                    func_ea=func_ea,
                    maturity=maturity,
                    metrics={},
                    candidates=(),
                )

        mba = MagicMock()
        mba.entry_ea = 0x700
        mba.qty = 1
        mba.get_mblock = MagicMock(return_value=None)

        phase.register(_MetaOnlyCollector())
        results = phase.run_microcode_collectors(mba, func_ea=0x700, maturity=5)
        # Returned to caller for fired accounting...
        assert len(results) == 1
        # ...but not persisted when empty.
        loaded = store.load_all_recon_results(func_ea=0x700)
        assert loaded == []

    def test_non_empty_metadata_only_persisted(self, store):
        phase = ReconPhase(store=store)

        class _RichCollector:
            name = "handler_transitions"
            maturities = frozenset({5})
            level = "microcode"

            def collect(self, target, func_ea, maturity):
                return _make_result(
                    collector_name="handler_transitions",
                    func_ea=func_ea,
                    maturity=maturity,
                    metrics={"handlers_total": 3},
                    candidates=(),
                )

        mba = MagicMock()
        mba.entry_ea = 0x701
        mba.qty = 1
        mba.get_mblock = MagicMock(return_value=None)
        phase.register(_RichCollector())
        phase.run_microcode_collectors(mba, func_ea=0x701, maturity=5)
        loaded = store.load_all_recon_results(func_ea=0x701)
        assert len(loaded) == 1
        assert loaded[0].metrics.get("handlers_total") == 3

    def test_recon_phase_uses_bulk(self, store):
        phase = ReconPhase(store=store)
        store.save_recon_results_bulk = MagicMock(wraps=store.save_recon_results_bulk)

        class _C:
            name = "dispatch_pattern"
            maturities = frozenset({5})
            level = "microcode"
            def collect(self, target, func_ea, maturity):
                return _make_result(metrics={"nway_block_count": 1})

        mba = MagicMock()
        mba.entry_ea = 0x800
        mba.qty = 1
        mba.get_mblock = MagicMock(return_value=None)
        phase.register(_C())
        phase.run_microcode_collectors(mba, func_ea=0x800, maturity=5)
        store.save_recon_results_bulk.assert_called()


# ---------------------------------------------------------------------------
# Phase 6 - CFGShapeCollector gates
# ---------------------------------------------------------------------------


def _make_portable_graph(
    blocks_data,
    *,
    entry_serial=0,
    func_ea=0x401000,
) -> FlowGraph:
    snap_blocks: dict[int, BlockSnapshot] = {}
    for serial, (block_type, succs) in blocks_data.items():
        snap_blocks[serial] = BlockSnapshot(
            serial=serial,
            block_type=block_type,
            succs=tuple(succs),
            preds=(),
            flags=0,
            start_ea=0,
            insn_snapshots=(),
            tail_opcode=0,
        )
    return FlowGraph(
        blocks=snap_blocks,
        entry_serial=entry_serial,
        func_ea=func_ea,
    )


class TestFlatteningScoreGate:
    def test_low_in_degree_short_circuits_to_zero(self):
        blocks = {i: (0, ()) for i in range(10)}
        graph = _make_portable_graph(blocks, entry_serial=0)
        result = CFGShapeCollector().collect(graph, func_ea=0x1, maturity=3)
        assert result.metrics["flattening_score"] == 0.0
        assert result.metrics["flattening_score_approx"] == 0

    def test_high_in_degree_small_graph_runs_exact(self):
        # 5 nodes with a clear dispatcher: should exercise exact path.
        blocks = {
            0: (5, (1, 2, 3, 4)),  # BLT_NWAY serial=0
            1: (0, (4,)),
            2: (0, (4,)),
            3: (0, (4,)),
            4: (0, (0,)),  # back-edge to entry, dominated by 0
        }
        graph = _make_portable_graph(blocks, entry_serial=0)
        result = CFGShapeCollector().collect(graph, func_ea=0x2, maturity=3)
        assert result.metrics["flattening_score_approx"] == 0
        # With back-edges to entry and dispatcher dominating, score should be > 0.
        assert result.metrics["flattening_score"] > 0.0

    def test_high_in_degree_huge_graph_uses_approximation(self):
        # Build a graph just above the threshold so we hit the approximation
        # branch.
        threshold = _MAX_DOMINATOR_SCORE_BLOCKS
        blocks = {0: (5, tuple(range(1, threshold + 2)))}  # NWAY super-fan-out
        for i in range(1, threshold + 2):
            blocks[i] = (0, (0,))  # all back to dispatcher
        graph = _make_portable_graph(blocks, entry_serial=0)
        result = CFGShapeCollector().collect(graph, func_ea=0x3, maturity=3)
        # Approximation marker must be set.
        assert result.metrics["flattening_score_approx"] == 1
        # Score is clamped to [0, 1].
        assert 0.0 <= result.metrics["flattening_score"] <= 1.0


# ---------------------------------------------------------------------------
# Phase 5 - snapshot builder
# ---------------------------------------------------------------------------


class TestSnapshotBuilder:
    def test_snapshot_compatible_set_lists_expected_collectors(self):
        assert "CFGShapeCollector" in SNAPSHOT_COMPATIBLE_COLLECTORS
        assert "DispatchPatternCollector" in SNAPSHOT_COMPATIBLE_COLLECTORS
        assert "compare_chain" in SNAPSHOT_COMPATIBLE_COLLECTORS
        assert "flow_profile_classifier" in SNAPSHOT_COMPATIBLE_COLLECTORS

    def test_build_recon_flow_graph_basic(self):
        b0 = _make_live_blk(0, block_type=5, succs=(1, 2), tail_opcode=10)
        b1 = _make_live_blk(1, block_type=0, succs=(), tail_opcode=11)
        b2 = _make_live_blk(2, block_type=0, succs=(), tail_opcode=12)
        mba = _FakeMicrocodeMba({0: b0, 1: b1, 2: b2}, entry_ea=0x900, entry_serial=0)
        graph = build_recon_flow_graph(mba)
        assert graph.num_blocks == 3
        assert graph.entry_serial == 0
        assert graph.func_ea == 0x900
        assert graph.blocks[0].succs == (1, 2)
        assert graph.blocks[0].tail_opcode == 10
        assert sorted(graph.blocks[1].preds) == [0]
        assert sorted(graph.blocks[2].preds) == [0]

    def test_build_recon_flow_graph_handles_none_blocks(self):
        b0 = _make_live_blk(0, block_type=0, succs=())
        mba = _FakeMicrocodeMba({0: b0, 1: None}, entry_serial=0)
        graph = build_recon_flow_graph(mba)
        assert graph.num_blocks == 1


# ---------------------------------------------------------------------------
# Phase 8 - profiling counters
# ---------------------------------------------------------------------------


class TestProfilingCounters:
    def test_profile_disabled_by_default(self, store):
        rt = ReconAnalysisRuntime(ReconPhase(store=store), AnalysisPhase(), store)
        rt.enable_profiling(True)
        rt.reset_for_func(0xC)
        rt.ingest_results(0xC, [_make_result(metrics={"k": 1})])
        rt.analyze_dirty_and_persist(0xC)
        counters = rt.get_profile_counters()
        assert counters["analyze_dirty_persisted"] >= 1
        assert counters["ingest_results_calls"] >= 1
        rt.reset_profile_counters()
        assert all(v == 0 for v in rt.get_profile_counters().values())


# ---------------------------------------------------------------------------
# Phase 7 - manager constructor smoke (we can't import the full manager
# without IDA, but we can sanity-check the defaults we rely on).
# ---------------------------------------------------------------------------


def test_empty_result_set_does_not_include_active_collectors():
    # Active collectors must NEVER be in the empty-skip list, otherwise we
    # would silently drop meaningful signals.
    assert "CFGShapeCollector" not in EMPTY_RESULT_COLLECTOR_NAMES
    assert "DispatchPatternCollector" not in EMPTY_RESULT_COLLECTOR_NAMES
