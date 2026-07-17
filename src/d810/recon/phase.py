"""ReconPhase orchestrator.

Manages a registry of ``ReconCollector`` instances and dispatches them to
the appropriate maturities. Results are persisted via ``ReconStore``.

When topology collectors (those in :data:`SNAPSHOT_COMPATIBLE_COLLECTORS`)
fire at the same maturity, the phase builds a single portable CFG snapshot
once and passes it to them, avoiding repeated ``get_mblock`` / ``succset``
walks of the live MBA.

No IDA imports at module level - collectors that need IDA guard their own
imports. This module is fully unit-testable.
"""
from __future__ import annotations

from d810.core.logging import getLogger
from d810.core.typing import Any, Protocol, runtime_checkable

from d810.recon.models import ReconResult
from d810.recon.snapshot import (
    SNAPSHOT_COMPATIBLE_COLLECTORS,
    build_recon_flow_graph,
)
from d810.recon.store import ReconStore

logger = getLogger("D810.recon.phase")

ALL_MATURITIES: frozenset[int] | None = None


# Collector names whose empty results are known metadata-only no-ops and
# rarely carry facts worth serialising. Skipping them avoids empty-row noise
# in SQLite while preserving fired accounting via the returned result list.
EMPTY_RESULT_COLLECTOR_NAMES: frozenset[str] = frozenset({
    "handler_transitions",
    "return_frontier",
})


def _is_empty_result(result: ReconResult) -> bool:
    """True when a result carries no metrics and no candidates."""
    return not bool(result.metrics) and not result.candidates


@runtime_checkable
class ReconCollector(Protocol):
    """Protocol for all recon collectors.

    Implementations must be read-only - they observe but never modify
    the microcode (``mba_t``) or ctree (``cfunc_t``).

    Attributes:
        name: Unique collector identifier, used as primary key in the store.
        maturities: Set of maturity levels at which this collector fires.
        level: ``"microcode"`` or ``"ctree"``.
    """
    name: str
    maturities: frozenset[int] | None
    level: str

    def collect(self, target: Any, func_ea: int, maturity: int) -> ReconResult:
        """Collect observations from ``target`` at ``maturity``.

        :param target: ``mba_t`` for microcode collectors, ``cfunc_t`` for ctree.
        :param func_ea: Function effective address.
        :param maturity: Current maturity level.
        :return: Immutable ``ReconResult`` with metrics and candidate flags.
        """
        ...


class ReconPhase:
    """Orchestrates ReconCollectors across microcode and ctree maturities.

    Maintains a per-function maturity guard so each collector fires at most
    once per (func_ea, maturity) pair per decompilation.

    Example:
        >>> store = ReconStore("/tmp/recon.db")
        >>> phase = ReconPhase(store=store)
        >>> phase.register(CFGShapeCollector())
        >>> phase.run_microcode_collectors(mba, func_ea=0x401000, maturity=5)
    """

    def __init__(self, store: ReconStore) -> None:
        self._store = store
        self._collectors: list[ReconCollector] = []
        # Per-function set of maturities already processed.
        # Key: func_ea, Value: set of maturity ints already fired.
        self._fired: dict[int, set[int]] = {}

    @property
    def collector_count(self) -> int:
        return len(self._collectors)

    def register(self, collector: ReconCollector) -> None:
        """Register a collector. Raises ValueError if already registered."""
        for existing in self._collectors:
            if existing.name == collector.name:
                raise ValueError(
                    f"ReconCollector '{collector.name}' already registered"
                )
        self._collectors.append(collector)
        logger.debug("Registered recon collector: %s", collector.name)

    @staticmethod
    def _collector_runs_at_maturity(
        collector: ReconCollector,
        maturity: int,
    ) -> bool:
        """Return True when *collector* should fire at *maturity*."""
        return collector.maturities is ALL_MATURITIES or maturity in collector.maturities

    def reset(self, *, func_ea: int) -> None:
        """Clear the maturity guard for a function (call on new decompilation).

        Also calls ``reset()`` on any collector that exposes it (used by
        collectors with per-function mutable audit state, such as the
        return frontier collector).
        """
        self._fired.pop(func_ea, None)
        for collector in self._collectors:
            reset = getattr(collector, "reset", None)
            if callable(reset):
                try:
                    reset()
                except Exception:
                    logger.exception(
                        "ReconCollector '%s' reset failed",
                        getattr(collector, "name", "<unknown>"),
                    )

    def run_microcode_collectors(
        self,
        target: Any,
        *,
        func_ea: int,
        maturity: int,
    ) -> list[ReconResult]:
        """Dispatch all microcode collectors registered for ``maturity``.

        Protected by a per-(func_ea, maturity) guard so each collector fires
        at most once per decompilation pass.

        Topology collectors (those in :data:`SNAPSHOT_COMPATIBLE_COLLECTORS`)
        receive a portable :class:`FlowGraph` built once for this call so
        the live MBA is walked only once.

        :param target: Live ``mba_t`` (passed through to collectors).
        :param func_ea: Function EA.
        :param maturity: Current microcode maturity level.
        :return: List of ``ReconResult`` produced this call (may be empty).
        """
        fired_maturities = self._fired.setdefault(func_ea, set())
        if maturity in fired_maturities:
            return []

        # Identify the collectors that will fire and check whether any of
        # them accept a snapshot. Build the snapshot at most once, only if
        # at least one topology collector will run.
        selected: list[Any] = []
        snapshot_needed = False
        for collector in self._collectors:
            if collector.level != "microcode":
                continue
            if not self._collector_runs_at_maturity(collector, maturity):
                continue
            selected.append(collector)
            if collector.name in SNAPSHOT_COMPATIBLE_COLLECTORS:
                snapshot_needed = True

        snapshot = None
        if snapshot_needed and target is not None and not (
            hasattr(target, "blocks") and hasattr(target, "entry_serial")
        ):
            try:
                snapshot = build_recon_flow_graph(target)
            except Exception:
                logger.exception(
                    "Recon snapshot build failed at func=0x%x maturity=%d; "
                    "falling back to live MBA for all collectors",
                    func_ea, maturity,
                )
                snapshot = None

        results: list[ReconResult] = []
        pending_save: list[ReconResult] = []
        for collector in selected:
            try:
                target_for_collector = (
                    snapshot
                    if (
                        snapshot is not None
                        and collector.name in SNAPSHOT_COMPATIBLE_COLLECTORS
                    )
                    else target
                )
                result = collector.collect(target_for_collector, func_ea, maturity)
            except Exception:
                logger.exception(
                    "ReconCollector '%s' failed at func=0x%x maturity=%d",
                    collector.name, func_ea, maturity,
                )
                continue
            results.append(result)
            # Skip persistence for empty results from known metadata-only
            # collectors to avoid stale-row noise; the result is still
            # returned so callers can see the collector fired.
            if (
                _is_empty_result(result)
                and result.collector_name in EMPTY_RESULT_COLLECTOR_NAMES
            ):
                continue
            pending_save.append(result)

        if pending_save:
            self._store.save_recon_results_bulk(pending_save)

        fired_maturities.add(maturity)
        return results

    def run_ctree_collectors(
        self,
        target: Any,
        *,
        func_ea: int,
        maturity: int,
    ) -> list[ReconResult]:
        """Dispatch all ctree collectors registered for ``maturity``."""
        fired_maturities = self._fired.setdefault(func_ea, set())
        ctree_key = (maturity, "ctree")
        if ctree_key in fired_maturities:  # type: ignore[operator]
            return []

        results: list[ReconResult] = []
        pending_save: list[ReconResult] = []
        for collector in self._collectors:
            if collector.level != "ctree":
                continue
            if not self._collector_runs_at_maturity(collector, maturity):
                continue
            try:
                result = collector.collect(target, func_ea, maturity)
            except Exception:
                logger.exception(
                    "ReconCollector '%s' (ctree) failed at func=0x%x maturity=%d",
                    collector.name, func_ea, maturity,
                )
                continue
            results.append(result)
            if (
                _is_empty_result(result)
                and result.collector_name in EMPTY_RESULT_COLLECTOR_NAMES
            ):
                continue
            pending_save.append(result)

        if pending_save:
            self._store.save_recon_results_bulk(pending_save)

        fired_maturities.add(ctree_key)  # type: ignore[arg-type]
        return results
