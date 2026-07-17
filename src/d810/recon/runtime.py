"""ReconAnalysisRuntime - thin coordinator for the recon-analysis lifecycle.

Wires together ``ReconPhase``, ``AnalysisPhase``, and ``ReconStore`` into
a single facade: collect -> persist -> analyze -> (optionally persist hints)
-> return hints.

Does NOT own: rule activation, planner scoring, CFG mutation.
No IDA imports - fully unit-testable.

Stale-hint policy: ``reset_for_func(func_ea)`` is called at the start of
each decompilation (when the optimizer managers detect a new func_ea).  This
clears the in-memory fired guard **and** persisted raw results / analyzed
hints so every decompilation pass starts from a clean slate.
"""
from __future__ import annotations

import json
from dataclasses import dataclass

from d810.core.logging import getLogger
from d810.core.typing import TYPE_CHECKING, Any

from d810.recon.analysis import AnalysisPhase
from d810.recon.models import DeobfuscationHints, ReconResult
from d810.recon.outcome import (
    ConsumerOutcomeReport,
    FlowGateOutcomeAdapter,
    PlannerOutcomeAdapter,
    ReconOutcomeLog,
    RuleScopeOutcomeAdapter,
)
from d810.recon.phase import ReconPhase
from d810.recon.flow_hints import derive_flow_context_summary
from d810.recon.store import ReconStore

if TYPE_CHECKING:
    from d810.core.rule_scope import ApplyHintsResult, RuleScopeService
    from d810.recon.flow_hints import FlowContextHintSummary

logger = getLogger("D810.recon.runtime")

# Lightweight opt-in profiling via env var or instance flag. Keep disabled
# overhead near zero when the module flag is false.
import os

_RECON_PROFILE_ENV = "D810_RECON_PROFILE"


@dataclass(frozen=True, slots=True)
class ReconOutcome:
    """Records what the lifecycle produced and what the consumer did.

    Attributes:
        func_ea: Function effective address.
        hints: Resolved hints, or ``None`` if unavailable.
        apply_result: Result from ``RuleScopeService.apply_hints()``, or
            ``None`` if hints were unavailable.
        source: How the hints were obtained: ``"cached"``, ``"analyzed"``,
            or ``"unavailable"``.
    """
    func_ea: int
    hints: DeobfuscationHints | None
    apply_result: ApplyHintsResult | None
    source: str  # "cached" | "analyzed" | "unavailable"


class ReconAnalysisRuntime:
    """Thin coordinator for the generic recon-analysis-consumer lifecycle.

    Lifecycle: collect -> persist canonical artifacts -> analyze into
    consumer-specific summaries -> optionally persist summaries -> feed consumer.

    Does NOT own: rule activation, planner scoring, CFG mutation.

    Example:
        >>> store = ReconStore("/tmp/recon.db")
        >>> phase = ReconPhase(store=store)
        >>> analysis = AnalysisPhase()
        >>> rt = ReconAnalysisRuntime(phase, analysis, store)
        >>> hints = rt.load_or_analyze(func_ea=0x401000, target=None, maturity=5)
    """

    def __init__(
        self,
        phase: ReconPhase,
        analysis: AnalysisPhase,
        store: ReconStore,
    ) -> None:
        self._phase = phase
        self._analysis = analysis
        self._store = store
        self._current_func_ea: int = -1
        self._outcome_log: ReconOutcomeLog = ReconOutcomeLog()
        # ---- in-memory caches (per decompilation, cleared by reset_for_func) ----
        # Fresh collector results waiting to be analyzed/persisted.
        self._results_by_func: dict[int, list[ReconResult]] = {}
        # Functions whose in-memory state is newer than the on-disk store.
        self._dirty_funcs: set[int] = set()
        # Last analyzed hints keyed by func_ea to skip repeat work.
        self._hints_cache_by_func: dict[int, DeobfuscationHints] = {}
        # Collector names that fired per function (independent of whether
        # their rows were persisted, to support session-summary accuracy
        # even when empty rows are skipped).
        self._collector_counts_by_func: dict[int, set[str]] = {}
        # Read-only profiling counters. Enable via env D810_RECON_PROFILE=1.
        self._profile_enabled: bool = bool(os.environ.get(_RECON_PROFILE_ENV))
        self._profile_counters: dict[str, int] = {
            "ingest_results_calls": 0,
            "results_ingested": 0,
            "empty_results_skipped": 0,
            "analyze_dirty_calls": 0,
            "analyze_dirty_cache_hits": 0,
            "analyze_dirty_persisted": 0,
            "analyze_and_persist_calls": 0,
            "analyze_and_persist_store_loads": 0,
            "load_all_recon_results_calls": 0,
        }

    # ------------------------------------------------------------------
    # Profiling
    # ------------------------------------------------------------------

    def enable_profiling(self, enabled: bool = True) -> None:
        """Enable or disable lightweight profiling counters."""
        self._profile_enabled = bool(enabled)

    def get_profile_counters(self) -> dict[str, int]:
        """Return a shallow copy of the current profiling counters."""
        return dict(self._profile_counters)

    def reset_profile_counters(self) -> None:
        """Reset profiling counters to zero."""
        for key in self._profile_counters:
            self._profile_counters[key] = 0

    def _bump(self, key: str, by: int = 1) -> None:
        if self._profile_enabled:
            self._profile_counters[key] = self._profile_counters.get(key, 0) + by

    def reset_for_func(self, func_ea: int) -> bool:
        """Reset recon state -- deduplicates across managers.

        Only the first call per decompilation actually clears state.
        Subsequent calls with the same *func_ea* are no-ops.

        Returns:
            ``True`` if the reset actually fired, ``False`` if deduplicated.
        """
        if func_ea == self._current_func_ea:
            return False  # already reset for this decompilation
        # Flush previous function's outcomes if not finalized.
        # Flush any pending dirty hints for the previous func first so
        # we don't lose analyses when decompilation finishes without an
        # explicit mark_decompilation_finished() on the same EA.
        prev_ea = self._current_func_ea
        if prev_ea != -1:
            if prev_ea in self._dirty_funcs:
                try:
                    self.analyze_dirty_and_persist(prev_ea)
                except Exception:
                    logger.exception(
                        "analyze_dirty_and_persist flush failed for func=0x%x",
                        prev_ea,
                    )
            self._persist_outcomes(prev_ea)
            # Drop the previous func's in-memory cache to keep the dict
            # bounded across long decompilation sessions.
            self._results_by_func.pop(prev_ea, None)
            self._dirty_funcs.discard(prev_ea)
            self._hints_cache_by_func.pop(prev_ea, None)
            self._collector_counts_by_func.pop(prev_ea, None)
        self._current_func_ea = func_ea
        self._phase.reset(func_ea=func_ea)
        self._store.clear_func(func_ea=func_ea)
        self._outcome_log.reset_for_func(func_ea)
        # Clear per-function in-memory cache for the new func.
        self._results_by_func.pop(func_ea, None)
        self._dirty_funcs.discard(func_ea)
        self._hints_cache_by_func.pop(func_ea, None)
        self._collector_counts_by_func.pop(func_ea, None)
        logger.debug("reset_for_func: func=0x%x prev=0x%x flushed=%s", func_ea, prev_ea, prev_ea != -1)
        return True

    def mark_decompilation_finished(self) -> None:
        """Called at decompilation end -- persist outcomes, then reset guard.

        Flushes any dirty in-memory hints for the current function before
        persisting outcomes so that analyses recorded late in the
        decompilation pass are not lost.
        """
        if self._current_func_ea != -1:
            cur = self._current_func_ea
            if cur in self._dirty_funcs:
                try:
                    self.analyze_dirty_and_persist(cur)
                except Exception:
                    logger.exception(
                        "analyze_dirty_and_persist flush failed for func=0x%x",
                        cur,
                    )
            self._persist_outcomes(cur)
        self._current_func_ea = -1

    def _persist_outcomes(self, func_ea: int) -> None:
        """Persist consumer outcomes to store.

        Session summaries are persisted eagerly by ``analyze_and_persist``
        and ``collect_and_analyze``, so this method only handles the
        consumer-outcome rows.
        """
        # Consumer outcomes (batched in one SQLite transaction).
        reports = self._outcome_log.get_func_reports(func_ea)
        if reports:
            payloads = []
            for report in reports:
                prov_dict = report.provenance_dict
                if prov_dict is not None:
                    try:
                        provenance = json.dumps(prov_dict)
                    except (TypeError, ValueError):
                        provenance = ""
                else:
                    provenance = ""
                payloads.append((
                    report.consumer_name,
                    report.source_artifacts_available,
                    report.summary_available,
                    report.consumer_verdict_applied,
                    report.detail,
                    provenance,
                ))
            self._store.save_consumer_outcomes_bulk(func_ea, payloads)

        summary = self._outcome_log.summary(func_ea)
        if summary.get("consumers"):
            logger.info(
                "decompilation_finished: func=0x%x outcome_summary=%s",
                func_ea, summary,
            )

    # ------------------------------------------------------------------
    # Outcome recording
    # ------------------------------------------------------------------

    @property
    def outcome_log(self) -> ReconOutcomeLog:
        """Read-only access to the outcome log."""
        return self._outcome_log

    def record_outcome(self, report: ConsumerOutcomeReport) -> None:
        """Record a consumer outcome report and log it at INFO level."""
        self._outcome_log.record(report)
        logger.info(
            "outcome: func=0x%x consumer=%s artifacts=%s summary=%s verdict=%s",
            report.func_ea, report.consumer_name,
            report.source_artifacts_available,
            report.summary_available,
            report.consumer_verdict_applied,
        )

    def record_rule_scope_outcome(
        self,
        func_ea: int,
        hints: DeobfuscationHints | None,
        apply_result: ApplyHintsResult | None,
        source: str,
    ) -> None:
        """Convenience: build a :class:`RuleScopeOutcomeAdapter` and record it.

        Keeps the :class:`ReconOutcome` / adapter construction in the recon
        layer so that ``d810.hexrays`` hooks do not need to import recon types.
        """
        outcome = ReconOutcome(
            func_ea=func_ea,
            hints=hints,
            apply_result=apply_result,
            source=source,
        )
        adapter = RuleScopeOutcomeAdapter(outcome)
        self.record_outcome(adapter)

    def record_planner_outcome(
        self,
        func_ea: int,
        provenance: Any,
    ) -> None:
        """Convenience: build a :class:`PlannerOutcomeAdapter` and record it."""
        adapter = PlannerOutcomeAdapter(provenance=provenance, func_ea=func_ea)
        self.record_outcome(adapter)

    def record_flow_gate_outcome(
        self,
        func_ea: int,
        decision: Any,
        gate_name: str = "flow_gate",
    ) -> None:
        """Convenience: build a :class:`FlowGateOutcomeAdapter` and record it."""
        adapter = FlowGateOutcomeAdapter(decision=decision, func_ea=func_ea, gate_name=gate_name)
        self.record_outcome(adapter)

    def get_outcome_summary(self, func_ea: int) -> dict:
        """One-line summary per consumer for a function."""
        return self._outcome_log.summary(func_ea)

    def collect_and_analyze(
        self,
        func_ea: int,
        target: Any,
        maturity: int,
        *,
        persist_hints: bool = True,
    ) -> DeobfuscationHints:
        """Run collectors, interpret results, optionally persist hints.

        Args:
            func_ea: Function effective address.
            target: Live ``mba_t`` passed through to collectors.
            maturity: Current microcode maturity level.
            persist_hints: When True, save the resulting hints to the store.

        Returns:
            DeobfuscationHints summarising the classification and recommendations.
        """
        results = self._phase.run_microcode_collectors(
            target, func_ea=func_ea, maturity=maturity,
        )
        logger.debug(
            "collect_and_analyze: func=0x%x maturity=%d collectors_fired=%d",
            func_ea, maturity, len(results),
        )
        if results:
            self.ingest_results(func_ea, results)

        if persist_hints:
            return self.analyze_dirty_and_persist(func_ea) or self._analysis.interpret(
                func_ea=func_ea, results=results, store=self._store,
            )

        return self._analysis.interpret(
            func_ea=func_ea, results=results, store=self._store,
        )

    # ------------------------------------------------------------------
    # In-memory result cache (Phase 2)
    # ------------------------------------------------------------------

    def ingest_results(self, func_ea: int, results: list[ReconResult]) -> None:
        """Stash fresh collector results for *func_ea* without touching SQLite.

        Marks the function dirty so :meth:`analyze_dirty_and_persist` will
        re-interpret the combined set. Empty input is a no-op.
        """
        self._bump("ingest_results_calls")
        if not results:
            return
        bucket = self._results_by_func.setdefault(func_ea, [])
        bucket.extend(results)
        self._dirty_funcs.add(func_ea)
        # Invalidate cached hints because new evidence arrived.
        self._hints_cache_by_func.pop(func_ea, None)
        names = self._collector_counts_by_func.setdefault(func_ea, set())
        non_empty = 0
        for r in results:
            names.add(r.collector_name)
            if r.metrics or r.candidates:
                non_empty += 1
            else:
                self._bump("empty_results_skipped")
        self._bump("results_ingested", len(results))

    def analyze_dirty_and_persist(
        self, func_ea: int
    ) -> DeobfuscationHints | None:
        """Re-interpret in-memory results for *func_ea* and persist them.

        When the function is dirty, runs :meth:`AnalysisPhase.interpret`
        on the union of fresh in-memory results plus any on-disk rows for
        earlier maturities, persists hints and a session summary in one
        transaction, then clears the dirty flag and caches the hints.

        When the function is not dirty, returns the previously cached
        hints (or ``None``) without hitting SQLite.
        """
        self._bump("analyze_dirty_calls")
        if func_ea not in self._dirty_funcs:
            cached = self._hints_cache_by_func.get(func_ea)
            if cached is not None:
                self._bump("analyze_dirty_cache_hits")
            return cached

        in_mem = list(self._results_by_func.get(func_ea, ()))
        fired_set = set(self._collector_counts_by_func.get(func_ea, set()))
        if not in_mem and not fired_set:
            return None

        # Union in-memory with on-disk so analyses include prior maturities.
        # Prefer memory for (func_ea, maturity, collector_name) collisions.
        disk = self._store.load_all_recon_results(func_ea=func_ea)
        self._bump("load_all_recon_results_calls")
        disk_index = {
            (int(r.func_ea), int(r.maturity), r.collector_name): r for r in disk
        }
        for r in in_mem:
            disk_index[(int(r.func_ea), int(r.maturity), r.collector_name)] = r
        results = list(disk_index.values())

        if not results:
            return None

        hints = self._analysis.interpret(
            func_ea=func_ea, results=results, store=self._store,
        )
        collectors_fired = len(
            fired_set
            if fired_set
            else {r.collector_name for r in results}
        )
        # Persist hints + session summary in a single transaction.
        self._store.save_analysis_bundle(
            hints, collectors_fired=collectors_fired,
        )
        self._bump("analyze_dirty_persisted")
        self._dirty_funcs.discard(func_ea)
        self._hints_cache_by_func[func_ea] = hints
        logger.info(
            "analyze_dirty_and_persist: persisted hints for func=0x%x "
            "(type=%s, confidence=%.2f, collectors=%d)",
            func_ea, hints.obfuscation_type, hints.confidence, collectors_fired,
        )
        return hints

    def analyze_and_persist(self, func_ea: int) -> DeobfuscationHints | None:
        """Run analysis on current state and persist hints.

        Prefer the in-memory cache when fresh results are available
        (added in :meth:`ingest_results`); otherwise fall back to
        loading all rows from the SQLite store.

        Returns ``None`` if no recon results are available.
        """
        self._bump("analyze_and_persist_calls")
        # Fast path: hook caller already ingested results; treat them as
        # dirty and reuse the cached-analytics path.
        if func_ea in self._results_by_func:
            self._dirty_funcs.add(func_ea)
            return self.analyze_dirty_and_persist(func_ea)

        # Backwards-compatible slow path: load everything from the store.
        if func_ea in self._hints_cache_by_func:
            return self._hints_cache_by_func[func_ea]
        self._bump("analyze_and_persist_store_loads")
        results = self._store.load_all_recon_results(func_ea=func_ea)
        self._bump("load_all_recon_results_calls")
        if not results:
            return None
        hints = self._analysis.interpret(
            func_ea=func_ea, results=results, store=self._store,
        )
        self._store.save_analysis_bundle(
            hints,
            collectors_fired=len({r.collector_name for r in results}),
        )
        self._hints_cache_by_func[func_ea] = hints
        logger.info(
            "analyze_and_persist: persisted hints for func=0x%x (type=%s, confidence=%.2f)",
            func_ea, hints.obfuscation_type, hints.confidence,
        )
        return hints

    def load_hints(self, func_ea: int) -> DeobfuscationHints | None:
        """Load previously persisted hints from the store.

        Args:
            func_ea: Function effective address.

        Returns:
            Stored hints, or ``None`` if no hints have been persisted for this
            function.
        """
        return self._store.load_hints(func_ea=func_ea)

    def load_flow_context_summary(self, func_ea: int) -> FlowContextHintSummary | None:
        """Load hints and derive a flow-context summary, or ``None``.

        This keeps the derivation in the recon layer so that hexrays hooks
        do not need to import ``d810.recon.flow_hints`` directly.
        """
        hints = self.load_hints(func_ea)
        if hints is None:
            return None
        return derive_flow_context_summary(hints)

    def load_or_analyze(
        self,
        func_ea: int,
        target: Any,
        maturity: int,
        *,
        persist_hints: bool = True,
    ) -> DeobfuscationHints:
        """Load hints if available, otherwise collect and analyze.

        .. deprecated::
            Analysis is now eager -- hints are persisted by
            :meth:`analyze_and_persist` after each collector pass.
            Consumers should call :meth:`load_hints` instead.
            This method is kept for backward compatibility and simply
            delegates to :meth:`load_hints`, falling back to
            :meth:`collect_and_analyze` only when no hints exist.

        Args:
            func_ea: Function effective address.
            target: Live ``mba_t`` passed through to collectors.
            maturity: Current microcode maturity level.
            persist_hints: When True and collection runs, save resulting hints.

        Returns:
            DeobfuscationHints from store or freshly computed.
        """
        existing = self.load_hints(func_ea)
        if existing is not None:
            logger.debug(
                "load_or_analyze: cache hit for func=0x%x type=%s",
                func_ea, existing.obfuscation_type,
            )
            return existing

        return self.collect_and_analyze(
            func_ea, target, maturity, persist_hints=persist_hints,
        )

    def apply_to_rule_scope(
        self,
        func_ea: int,
        rule_scope: RuleScopeService,
        target: Any = None,
        maturity: int | None = None,
        *,
        persist_hints: bool = True,
    ) -> ReconOutcome:
        """Convenience helper: load-or-analyze hints, apply to rule scope, record outcome.

        .. note::
            The primary hint-application path is now **hook-driven (push)**:
            after :meth:`analyze_and_persist` returns hints in the optimizer
            manager hooks, they are applied to ``RuleScopeService`` immediately.
            This method remains available for manual/script use and standalone
            workflows where the hook wiring is not active.

        Checks the store for cached hints first. When a cache miss occurs
        and *target* / *maturity* are provided, runs collectors and analysis.
        If hints are resolved, they are applied to *rule_scope* via
        ``apply_hints()``.

        Args:
            func_ea: Function effective address.
            rule_scope: Consumer rule-scope service (not stored).
            target: Live ``mba_t`` for collectors (may be ``None``).
            maturity: Current microcode maturity level (may be ``None``).
            persist_hints: When True and collection runs, save resulting hints.

        Returns:
            ``ReconOutcome`` recording hints, apply result, and provenance.
        """
        # --- 1. Resolve hints (cached or fresh) ---
        hints: DeobfuscationHints | None = None
        source: str = "unavailable"

        existing = self.load_hints(func_ea)
        if existing is not None:
            hints = existing
            source = "cached"
            logger.info(
                "apply_to_rule_scope: func=0x%x using cached hints "
                "(type=%s confidence=%.2f)",
                func_ea, hints.obfuscation_type, hints.confidence,
            )
        elif target is not None and maturity is not None:
            hints = self.collect_and_analyze(
                func_ea, target, maturity, persist_hints=persist_hints,
            )
            source = "analyzed"
            logger.info(
                "apply_to_rule_scope: func=0x%x freshly analyzed hints "
                "(type=%s confidence=%.2f)",
                func_ea, hints.obfuscation_type, hints.confidence,
            )
        else:
            logger.info(
                "apply_to_rule_scope: func=0x%x no hints available "
                "(no cached hints and no target/maturity provided)",
                func_ea,
            )

        # --- 2. Apply to rule scope if we have hints ---
        apply_result = None
        if hints is not None:
            apply_result = rule_scope.apply_hints(hints)
            logger.info(
                "apply_to_rule_scope: func=0x%x applied -> "
                "inferences=%s suppressed=%s gen=%d->%d",
                func_ea,
                apply_result.inferences_applied,
                apply_result.rules_suppressed,
                apply_result.generation_before,
                apply_result.generation_after,
            )

        return ReconOutcome(
            func_ea=func_ea,
            hints=hints,
            apply_result=apply_result,
            source=source,
        )
