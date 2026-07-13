"""Headless D810 check utility backed by Hex-Rays' ``ida_domain`` package.

This module provides a CLI entry point (``d810-ida-domain-check``) that opens
a binary/IDB through ``ida_domain.Database``, applies a D810 project
configuration, decompiles one or more target functions, and reports a
deterministic JSON-serialisable result with a stable exit code.

Design notes (see ``.kilo/plans/1783565194614-ida-domain-cli-check-plan.md``
for the full design contract):

* The module intentionally avoids importing ``ida_domain`` at import time,
  because importing it initialises an IDA plugin context in the current
  environment. ``ida_domain`` is therefore imported lazily inside
  :func:`_open_database`.
* D810 hooks and Hex-Rays decompilation are implemented on the native IDA
  Python modules (``idaapi``, ``ida_hexrays``, ``idc``), so the helper still
  relies on those even though the database is opened through ``ida_domain``.
* The runner is a smoke/stability checker, not a golden-output comparator. It
  answers: "does this config decompile these functions without D810/Hex-Rays
  failure?".
"""

from __future__ import annotations

import argparse
import contextlib
import dataclasses
import json
import logging
import os
import pathlib
import re
import sys
import time
import traceback
import typing
from pathlib import Path

# ``d810.conf`` imports IDA-only modules (``ida_diskio``) at load time and
# ``d810.errors`` is IDA-free, so we keep d810 imports local to where they
# are needed. This keeps ``import d810.testing.ida_domain_check`` safe in a
# plain Python interpreter that does not have IDA installed.
from d810.errors import D810Exception

# Use a regular logging logger so importing this module does not require
# ``d810.conf``. The D-810 logger configuration will pick up this logger
# via ``propagate`` defaults when running inside IDA.
logger = logging.getLogger("D810.ida_domain_check")


SCHEMA_VERSION = 1


# ---------------------------------------------------------------------------
# Exit codes
# ---------------------------------------------------------------------------


EXIT_OK = 0
EXIT_TARGET_FAILURES = 1
EXIT_ARG_ERROR = 2
EXIT_IDA_INIT_ERROR = 3
EXIT_HEXRAYS_UNAVAILABLE = 4
EXIT_UNHANDLED_EXCEPTION = 5


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclasses.dataclass(slots=True)
class CheckArgs:
    """Parsed CLI options for the headless check."""

    binary: Path
    config: str | None
    config_path: Path | None
    functions: list[str]
    functions_file: Path | None
    all_functions: bool
    json_out: Path | None
    artifacts_dir: Path
    ida_log: Path | None
    processor: str | None
    output_idb: Path | None
    save_idb: bool
    hexrays_config_defaults: bool
    require_rule_fired: list[str]
    fail_on_log_error: bool
    fail_on_verify_artifact: bool
    summary_only: bool


@dataclasses.dataclass(slots=True)
class FunctionTarget:
    """One requested decompilation target, post-resolution."""

    raw: str
    ea: int | None
    name: str | None
    resolution_status: str  # 'resolved' or 'unresolved'


@dataclasses.dataclass(slots=True)
class FunctionResult:
    """Per-function decompilation outcome."""

    target: str
    ea: str | None
    name: str | None
    success: bool
    error_type: str | None
    error_message: str | None
    rules_fired_delta: list[str]
    decompile_elapsed_s: float
    pseudocode_lines: int | None


@dataclasses.dataclass(slots=True)
class CheckResult:
    """Top-level check outcome."""

    schema_version: int
    success: bool
    exit_code: int
    binary: str
    config: dict[str, typing.Any]
    database: dict[str, typing.Any]
    functions: list[FunctionResult]
    stats: dict[str, typing.Any]
    verify_artifacts: list[str]
    log_errors: list[dict[str, typing.Any]]
    rules_fired: list[str]
    missing_required_rules: list[str]


# ---------------------------------------------------------------------------
# Log record capture
# ---------------------------------------------------------------------------


class _LogCaptureHandler(logging.Handler):
    """In-memory handler that stores log records emitted at or above a level."""

    def __init__(self, level: int = logging.ERROR) -> None:
        super().__init__(level=level)
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:  # noqa: D401
        self.records.append(record)

    def as_dicts(self) -> list[dict[str, typing.Any]]:
        return [
            {
                "logger": rec.name,
                "level": logging.getLevelName(rec.levelno),
                "message": rec.getMessage(),
            }
            for rec in self.records
        ]


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------


_HEXRAYS_RULE_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.]*$")


def build_argparser() -> argparse.ArgumentParser:
    """Return the ``argparse.ArgumentParser`` used by the CLI."""
    parser = argparse.ArgumentParser(
        prog="d810-ida-domain-check",
        description=(
            "Run D810 headlessly through the Hex-Rays ida_domain package, "
            "apply a project configuration, decompile selected functions, "
            "and emit a JSON check report with a stable exit code."
        ),
    )
    parser.add_argument(
        "--binary",
        required=True,
        type=Path,
        help="Path to the binary (or pre-built IDB) passed to ida_domain.Database.open().",
    )
    config_group = parser.add_mutually_exclusive_group(required=True)
    config_group.add_argument(
        "--config",
        type=str,
        default=None,
        help="Built-in or user D810 project configuration filename (e.g. default_instruction_only.json).",
    )
    config_group.add_argument(
        "--config-path",
        type=Path,
        default=None,
        help="Explicit path to a D810 project configuration JSON file.",
    )

    target_group = parser.add_argument_group("function targets")
    target_group.add_argument(
        "--function",
        action="append",
        default=[],
        dest="functions",
        help="Function name or EA (0x... or decimal). Repeatable.",
    )
    target_group.add_argument(
        "--functions-file",
        type=Path,
        default=None,
        help="Optional newline-delimited list of function names or EAs. "
             "# comments and blank lines are ignored.",
    )
    target_group.add_argument(
        "--all-functions",
        action="store_true",
        help="Decompile every function discovered by db.functions.get_all().",
    )

    output_group = parser.add_argument_group("output")
    output_group.add_argument(
        "--json-out",
        type=Path,
        default=None,
        help="Write the JSON report to this path instead of stdout.",
    )
    output_group.add_argument(
        "--artifacts-dir",
        type=Path,
        default=None,
        help="Directory used for verify-capture artifacts and logs. "
             "Defaults to <cwd>/d810_ida_domain_artifacts.",
    )
    output_group.add_argument(
        "--summary-only",
        action="store_true",
        help="Omit pseudocode line counts from per-function results (default behaviour).",
    )

    ida_group = parser.add_argument_group("ida options")
    ida_group.add_argument(
        "--ida-log",
        type=Path,
        default=None,
        help="Path passed to IdaCommandOptions(log_file=...).",
    )
    ida_group.add_argument(
        "--processor",
        type=str,
        default=None,
        help="Processor string passed to IdaCommandOptions(processor=...).",
    )
    ida_group.add_argument(
        "--output-idb",
        type=Path,
        default=None,
        help="Optional path passed to IdaCommandOptions(output_database=...).",
    )
    save_group = ida_group.add_mutually_exclusive_group()
    save_group.add_argument(
        "--save-idb",
        dest="save_idb",
        action="store_true",
        default=False,
        help="Close the database with save_on_close=True.",
    )
    save_group.add_argument(
        "--no-save-idb",
        dest="save_idb",
        action="store_false",
        help="Close the database with save_on_close=False (default).",
    )

    check_group = parser.add_argument_group("check options")
    hexrays_defaults_group = check_group.add_mutually_exclusive_group()
    hexrays_defaults_group.add_argument(
        "--hexrays-config-defaults",
        dest="hexrays_config_defaults",
        action="store_true",
        default=True,
        help="Apply deterministic Hex-Rays configuration lines (default).",
    )
    hexrays_defaults_group.add_argument(
        "--no-hexrays-config-defaults",
        dest="hexrays_config_defaults",
        action="store_false",
        help="Skip applying deterministic Hex-Rays configuration lines.",
    )

    check_group.add_argument(
        "--require-rule-fired",
        action="append",
        default=[],
        dest="require_rule_fired",
        help="Require that the named rule fired during the run. Repeatable.",
    )

    log_group = check_group.add_mutually_exclusive_group()
    log_group.add_argument(
        "--fail-on-log-error",
        dest="fail_on_log_error",
        action="store_true",
        default=True,
        help="Fail the run if any D810 logger records at ERROR+ (default).",
    )
    log_group.add_argument(
        "--no-fail-on-log-error",
        dest="fail_on_log_error",
        action="store_false",
        help="Do not fail on D810 log errors.",
    )

    verify_group = check_group.add_mutually_exclusive_group()
    verify_group.add_argument(
        "--fail-on-verify-artifact",
        dest="fail_on_verify_artifact",
        action="store_true",
        default=True,
        help="Fail the run if any verify_fail_*.json artifact is emitted (default).",
    )
    verify_group.add_argument(
        "--no-fail-on-verify-artifact",
        dest="fail_on_verify_artifact",
        action="store_false",
        help="Ignore verify-capture artifacts.",
    )

    return parser


def parse_args(argv: list[str] | None) -> CheckArgs:
    """Parse CLI args and validate target-selection requirements.

    Returns:
        CheckArgs: structured command-line arguments.

    Raises:
        SystemExit: via argparse if the user provided an incompatible combination.
    """
    parser = build_argparser()
    args = parser.parse_args(argv)

    # At least one target selection mode must be set.
    if not (args.functions or args.functions_file or args.all_functions):
        parser.error(
            "specify at least one of --function, --functions-file, or --all-functions"
        )

    # Validate rule-name patterns early to surface obvious typos at exit code 2.
    for rule_name in args.require_rule_fired:
        if not _HEXRAYS_RULE_RE.match(rule_name):
            parser.error(
                f"--require-rule-fired value {rule_name!r} is not a valid rule identifier"
            )

    default_artifacts = Path.cwd() / "d810_ida_domain_artifacts"
    artifacts_dir: Path = args.artifacts_dir or default_artifacts

    return CheckArgs(
        binary=args.binary,
        config=args.config,
        config_path=args.config_path,
        functions=list(args.functions),
        functions_file=args.functions_file,
        all_functions=args.all_functions,
        json_out=args.json_out,
        artifacts_dir=artifacts_dir,
        ida_log=args.ida_log,
        processor=args.processor,
        output_idb=args.output_idb,
        save_idb=args.save_idb,
        hexrays_config_defaults=args.hexrays_config_defaults,
        require_rule_fired=list(args.require_rule_fired),
        fail_on_log_error=args.fail_on_log_error,
        fail_on_verify_artifact=args.fail_on_verify_artifact,
        summary_only=args.summary_only or True,  # default summary-only
    )


# ---------------------------------------------------------------------------
# Target / list parsing
# ---------------------------------------------------------------------------


def _parse_ea(value: str) -> int | None:
    """Parse a ``0x...`` or decimal string to an int, or return ``None``."""
    value = value.strip()
    if not value:
        return None
    try:
        if value.lower().startswith("0x"):
            return int(value, 16)
        return int(value, 0)
    except ValueError:
        return None


def parse_functions_file(path: Path) -> list[str]:
    """Parse a newline-delimited function-list file.

    Blank lines and lines starting with ``#`` are ignored.
    """
    entries: list[str] = []
    with path.open("r", encoding="utf-8") as fp:
        for raw_line in fp:
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            entries.append(line)
    return entries


# ---------------------------------------------------------------------------
# Result helpers
# ---------------------------------------------------------------------------


def _format_ea(ea: int | None) -> str | None:
    if ea is None:
        return None
    return f"0x{ea & 0xFFFFFFFFFFFFFFFF:X}"


def _result_to_dict(result: FunctionResult) -> dict[str, typing.Any]:
    return {
        "target": result.target,
        "name": result.name,
        "ea": result.ea,
        "success": result.success,
        "error_type": result.error_type,
        "error_message": result.error_message,
        "rules_fired_delta": sorted(set(result.rules_fired_delta)),
        "elapsed_s": round(result.decompile_elapsed_s, 6),
        "pseudocode_lines": result.pseudocode_lines,
    }


def _exit_code_from_result(
    result: CheckResult,
    *,
    fail_on_log_error: bool,
    fail_on_verify_artifact: bool,
) -> int:
    """Compute the final exit code for a :class:`CheckResult`."""
    if result.exit_code != EXIT_OK:
        return result.exit_code
    if any(not fr.success for fr in result.functions):
        return EXIT_TARGET_FAILURES
    if fail_on_verify_artifact and result.verify_artifacts:
        return EXIT_TARGET_FAILURES
    if fail_on_log_error and result.log_errors:
        return EXIT_TARGET_FAILURES
    if result.missing_required_rules:
        return EXIT_TARGET_FAILURES
    return EXIT_OK


# ---------------------------------------------------------------------------
# IDA-side helpers
# ---------------------------------------------------------------------------


def _configure_hexrays_defaults() -> None:
    """Apply deterministic Hex-Rays decompiler configuration lines."""
    try:
        import idaapi  # local import
    except Exception as exc:  # pragma: no cover - requires IDA
        raise RuntimeError(f"idaapi unavailable: {exc}") from exc

    settings = [
        "RIGHT_MARGIN = 100",
        "PSEUDOCODE_SYNCED = YES",
        "PSEUDOCODE_DOCKPOS = DP_RIGHT",
        "GENERATE_EMPTY_LINES = YES",
        "BLOCK_INDENT = 4",
        "MAX_FUNCSIZE = 2048",
        "MAX_NCOMMAS = 1",
        "COLLAPSE_LVARS = YES",
        "GENERATE_EA_LABELS = YES",
        "AUTO_UNHIDE = YES",
        "DEFAULT_RADIX = 16",
    ]
    for line in settings:
        with contextlib.suppress(Exception):
            idaapi.change_hexrays_config(line)


def _init_hexrays() -> bool:
    """Load the architecture-specific decompiler plugin.

    Mirrors :func:`d810ng.init_hexrays` but without the plugin/UI imports.
    """
    try:
        import idaapi  # local import
    except Exception as exc:  # pragma: no cover - requires IDA
        logger.error("idaapi import failed: %s", exc)
        return False

    ALL_DECOMPILERS = {
        getattr(idaapi, "PLFM_386", None): "hexx64",
        getattr(idaapi, "PLFM_ARM", None): "hexarm",
        getattr(idaapi, "PLFM_PPC", None): "hexppc",
        getattr(idaapi, "PLFM_MIPS", None): "hexmips",
        getattr(idaapi, "PLFM_RISCV", None): "hexrv",
    }
    cpu = getattr(getattr(idaapi, "ph", None), "id", None)
    decompiler = ALL_DECOMPILERS.get(cpu)
    if not decompiler:
        logger.error("No known decompiler for architecture id=%s", cpu)
        return False

    loaded = bool(idaapi.load_plugin(decompiler))
    initialised = False
    if loaded:
        init_func = getattr(idaapi, "init_hexrays_plugin", None)
        if init_func is not None:
            initialised = bool(init_func())
        else:
            init_func = None  # idaapi provides no plugin init in this build
    if not (loaded and initialised):
        logger.error("Failed to load/init decompiler plugin: %s", decompiler)
        return False
    return True


def _setup_verify_capture(artifacts_dir: Path) -> Path:
    """Configure D810 verify-capture environment variables."""
    capture_dir = artifacts_dir / "verify_failures"
    capture_dir.mkdir(parents=True, exist_ok=True)
    os.environ.setdefault("D810_VERIFY_CAPTURE", "1")
    os.environ["D810_VERIFY_CAPTURE_DIR"] = str(capture_dir)
    return capture_dir


def _scan_verify_artifacts(capture_dir: Path) -> list[str]:
    """Return a sorted list of verify-capture artifact paths that exist."""
    if not capture_dir.exists():
        return []
    return sorted(str(p) for p in capture_dir.glob("verify_fail_*.json"))


@contextlib.contextmanager
def _install_log_capture():
    """Temporarily capture ERROR+ log records from D810 loggers."""
    handler = _LogCaptureHandler(level=logging.ERROR)
    captured_loggers = ("D810", "D810.optimizer")
    attached: list[logging.Logger] = []
    for name in captured_loggers:
        log = logging.getLogger(name)
        log.addHandler(handler)
        attached.append(log)
    try:
        yield handler
    finally:
        for log in attached:
            with contextlib.suppress(Exception):
                log.removeHandler(handler)


# ---------------------------------------------------------------------------
# Project / config resolution
# ---------------------------------------------------------------------------


def _known_rule_names(state) -> tuple[set[str], set[str]]:
    """Return (``known_ins_rules``, ``known_blk_rules``) as sets of names."""
    ins: set[str] = set()
    blk: set[str] = set()
    for rule in getattr(state, "known_ins_rules", []) or []:
        name = getattr(rule, "name", None) or rule.__class__.__name__
        ins.add(name)
    for rule in getattr(state, "known_blk_rules", []) or []:
        name = getattr(rule, "name", None) or rule.__class__.__name__
        blk.add(name)
    return ins, blk


def _config_unknown_rules(state, project: ProjectConfiguration) -> list[str]:
    """Return rule names referenced by ``project`` that are unknown to ``state``."""
    ins_known, blk_known = _known_rule_names(state)
    unknown: list[str] = []
    for rule_conf in project.ins_rules:
        if rule_conf.is_activated and rule_conf.name and rule_conf.name not in ins_known:
            unknown.append(rule_conf.name)
    for rule_conf in project.blk_rules:
        if rule_conf.is_activated and rule_conf.name and rule_conf.name not in blk_known:
            unknown.append(rule_conf.name)
    return sorted(set(unknown))


def _resolve_project(state, args: CheckArgs) -> tuple[int | None, ProjectConfiguration | None, str | None]:
    """Resolve the project index/instance under one of the two modes.

    Returns ``(project_index, project, error_message)``. On success,
    ``error_message`` is ``None`` and both prior values are non-``None``.
    """
    pm = state.project_manager
    if args.config:
        try:
            index = pm.index(args.config)
        except ValueError:
            available = sorted(pm.project_names())
            return None, None, (
                f"unknown --config {args.config!r}; available: {available}"
            )
        project = pm.get(index)
        state.load_project(index)
        return index, project, None

    if args.config_path:
        try:
            from d810.conf import ProjectConfiguration  # local; IDA-free wrapper
            project = ProjectConfiguration.from_file(args.config_path)
        except FileNotFoundError as exc:
            return None, None, f"--config-path not found: {exc}"
        except json.JSONDecodeError as exc:
            return None, None, f"--config-path is not valid JSON: {exc}"
        name = project.path.name
        pm.register_transient(project)
        try:
            index = pm.index(name)
        except ValueError as exc:
            return None, None, f"failed to resolve transient project {name!r}: {exc}"
        state.load_project(index)
        return index, project, None

    return None, None, "no config specified (internal error)"


# ---------------------------------------------------------------------------
# Target resolution against the open database
# ---------------------------------------------------------------------------


def _resolve_targets(
    *,
    raw_targets: list[str],
    all_functions: bool,
    functions_file_entries: list[str],
) -> tuple[list[FunctionTarget], list[FunctionTarget]]:
    """Resolve all requested function targets.

    Returns ``(resolved_targets, unresolved_targets)``.
    """
    raw_combined: list[str] = list(raw_targets) + list(functions_file_entries)

    resolved: list[FunctionTarget] = []
    unresolved: list[FunctionTarget] = []

    if not raw_combined and not all_functions:
        return resolved, unresolved

    try:
        import idc  # local import; requires IDA
    except Exception as exc:  # pragma: no cover - requires IDA
        logger.error("idc import failed during target resolution: %s", exc)
        for raw in raw_combined:
            unresolved.append(FunctionTarget(raw=raw, ea=None, name=None, resolution_status="unresolved"))
        return resolved, unresolved

    if all_functions:
        # Caller passes ``db`` indirectly through the database context. We do
        # not have direct access here, so fall back to ``idautils.Functions``,
        # which is the canonical IDA Python enumeration helper.
        try:
            import idautils  # local import; requires IDA
            for func_addr in idautils.Functions():
                fname = idc.get_func_name(func_addr) or ""
                resolved.append(
                    FunctionTarget(
                        raw=fname or _format_ea(func_addr) or str(func_addr),
                        ea=int(func_addr),
                        name=fname or None,
                        resolution_status="resolved",
                    )
                )
        except Exception as exc:
            logger.error("all-functions resolution failed: %s", exc)

    for raw in raw_combined:
        # Try EA first.
        ea = _parse_ea(raw)
        if ea is not None:
            func_ea = idc.get_func_attr(ea, idc.FUNCATTR_START) if hasattr(idc, "FUNCATTR_START") else None
            if not func_ea:
                # fall back: try exact address
                try:
                    import idaapi  # local import
                    func_ea = int(idaapi.get_func(int(ea)).start_ea)
                except Exception:
                    func_ea = None
            if func_ea:
                name = idc.get_func_name(func_ea) or idc.get_name(int(func_ea), 0) or None
                resolved.append(
                    FunctionTarget(
                        raw=raw,
                        ea=int(func_ea),
                        name=name,
                        resolution_status="resolved",
                    )
                )
                continue
            unresolved.append(FunctionTarget(raw=raw, ea=None, name=None, resolution_status="unresolved"))
            continue

        # Try by name (with `_name` fallback for macOS-style exports).
        name_candidates = [raw]
        if not raw.startswith("_"):
            name_candidates.append("_" + raw)
        candidate_ea: int | None = None
        candidate_name: str | None = None
        for cand in name_candidates:
            try:
                ea_val = int(idc.get_name_ea_simple(cand))
            except Exception:
                ea_val = idc.BADADDR if hasattr(idc, "BADADDR") else -1
            if ea_val is None or ea_val == getattr(idc, "BADADDR", -1):
                continue
            try:
                import idaapi  # local import
                func_obj = idaapi.get_func(int(ea_val))
            except Exception:
                func_obj = None
            if func_obj is None:
                continue
            candidate_ea = int(func_obj.start_ea)
            candidate_name = idc.get_func_name(candidate_ea) or cand
            break

        if candidate_ea is not None:
            resolved.append(
                FunctionTarget(
                    raw=raw,
                    ea=candidate_ea,
                    name=candidate_name,
                    resolution_status="resolved",
                )
            )
        else:
            unresolved.append(FunctionTarget(raw=raw, ea=None, name=None, resolution_status="unresolved"))

    return resolved, unresolved


# ---------------------------------------------------------------------------
# D810 lifecycle
# ---------------------------------------------------------------------------


@contextlib.contextmanager
def _d810_state_lifecycle(gui: bool = False):
    """Drive D810State through load → start → (yield) → stop → unload.

    Mirrors ``_d810_state_cm`` from ``tests/system/conftest.py`` but bounded
    to the headless path. Tracks whether the state was already loaded or
    started so we restore prior state instead of stomping it.
    """
    from d810.manager import D810State

    state = D810State()
    was_loaded = bool(state.is_loaded())

    if not was_loaded:
        state.load(gui=gui)

    was_started = bool(getattr(state.manager, "started", False))
    if not was_started:
        state.start_d810()

    # Cache clearing matches the test fixture semantics.
    try:
        from d810.expr.utils import MOP_CONSTANT_CACHE, MOP_TO_AST_CACHE
        from d810.core import (
            MOP_CONSTANT_CACHE as CORE_MOP_CONSTANT_CACHE,
            MOP_TO_AST_CACHE as CORE_MOP_TO_AST_CACHE,
        )
        MOP_CONSTANT_CACHE.clear()
        MOP_TO_AST_CACHE.clear()
        CORE_MOP_CONSTANT_CACHE.clear()
        CORE_MOP_TO_AST_CACHE.clear()
    except Exception as exc:  # pragma: no cover - best-effort
        logger.debug("MOP cache clearing skipped: %s", exc)

    try:
        from d810.optimizers.microcode.flow.flattening.dispatcher_detection import DispatcherCache
        DispatcherCache.clear_cache()
    except Exception as exc:  # pragma: no cover - best-effort
        logger.debug("DispatcherCache clearing skipped: %s", exc)

    try:
        from d810.hexrays.tracker import MopTracker
        MopTracker.reset()
    except Exception as exc:  # pragma: no cover - best-effort
        logger.debug("MopTracker.reset skipped: %s", exc)

    try:
        from d810.optimizers.microcode.flow.flattening import (
            fix_pred_cond_jump_block,
        )
        fix_pred_cond_jump_block.clear_cache()
    except Exception as exc:  # pragma: no cover - best-effort
        logger.debug("fix_pred_cond_jump_block clearing skipped: %s", exc)

    with contextlib.suppress(Exception):
        state.stats.reset()

    try:
        yield state
    finally:
        if not was_started:
            with contextlib.suppress(Exception):
                state.stop_d810()
        if not was_loaded:
            with contextlib.suppress(Exception):
                state.unload(gui=gui)


def _stats_snapshot(state) -> set[str]:
    """Return the set of fired rule names at this moment in time."""
    try:
        names = state.stats.get_fired_rule_names()
        return {str(n) for n in names}
    except Exception:
        return set()


# ---------------------------------------------------------------------------
# Database lifecycle
# ---------------------------------------------------------------------------


@contextlib.contextmanager
def _open_database(args: CheckArgs, log_capture_handler: _LogCaptureHandler):
    """Open a database through ``ida_domain`` and yield it.

    ``ida_domain`` is imported lazily inside this function so that simply
    importing this module does not initialise an IDA plugin context.
    """
    try:
        from ida_domain import Database  # type: ignore
        from ida_domain.database import IdaCommandOptions  # type: ignore
    except ImportError as exc:
        raise RuntimeError(
            "ida_domain is not importable in this interpreter"
        ) from exc

    opts_kwargs: dict[str, typing.Any] = {
        "auto_analysis": True,
        "new_database": bool(args.output_idb),
    }
    if args.processor is not None:
        opts_kwargs["processor"] = args.processor
    if args.ida_log is not None:
        opts_kwargs["log_file"] = str(args.ida_log)
    if args.output_idb is not None:
        opts_kwargs["output_database"] = str(args.output_idb)

    try:
        opts = IdaCommandOptions(**opts_kwargs)
    except TypeError:
        # Older ida_domain versions may not accept all kwargs — try a minimal set.
        minimal = {"auto_analysis": True}
        if args.processor is not None:
            minimal["processor"] = args.processor
        if args.ida_log is not None:
            minimal["log_file"] = str(args.ida_log)
        if args.output_idb is not None:
            minimal["output_database"] = str(args.output_idb)
        opts = IdaCommandOptions(**minimal)

    log_capture_handler.emit(
        _LoggingRecordShim("D810.ida_domain_check", logging.DEBUG, f"opening {args.binary}")
    )

    with Database.open(str(args.binary), args=opts, save_on_close=args.save_idb) as db:
        yield db


class _LoggingRecordShim(logging.LogRecord):
    """Helper to feed pre-formatted messages into the local capture handler."""

    def __init__(self, name: str, level: int, message: str) -> None:
        super().__init__(
            name=name,
            level=level,
            pathname=__file__,
            lineno=0,
            msg=message,
            args=(),
            exc_info=None,
        )


# ---------------------------------------------------------------------------
# Decompilation
# ---------------------------------------------------------------------------


def _decompile_target(target: FunctionTarget, args: CheckArgs) -> FunctionResult:
    """Decompile ``target`` (cache-disabled) and capture the outcome."""
    if target.ea is None:
        return FunctionResult(
            target=target.raw,
            ea=None,
            name=target.name,
            success=False,
            error_type="UnresolvedFunction",
            error_message="function target could not be resolved",
            rules_fired_delta=[],
            decompile_elapsed_s=0.0,
            pseudocode_lines=None,
        )

    try:
        import idaapi  # local import
    except Exception as exc:
        return FunctionResult(
            target=target.raw,
            ea=_format_ea(target.ea),
            name=target.name,
            success=False,
            error_type="IdaMissing",
            error_message=f"idaapi unavailable: {exc}",
            rules_fired_delta=[],
            decompile_elapsed_s=0.0,
            pseudocode_lines=None,
        )

    # Capture stats before decompilation.
    from d810.manager import D810State

    try:
        state = D810State()
    except Exception as exc:  # pragma: no cover - requires IDA
        return FunctionResult(
            target=target.raw,
            ea=_format_ea(target.ea),
            name=target.name,
            success=False,
            error_type="StateMissing",
            error_message=f"D810State unavailable: {exc}",
            rules_fired_delta=[],
            decompile_elapsed_s=0.0,
            pseudocode_lines=None,
        )

    fired_before = _stats_snapshot(state)

    start = time.perf_counter()
    rules_fired: list[str] = []
    error_type: str | None = None
    error_message: str | None = None
    pseudocode_lines: int | None = None
    try:
        cfunc = idaapi.decompile(int(target.ea), flags=idaapi.DECOMP_NO_CACHE)
    except (RuntimeError, D810Exception) as exc:
        cfunc = None
        error_type = type(exc).__name__
        error_message = str(exc)
    except Exception as exc:
        cfunc = None
        error_type = type(exc).__name__
        error_message = str(exc)
    elapsed = time.perf_counter() - start

    if cfunc is None and error_type is None:
        error_type = "DecompileFailed"
        error_message = f"idaapi.decompile returned None for ea=0x{target.ea:X}"

    success = cfunc is not None and error_type is None
    if success:
        try:
            lines = getattr(cfunc, "lines", None)
            if lines is not None:
                pseudocode_lines = sum(1 for _ in lines)
            else:
                pseudocode_lines = 0
        except Exception:
            pseudocode_lines = None

    fired_after = _stats_snapshot(state)
    delta = fired_after - fired_before
    rules_fired = sorted(delta)

    return FunctionResult(
        target=target.raw,
        ea=_format_ea(target.ea),
        name=target.name,
        success=success,
        error_type=error_type,
        error_message=error_message,
        rules_fired_delta=rules_fired,
        decompile_elapsed_s=elapsed,
        pseudocode_lines=pseudocode_lines if not args.summary_only else None,
    )


# ---------------------------------------------------------------------------
# Top-level runner
# ---------------------------------------------------------------------------


def run_check(args: CheckArgs) -> CheckResult:
    """Execute the full check and return a :class:`CheckResult`."""
    capture_dir = _setup_verify_capture(args.artifacts_dir)

    early: list[FunctionResult] = []
    config_payload: dict[str, typing.Any] = {}
    db_payload: dict[str, typing.Any] = {}
    project: ProjectConfiguration | None = None
    exit_code: int = EXIT_OK

    def fail(run_exit_code: int) -> CheckResult:
        return CheckResult(
            schema_version=SCHEMA_VERSION,
            success=False,
            exit_code=run_exit_code,
            binary=str(args.binary),
            config=config_payload,
            database=db_payload,
            functions=early,
            stats={},
            verify_artifacts=_scan_verify_artifacts(capture_dir),
            log_errors=[],
            rules_fired=[],
            missing_required_rules=[],
        )

    # --- Config resolution (before opening the database) ----------------
    if not (args.binary.exists() if hasattr(args.binary, "exists") else True):
        return fail(EXIT_ARG_ERROR)

    from d810.manager import D810State

    state = D810State()  # singleton
    try:
        index, project, err = _resolve_project(state, args)
    except Exception as exc:
        logger.error("project resolution raised: %s", exc)
        return fail(EXIT_ARG_ERROR)

    if err is not None or project is None:
        return fail(EXIT_ARG_ERROR)

    config_payload = {
        "name": project.path.name,
        "path": str(project.path),
        "unknown_rules": [],
    }

    try:
        unknown_rules = _config_unknown_rules(state, project)
    except Exception as exc:
        logger.error("unknown-rule validation failed: %s", exc)
        unknown_rules = []
    if unknown_rules:
        config_payload["unknown_rules"] = unknown_rules

    # Active ins+blk rules that are activated.
    activated = [
        rc.name for rc in project.ins_rules if rc.is_activated and rc.name
    ] + [
        rc.name for rc in project.blk_rules if rc.is_activated and rc.name
    ]
    if not activated:
        config_payload["empty"] = True

    # --- Parse function-list file ---------------------------------------
    functions_file_entries: list[str] = []
    if args.functions_file is not None:
        try:
            functions_file_entries = parse_functions_file(args.functions_file)
        except FileNotFoundError as exc:
            logger.error("functions file not found: %s", exc)
            return fail(EXIT_ARG_ERROR)
        except Exception as exc:
            logger.error("functions file parse error: %s", exc)
            return fail(EXIT_ARG_ERROR)

    # --- Open the database ----------------------------------------------
    with _install_log_capture() as log_handler:
        try:
            with _open_database(args, log_handler) as db:
                # Database metadata (best effort).
                try:
                    module_name = getattr(db, "filename", None) or str(args.binary)
                    min_ea = getattr(db, "min_ea", None)
                    max_ea = getattr(db, "max_ea", None)
                    arch_name = getattr(getattr(db, "processor", None), "name", None)
                    bitness = getattr(db, "bitness", None)
                    db_payload = {
                        "module": module_name,
                        "path": str(args.binary),
                        "minimum_ea": _format_ea(int(min_ea)) if min_ea else None,
                        "maximum_ea": _format_ea(int(max_ea)) if max_ea else None,
                        "architecture": arch_name,
                        "bitness": bitness,
                    }
                except Exception as exc:
                    logger.debug("database metadata extraction failed: %s", exc)

                # Configure Hex-Rays defaults.
                if args.hexrays_config_defaults:
                    try:
                        _configure_hexrays_defaults()
                    except Exception as exc:
                        logger.warning("hexrays defaults configuration failed: %s", exc)

                # Initialize decompiler plugin.
                if not _init_hexrays():
                    return fail(EXIT_HEXRAYS_UNAVAILABLE)

                # D810 lifecycle.
                with _d810_state_lifecycle(gui=False) as d810_state:
                    # Resolve targets.
                    resolved, unresolved = _resolve_targets(
                        raw_targets=args.functions,
                        all_functions=args.all_functions,
                        functions_file_entries=functions_file_entries,
                    )

                    function_results: list[FunctionResult] = []

                    for tgt in unresolved:
                        function_results.append(
                            FunctionResult(
                                target=tgt.raw,
                                ea=None,
                                name=None,
                                success=False,
                                error_type="UnresolvedFunction",
                                error_message="function target could not be resolved",
                                rules_fired_delta=[],
                                decompile_elapsed_s=0.0,
                                pseudocode_lines=None,
                            )
                        )

                    fired_names_before = _stats_snapshot(d810_state)
                    for tgt in resolved:
                        fr = _decompile_target(tgt, args)
                        function_results.append(fr)
                    fired_names_after = _stats_snapshot(d810_state)

                    all_fired = sorted(fired_names_after | fired_names_before)

                    stats_payload: dict[str, typing.Any] = {}
                    try:
                        stats_payload = d810_state.stats.to_dict()
                    except Exception:
                        stats_payload = {}

                    verify_artifacts = _scan_verify_artifacts(capture_dir)
                    log_errors = log_handler.as_dicts()

                    missing_required = sorted(
                        name for name in args.require_rule_fired
                        if name not in all_fired
                    )

                    result = CheckResult(
                        schema_version=SCHEMA_VERSION,
                        success=False,  # determined below
                        exit_code=EXIT_OK,
                        binary=str(args.binary),
                        config=config_payload,
                        database=db_payload,
                        functions=function_results,
                        stats=stats_payload,
                        verify_artifacts=verify_artifacts,
                        log_errors=log_errors,
                        rules_fired=all_fired,
                        missing_required_rules=missing_required,
                    )
                    result.exit_code = _exit_code_from_result(
                        result,
                        fail_on_log_error=args.fail_on_log_error,
                        fail_on_verify_artifact=args.fail_on_verify_artifact,
                    )
                    result.success = result.exit_code == EXIT_OK
                    return result

        except RuntimeError as exc:
            logger.error("database / ida_domain failure: %s", exc)
            return fail(EXIT_IDA_INIT_ERROR)
        except (RuntimeError, D810Exception) as exc:
            logger.error("runtime failure during check: %s", exc)
            return fail(EXIT_IDA_INIT_ERROR)
        except ImportError as exc:
            logger.error("required IDA module missing: %s", exc)
            return fail(EXIT_IDA_INIT_ERROR)
        except Exception as exc:
            logger.error("unexpected failure during check: %s", exc)
            logger.debug("traceback: %s", traceback.format_exc())
            return fail(EXIT_UNHANDLED_EXCEPTION)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def _write_result(result: CheckResult, json_out: Path | None) -> None:
    payload = {
        "schema_version": result.schema_version,
        "success": result.success,
        "exit_code": result.exit_code,
        "binary": result.binary,
        "config": result.config,
        "database": result.database,
        "functions": [_result_to_dict(fr) for fr in result.functions],
        "stats": result.stats,
        "verify_artifacts": result.verify_artifacts,
        "log_errors": result.log_errors,
        "rules_fired": result.rules_fired,
        "missing_required_rules": result.missing_required_rules,
    }
    encoded = json.dumps(payload, indent=2, sort_keys=True, default=str)
    if json_out is not None:
        json_out.parent.mkdir(parents=True, exist_ok=True)
        json_out.write_text(encoded, encoding="utf-8")
        logger.info("wrote JSON report to %s", json_out)
    else:
        sys.stdout.write(encoded + "\n")
        sys.stdout.flush()


def main(argv: list[str] | None = None) -> int:
    """CLI entry point. Returns a process exit code."""
    args = parse_args(argv)

    args.artifacts_dir.mkdir(parents=True, exist_ok=True)

    try:
        result = run_check(args)
    except SystemExit:
        raise
    except Exception as exc:
        logger.error("unhandled exception in run_check: %s", exc)
        logger.debug("traceback: %s", traceback.format_exc())
        # Emit a fallback report so callers always get structured output.
        fallback = CheckResult(
            schema_version=SCHEMA_VERSION,
            success=False,
            exit_code=EXIT_UNHANDLED_EXCEPTION,
            binary=str(args.binary),
            config={
                "name": args.config,
                "path": str(args.config_path) if args.config_path else None,
                "error": f"run_check raised: {exc}",
            },
            database={},
            functions=[],
            stats={},
            verify_artifacts=[],
            log_errors=[],
            rules_fired=[],
            missing_required_rules=[],
        )
        _write_result(fallback, args.json_out)
        return EXIT_UNHANDLED_EXCEPTION

    _write_result(result, args.json_out)
    return result.exit_code


if __name__ == "__main__":  # pragma: no cover - script entry
    raise SystemExit(main())
