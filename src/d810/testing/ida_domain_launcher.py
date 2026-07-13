"""One-shot subprocess launcher for ``d810.testing.ida_domain_check``.

This module provides a separate CLI entry point (``d810-ida-domain-run``) that
runs the existing IDA-bound worker :mod:`d810.testing.ida_domain_check` in an
IDA-capable Python interpreter without requiring the user to open the IDA GUI.

Design notes:

* The launcher parent process never imports ``idaapi``, ``idc``, ``idautils``,
  ``ida_hexrays``, or ``ida_domain``. Only standard-library modules are used.
* The child interpreter is resolved from ``--ida-python``, then
  ``$D810_IDA_DOMAIN_PYTHON``, then :data:`sys.executable`.
* The child is invoked as ``<interpreter> -m d810.testing.ida_domain_check``
  with the unchanged forwarded arguments. The launcher does not parse the
  worker CLI itself.
* JSON output is forwarded through a JSON file. When the caller does not
  supply ``--json-out``, the launcher allocates a temporary path, appends it
  to the worker args, prints the parsed JSON to stdout once, and deletes the
  temp file unless ``--keep-temp`` is set.
* When the worker fails to produce JSON, the launcher emits a synthetic
  failure report shaped like :class:`d810.testing.ida_domain_check.CheckResult`
  so callers always get machine-readable output.
"""

from __future__ import annotations

import argparse
import contextlib
import dataclasses
import json
import logging
import os
import shlex
import subprocess
import sys
import tempfile
import traceback
from pathlib import Path
from typing import Sequence


logger = logging.getLogger("D810.ida_domain_launcher")


# ---------------------------------------------------------------------------
# Exit codes
# ---------------------------------------------------------------------------


EXIT_OK = 0
# Worker exit codes mirror those of ``d810.testing.ida_domain_check``: 1, 2, 3,
# 4, 5. The launcher reuses those codes through the worker; the launcher-only
# codes below are reserved for failures that happen *before* valid worker JSON
# is produced.
EXIT_LAUNCHER_LAUNCH_ERROR = 3
EXIT_LAUNCHER_UNEXPECTED = 5


WORKER_MODULE = "d810.testing.ida_domain_check"


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclasses.dataclass(slots=True)
class LauncherArgs:
    """Parsed launcher-specific options."""

    ida_python: str | None
    timeout_s: float | None
    pythonpath: list[str]
    child_env: list[str]
    keep_temp: bool
    print_child_stderr: bool


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------


def build_argparser() -> argparse.ArgumentParser:
    """Return the launcher-only :class:`argparse.ArgumentParser`."""
    parser = argparse.ArgumentParser(
        prog="d810-ida-domain-run",
        description=(
            "Run d810.testing.ida_domain_check inside an IDA-capable Python "
            "interpreter as a one-shot subprocess. The parent process stays "
            "IDA-free; all unrecognised arguments are forwarded to the "
            "worker unchanged."
        ),
        add_help=True,
    )
    parser.add_argument(
        "--ida-python",
        dest="ida_python",
        default=None,
        help=(
            "Path to an IDA-capable Python interpreter. Falls back to "
            "$D810_IDA_DOMAIN_PYTHON, then sys.executable."
        ),
    )
    parser.add_argument(
        "--timeout-s",
        dest="timeout_s",
        type=float,
        default=None,
        help=(
            "Subprocess timeout in seconds. Falls back to "
            "$D810_IDA_DOMAIN_TIMEOUT_S; if unset, no timeout is applied."
        ),
    )
    parser.add_argument(
        "--pythonpath",
        dest="pythonpath",
        action="append",
        default=[],
        help=(
            "Additional PYTHONPATH entry prepended for the child. Repeatable. "
            "Useful when launching from a source checkout."
        ),
    )
    parser.add_argument(
        "--child-env",
        dest="child_env",
        action="append",
        default=[],
        help=(
            "Explicit KEY=VALUE override applied to the child environment. "
            "Repeatable; later values override earlier ones."
        ),
    )
    parser.add_argument(
        "--keep-temp",
        dest="keep_temp",
        action="store_true",
        default=False,
        help=(
            "Keep launcher-created temporary JSON files for debugging. "
            "Caller-supplied --json-out files are never deleted."
        ),
    )
    parser.add_argument(
        "--print-child-stderr",
        dest="print_child_stderr",
        action="store_true",
        default=False,
        help="Echo the child process stderr to the parent stderr on completion.",
    )
    return parser


def parse_launcher_args(argv: Sequence[str] | None) -> tuple[LauncherArgs, list[str]]:
    """Parse launcher-only args and return forwarded worker args unchanged.

    Returns:
        A ``(launcher_args, worker_args)`` tuple. ``worker_args`` contains the
        unrecognised positional and optional arguments in their original order.
    """
    parser = build_argparser()
    namespace, worker_args = parser.parse_known_args(list(argv) if argv is not None else None)
    return LauncherArgs(
        ida_python=namespace.ida_python,
        timeout_s=namespace.timeout_s,
        pythonpath=list(namespace.pythonpath),
        child_env=list(namespace.child_env),
        keep_temp=bool(namespace.keep_temp),
        print_child_stderr=bool(namespace.print_child_stderr),
    ), worker_args


# ---------------------------------------------------------------------------
# Interpreter / timeout resolution
# ---------------------------------------------------------------------------


def resolve_child_python(args: LauncherArgs) -> str:
    """Return the interpreter path used to launch the worker subprocess."""
    if args.ida_python:
        return args.ida_python
    env_value = os.environ.get("D810_IDA_DOMAIN_PYTHON")
    if env_value:
        return env_value
    return sys.executable


def resolve_timeout(args: LauncherArgs) -> float | None:
    """Return the subprocess timeout in seconds, or ``None`` for no timeout."""
    if args.timeout_s is not None:
        return float(args.timeout_s)
    env_value = os.environ.get("D810_IDA_DOMAIN_TIMEOUT_S")
    if env_value:
        return float(env_value)
    return None


# ---------------------------------------------------------------------------
# Forwarded-arg inspection
# ---------------------------------------------------------------------------


def _extract_value_after(args: list[str], index: int) -> str | None:
    """Return the next token after ``args[index]`` or ``None`` if absent."""
    if index + 1 >= len(args):
        return None
    value = args[index + 1]
    if value.startswith("-"):
        return None
    return value


def find_worker_json_out(worker_args: Sequence[str]) -> str | None:
    """Return the value of ``--json-out`` in ``worker_args``, or ``None``.

    Honours both ``--json-out PATH`` and ``--json-out=PATH`` forms. Returns
    ``None`` when not supplied. The returned string is the raw token from the
    forwarded args.
    """
    items = list(worker_args)
    for index, token in enumerate(items):
        if token == "--json-out":
            value = _extract_value_after(items, index)
            if value is not None:
                return value
        elif token.startswith("--json-out="):
            return token.split("=", 1)[1] or None
    return None


# ---------------------------------------------------------------------------
# JSON output path management
# ---------------------------------------------------------------------------


def prepare_worker_json_out(
    worker_args: Sequence[str],
) -> tuple[list[str], Path, bool]:
    """Ensure the forwarded worker args contain exactly one ``--json-out`` path.

    Returns:
        A ``(new_worker_args, json_out_path, owns_temp_file)`` tuple. When the
        caller already supplied ``--json-out`` the launcher does not own the
        file and never deletes it.
    """
    args = list(worker_args)
    existing = find_worker_json_out(args)
    if existing is not None:
        return args, Path(existing), False

    fd, temp_name = tempfile.mkstemp(prefix="d810_ida_domain_", suffix=".json")
    os.close(fd)
    temp_path = Path(temp_name)
    args = [*args, "--json-out", str(temp_path)]
    return args, temp_path, True


# ---------------------------------------------------------------------------
# Environment construction
# ---------------------------------------------------------------------------


def _source_src_dirs() -> list[Path]:
    """Return candidate source-checkout ``src`` directories to prepend."""
    here = Path(__file__).resolve()
    seen: set[Path] = set()
    candidates: list[Path] = []
    # Walker upward from the launcher file looking for a directory whose
    # ``d810`` subdirectory is a real package (i.e. has ``__init__.py``). This
    # handles both the standard ``src/d810/testing/...`` layout and editable
    # installs whose top-level package lives one level up.
    for parent in here.parents:
        src_candidate = parent / "src"
        if src_candidate in seen:
            continue
        seen.add(src_candidate)
        d810_candidate = src_candidate / "d810"
        init_candidate = d810_candidate / "__init__.py"
        if d810_candidate.is_dir() and init_candidate.exists():
            candidates.append(src_candidate)
    return candidates


def build_child_env(args: LauncherArgs) -> dict[str, str]:
    """Construct the child process environment dictionary."""
    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"

    existing_pythonpath = env.get("PYTHONPATH")
    new_entries: list[str] = []
    for src_dir in _source_src_dirs():
        new_entries.append(str(src_dir))
    for entry in args.pythonpath:
        if entry:
            new_entries.append(entry)
    if existing_pythonpath:
        new_entries.append(existing_pythonpath)

    if new_entries:
        env["PYTHONPATH"] = os.pathsep.join(new_entries)

    for raw in args.child_env:
        if "=" not in raw:
            raise ValueError(
                f"--child-env value must be KEY=VALUE; got {raw!r}"
            )
        key, _, value = raw.partition("=")
        key = key.strip()
        if not key:
            raise ValueError(
                f"--child-env value must include a non-empty key; got {raw!r}"
            )
        env[key] = value

    return env


# ---------------------------------------------------------------------------
# Command construction
# ---------------------------------------------------------------------------


def build_worker_command(child_python: str, worker_args: Sequence[str]) -> list[str]:
    """Return the child argv list for ``subprocess.run``."""
    return [child_python, "-m", WORKER_MODULE, *worker_args]


# ---------------------------------------------------------------------------
# Child execution
# ---------------------------------------------------------------------------


def run_worker(
    command: Sequence[str],
    env: dict[str, str],
    timeout_s: float | None,
) -> subprocess.CompletedProcess[str]:
    """Run ``command`` with captured stdout/stderr and optional timeout."""
    return subprocess.run(
        list(command),
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout_s,
        check=False,
    )


# ---------------------------------------------------------------------------
# JSON I/O
# ---------------------------------------------------------------------------


def load_worker_json(path: Path) -> dict[str, object]:
    """Read ``path`` and return a parsed JSON object.

    Raises:
        FileNotFoundError: when ``path`` does not exist.
        ValueError: when the file is not valid JSON or not a JSON object.
    """
    raw = path.read_text(encoding="utf-8")
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid JSON in {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError(
            f"expected JSON object at {path}; got {type(payload).__name__}"
        )
    return payload


def write_json_payload(
    payload: dict[str, object],
    json_out: Path | None,
    print_to_stdout: bool,
) -> None:
    """Persist ``payload`` to ``json_out`` and/or stdout exactly once."""
    encoded = json.dumps(payload, indent=2, sort_keys=True, default=str)
    if json_out is not None:
        json_out.parent.mkdir(parents=True, exist_ok=True)
        json_out.write_text(encoded, encoding="utf-8")
    if print_to_stdout:
        sys.stdout.write(encoded + "\n")
        sys.stdout.flush()


# ---------------------------------------------------------------------------
# Synthetic failure helpers
# ---------------------------------------------------------------------------


def _extract_flag_value(args: Sequence[str], flag: str) -> str | None:
    """Return the best-effort value of ``flag`` (with or without ``=``) in args."""
    items = list(args)
    for index, token in enumerate(items):
        if token == flag:
            value = _extract_value_after(items, index)
            if value is not None:
                return value
        elif token.startswith(flag + "="):
            return token.split("=", 1)[1] or None
    return None


def synthetic_failure(
    exit_code: int,
    message: str,
    worker_args: Sequence[str],
    stderr: str | None = None,
) -> dict[str, object]:
    """Return a minimal :class:`CheckResult`-shaped failure payload."""
    binary_value = _extract_flag_value(worker_args, "--binary") or ""
    config_value = _extract_flag_value(worker_args, "--config")
    config_path_value = _extract_flag_value(worker_args, "--config-path")
    config_payload: dict[str, object] = {
        "name": config_value,
        "path": config_path_value,
        "error": f"launcher failure: {message}",
    }
    log_error: dict[str, object] = {
        "logger": "D810.ida_domain_launcher",
        "level": "ERROR",
        "message": message,
    }
    if stderr:
        truncated = stderr[-2000:] if len(stderr) > 2000 else stderr
        log_error["stderr_tail"] = truncated
    return {
        "schema_version": 1,
        "success": False,
        "exit_code": int(exit_code),
        "binary": binary_value,
        "config": config_payload,
        "database": {},
        "functions": [],
        "stats": {},
        "verify_artifacts": [],
        "log_errors": [log_error],
        "rules_fired": [],
        "missing_required_rules": [],
    }


# ---------------------------------------------------------------------------
# Timeout / subprocess helpers
# ---------------------------------------------------------------------------


def _decode_timeout_stderr(exc: subprocess.TimeoutExpired) -> str:
    """Best-effort decode of stderr attached to a :class:`TimeoutExpired`."""
    stderr = getattr(exc, "stderr", None)
    if isinstance(stderr, str):
        return stderr
    if isinstance(stderr, (bytes, bytearray)):
        try:
            return stderr.decode("utf-8", errors="replace")
        except Exception:
            return ""
    return ""


# ---------------------------------------------------------------------------
# Top-level entry point
# ---------------------------------------------------------------------------


def _delete_temp(path: Path) -> None:
    """Best-effort unlink for launcher-owned temp files."""
    with contextlib.suppress(Exception):
        path.unlink()


def main(argv: Sequence[str] | None = None) -> int:
    """Run the launcher and return a process exit code."""
    try:
        launcher_args, worker_args = parse_launcher_args(argv)
    except SystemExit:
        raise
    except Exception as exc:  # pragma: no cover - argparse handler
        logger.error("failed to parse launcher args: %s", exc)
        return EXIT_LAUNCHER_UNEXPECTED

    worker_args, json_out, owns_temp = prepare_worker_json_out(worker_args)
    child_python = resolve_child_python(launcher_args)
    timeout_s = resolve_timeout(launcher_args)

    def emit_and_return(
        payload: dict[str, object],
        return_code: int,
        child_stderr: str | None = None,
    ) -> int:
        try:
            write_json_payload(payload, json_out, print_to_stdout=owns_temp)
        except Exception as exc:
            logger.error("failed to write JSON payload: %s", exc)
            return EXIT_LAUNCHER_UNEXPECTED
        if (
            child_stderr
            and launcher_args.print_child_stderr
        ):
            sys.stderr.write(child_stderr)
            sys.stderr.flush()
        if owns_temp and not launcher_args.keep_temp:
            _delete_temp(json_out)
        return return_code

    try:
        env = build_child_env(launcher_args)
    except ValueError as exc:
        logger.error("invalid --child-env: %s", exc)
        payload = synthetic_failure(EXIT_LAUNCHER_UNEXPECTED, str(exc), worker_args)
        return emit_and_return(payload, EXIT_LAUNCHER_UNEXPECTED)

    command = build_worker_command(child_python, worker_args)

    try:
        completed = run_worker(command, env, timeout_s)
    except subprocess.TimeoutExpired as exc:
        stderr_text = _decode_timeout_stderr(exc)
        message = (
            f"subprocess timed out after {timeout_s}s; "
            f"command={shlex.join(command)}"
        )
        logger.error(message)
        payload = synthetic_failure(
            EXIT_LAUNCHER_UNEXPECTED, message, worker_args, stderr=stderr_text
        )
        return emit_and_return(payload, EXIT_LAUNCHER_UNEXPECTED)
    except (OSError, FileNotFoundError) as exc:
        message = (
            f"failed to launch child interpreter {child_python}: {exc}"
        )
        logger.error(message)
        payload = synthetic_failure(
            EXIT_LAUNCHER_LAUNCH_ERROR, message, worker_args
        )
        return emit_and_return(payload, EXIT_LAUNCHER_LAUNCH_ERROR)
    except Exception as exc:
        logger.error("unexpected launcher exception: %s", exc)
        logger.debug("traceback: %s", traceback.format_exc())
        message = f"unexpected launcher exception: {exc}"
        payload = synthetic_failure(
            EXIT_LAUNCHER_UNEXPECTED, message, worker_args
        )
        return emit_and_return(payload, EXIT_LAUNCHER_UNEXPECTED)

    try:
        payload = load_worker_json(json_out)
    except FileNotFoundError:
        message = (
            f"worker did not write JSON to {json_out} "
            f"(exit={completed.returncode})"
        )
        payload = synthetic_failure(
            EXIT_LAUNCHER_UNEXPECTED, message, worker_args,
            stderr=completed.stderr or "",
        )
        return emit_and_return(
            payload, EXIT_LAUNCHER_UNEXPECTED, completed.stderr
        )
    except ValueError as exc:
        message = str(exc)
        payload = synthetic_failure(
            EXIT_LAUNCHER_UNEXPECTED, message, worker_args,
            stderr=completed.stderr or "",
        )
        return emit_and_return(
            payload, EXIT_LAUNCHER_UNEXPECTED, completed.stderr
        )

    return emit_and_return(
        payload, int(completed.returncode), completed.stderr
    )


if __name__ == "__main__":  # pragma: no cover - script entry
    raise SystemExit(main())
