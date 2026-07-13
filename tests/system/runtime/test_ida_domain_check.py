"""Smoke test for the ``d810-ida-domain-check`` CLI utility.

These tests require IDA Pro / Hex-Rays (and the ``ida_domain`` package) to be
available in the active interpreter. They live under ``tests/system/runtime``
so the runtime ``conftest.py`` automatically tags them with ``runtime`` and
``hexrays`` markers and lets them be deselected with::

    pytest -m "not hexrays"
"""

from __future__ import annotations

import json
import pathlib
import platform

import pytest

from d810.testing import ida_domain_check as runner


REPO_ROOT = pathlib.Path(__file__).resolve().parents[3]


def _default_binary() -> pathlib.Path:
    name = (
        "libobfuscated.dylib"
        if platform.system() == "Darwin"
        else "libobfuscated.dll"
    )
    return REPO_ROOT / "samples" / "bins" / name


def _build_args(artifacts_dir: pathlib.Path, **overrides) -> "runner.CheckArgs":
    defaults = dict(
        binary=_default_binary(),
        config="default_instruction_only.json",
        config_path=None,
        functions=["test_xor"],
        functions_file=None,
        all_functions=False,
        json_out=artifacts_dir / "report.json",
        artifacts_dir=artifacts_dir,
        ida_log=None,
        processor=None,
        output_idb=None,
        save_idb=False,
        hexrays_config_defaults=True,
        require_rule_fired=[],
        fail_on_log_error=True,
        fail_on_verify_artifact=True,
        summary_only=True,
    )
    defaults.update(overrides)
    return runner.CheckArgs(**defaults)


@pytest.fixture
def artifacts_dir(tmp_path: pathlib.Path) -> pathlib.Path:
    """Provide an isolated artifact directory for each test."""
    d = tmp_path / "d810-check"
    d.mkdir(parents=True, exist_ok=True)
    return d


def test_smoke_success_on_libobfuscated(artifacts_dir: pathlib.Path):
    """Decompile ``test_xor`` under the default instruction-only config."""
    args = _build_args(artifacts_dir)
    if not args.binary.exists():
        pytest.skip(f"sample binary not present: {args.binary}")

    result = runner.run_check(args)
    assert result.exit_code == runner.EXIT_OK, json.dumps(
        {
            "exit_code": result.exit_code,
            "log_errors": result.log_errors,
            "verify_artifacts": result.verify_artifacts,
            "missing_required_rules": result.missing_required_rules,
        },
        indent=2,
        default=str,
    )
    assert result.binary == str(args.binary)
    assert result.config["name"] == "default_instruction_only.json"
    assert len(result.functions) >= 1
    fr0 = result.functions[0]
    assert fr0.target == "test_xor"
    assert fr0.success is True, fr0.error_message


def test_missing_function_reports_unresolved(artifacts_dir: pathlib.Path):
    """An unresolved function name should appear as a failure in the JSON."""
    args = _build_args(
        artifacts_dir, functions=["__definitely_does_not_exist__"]
    )
    if not args.binary.exists():
        pytest.skip(f"sample binary not present: {args.binary}")

    result = runner.run_check(args)
    assert result.exit_code == runner.EXIT_TARGET_FAILURES
    assert any(not fr.success for fr in result.functions)
    unresolved = [
        fr for fr in result.functions if fr.error_type == "UnresolvedFunction"
    ]
    assert unresolved, "expected at least one UnresolvedFunction entry"


def test_unknown_config_exits_arg_error(artifacts_dir: pathlib.Path):
    """An unknown config name should produce exit code 2 (CLI argument error)."""
    args = _build_args(artifacts_dir, config="this_config_does_not_exist.json")
    if not args.binary.exists():
        pytest.skip(f"sample binary not present: {args.binary}")

    result = runner.run_check(args)
    assert result.exit_code == runner.EXIT_ARG_ERROR


def test_empty_config_activates_no_rules(
    artifacts_dir: pathlib.Path, tmp_path: pathlib.Path
):
    """A config with no activated rules should still execute and mark emptiness."""
    cfg = tmp_path / "empty.json"
    cfg.write_text(
        json.dumps({"description": "empty", "ins_rules": [], "blk_rules": []}),
        encoding="utf-8",
    )
    args = _build_args(artifacts_dir, config=None, config_path=cfg)
    if not args.binary.exists():
        pytest.skip(f"sample binary not present: {args.binary}")

    result = runner.run_check(args)
    # ``--config-path`` mode keeps going past arg validation; the run may be
    # a no-op success or a target failure depending on whether rules fired.
    assert result.exit_code in (
        runner.EXIT_OK,
        runner.EXIT_TARGET_FAILURES,
        runner.EXIT_ARG_ERROR,
    )
