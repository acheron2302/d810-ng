"""Unit tests for ``d810.testing.ida_domain_check``.

These tests do not require IDA Pro or Hex-Rays to run: they exercise the
parts of the CLI utility that are importable from a stock Python interpreter
(dataclasses, argument parsing, list-file parsing, JSON serialisation,
exit-code mapping) and verify structural properties of the module
(lazy ``ida_domain`` import).
"""

from __future__ import annotations

import dataclasses
import json
import sys
from pathlib import Path

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _import_module():
    """Lazy import of the module under test."""
    from d810.testing import ida_domain_check as mod
    return mod


def _build_args(**overrides):
    """Construct a :class:`CheckArgs` with sane defaults for tests."""
    defaults = dict(
        binary=Path("/tmp/fake-binary.dll"),
        config="default_instruction_only.json",
        config_path=None,
        functions=["test_xor"],
        functions_file=None,
        all_functions=False,
        json_out=None,
        artifacts_dir=Path("/tmp/artifacts"),
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
    return _import_module().CheckArgs(**defaults)


def _build_function_result(**overrides):
    defaults = dict(
        target="test_xor",
        ea="0x401000",
        name="test_xor",
        success=True,
        error_type=None,
        error_message=None,
        rules_fired_delta=[],
        decompile_elapsed_s=0.123,
        pseudocode_lines=12,
    )
    defaults.update(overrides)
    return _import_module().FunctionResult(**defaults)


def _build_check_result(**overrides):
    defaults = dict(
        schema_version=1,
        success=True,
        exit_code=0,
        binary="/tmp/fake-binary.dll",
        config={"name": "default_instruction_only.json", "path": "/x.json"},
        database={},
        functions=[],
        stats={},
        verify_artifacts=[],
        log_errors=[],
        rules_fired=[],
        missing_required_rules=[],
    )
    defaults.update(overrides)
    return _import_module().CheckResult(**defaults)


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------


class TestArgumentParsing:
    def test_requires_config_or_config_path(self):
        mod = _import_module()
        with pytest.raises(SystemExit):
            mod.parse_args(["--binary", "/tmp/x", "--function", "fn"])

    def test_config_and_config_path_are_mutually_exclusive(self):
        mod = _import_module()
        with pytest.raises(SystemExit):
            mod.parse_args([
                "--binary", "/tmp/x",
                "--config", "c.json",
                "--config-path", "/tmp/c.json",
                "--function", "fn",
            ])

    def test_requires_a_function_target(self):
        mod = _import_module()
        with pytest.raises(SystemExit):
            mod.parse_args([
                "--binary", "/tmp/x",
                "--config", "c.json",
            ])

    def test_accepts_function_only(self):
        mod = _import_module()
        args = mod.parse_args([
            "--binary", "/tmp/x",
            "--config", "c.json",
            "--function", "test_xor",
        ])
        assert args.config == "c.json"
        assert args.functions == ["test_xor"]
        assert args.artifacts_dir == Path.cwd() / "d810_ida_domain_artifacts"
        assert args.save_idb is False
        assert args.hexrays_config_defaults is True
        assert args.fail_on_log_error is True
        assert args.fail_on_verify_artifact is True

    def test_rejects_invalid_rule_fired_identifier(self):
        mod = _import_module()
        with pytest.raises(SystemExit):
            mod.parse_args([
                "--binary", "/tmp/x",
                "--config", "c.json",
                "--function", "fn",
                "--require-rule-fired", "bad rule!",
            ])

    def test_accepts_all_functions_flag(self):
        mod = _import_module()
        args = mod.parse_args([
            "--binary", "/tmp/x",
            "--config", "c.json",
            "--all-functions",
        ])
        assert args.all_functions is True

    def test_custom_artifacts_dir(self):
        mod = _import_module()
        args = mod.parse_args([
            "--binary", "/tmp/x",
            "--config", "c.json",
            "--function", "fn",
            "--artifacts-dir", "/tmp/art",
        ])
        assert args.artifacts_dir == Path("/tmp/art")

    def test_save_idb_toggle(self):
        mod = _import_module()
        args = mod.parse_args([
            "--binary", "/tmp/x",
            "--config", "c.json",
            "--function", "fn",
            "--save-idb",
        ])
        assert args.save_idb is True

        args = mod.parse_args([
            "--binary", "/tmp/x",
            "--config", "c.json",
            "--function", "fn",
            "--no-save-idb",
        ])
        assert args.save_idb is False

    def test_negation_flags(self):
        mod = _import_module()
        args = mod.parse_args([
            "--binary", "/tmp/x",
            "--config", "c.json",
            "--function", "fn",
            "--no-fail-on-log-error",
            "--no-fail-on-verify-artifact",
            "--no-hexrays-config-defaults",
        ])
        assert args.fail_on_log_error is False
        assert args.fail_on_verify_artifact is False
        assert args.hexrays_config_defaults is False


# ---------------------------------------------------------------------------
# Functions file parsing
# ---------------------------------------------------------------------------


class TestFunctionsFileParsing:
    def test_parses_names_and_eas(self, tmp_path: Path):
        mod = _import_module()
        path = tmp_path / "functions.txt"
        path.write_text(
            "test_xor\n"
            "0x401000\n"
            "  _test_or  \n"
            "# comment\n"
            "\n"
            "test_and\n",
            encoding="utf-8",
        )
        out = mod.parse_functions_file(path)
        assert out == ["test_xor", "0x401000", "_test_or", "test_and"]

    def test_ignores_blanks_and_comments(self, tmp_path: Path):
        mod = _import_module()
        path = tmp_path / "functions.txt"
        path.write_text(
            "\n# this file is empty\n\n\n   \n# trailing\n",
            encoding="utf-8",
        )
        assert mod.parse_functions_file(path) == []


# ---------------------------------------------------------------------------
# EA parsing / formatting
# ---------------------------------------------------------------------------


class TestEaHelpers:
    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("0x401000", 0x401000),
            ("0X401000", 0x401000),
            ("4198400", 4198400),
            ("0o10", 8),
            ("", None),
            ("not-a-number", None),
        ],
    )
    def test_parse_ea(self, raw, expected):
        mod = _import_module()
        assert mod._parse_ea(raw) == expected

    @pytest.mark.parametrize(
        "ea,expected",
        [
            (0x401000, "0x401000"),
            (None, None),
            (0xFFFFFFFFFFFFFFFF, "0xFFFFFFFFFFFFFFFF"),
            (0, "0x0"),
        ],
    )
    def test_format_ea(self, ea, expected):
        mod = _import_module()
        assert mod._format_ea(ea) == expected


# ---------------------------------------------------------------------------
# Result-to-exit-code mapping
# ---------------------------------------------------------------------------


class TestExitCodeMapping:
    def test_all_green_is_zero(self):
        mod = _import_module()
        result = _build_check_result(
            functions=[_build_function_result()],
            verify_artifacts=[],
            log_errors=[],
            missing_required_rules=[],
        )
        result.exit_code = mod._exit_code_from_result(
            result,
            fail_on_log_error=True,
            fail_on_verify_artifact=True,
        )
        assert result.exit_code == 0

    def test_function_failure_is_one(self):
        mod = _import_module()
        bad = _build_function_result(success=False, error_type="DecompileFailed")
        result = _build_check_result(functions=[bad])
        result.exit_code = mod._exit_code_from_result(
            result,
            fail_on_log_error=True,
            fail_on_verify_artifact=True,
        )
        assert result.exit_code == mod.EXIT_TARGET_FAILURES

    def test_verify_artifacts_failure_is_one(self):
        mod = _import_module()
        result = _build_check_result(
            functions=[_build_function_result()],
            verify_artifacts=["/tmp/d810/verify_failures/x.json"],
        )
        result.exit_code = mod._exit_code_from_result(
            result,
            fail_on_log_error=True,
            fail_on_verify_artifact=True,
        )
        assert result.exit_code == mod.EXIT_TARGET_FAILURES

    def test_log_errors_failure_is_one(self):
        mod = _import_module()
        result = _build_check_result(
            functions=[_build_function_result()],
            log_errors=[{"logger": "D810", "level": "ERROR", "message": "boom"}],
        )
        result.exit_code = mod._exit_code_from_result(
            result,
            fail_on_log_error=True,
            fail_on_verify_artifact=True,
        )
        assert result.exit_code == mod.EXIT_TARGET_FAILURES

    def test_missing_required_rule_is_one(self):
        mod = _import_module()
        result = _build_check_result(
            functions=[_build_function_result()],
            missing_required_rules=["XorRule"],
        )
        result.exit_code = mod._exit_code_from_result(
            result,
            fail_on_log_error=True,
            fail_on_verify_artifact=True,
        )
        assert result.exit_code == mod.EXIT_TARGET_FAILURES

    def test_disabling_failure_modes_makes_run_pass(self):
        mod = _import_module()
        # --no-fail-on-log-error and --no-fail-on-verify-artifact disable
        # those failure modes. ``--require-rule-fired`` is always enforced,
        # so we exclude ``missing_required_rules`` here.
        result = _build_check_result(
            functions=[_build_function_result()],
            verify_artifacts=["/tmp/x.json"],
            log_errors=[{"logger": "D810", "level": "ERROR", "message": "x"}],
            missing_required_rules=[],
        )
        result.exit_code = mod._exit_code_from_result(
            result,
            fail_on_log_error=False,
            fail_on_verify_artifact=False,
        )
        assert result.exit_code == 0

    def test_preserves_preset_exit_code(self):
        mod = _import_module()
        result = _build_check_result(
            functions=[_build_function_result()],
            exit_code=mod.EXIT_ARG_ERROR,
        )
        result.exit_code = mod._exit_code_from_result(
            result,
            fail_on_log_error=True,
            fail_on_verify_artifact=True,
        )
        assert result.exit_code == mod.EXIT_ARG_ERROR


# ---------------------------------------------------------------------------
# Unknown-rule validation
# ---------------------------------------------------------------------------


class _FakeRule:
    def __init__(self, name: str) -> None:
        self.name = name


class TestUnknownRuleValidation:
    def test_returns_unknown_names(self, tmp_path: Path):
        mod = _import_module()

        class _State:
            known_ins_rules = [_FakeRule("XorRule")]
            known_blk_rules = [_FakeRule("FlatFold")]

        @dataclasses.dataclass
        class _Cfg:
            is_activated: bool
            name: str

        class _Project:
            ins_rules = [_Cfg(True, "XorRule"), _Cfg(True, "NoSuchRule")]
            blk_rules = [_Cfg(True, "FlatFold"), _Cfg(False, "MissingBlock")]
            path = Path("anything.json")

        unknown = mod._config_unknown_rules(_State(), _Project())
        assert unknown == ["NoSuchRule"]

    def test_ignores_inactive_rules(self, tmp_path: Path):
        mod = _import_module()

        class _State:
            known_ins_rules = []
            known_blk_rules = []

        @dataclasses.dataclass
        class _Cfg:
            is_activated: bool
            name: str

        class _Project:
            ins_rules = [_Cfg(False, "XorRule")]
            blk_rules = []
            path = Path("anything.json")

        unknown = mod._config_unknown_rules(_State(), _Project())
        assert unknown == []


# ---------------------------------------------------------------------------
# JSON serialisation
# ---------------------------------------------------------------------------


class TestJsonSerialization:
    def test_write_result_to_buffer(self, capsys):
        mod = _import_module()
        result = _build_check_result(
            functions=[_build_function_result()],
            rules_fired=["XorRule", "ConstSimplification"],
            log_errors=[{"logger": "D810", "level": "ERROR", "message": "x"}],
        )
        result.success = True
        result.exit_code = 0
        mod._write_result(result, None)
        captured = capsys.readouterr()
        payload = json.loads(captured.out)
        assert payload["schema_version"] == 1
        assert payload["success"] is True
        assert payload["exit_code"] == 0
        assert payload["functions"][0]["target"] == "test_xor"
        assert payload["functions"][0]["ea"] == "0x401000"
        assert sorted(payload["rules_fired"]) == ["ConstSimplification", "XorRule"]

    def test_write_result_to_path(self, tmp_path: Path):
        mod = _import_module()
        out = tmp_path / "report.json"
        result = _build_check_result(functions=[_build_function_result()])
        result.success = True
        result.exit_code = 0
        mod._write_result(result, out)
        assert out.exists()
        payload = json.loads(out.read_text(encoding="utf-8"))
        assert payload["functions"][0]["target"] == "test_xor"


# ---------------------------------------------------------------------------
# Module safety
# ---------------------------------------------------------------------------


class TestModuleImportSafety:
    def test_importing_module_does_not_import_ida_domain(self):
        # Make sure ``ida_domain`` is *not* already loaded before import, so
        # the test can detect any module-level import added in the future.
        for name in list(sys.modules):
            if name == "ida_domain" or name.startswith("ida_domain."):
                del sys.modules[name]
        # The module under test must import cleanly without ``ida_domain``.
        from d810.testing import ida_domain_check as mod  # noqa: F401
        assert "ida_domain" not in sys.modules
        assert callable(mod.main)
        assert callable(mod.run_check)

    def test_module_export_keys(self):
        mod = _import_module()
        for name in (
            "CheckArgs",
            "FunctionTarget",
            "FunctionResult",
            "CheckResult",
            "main",
            "parse_args",
            "run_check",
            "build_argparser",
        ):
            assert hasattr(mod, name), f"missing export: {name}"


# ---------------------------------------------------------------------------
# Main entry point behaviour
# ---------------------------------------------------------------------------


class TestMainEntryPoint:
    def test_main_emits_json_to_stdout(self, capsys, monkeypatch, tmp_path: Path):
        mod = _import_module()
        sentinel = _build_check_result(
            functions=[_build_function_result()],
            exit_code=mod.EXIT_OK,
        )
        sentinel.success = True
        sentinel.exit_code = 0

        # Patch run_check to return our sentinel. Importing here keeps the
        # IDA-free path local.
        monkeypatch.setattr(mod, "run_check", lambda _a: sentinel)

        exit_code = mod.main([
            "--binary", str(tmp_path / "fake-binary.dll"),
            "--config", "default_instruction_only.json",
            "--function", "test_xor",
            "--artifacts-dir", str(tmp_path / "artifacts"),
        ])
        assert exit_code == 0
        captured = capsys.readouterr()
        payload = json.loads(captured.out)
        assert payload["exit_code"] == 0
        assert payload["success"] is True
        assert payload["functions"][0]["target"] == "test_xor"

    def test_main_returns_nonzero_when_run_check_returns_failure(
        self, capsys, monkeypatch, tmp_path: Path
    ):
        mod = _import_module()
        sentinel = _build_check_result(
            functions=[_build_function_result(success=False, error_type="Boom")],
            exit_code=mod.EXIT_TARGET_FAILURES,
        )
        sentinel.success = False
        sentinel.exit_code = mod.EXIT_TARGET_FAILURES

        monkeypatch.setattr(mod, "run_check", lambda _a: sentinel)

        exit_code = mod.main([
            "--binary", str(tmp_path / "fake-binary.dll"),
            "--config", "default_instruction_only.json",
            "--function", "test_xor",
            "--artifacts-dir", str(tmp_path / "artifacts"),
        ])
        assert exit_code == mod.EXIT_TARGET_FAILURES

    def test_main_returns_2_on_missing_target_spec(self, tmp_path: Path):
        mod = _import_module()
        with pytest.raises(SystemExit):
            mod.main([
                "--binary", str(tmp_path / "x.dll"),
                "--config", "c.json",
                # No function/--all-functions/--functions-file.
            ])


# ---------------------------------------------------------------------------
# argparse help
# ---------------------------------------------------------------------------


class TestConsoleScript:
    def test_help_exits_zero(self):
        mod = _import_module()
        parser = mod.build_argparser()
        with pytest.raises(SystemExit) as exc_info:
            parser.parse_args(["--help"])
        assert exc_info.value.code == 0
