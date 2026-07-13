"""Unit tests for ``d810.testing.ida_domain_launcher``.

These tests do not require IDA Pro / Hex-Rays to run. They monkeypatch
``subprocess.run`` so the launcher's subprocess layer can be exercised
deterministically without IDA.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _import_module():
    """Lazy import of the module under test."""
    from d810.testing import ida_domain_launcher as mod
    return mod


# ---------------------------------------------------------------------------
# Module import safety
# ---------------------------------------------------------------------------


class TestModuleImportSafety:
    def test_importing_launcher_does_not_import_ida_modules(self):
        # Pre-clean any IDA-only modules so we can detect any import added
        # by the launcher in the future.
        for name in list(sys.modules):
            if name in (
                "ida_domain", "idaapi", "idc", "idautils", "ida_hexrays",
            ) or name.startswith("ida_domain.") or name.startswith("idaapi.") \
                    or name.startswith("ida_hexrays."):
                del sys.modules[name]
        from d810.testing import ida_domain_launcher as mod  # noqa: F401
        forbidden = {
            "ida_domain", "idaapi", "idc", "idautils", "ida_hexrays",
        }
        leaked = [name for name in sys.modules if name in forbidden]
        assert not leaked, f"launcher imported IDA modules: {leaked}"

    def test_module_export_keys(self):
        mod = _import_module()
        for name in (
            "LauncherArgs",
            "main",
            "parse_launcher_args",
            "resolve_child_python",
            "resolve_timeout",
            "find_worker_json_out",
            "prepare_worker_json_out",
            "build_child_env",
            "build_worker_command",
            "run_worker",
            "load_worker_json",
            "write_json_payload",
            "synthetic_failure",
            "build_argparser",
        ):
            assert hasattr(mod, name), f"missing export: {name}"


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------


class TestParseLauncherArgs:
    def test_forwards_worker_args_unchanged(self):
        mod = _import_module()
        launcher_args, worker_args = mod.parse_launcher_args([
            "--binary", "/tmp/x.dll",
            "--config", "default_instruction_only.json",
            "--function", "test_xor",
            "--artifacts-dir", "/tmp/art",
        ])
        assert launcher_args.ida_python is None
        assert launcher_args.timeout_s is None
        assert launcher_args.pythonpath == []
        assert launcher_args.child_env == []
        assert launcher_args.keep_temp is False
        assert launcher_args.print_child_stderr is False
        assert worker_args == [
            "--binary", "/tmp/x.dll",
            "--config", "default_instruction_only.json",
            "--function", "test_xor",
            "--artifacts-dir", "/tmp/art",
        ]

    def test_parses_launcher_only_options(self):
        mod = _import_module()
        launcher_args, worker_args = mod.parse_launcher_args([
            "--ida-python", "/opt/ida/python",
            "--timeout-s", "12.5",
            "--pythonpath", "/extra/path",
            "--pythonpath", "/another/path",
            "--child-env", "FOO=bar",
            "--child-env", "BAZ=qux",
            "--keep-temp",
            "--print-child-stderr",
            "--", "--binary", "/x",
        ])
        assert launcher_args.ida_python == "/opt/ida/python"
        assert launcher_args.timeout_s == 12.5
        assert launcher_args.pythonpath == ["/extra/path", "/another/path"]
        assert launcher_args.child_env == ["FOO=bar", "BAZ=qux"]
        assert launcher_args.keep_temp is True
        assert launcher_args.print_child_stderr is True
        assert worker_args == ["--", "--binary", "/x"]


# ---------------------------------------------------------------------------
# Interpreter resolution
# ---------------------------------------------------------------------------


class TestResolveChildPython:
    def test_ida_python_flag_overrides_env(self, monkeypatch, tmp_path: Path):
        mod = _import_module()
        flag_value = str(tmp_path / "flag-python")
        env_value = str(tmp_path / "env-python")
        monkeypatch.setenv("D810_IDA_DOMAIN_PYTHON", env_value)
        args = mod.LauncherArgs(
            ida_python=flag_value, timeout_s=None, pythonpath=[],
            child_env=[], keep_temp=False, print_child_stderr=False,
        )
        assert mod.resolve_child_python(args) == flag_value

    def test_env_var_used_when_no_flag(self, monkeypatch, tmp_path: Path):
        mod = _import_module()
        env_value = str(tmp_path / "env-python")
        monkeypatch.setenv("D810_IDA_DOMAIN_PYTHON", env_value)
        args = mod.LauncherArgs(
            ida_python=None, timeout_s=None, pythonpath=[],
            child_env=[], keep_temp=False, print_child_stderr=False,
        )
        assert mod.resolve_child_python(args) == env_value

    def test_falls_back_to_sys_executable(self, monkeypatch):
        mod = _import_module()
        monkeypatch.delenv("D810_IDA_DOMAIN_PYTHON", raising=False)
        args = mod.LauncherArgs(
            ida_python=None, timeout_s=None, pythonpath=[],
            child_env=[], keep_temp=False, print_child_stderr=False,
        )
        assert mod.resolve_child_python(args) == sys.executable


# ---------------------------------------------------------------------------
# Timeout resolution
# ---------------------------------------------------------------------------


class TestResolveTimeout:
    def test_flag_overrides_env(self, monkeypatch):
        mod = _import_module()
        monkeypatch.setenv("D810_IDA_DOMAIN_TIMEOUT_S", "99")
        args = mod.LauncherArgs(
            ida_python=None, timeout_s=12.5, pythonpath=[],
            child_env=[], keep_temp=False, print_child_stderr=False,
        )
        assert mod.resolve_timeout(args) == 12.5

    def test_env_used_when_no_flag(self, monkeypatch):
        mod = _import_module()
        monkeypatch.setenv("D810_IDA_DOMAIN_TIMEOUT_S", "42")
        args = mod.LauncherArgs(
            ida_python=None, timeout_s=None, pythonpath=[],
            child_env=[], keep_temp=False, print_child_stderr=False,
        )
        assert mod.resolve_timeout(args) == 42.0

    def test_default_is_no_timeout(self, monkeypatch):
        mod = _import_module()
        monkeypatch.delenv("D810_IDA_DOMAIN_TIMEOUT_S", raising=False)
        args = mod.LauncherArgs(
            ida_python=None, timeout_s=None, pythonpath=[],
            child_env=[], keep_temp=False, print_child_stderr=False,
        )
        assert mod.resolve_timeout(args) is None

    def test_invalid_timeout_string_fails_cleanly(self, monkeypatch):
        mod = _import_module()
        monkeypatch.setenv("D810_IDA_DOMAIN_TIMEOUT_S", "not-a-number")
        args = mod.LauncherArgs(
            ida_python=None, timeout_s=None, pythonpath=[],
            child_env=[], keep_temp=False, print_child_stderr=False,
        )
        with pytest.raises(ValueError):
            mod.resolve_timeout(args)


# ---------------------------------------------------------------------------
# JSON-output path handling
# ---------------------------------------------------------------------------


class TestPrepareWorkerJsonOut:
    def test_appends_temp_when_caller_omits(self):
        mod = _import_module()
        args, path, owns = mod.prepare_worker_json_out([
            "--binary", "/x.dll",
            "--function", "fn",
        ])
        assert owns is True
        assert path.exists()
        try:
            assert "--json-out" in args
            assert args[args.index("--json-out") + 1] == str(path)
            assert args[:3] == ["--binary", "/x.dll", "--function"]
        finally:
            path.unlink(missing_ok=True)

    def test_preserves_existing_json_out_space(self, tmp_path: Path):
        mod = _import_module()
        caller_path = tmp_path / "report.json"
        args, path, owns = mod.prepare_worker_json_out([
            "--binary", "/x.dll",
            "--json-out", str(caller_path),
            "--function", "fn",
        ])
        assert owns is False
        assert path == caller_path
        assert args.count("--json-out") == 1
        assert args[args.index("--json-out") + 1] == str(caller_path)

    def test_preserves_existing_json_out_equals(self, tmp_path: Path):
        mod = _import_module()
        caller_path = tmp_path / "report.json"
        flag = f"--json-out={caller_path}"
        args, path, owns = mod.prepare_worker_json_out([
            "--binary", "/x.dll",
            flag,
            "--function", "fn",
        ])
        assert owns is False
        assert path == caller_path
        assert args.count("--json-out") == 0
        assert flag in args


class TestFindWorkerJsonOut:
    @pytest.mark.parametrize(
        "args,expected",
        [
            (["--binary", "/x"], None),
            (["--json-out", "/tmp/r.json", "--function", "fn"], "/tmp/r.json"),
            (["--json-out=/tmp/r.json", "--function", "fn"], "/tmp/r.json"),
        ],
    )
    def test_recognises_known_forms(self, args, expected):
        mod = _import_module()
        assert mod.find_worker_json_out(args) == expected


# ---------------------------------------------------------------------------
# Environment construction
# ---------------------------------------------------------------------------


class TestBuildChildEnv:
    def test_pythonpath_prepends_source_and_repeated_options(
        self, monkeypatch, tmp_path: Path
    ):
        mod = _import_module()
        monkeypatch.setenv("PYTHONPATH", "/existing/path")
        args = mod.LauncherArgs(
            ida_python=None, timeout_s=None,
            pythonpath=[str(tmp_path / "p1"), str(tmp_path / "p2")],
            child_env=[],
            keep_temp=False, print_child_stderr=False,
        )
        env = mod.build_child_env(args)
        assert env["PYTHONUNBUFFERED"] == "1"
        py_path = env["PYTHONPATH"].split(os_sep())

        # Source checkout path should be the first entry when present.
        src_candidates = mod._source_src_dirs()
        if src_candidates:
            assert py_path[0] == str(src_candidates[0])
            assert str(tmp_path / "p1") in py_path
            assert str(tmp_path / "p2") in py_path
        # Existing PYTHONPATH is preserved (last).
        assert py_path[-1] == "/existing/path"

    def test_child_env_overrides_environment(self, monkeypatch):
        mod = _import_module()
        monkeypatch.setenv("FOO", "before")
        args = mod.LauncherArgs(
            ida_python=None, timeout_s=None, pythonpath=[],
            child_env=["FOO=after", "NEW=1"],
            keep_temp=False, print_child_stderr=False,
        )
        env = mod.build_child_env(args)
        assert env["FOO"] == "after"
        assert env["NEW"] == "1"

    def test_invalid_child_env_raises(self):
        mod = _import_module()
        args = mod.LauncherArgs(
            ida_python=None, timeout_s=None, pythonpath=[],
            child_env=["NOVALUE"],
            keep_temp=False, print_child_stderr=False,
        )
        with pytest.raises(ValueError):
            mod.build_child_env(args)

    def test_child_env_rejects_blank_key(self):
        mod = _import_module()
        args = mod.LauncherArgs(
            ida_python=None, timeout_s=None, pythonpath=[],
            child_env=["=value"],
            keep_temp=False, print_child_stderr=False,
        )
        with pytest.raises(ValueError):
            mod.build_child_env(args)


def os_sep():
    """Compatibility helper to avoid hard-coding the path separator."""
    import os as _os
    return _os.pathsep


# ---------------------------------------------------------------------------
# Command construction
# ---------------------------------------------------------------------------


class TestBuildWorkerCommand:
    def test_command_structure(self, tmp_path: Path):
        mod = _import_module()
        cmd = mod.build_worker_command(
            str(tmp_path / "python"),
            ["--binary", "/x.dll", "--json-out", "/tmp/r.json"],
        )
        assert cmd[0] == str(tmp_path / "python")
        assert cmd[1:3] == ["-m", "d810.testing.ida_domain_check"]
        assert cmd[3:] == ["--binary", "/x.dll", "--json-out", "/tmp/r.json"]


# ---------------------------------------------------------------------------
# JSON I/O
# ---------------------------------------------------------------------------


class TestWorkerJsonIO:
    def test_load_worker_json_round_trip(self, tmp_path: Path):
        mod = _import_module()
        report = tmp_path / "report.json"
        report.write_text(json.dumps({"schema_version": 1, "success": True}),
                          encoding="utf-8")
        payload = mod.load_worker_json(report)
        assert payload["schema_version"] == 1
        assert payload["success"] is True

    def test_load_worker_json_invalid_raises(self, tmp_path: Path):
        mod = _import_module()
        report = tmp_path / "report.json"
        report.write_text("not-json", encoding="utf-8")
        with pytest.raises(ValueError):
            mod.load_worker_json(report)

    def test_load_worker_json_rejects_non_object(self, tmp_path: Path):
        mod = _import_module()
        report = tmp_path / "report.json"
        report.write_text(json.dumps([1, 2, 3]), encoding="utf-8")
        with pytest.raises(ValueError):
            mod.load_worker_json(report)


class TestWriteJsonPayload:
    def test_writes_to_path_and_stdout(self, tmp_path: Path, capsys):
        mod = _import_module()
        out = tmp_path / "out.json"
        payload = {"alpha": 1, "beta": [1, 2]}
        mod.write_json_payload(payload, out, print_to_stdout=True)
        captured = capsys.readouterr()
        parsed_from_stdout = json.loads(captured.out)
        parsed_from_file = json.loads(out.read_text(encoding="utf-8"))
        assert parsed_from_stdout == payload
        assert parsed_from_file == payload

    def test_only_writes_file_when_stdout_disabled(
        self, tmp_path: Path, capsys
    ):
        mod = _import_module()
        out = tmp_path / "out.json"
        mod.write_json_payload({"x": 1}, out, print_to_stdout=False)
        captured = capsys.readouterr()
        assert captured.out == ""
        assert json.loads(out.read_text(encoding="utf-8")) == {"x": 1}


# ---------------------------------------------------------------------------
# Synthetic failure
# ---------------------------------------------------------------------------


class TestSyntheticFailure:
    def test_shape_matches_check_result(self):
        mod = _import_module()
        worker_args = [
            "--binary", "/tmp/x.dll",
            "--config", "c.json",
            "--config-path", "/cfg/c.json",
            "--function", "fn",
        ]
        payload = mod.synthetic_failure(
            mod.EXIT_LAUNCHER_UNEXPECTED, "boom", worker_args,
            stderr="traceback line\n",
        )
        for key in (
            "schema_version", "success", "exit_code", "binary", "config",
            "database", "functions", "stats", "verify_artifacts",
            "log_errors", "rules_fired", "missing_required_rules",
        ):
            assert key in payload, key
        assert payload["schema_version"] == 1
        assert payload["success"] is False
        assert payload["exit_code"] == mod.EXIT_LAUNCHER_UNEXPECTED
        assert payload["binary"] == "/tmp/x.dll"
        assert payload["config"]["name"] == "c.json"
        assert payload["config"]["path"] == "/cfg/c.json"
        assert "launcher failure: boom" in payload["config"]["error"]
        assert payload["functions"] == []
        assert payload["log_errors"][0]["stderr_tail"] == "traceback line\n"

    def test_missing_flags_default_to_none(self):
        mod = _import_module()
        payload = mod.synthetic_failure(
            mod.EXIT_LAUNCHER_LAUNCH_ERROR, "nope", []
        )
        assert payload["binary"] == ""
        assert payload["config"]["name"] is None
        assert payload["config"]["path"] is None
        assert "stderr_tail" not in payload["log_errors"][0]


# ---------------------------------------------------------------------------
# Subprocess layer (end-to-end via monkeypatched ``subprocess.run``)
# ---------------------------------------------------------------------------


def _make_completed(returncode: int = 0, stdout: str = "", stderr: str = ""):
    """Construct a minimal :class:`CompletedProcess`-like object."""
    return subprocess.CompletedProcess(
        args=[], returncode=returncode, stdout=stdout, stderr=stderr
    )


class TestMainSubprocess:
    def _stub_run(
        self, monkeypatch, completed_or_exc, command_holder=None
    ):
        """Replace ``subprocess.run`` with a stub returning or raising."""
        def stub_run(argv, *args, **kwargs):
            if command_holder is not None:
                command_holder.append(list(argv))
            if isinstance(completed_or_exc, BaseException):
                raise completed_or_exc
            return completed_or_exc
        monkeypatch.setattr(subprocess, "run", stub_run)

    def test_valid_child_json_returns_child_exit_code(
        self, monkeypatch, tmp_path: Path
    ):
        mod = _import_module()
        captured = {}
        completed = _make_completed(returncode=7, stdout="ignored", stderr="")

        def stub_run(argv, *args, **kwargs):
            captured["command"] = list(argv)
            captured["env"] = dict(kwargs.get("env", {}))
            captured["timeout"] = kwargs.get("timeout")
            # Write a valid worker JSON file to the temp path the launcher
            # allocated; ``load_worker_json`` will read it back.
            worker_args = list(argv)[3:]
            json_index = worker_args.index("--json-out")
            json_path = Path(worker_args[json_index + 1])
            json_path.write_text(
                json.dumps({
                    "schema_version": 1,
                    "success": True,
                    "exit_code": 0,
                    "binary": "fake.dll",
                    "config": {"name": "c.json"},
                    "database": {},
                    "functions": [{
                        "target": "test_xor", "name": "test_xor",
                        "ea": "0x401000", "success": True,
                        "error_type": None, "error_message": None,
                        "rules_fired_delta": [], "elapsed_s": 0.123,
                        "pseudocode_lines": None,
                    }],
                    "stats": {}, "verify_artifacts": [],
                    "log_errors": [], "rules_fired": [],
                    "missing_required_rules": [],
                }),
                encoding="utf-8",
            )
            return completed

        monkeypatch.setattr(subprocess, "run", stub_run)
        exit_code = mod.main([
            "--ida-python", str(tmp_path / "child-python"),
            "--binary", str(tmp_path / "fake.dll"),
            "--config", "c.json",
            "--function", "test_xor",
        ])
        assert exit_code == 7

    def test_missing_json_produces_synthetic_failure(
        self, monkeypatch, tmp_path: Path, capsys
    ):
        mod = _import_module()
        completed = _make_completed(returncode=0, stderr="child stderr noise")
        command_holder: list[list[str]] = []

        def stub_run(argv, *args, **kwargs):
            command_holder.append(list(argv))
            # Simulate worker producing no JSON.
            return completed

        monkeypatch.setattr(subprocess, "run", stub_run)
        exit_code = mod.main([
            "--binary", str(tmp_path / "fake.dll"),
            "--config", "c.json",
            "--function", "test_xor",
        ])
        assert exit_code == mod.EXIT_LAUNCHER_UNEXPECTED
        worker_args = command_holder[0][3:]
        json_index = worker_args.index("--json-out")
        json_path = Path(worker_args[json_index + 1])
        # When synthetic failure is printed to stdout the temp file is
        # removed before we can re-read it; capture stdout instead.
        captured = capsys.readouterr()
        payload = json.loads(captured.out)
        assert payload["success"] is False
        assert payload["exit_code"] == mod.EXIT_LAUNCHER_UNEXPECTED
        assert payload["binary"] == str(tmp_path / "fake.dll")
        assert payload["config"]["error"].startswith("launcher failure: ")
        # Temp file should be cleaned up by default.
        assert not json_path.exists()

    def test_invalid_json_produces_synthetic_failure(
        self, monkeypatch, tmp_path: Path
    ):
        mod = _import_module()
        completed = _make_completed(returncode=0, stderr="junk")
        command_holder: list[list[str]] = []

        def stub_run(argv, *args, **kwargs):
            command_holder.append(list(argv))
            # Write invalid JSON to the temp file before returning.
            worker_args = list(argv)[3:]
            json_index = worker_args.index("--json-out")
            json_path = Path(worker_args[json_index + 1])
            json_path.write_text("{not json", encoding="utf-8")
            return completed

        monkeypatch.setattr(subprocess, "run", stub_run)
        exit_code = mod.main([
            "--keep-temp",
            "--binary", str(tmp_path / "fake.dll"),
            "--config", "c.json",
            "--function", "test_xor",
        ])
        assert exit_code == mod.EXIT_LAUNCHER_UNEXPECTED
        worker_args = command_holder[0][3:]
        json_index = worker_args.index("--json-out")
        json_path = Path(worker_args[json_index + 1])
        try:
            # ``--keep-temp`` keeps the file; it should now hold the
            # synthetic failure payload.
            payload = json.loads(json_path.read_text(encoding="utf-8"))
        finally:
            if json_path.exists():
                json_path.unlink()
        assert payload["success"] is False
        assert "invalid JSON" in payload["log_errors"][0]["message"]

    def test_timeout_produces_synthetic_failure(
        self, monkeypatch, tmp_path: Path
    ):
        mod = _import_module()
        sentinel_child = str(tmp_path / "child-python")

        def stub_run(argv, *args, **kwargs):
            raise subprocess.TimeoutExpired(
                cmd=list(argv), timeout=0.01,
                output="stdout text",
                stderr="stderr text",
            )

        monkeypatch.setattr(subprocess, "run", stub_run)
        exit_code = mod.main([
            "--ida-python", sentinel_child,
            "--timeout-s", "0.01",
            "--binary", str(tmp_path / "fake.dll"),
            "--config", "c.json",
            "--function", "test_xor",
        ])
        assert exit_code == mod.EXIT_LAUNCHER_UNEXPECTED

    def test_subprocess_launch_failure_produces_synthetic_failure(
        self, monkeypatch, tmp_path: Path, capsys
    ):
        mod = _import_module()
        missing = str(tmp_path / "missing-python.exe")
        monkeypatch.setattr(
            subprocess, "run",
            lambda *a, **kw: (_ for _ in ()).throw(FileNotFoundError(2, "not found", missing)),
        )
        exit_code = mod.main([
            "--ida-python", missing,
            "--binary", str(tmp_path / "fake.dll"),
            "--config", "c.json",
            "--function", "test_xor",
        ])
        assert exit_code == mod.EXIT_LAUNCHER_LAUNCH_ERROR
        captured = capsys.readouterr()
        payload = json.loads(captured.out)
        assert payload["success"] is False
        assert payload["exit_code"] == mod.EXIT_LAUNCHER_LAUNCH_ERROR
        assert missing in payload["config"]["error"]

    def test_invalid_child_env_fails_cleanly(
        self, monkeypatch, tmp_path: Path, capsys
    ):
        mod = _import_module()
        # Avoid actually spawning the child.
        monkeypatch.setattr(
            subprocess, "run", lambda *a, **kw: pytest.fail("subprocess should not run")
        )
        exit_code = mod.main([
            "--ida-python", str(tmp_path / "child"),
            "--child-env", "BADVALUE",
            "--binary", str(tmp_path / "fake.dll"),
            "--config", "c.json",
            "--function", "test_xor",
        ])
        assert exit_code == mod.EXIT_LAUNCHER_UNEXPECTED
        captured = capsys.readouterr()
        payload = json.loads(captured.out)
        assert payload["success"] is False
        assert "KEY=VALUE" in payload["config"]["error"]

    def test_invalid_timeout_flag_fails_cleanly(self, monkeypatch, tmp_path: Path):
        mod = _import_module()
        # ``type=float`` makes argparse reject invalid floats with SystemExit
        # before main()'s body runs; we verify this by ensuring argparse
        # is the only failure surface.
        with pytest.raises(SystemExit):
            mod.main([
                "--timeout-s", "not-a-float",
                "--binary", str(tmp_path / "fake.dll"),
                "--config", "c.json",
                "--function", "test_xor",
            ])

    def test_existing_caller_json_out_writes_to_callers_path(
        self, monkeypatch, tmp_path: Path
    ):
        mod = _import_module()
        caller_path = tmp_path / "caller.json"

        def stub_run(argv, *args, **kwargs):
            worker_args = list(argv)[3:]
            json_index = worker_args.index("--json-out")
            assert Path(worker_args[json_index + 1]) == caller_path
            caller_path.write_text(
                json.dumps({
                    "schema_version": 1, "success": True, "exit_code": 0,
                    "binary": "/x", "config": {}, "database": {},
                    "functions": [], "stats": {}, "verify_artifacts": [],
                    "log_errors": [], "rules_fired": [], "missing_required_rules": [],
                }),
                encoding="utf-8",
            )
            return _make_completed(returncode=0, stdout="", stderr="")

        monkeypatch.setattr(subprocess, "run", stub_run)
        exit_code = mod.main([
            "--json-out", str(caller_path),
            "--binary", str(tmp_path / "fake.dll"),
            "--config", "c.json",
            "--function", "test_xor",
        ])
        assert exit_code == 0
        # Caller-supplied file is preserved.
        assert caller_path.exists()
        payload = json.loads(caller_path.read_text(encoding="utf-8"))
        assert payload["schema_version"] == 1

    def test_print_child_stderr_writes_to_parent_stderr(
        self, monkeypatch, tmp_path: Path, capsys
    ):
        mod = _import_module()
        captured_path = tmp_path / "out.json"
        captured_path.write_text(
            json.dumps({
                "schema_version": 1, "success": True, "exit_code": 0,
                "binary": "/x", "config": {}, "database": {},
                "functions": [], "stats": {}, "verify_artifacts": [],
                "log_errors": [], "rules_fired": [], "missing_required_rules": [],
            }),
            encoding="utf-8",
        )

        monkeypatch.setattr(
            subprocess, "run",
            lambda *a, **kw: _make_completed(returncode=0, stderr="child stderr line"),
        )
        exit_code = mod.main([
            "--json-out", str(captured_path),
            "--print-child-stderr",
            "--binary", str(tmp_path / "fake.dll"),
            "--config", "c.json",
            "--function", "test_xor",
        ])
        assert exit_code == 0
        captured = capsys.readouterr()
        assert "child stderr line" in captured.err
