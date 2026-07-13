"""Optional runtime test for ``d810-ida-domain-run``.

This test invokes the launcher as a function against the same sample binary
``tests/system/runtime/test_ida_domain_check.py`` uses to smoke
``d810-ida-domain-check``. It skips unless:

* the sample binary is present, and
* ``import ida_domain`` succeeds in the current interpreter.

Both conditions are required because the launcher uses the *current*
interpreter (``sys.executable``) as the child IDA-capable interpreter for the
runtime test. The marker configuration (``runtime`` + ``hexrays``) is applied
automatically by ``tests/system/runtime/conftest.py``.
"""

from __future__ import annotations

import importlib.util
import json
import pathlib
import platform
import sys

import pytest

from d810.testing import ida_domain_launcher as launcher


REPO_ROOT = pathlib.Path(__file__).resolve().parents[3]


def _default_binary() -> pathlib.Path:
    name = (
        "libobfuscated.dylib"
        if platform.system() == "Darwin"
        else "libobfuscated.dll"
    )
    return REPO_ROOT / "samples" / "bins" / name


def _ida_domain_importable() -> bool:
    return importlib.util.find_spec("ida_domain") is not None


def _ida_hexrays_importable() -> bool:
    return importlib.util.find_spec("ida_hexrays") is not None


def test_launcher_smoke_success_on_libobfuscated(tmp_path: pathlib.Path):
    """Run the launcher against the current interpreter and verify JSON output."""
    binary = _default_binary()
    if not binary.exists():
        pytest.skip(f"sample binary not present: {binary}")
    domain_ok = _ida_domain_importable()
    hexrays_ok = _ida_hexrays_importable()
    if not (domain_ok and hexrays_ok):
        pytest.skip(
            "ida_domain or ida_hexrays not importable in this interpreter "
            f"(domain={domain_ok}, hexrays={hexrays_ok})"
        )

    # The launcher spawns the child as a *separate* process. Some test
    # harnesses load IDA modules in the parent process via an ``idapro`` shim
    # that does not propagate to subprocesses. Probe the child interpreter for
    # actual ``ida_hexrays`` importability so we skip when the launcher cannot
    # in principle succeed against ``sys.executable``.
    import subprocess
    probe = subprocess.run(
        [sys.executable, "-c", "import ida_hexrays"],
        capture_output=True,
        text=True,
        check=False,
    )
    if probe.returncode != 0:
        pytest.skip(
            "child interpreter cannot import ida_hexrays standalone; "
            "likely an idapro-shim-only environment: "
            f"{probe.stderr.strip() or probe.stdout.strip()}"
        )

    artifacts_dir = tmp_path / "d810-launcher"
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    json_out = tmp_path / "launcher-report.json"

    exit_code = launcher.main([
        "--ida-python", sys.executable,
        "--json-out", str(json_out),
        "--binary", str(binary),
        "--config", "default_instruction_only.json",
        "--function", "test_xor",
        "--artifacts-dir", str(artifacts_dir),
    ])

    assert exit_code == 0, json.dumps({
        "exit_code": exit_code,
        "json_out_exists": json_out.exists(),
    }, indent=2, default=str)

    assert json_out.exists()
    payload = json.loads(json_out.read_text(encoding="utf-8"))
    assert payload["success"] is True
    assert payload["exit_code"] == 0
    assert payload["binary"].endswith(binary.name)
    assert payload["config"]["name"] == "default_instruction_only.json"
    assert payload["functions"], "expected at least one function result"
    fr0 = payload["functions"][0]
    assert fr0["target"] == "test_xor"
    assert fr0["success"] is True, fr0.get("error_message")
