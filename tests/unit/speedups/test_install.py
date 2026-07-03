"""Unit tests for ``d810.speedups.install``.

The installer shells out to ``pip``.  We mock ``subprocess.run`` so the
tests do not actually invoke pip and assert that:

* The correct pip argv is constructed (with the safety flags).
* Failures propagate with a clear error message instead of being
  silently swallowed.
"""

from __future__ import annotations

from unittest import mock

import pytest


class TestInstallSpeedups:
    def test_pip_argv_includes_safety_flags(self, monkeypatch, tmp_path):
        monkeypatch.setenv("D810_SPEEDUPS_DIR", str(tmp_path))
        captured = {}

        def _fake_run(cmd, **kwargs):
            captured["cmd"] = cmd
            captured["kwargs"] = kwargs
            class _R:
                returncode = 0
                stdout = ""
                stderr = ""
            return _R()

        monkeypatch.setattr("subprocess.run", _fake_run)
        from d810.speedups.install import install_speedups

        install_speedups()
        cmd = captured["cmd"]
        assert "--no-input" in cmd
        assert "--disable-pip-version-check" in cmd
        assert "--no-cache-dir" in cmd
        assert "--target" in cmd
        # z3-solver is the default package set.
        assert any("z3-solver" in arg for arg in cmd)

    def test_failure_raises_with_message(self, monkeypatch, tmp_path, caplog):
        monkeypatch.setenv("D810_SPEEDUPS_DIR", str(tmp_path))
        import subprocess

        def _fake_run(cmd, **kwargs):
            raise subprocess.CalledProcessError(
                returncode=1,
                cmd=cmd,
                output="boom stdout",
                stderr="boom stderr",
            )

        monkeypatch.setattr("subprocess.run", _fake_run)
        from d810.speedups.install import install_speedups

        with caplog.at_level("ERROR"):
            with pytest.raises(subprocess.CalledProcessError):
                install_speedups()

        assert any(
            "pip install failed" in rec.message for rec in caplog.records
        )

    def test_custom_packages_are_honored(self, monkeypatch, tmp_path):
        monkeypatch.setenv("D810_SPEEDUPS_DIR", str(tmp_path))
        captured = {}

        def _fake_run(cmd, **kwargs):
            captured["cmd"] = cmd
            class _R:
                returncode = 0
                stdout = ""
                stderr = ""
            return _R()

        monkeypatch.setattr("subprocess.run", _fake_run)
        from d810.speedups.install import install_speedups

        install_speedups(["requests==2.31.0", "rich"])
        assert "requests==2.31.0" in captured["cmd"]
        assert "rich" in captured["cmd"]
        # The default package should NOT have been appended.
        assert not any(
            "z3-solver" in arg for arg in captured["cmd"]
        )

    def test_target_dir_is_created(self, monkeypatch, tmp_path):
        target = tmp_path / "new-speedups"
        monkeypatch.setenv("D810_SPEEDUPS_DIR", str(target))
        monkeypatch.setattr(
            "subprocess.run",
            lambda cmd, **kw: type("R", (), {"returncode": 0, "stdout": "", "stderr": ""})(),
        )
        from d810.speedups.install import install_speedups

        install_speedups()
        assert target.exists()