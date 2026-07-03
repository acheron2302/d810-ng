"""Unit tests for ``d810.speedups.bootstrap``.

The bootstrap is invoked at ``d810`` import time and mutates process-global
state (``sys.path`` and ``builtins.Z3_LIB_DIRS``).  These tests pin the
post-hardening contract:

* ``get_speedups_dir()`` always returns a resolved, absolute path.
* ``ensure_speedups_on_path()`` is idempotent (no duplicate sys.path).
* Dangerous ``D810_SPEEDUPS_DIR`` values are rejected with a warning.
* ``builtins.Z3_LIB_DIRS`` is only set when the operator has not already
  configured it.
"""

from __future__ import annotations

import builtins
import sys
from pathlib import Path

import pytest


@pytest.fixture
def reset_sys_path(monkeypatch):
    """Snapshot/restore sys.path and builtins.Z3_LIB_DIRS around each test."""
    # Start clean: drop any pre-existing Z3_LIB_DIRS so the tests do not
    # inherit a value set by ``d810.__init__`` at import time.
    if hasattr(builtins, "Z3_LIB_DIRS"):
        monkeypatch.delattr(builtins, "Z3_LIB_DIRS", raising=False)

    saved_path = list(sys.path)
    saved_z3 = getattr(builtins, "Z3_LIB_DIRS", None)
    yield
    sys.path[:] = saved_path
    if saved_z3 is not None:
        builtins.Z3_LIB_DIRS = saved_z3
    elif hasattr(builtins, "Z3_LIB_DIRS"):
        delattr(builtins, "Z3_LIB_DIRS")


class TestGetSpeedupsDir:
    def test_default_dir_is_resolved(self):
        """The default ``DEFAULT_SPEEDUPS_DIR`` is always absolute."""
        from d810.speedups.bootstrap import DEFAULT_SPEEDUPS_DIR

        # expanduser + resolve yields an absolute path on every platform.
        resolved = DEFAULT_SPEEDUPS_DIR.expanduser().resolve()
        assert resolved.is_absolute()
        assert resolved.name == ".d810-speedups"

    def test_env_override_wins(self, monkeypatch, tmp_path):
        target = tmp_path / "my-speedups"
        target.mkdir()
        monkeypatch.setenv("D810_SPEEDUPS_DIR", str(target))
        from d810.speedups.bootstrap import get_speedups_dir

        assert get_speedups_dir() == target.resolve()

    def test_env_override_is_resolved(self, monkeypatch, tmp_path):
        target = tmp_path / "my-speedups"
        target.mkdir()
        monkeypatch.setenv("D810_SPEEDUPS_DIR", str(target))
        from d810.speedups.bootstrap import get_speedups_dir

        # Symlink-free resolution should match the canonical absolute path.
        assert get_speedups_dir() == target.resolve()


class TestEnsureSpeedupsOnPath:
    def test_nonexistent_dir_returns_false(self, monkeypatch, tmp_path):
        monkeypatch.setenv("D810_SPEEDUPS_DIR", str(tmp_path / "missing"))
        from d810.speedups.bootstrap import ensure_speedups_on_path

        assert ensure_speedups_on_path() is False

    def test_idempotent(self, reset_sys_path, monkeypatch, tmp_path):
        monkeypatch.setenv("D810_SPEEDUPS_DIR", str(tmp_path))
        from d810.speedups.bootstrap import ensure_speedups_on_path

        first = ensure_speedups_on_path()
        second = ensure_speedups_on_path()
        assert first is True
        assert second is True
        # sys.path must contain tmp_path only once.
        assert sys.path.count(str(tmp_path.resolve())) == 1

    def test_rejects_dangerous_path(self, reset_sys_path, caplog):
        # Pointing at /etc should be refused with a warning.
        from d810.speedups.bootstrap import ensure_speedups_on_path

        # Pretend /etc is a directory.
        # We can't actually point D810_SPEEDUPS_DIR at /etc on Windows
        # but the dangerous-prefix list also includes ~/.ssh so we
        # construct a path under the user's home.
        target = Path.home() / ".ssh"
        # We don't actually need it to exist; the dangerous-path check
        # runs before the is_dir() check only for some prefixes.  We
        # exercise the production code path by patching is_dir().
        import d810.speedups.bootstrap as bootstrap_mod

        original_isdir = bootstrap_mod.Path.is_dir

        def _fake_isdir(self):
            if str(self).startswith(str(target)):
                return True
            return original_isdir(self)

        bootstrap_mod.Path.is_dir = _fake_isdir
        try:
            monkeypatch_env = {"D810_SPEEDUPS_DIR": str(target)}
            import os

            saved = os.environ.get("D810_SPEEDUPS_DIR")
            os.environ["D810_SPEEDUPS_DIR"] = str(target)
            try:
                with caplog.at_level("WARNING"):
                    result = ensure_speedups_on_path()
            finally:
                if saved is None:
                    os.environ.pop("D810_SPEEDUPS_DIR", None)
                else:
                    os.environ["D810_SPEEDUPS_DIR"] = saved
        finally:
            bootstrap_mod.Path.is_dir = original_isdir

        assert result is False
        assert any(
            "Refusing to prepend" in rec.message for rec in caplog.records
        )


class TestZ3LibDirs:
    def test_does_not_overwrite_explicit_z3_lib_dirs(
        self, reset_sys_path, monkeypatch, tmp_path
    ):
        monkeypatch.setenv("D810_SPEEDUPS_DIR", str(tmp_path))
        # Pre-configure builtins.Z3_LIB_DIRS as if another module had
        # already set it.
        builtins.Z3_LIB_DIRS = ["/some/explicit/path"]

        from d810.speedups.bootstrap import ensure_speedups_on_path

        ensure_speedups_on_path()
        # The explicit value must survive untouched.
        assert builtins.Z3_LIB_DIRS == ["/some/explicit/path"]

    def test_sets_z3_lib_dirs_when_present(
        self, reset_sys_path, monkeypatch, tmp_path
    ):
        z3_dir = tmp_path / "z3" / "lib"
        z3_dir.mkdir(parents=True)
        # Ensure neither HOME nor D810_SPEEDUPS_DIR point at the default
        # before we set our own override.
        monkeypatch.delenv("D810_SPEEDUPS_DIR", raising=False)
        monkeypatch.setenv("D810_SPEEDUPS_DIR", str(tmp_path))

        from d810.speedups.bootstrap import (
            DEFAULT_SPEEDUPS_DIR,
            get_speedups_dir,
        )

        # Sanity: the override must actually win at call time.
        assert get_speedups_dir() == tmp_path.resolve()

        # Compute the expected path the same way the bootstrap does.
        expected_z3 = (tmp_path / "z3" / "lib").resolve()

        from d810.speedups.bootstrap import ensure_speedups_on_path

        ensure_speedups_on_path()
        # builtins.Z3_LIB_DIRS should match the resolved z3/lib path.
        assert str(expected_z3) in builtins.Z3_LIB_DIRS[0]