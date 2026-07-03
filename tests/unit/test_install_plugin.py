"""Unit tests for the explicit symlink installer and the corrected config
fallback paths in :mod:`d810.core.config` and :mod:`d810.conf`.

The installer is tested end-to-end against a temporary fake source tree and
a temporary plugins directory. Real symlink creation is skipped on platforms
where the user lacks permission to create symlinks (e.g. locked-down Windows
CI runners); the rest of the validation logic remains covered.
"""

from __future__ import annotations

import importlib
import io
import os
import pathlib
import sys
from pathlib import Path
from unittest.mock import patch

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _fake_src_dir(root: Path) -> tuple[Path, Path]:
    """Create a fake ``src/`` directory containing ``d810ng.py`` and ``d810/``.

    Returns ``(src_dir, d810_pkg)``.
    """
    src_dir = root / "src"
    d810_pkg = src_dir / "d810"
    d810_pkg.mkdir(parents=True)
    (src_dir / "d810ng.py").write_text("# fake plugin loader\n")
    (d810_pkg / "__init__.py").write_text("__version__ = '0.0.0'\n")
    (d810_pkg / "placeholder.json").write_text("{}\n")
    return src_dir, d810_pkg


def _can_create_symlink(tmp_path: Path) -> bool:
    """Return True if the current environment permits symlink creation."""
    target = tmp_path / "_symlink_probe_target"
    link = tmp_path / "_symlink_probe"
    try:
        target.write_text("probe")
        if link.exists() or link.is_symlink():
            link.unlink()
        link.symlink_to(target)
    except OSError:
        return False
    finally:
        try:
            if link.is_symlink():
                link.unlink()
            if target.exists():
                target.unlink()
        except OSError:
            pass
    return True


@pytest.fixture
def install_module():
    """Re-import :mod:`d810.install_plugin` to keep tests isolated."""
    return importlib.import_module("d810.install_plugin")


def _set_appdata(monkeypatch: pytest.MonkeyPatch, value: Path | None) -> None:
    """Tiny helper to set/clear APPDATA via monkeypatch."""
    if value is None:
        monkeypatch.delenv("APPDATA", raising=False)
    else:
        monkeypatch.setenv("APPDATA", str(value))


# ---------------------------------------------------------------------------
# Source / plugin-dir resolution
# ---------------------------------------------------------------------------


class TestDefaultPluginsDir:
    def test_windows_uses_appdata(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
        install = importlib.import_module("d810.install_plugin")
        monkeypatch.setattr(install.sys, "platform", "win32")
        _set_appdata(monkeypatch, tmp_path)
        assert install.default_plugins_dir() == tmp_path / "Hex-Rays" / "IDA Pro" / "plugins"

    def test_windows_missing_appdata_raises(self, monkeypatch: pytest.MonkeyPatch):
        install = importlib.import_module("d810.install_plugin")
        monkeypatch.setattr(install.sys, "platform", "win32")
        _set_appdata(monkeypatch, None)
        with pytest.raises(RuntimeError):
            install.default_plugins_dir()

    def test_linux_uses_idapro(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
        install = importlib.import_module("d810.install_plugin")
        monkeypatch.setattr(install.sys, "platform", "linux")
        monkeypatch.setattr(install.Path, "home", lambda: tmp_path)
        assert install.default_plugins_dir() == tmp_path / ".idapro" / "plugins"


class TestResolveSrcDir:
    def test_explicit_src_dir_is_resolved(self, tmp_path: Path):
        install = importlib.import_module("d810.install_plugin")
        explicit = tmp_path / "some" / "src"
        explicit.mkdir(parents=True)
        assert install.resolve_src_dir(explicit) == explicit.resolve()

    def test_derived_from_d810_package(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        install = importlib.import_module("d810.install_plugin")
        # Pretend d810 was loaded from <tmp>/src/d810/__init__.py
        fake_d810_init = tmp_path / "src" / "d810" / "__init__.py"
        fake_d810_init.parent.mkdir(parents=True)
        fake_d810_init.write_text("")
        fake_d810 = type(sys)("d810")
        fake_d810.__file__ = str(fake_d810_init)
        with patch.dict(sys.modules, {"d810": fake_d810}):
            assert install.resolve_src_dir(None) == (tmp_path / "src").resolve()


class TestValidateSrcDir:
    def test_missing_d810ng_py(self, install_module, tmp_path: Path):
        d810_pkg = tmp_path / "d810"
        d810_pkg.mkdir()
        with pytest.raises(FileNotFoundError) as exc:
            install_module.validate_src_dir(tmp_path)
        assert "d810ng.py" in str(exc.value)

    def test_missing_d810_pkg(self, install_module, tmp_path: Path):
        (tmp_path / "d810ng.py").write_text("")
        with pytest.raises(FileNotFoundError) as exc:
            install_module.validate_src_dir(tmp_path)
        assert "d810/" in str(exc.value)

    def test_happy_path_returns_paths(self, install_module, tmp_path: Path):
        src_dir, d810_pkg = _fake_src_dir(tmp_path)
        d810ng_py, d810_pkg_out = install_module.validate_src_dir(src_dir)
        assert d810ng_py == src_dir / "d810ng.py"
        assert d810_pkg_out == d810_pkg


# ---------------------------------------------------------------------------
# Conflict detection / removal
# ---------------------------------------------------------------------------


class TestCheckExistingTargets:
    def test_clean_dir_has_no_blockers(self, install_module, tmp_path: Path):
        assert install_module.check_existing_targets(tmp_path) == []

    def test_refuses_existing_symlink_without_force(self, install_module, tmp_path: Path):
        if not _can_create_symlink(tmp_path):
            pytest.skip("environment does not permit symlink creation")
        target = tmp_path / "real"
        target.write_text("real")
        link = tmp_path / "d810ng.py"
        link.symlink_to(target)
        with pytest.raises(FileExistsError):
            install_module.check_existing_targets(tmp_path)

    def test_refuses_existing_real_directory_without_force(self, install_module, tmp_path: Path):
        (tmp_path / "d810").mkdir()
        with pytest.raises(FileExistsError):
            install_module.check_existing_targets(tmp_path)

    def test_force_returns_blockers_without_raising(self, install_module, tmp_path: Path):
        (tmp_path / "d810ng.py").write_text("x")
        (tmp_path / "d810").mkdir()
        blockers = install_module.check_existing_targets(tmp_path, force=True)
        assert set(blockers) == {tmp_path / "d810ng.py", tmp_path / "d810"}

    def test_broken_symlink_is_detected_as_symlink(self, install_module, tmp_path: Path):
        if not _can_create_symlink(tmp_path):
            pytest.skip("environment does not permit symlink creation")
        target = tmp_path / "missing"
        link = tmp_path / "d810ng.py"
        link.symlink_to(target)
        # _target_kind must classify the broken symlink as "symlink"
        assert install_module._target_kind(link) == "symlink"
        with pytest.raises(FileExistsError):
            install_module.check_existing_targets(tmp_path)


class TestRemoveExistingTarget:
    def test_unlink_symlink(self, install_module, tmp_path: Path):
        if not _can_create_symlink(tmp_path):
            pytest.skip("environment does not permit symlink creation")
        target = tmp_path / "real"
        target.write_text("x")
        link = tmp_path / "d810ng.py"
        link.symlink_to(target)
        install_module.remove_existing_target(link)
        assert not link.is_symlink()
        assert not link.exists()
        # Original target must be untouched.
        assert target.exists()

    def test_unlink_regular_file(self, install_module, tmp_path: Path):
        f = tmp_path / "d810ng.py"
        f.write_text("x")
        install_module.remove_existing_target(f)
        assert not f.exists()

    def test_directory_requires_explicit_flag(self, install_module, tmp_path: Path):
        d = tmp_path / "d810"
        d.mkdir()
        (d / "user.json").write_text("user edited")
        with pytest.raises(IsADirectoryError):
            install_module.remove_existing_target(d)
        # The directory and its contents must be preserved.
        assert (d / "user.json").exists()

    def test_directory_removed_when_flag_set(self, install_module, tmp_path: Path):
        d = tmp_path / "d810"
        d.mkdir()
        (d / "user.json").write_text("user edited")
        install_module.remove_existing_target(d, force_remove_directory=True)
        assert not d.exists()

    def test_missing_is_noop(self, install_module, tmp_path: Path):
        # Should not raise even when the target does not exist.
        install_module.remove_existing_target(tmp_path / "ghost")


# ---------------------------------------------------------------------------
# End-to-end install_plugin
# ---------------------------------------------------------------------------


class TestInstallPlugin:
    def test_install_creates_symlinks(
        self, install_module, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ):
        if not _can_create_symlink(tmp_path):
            pytest.skip("environment does not permit symlink creation")
        src_dir, d810_pkg = _fake_src_dir(tmp_path / "src")
        plugins_dir = tmp_path / "plugins"

        buf = io.StringIO()
        rc = install_module.install_plugin(
            plugins_dir=plugins_dir,
            src_dir=src_dir,
            force=False,
            stdout=buf,
        )
        assert rc == 0

        link_py = plugins_dir / "d810ng.py"
        link_pkg = plugins_dir / "d810"
        assert link_py.is_symlink()
        assert link_pkg.is_symlink()
        assert os.readlink(str(link_py)) == str(src_dir / "d810ng.py")
        assert os.readlink(str(link_pkg)) == str(d810_pkg)
        assert not (plugins_dir / "ida-plugin.json").exists()

    def test_refuses_existing_targets(
        self, install_module, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ):
        src_dir, _ = _fake_src_dir(tmp_path / "src")
        plugins_dir = tmp_path / "plugins"
        plugins_dir.mkdir()
        (plugins_dir / "d810ng.py").write_text("already installed")
        rc = install_module.install_plugin(
            plugins_dir=plugins_dir, src_dir=src_dir, force=False
        )
        assert rc == 2
        # The pre-existing file must remain untouched.
        assert (plugins_dir / "d810ng.py").read_text() == "already installed"

    def test_force_replaces_existing_symlinks(
        self, install_module, tmp_path: Path
    ):
        if not _can_create_symlink(tmp_path):
            pytest.skip("environment does not permit symlink creation")
        # First install into plugins_dir.
        src_dir, d810_pkg = _fake_src_dir(tmp_path / "src")
        plugins_dir = tmp_path / "plugins"
        rc1 = install_module.install_plugin(
            plugins_dir=plugins_dir, src_dir=src_dir
        )
        assert rc1 == 0
        # Create a stale symlink alongside the installer-created one to
        # ensure --force clears it.
        stale = plugins_dir / "d810ng.py"
        assert stale.is_symlink()
        # Second install with --force must succeed and the symlink must
        # still point at our source.
        rc2 = install_module.install_plugin(
            plugins_dir=plugins_dir, src_dir=src_dir, force=True
        )
        assert rc2 == 0
        assert stale.is_symlink()
        assert os.readlink(str(stale)) == str(src_dir / "d810ng.py")

    def test_force_refuses_real_directory(
        self, install_module, tmp_path: Path
    ):
        src_dir, _ = _fake_src_dir(tmp_path / "src")
        plugins_dir = tmp_path / "plugins"
        plugins_dir.mkdir()
        (plugins_dir / "d810").mkdir()
        (plugins_dir / "d810" / "user.json").write_text("user edited")
        rc = install_module.install_plugin(
            plugins_dir=plugins_dir, src_dir=src_dir, force=True
        )
        assert rc == 2
        assert (plugins_dir / "d810" / "user.json").exists()

    def test_missing_source_returns_error_code(
        self, install_module, tmp_path: Path
    ):
        plugins_dir = tmp_path / "plugins"
        rc = install_module.install_plugin(
            plugins_dir=plugins_dir, src_dir=tmp_path / "missing"
        )
        assert rc == 2

    def test_no_ida_plugin_json_created(
        self, install_module, tmp_path: Path
    ):
        if not _can_create_symlink(tmp_path):
            pytest.skip("environment does not permit symlink creation")
        src_dir, _ = _fake_src_dir(tmp_path / "src")
        plugins_dir = tmp_path / "plugins"
        install_module.install_plugin(
            plugins_dir=plugins_dir, src_dir=src_dir
        )
        assert not (plugins_dir / "ida-plugin.json").exists()


# ---------------------------------------------------------------------------
# CLI surface
# ---------------------------------------------------------------------------


class TestArgparser:
    def test_help_exits_cleanly(self, install_module, capsys: pytest.CaptureFixture[str]):
        with pytest.raises(SystemExit) as exc:
            install_module.build_argparser().parse_args(["--help"])
        assert exc.value.code == 0

    def test_parses_plugins_dir_and_src_dir(self, install_module):
        args = install_module.build_argparser().parse_args(
            ["--plugins-dir", "/tmp/p", "--src-dir", "/tmp/s", "--force"]
        )
        assert args.plugins_dir == Path("/tmp/p")
        assert args.src_dir == Path("/tmp/s")
        assert args.force is True
        assert args.force_remove_directory is False


# ---------------------------------------------------------------------------
# Config fallback path regression tests
# ---------------------------------------------------------------------------


class TestResolveConfigPathFallback:
    """Regression tests for the corrected ``_resolve_config_path`` fallbacks."""

    def test_core_config_fallback_points_at_d810_conf(self, tmp_path: Path):
        # Point the active config at a fake IDA user dir with NO user
        # override, so the fallback branch must be exercised.
        from d810.core.config import D810Configuration

        cfg = D810Configuration(ida_user_dir=tmp_path)
        # Sanity: no user override for default.json.
        assert not (cfg.config_dir / "default.json").exists()
        resolved = cfg._resolve_config_path("default.json")
        # The fallback must live in src/d810/conf/, not src/d810/core/conf/.
        resolved_path = Path(resolved).resolve()
        package_root = Path(__file__).resolve().parents[2] / "src" / "d810"
        assert resolved_path.parent == (package_root / "conf").resolve()
        # And the resolved path must actually be the bundled file.
        assert resolved_path.name == "default.json"

    def test_conf_module_fallback_points_at_d810_conf(self, tmp_path: Path):
        # ``d810.conf`` imports ``ida_diskio`` at module load. Inject a tiny
        # stand-in so we can exercise its fallback path without IDA.
        import importlib
        import types

        fake_idadir = tmp_path / "fake_ida_user_dir"
        fake_idadir.mkdir(parents=True, exist_ok=True)
        dummy = types.ModuleType("ida_diskio")
        dummy.get_user_idadir = lambda: str(fake_idadir)
        with patch.dict(sys.modules, {"ida_diskio": dummy}):
            # Force a fresh import so the patched module is honored.
            sys.modules.pop("d810.conf", None)
            conf_module = importlib.import_module("d810.conf")
            cfg = conf_module.D810Configuration()

        assert not (cfg.config_dir / "default.json").exists()
        resolved = Path(cfg._resolve_config_path("default.json")).resolve()
        package_root = Path(__file__).resolve().parents[2] / "src" / "d810"
        assert resolved.parent == (package_root / "conf").resolve()
        assert resolved.name == "default.json"