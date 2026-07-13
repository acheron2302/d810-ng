"""Unit tests for ``d810.project_manager.register_transient``.

This test focuses on the new non-persisting helper and guards against
regressions to ``ProjectManager.add`` which still writes user options.

The test stubs ``ida_diskio`` because ``d810.project_manager`` pulls in
``d810.conf`` at import time. With ``ida_diskio`` replaced by a tiny fake,
we can exercise the manager without a full IDA environment.
"""

from __future__ import annotations

import dataclasses
import importlib
import json
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest


@pytest.fixture
def fake_options_path(tmp_path: Path) -> Path:
    """A writable options.json path the manager will use."""
    p = tmp_path / "options.json"
    p.write_text(json.dumps({"configurations": []}), encoding="utf-8")
    return p


@dataclasses.dataclass
class _FakeProject:
    path: Path
    description: str = ""
    ins_rules: list = dataclasses.field(default_factory=list)
    blk_rules: list = dataclasses.field(default_factory=list)
    additional_configuration: dict = dataclasses.field(default_factory=dict)


class _FakeConfig:
    """Minimal ``D810Configuration`` stand-in keeping state in memory only."""

    def __init__(self, options_path: Path) -> None:
        self._options_path = options_path
        self._options: dict = {"configurations": []}
        self.save_calls: list[dict] = []

    def discover_projects(self) -> list:
        return []

    def get(self, key: str, default=None):
        return self._options.get(key, default)

    def __setitem__(self, key: str, value) -> None:
        self._options[key] = value

    def save(self) -> None:
        self.save_calls.append(dict(self._options))
        self._options_path.write_text(
            json.dumps(self._options), encoding="utf-8"
        )


def _build_manager(options_path: Path):
    """Import ``ProjectManager`` after faking ``ida_diskio`` and friends."""
    fake_idadir = SimpleNamespace()
    fake_idadir.cwd = lambda: str(options_path.parent)
    fake_ida_diskio = SimpleNamespace(get_user_idadir=lambda: str(options_path.parent))
    fake_ida_diskio.ida_dir = fake_idadir
    sys.modules.pop("d810.project_manager", None)
    sys.modules.pop("d810.conf", None)
    sys.modules.pop("d810.conf.loggers", None)

    fake_loggers_module = SimpleNamespace(
        D810Formatter=type("D810Formatter", (), {}),
        conf={"loggers": {}},
        configure_loggers=lambda *a, **k: None,
        getLogger=lambda *a, **k: SimpleNamespace(
            debug=lambda *a, **k: None,
            info=lambda *a, **k: None,
            warning=lambda *a, **k: None,
            error=lambda *a, **k: None,
            critical=lambda *a, **k: None,
            debug_on=False,
            info_on=False,
            warning_on=False,
            error_on=False,
            critical_on=False,
        ),
    )

    fake_conf_init = SimpleNamespace(
        ConfigConstants=SimpleNamespace(
            DEFAULT_LOG_DIR=Path(options_path.parent),
            OPTIONS_FILENAME="options.json",
        ),
        ProjectConfiguration=type(
            "ProjectConfiguration",
            (),
            {
                "from_file": classmethod(
                    lambda cls, _path: _FakeProject(path=Path("dummy.json"))
                )
            },
        ),
        D810Configuration=_FakeConfig,
    )

    def _real_build_manager():
        pm_lib = importlib.import_module("d810.project_manager")
        return pm_lib.ProjectManager(_FakeConfig(options_path))

    with patch.dict(
        "sys.modules",
        {
            "ida_diskio": fake_ida_diskio,
            "d810.conf.loggers": fake_loggers_module,
            "d810.conf": fake_conf_init,
        },
    ):
        return _real_build_manager()


def test_register_transient_does_not_persist(fake_options_path: Path):
    """``register_transient`` must not save ``options.json``."""
    pm = _build_manager(fake_options_path)
    initial_save_count = len(pm.config.save_calls)

    project = _FakeProject(
        path=Path("ephemeral_config.json"),
        description="not persisted",
    )
    pm.register_transient(project)

    # It is registered and reachable.
    assert "ephemeral_config.json" in pm.project_names()
    assert pm.get("ephemeral_config.json") is project

    # No new save() call should have happened.
    assert len(pm.config.save_calls) == initial_save_count


def test_register_transient_does_not_modify_configurations(fake_options_path: Path):
    """Registered projects must not appear in the persisted configurations list."""
    pm = _build_manager(fake_options_path)
    project = _FakeProject(
        path=Path("transient_only.json"),
        description="transient",
    )
    pm.register_transient(project)

    assert pm.config.get("configurations") == []
    raw = json.loads(fake_options_path.read_text(encoding="utf-8"))
    assert raw["configurations"] == []


def test_register_transient_overwrites_in_memory(fake_options_path: Path):
    """A second ``register_transient`` with the same name replaces the prior binding."""
    pm = _build_manager(fake_options_path)
    p1 = _FakeProject(path=Path("same_name.json"), description="first")
    p2 = _FakeProject(path=Path("same_name.json"), description="second")
    pm.register_transient(p1)
    pm.register_transient(p2)

    assert pm.get("same_name.json") is p2
    assert pm.get("same_name.json").description == "second"


def test_add_still_persists(fake_options_path: Path):
    """Regression guard: ``add`` keeps saving ``options.json``."""
    pm = _build_manager(fake_options_path)
    user_json = fake_options_path.parent / "real_user_project.json"
    user_json.write_text(
        json.dumps({
            "description": "user",
            "ins_rules": [],
            "blk_rules": [],
        }),
        encoding="utf-8",
    )
    initial_save_count = len(pm.config.save_calls)
    pm.add(_FakeProject(path=user_json))

    assert len(pm.config.save_calls) > initial_save_count
