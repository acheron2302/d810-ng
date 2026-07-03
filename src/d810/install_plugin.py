"""IDA plugin installer.

This module exposes an explicit installer command that registers D-810 ng with
an IDA Pro installation by creating symlinks under the IDA ``plugins``
directory.

The installer intentionally uses the flat legacy plugin layout used by older
IDA versions: it creates ``<plugins>/d810ng.py`` and ``<plugins>/d810`` as
symlinks pointing into the live source tree. Editing the source tree takes
effect on the next IDA start without any further ``pip install`` step.

Run it from any Python interpreter:

    python -m d810.install_plugin                     # auto-detect source
    python -m d810.install_plugin --src-dir <path>    # explicit source dir
    python -m d810.install_plugin --force             # replace existing links

The module deliberately has no dependency on IDA's Python API so it can run
under any interpreter, including a venv or a plain system Python.
"""

from __future__ import annotations

import argparse
import os
import shutil
import sys
from pathlib import Path

__all__ = [
    "LINK_NAMES",
    "default_plugins_dir",
    "resolve_src_dir",
    "validate_src_dir",
    "check_existing_targets",
    "remove_existing_target",
    "create_symlink",
    "install_plugin",
    "build_argparser",
    "main",
]


LINK_NAMES = ("d810ng.py", "d810")


def default_plugins_dir() -> Path:
    """Return the default IDA plugins directory for the current platform.

    - Windows: ``%APPDATA%\\Hex-Rays\\IDA Pro\\plugins``
    - Linux / macOS: ``~/.idapro/plugins``

    Returns ``None`` indirectly via raising :class:`RuntimeError` when the
    platform default cannot be determined (for example, when ``APPDATA`` is
    not set on Windows).
    """
    if sys.platform == "win32":
        appdata = os.environ.get("APPDATA")
        if not appdata:
            raise RuntimeError(
                "APPDATA environment variable is not set on Windows; "
                "pass --plugins-dir explicitly."
            )
        return Path(appdata) / "Hex-Rays" / "IDA Pro" / "plugins"
    # Linux and macOS share the ~/.idapro plugins layout.
    return Path.home() / ".idapro" / "plugins"


def resolve_src_dir(explicit: str | os.PathLike[str] | None = None) -> Path:
    """Return the source directory that contains ``d810ng.py`` and ``d810/``.

    Resolution order:
    1. ``explicit`` argument, if provided.
    2. The parent directory of :mod:`d810` (works for both editable installs
       pointing into the repo ``src/`` tree and for layout patterns where
       ``d810ng.py`` sits next to the ``d810`` package).

    For editable installs (``pip install -e .``) and source checkouts the
    function returns ``<repo>/src``.
    """
    if explicit is not None:
        return Path(explicit).expanduser().resolve()

    # ``d810.__file__`` points at <src>/d810/__init__.py in editable installs.
    # The plugin loader (<src>/d810ng.py) and the package (<src>/d810) live
    # in the same parent directory, which is the source root we want.
    import d810  # local import keeps the module IDA-free at import time

    d810_pkg = Path(d810.__file__).resolve().parent
    return d810_pkg.parent


def validate_src_dir(src_dir: Path) -> tuple[Path, Path]:
    """Validate ``src_dir`` contains the expected plugin loader entries.

    Returns a tuple ``(d810ng_py, d810_pkg)`` of the resolved source paths.
    Raises :class:`FileNotFoundError` with an actionable message if either is
    missing.
    """
    d810ng_py = src_dir / "d810ng.py"
    d810_pkg = src_dir / "d810"
    missing = [name for name, p in (("d810ng.py", d810ng_py), ("d810/", d810_pkg)) if not p.exists()]
    if missing:
        raise FileNotFoundError(
            "Source directory %s is missing: %s. "
            "Pass --src-dir pointing at a directory that contains d810ng.py "
            "and the d810/ package." % (src_dir, ", ".join(missing))
        )
    return d810ng_py, d810_pkg


def _target_kind(target: Path) -> str:
    """Return a string describing what currently occupies ``target``.

    Possible values: ``"missing"``, ``"symlink"``, ``"file"``, ``"directory"``,
    ``"other"``. A broken symlink (where the link target no longer exists)
    is reported as ``"symlink"``.
    """
    if target.is_symlink():
        return "symlink"
    if not target.exists():
        return "missing"
    if target.is_file():
        return "file"
    if target.is_dir():
        return "directory"
    return "other"


def check_existing_targets(
    plugins_dir: Path, *, force: bool = False
) -> list[Path]:
    """Return the list of plugin entries that would block a fresh install.

    Validation runs against both expected targets before any modification so
    a partial install cannot leave the plugins directory in a mixed state.

    If ``force`` is ``True`` the function never raises and instead returns
    the list of targets that the installer will need to clear first; the
    caller is responsible for actually removing them via
    :func:`remove_existing_target`.
    """
    blockers: list[Path] = []
    for name in LINK_NAMES:
        target = plugins_dir / name
        kind = _target_kind(target)
        if kind == "missing":
            continue
        if kind == "symlink":
            blockers.append(target)
            continue
        if kind == "file":
            blockers.append(target)
            continue
        if kind == "directory":
            # A real directory under plugins/d810 likely contains a previous
            # manual install or user modifications. Refuse to remove it by
            # default even with --force; the user must opt in via
            # --force-remove-directory (handled in main()).
            blockers.append(target)
            continue
        # 'other' (socket, fifo, block device, ...) is also refused.
        blockers.append(target)

    if not blockers:
        return []

    if force:
        return blockers

    details = []
    for path in blockers:
        details.append(f"  - {path} ({_target_kind(path)})")
    raise FileExistsError(
        "Refusing to overwrite existing plugin entries:\n"
        + "\n".join(details)
        + "\n\nRe-run with --force to replace them. The installer never deletes "
        "non-symlink 'd810/' directories; remove it manually if you really "
        "want to."
    )


def remove_existing_target(target: Path, *, force_remove_directory: bool = False) -> None:
    """Remove a single plugin entry that is blocking a fresh install.

    - Symlinks (including broken ones) are unlinked.
    - Regular files are unlinked.
    - Directories are only removed when ``force_remove_directory`` is set;
      this is a safety net because a real directory at ``plugins/d810``
      likely contains user-edited configurations.
    """
    kind = _target_kind(target)
    if kind == "symlink":
        # Use lexists semantics: is_symlink() already returns True for broken
        # symlinks, but unlink() handles both fine.
        target.unlink()
        return
    if kind == "file":
        target.unlink()
        return
    if kind == "directory":
        if not force_remove_directory:
            raise IsADirectoryError(
                f"Refusing to delete real directory {target}. "
                "Pass --force-remove-directory to remove it (dangerous: "
                "may contain user-edited configurations)."
            )
        shutil.rmtree(target)
        return
    if kind == "other":
        raise OSError(f"Refusing to remove non-regular entry {target}")
    # 'missing' should not reach here, but be defensive.
    return


def create_symlink(link_path: Path, source: Path, *, target_is_directory: bool) -> None:
    """Create ``link_path`` as a symlink pointing at ``source``.

    ``OSError`` raised by :meth:`Path.symlink_to` (typically
    ``WinError 1314`` on Windows when Developer Mode is off and the shell is
    not elevated) is propagated unchanged so the caller can format an
    actionable error message.
    """
    link_path.symlink_to(source, target_is_directory=target_is_directory)


def _windows_symlink_help() -> str:
    return (
        "On Windows, symlink creation requires either:\n"
        "  - Developer Mode enabled in Settings > Privacy & security > For developers, or\n"
        "  - an elevated (Run as administrator) shell.\n"
        "Alternatively, create the links manually from an elevated shell:\n"
        "    mklink \"%APPDATA%\\Hex-Rays\\IDA Pro\\plugins\\d810ng.py\" \"<src>\\d810ng.py\"\n"
        "    mklink /D \"%APPDATA%\\Hex-Rays\\IDA Pro\\plugins\\d810\" \"<src>\\d810\""
    )


def _unix_symlink_help(src_dir: Path, plugins_dir: Path) -> str:
    return (
        "On Unix, create the links manually with:\n"
        f"    ln -s \"{src_dir / 'd810ng.py'}\" \"{plugins_dir / 'd810ng.py'}\"\n"
        f"    ln -s \"{src_dir / 'd810'}\" \"{plugins_dir / 'd810'}\""
    )


def install_plugin(
    plugins_dir: Path | None = None,
    src_dir: Path | None = None,
    *,
    force: bool = False,
    force_remove_directory: bool = False,
    stdout=sys.stdout,
) -> int:
    """Install the plugin via symlinks and return a shell-style exit code.

    Exposed for tests; the :func:`main` entrypoint parses arguments and calls
    this function. ``stdout`` is overridable so tests can capture output.
    """
    try:
        target_plugins_dir = Path(plugins_dir).expanduser().resolve() if plugins_dir else default_plugins_dir()
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    resolved_src_dir = resolve_src_dir(src_dir)
    try:
        d810ng_py, d810_pkg = validate_src_dir(resolved_src_dir)
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    target_plugins_dir.mkdir(parents=True, exist_ok=True)

    try:
        blockers = check_existing_targets(target_plugins_dir, force=force)
    except FileExistsError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if force and blockers:
        for blocker in blockers:
            try:
                remove_existing_target(blocker, force_remove_directory=force_remove_directory)
            except (IsADirectoryError, OSError) as exc:
                print(f"error: {exc}", file=sys.stderr)
                return 2

    print(f"Source: {resolved_src_dir}")
    print(f"Target: {target_plugins_dir}")

    plan = (
        (target_plugins_dir / "d810ng.py", d810ng_py, False),
        (target_plugins_dir / "d810", d810_pkg, True),
    )

    for link_path, source, target_is_directory in plan:
        try:
            create_symlink(link_path, source, target_is_directory=target_is_directory)
        except OSError as exc:
            print(
                f"error: failed to create symlink {link_path} -> {source}: {exc}",
                file=sys.stderr,
            )
            if sys.platform == "win32":
                print(_windows_symlink_help(), file=sys.stderr)
            else:
                print(_unix_symlink_help(resolved_src_dir, target_plugins_dir), file=sys.stderr)
            return 1
        kind = "directory" if target_is_directory else "file"
        print(f"Linked {link_path} -> {source} ({kind})")

    print(
        "\nD-810 ng plugin installed via symlinks. Restart IDA Pro to load it "
        "(or load it manually with the existing Ctrl-Shift-D hotkey).\n"
        "Note: this installer intentionally does not place ida-plugin.json in "
        "the flat plugin layout; the legacy plugin entry point lives at "
        "plugins/d810ng.py."
    )
    return 0


def build_argparser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m d810.install_plugin",
        description=(
            "Install D-810 ng into an IDA Pro plugins directory by creating "
            "symlinks to the live source tree."
        ),
    )
    parser.add_argument(
        "--plugins-dir",
        type=Path,
        default=None,
        help=(
            "Override the IDA plugins directory. Defaults to "
            "%%APPDATA%%\\Hex-Rays\\IDA Pro\\plugins on Windows and "
            "~/.idapro/plugins on Linux/macOS."
        ),
    )
    parser.add_argument(
        "--src-dir",
        type=Path,
        default=None,
        help=(
            "Path to the directory containing d810ng.py and the d810/ package "
            "(usually <repo>/src). When omitted, the installer derives this "
            "from the installed d810 package location."
        ),
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help=(
            "Replace existing symlinks and conflicting files at the target. "
            "Real directories under plugins/d810 are never removed unless "
            "--force-remove-directory is also passed."
        ),
    )
    parser.add_argument(
        "--force-remove-directory",
        action="store_true",
        help=(
            "Allow --force to also remove a real plugins/d810 directory. "
            "Dangerous: that directory may contain user-edited configurations."
        ),
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_argparser()
    args = parser.parse_args(argv)
    return install_plugin(
        plugins_dir=args.plugins_dir,
        src_dir=args.src_dir,
        force=args.force,
        force_remove_directory=args.force_remove_directory,
    )


if __name__ == "__main__":
    raise SystemExit(main())