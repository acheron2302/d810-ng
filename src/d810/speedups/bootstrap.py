"""Path bootstrap for isolated optional speedups dependencies."""

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path

logger = logging.getLogger(__name__)

DEFAULT_SPEEDUPS_DIR = Path.home() / ".d810-speedups"

# Paths we never want to silently prepend to sys.path, even if the
# operator points ``D810_SPEEDUPS_DIR`` at them.  These are locations
# that contain Python distributions, system tooling, or attacker-
# controlled files; importing code from them would be a security hole.
_DENY_PATH_PREFIXES = (
    "/etc/",
    "/usr/lib/python",
    "/usr/local/lib/python",
    "/var/",
    str(Path.home() / ".ssh"),
)


def get_speedups_dir() -> Path:
    """Return the configured directory where isolated speedups dependencies live.

    The returned path is always resolved (absolute, no symlinks, no
    ``..`` components) so that downstream code can compare it without
    worrying about alternate spellings pointing at the same location.
    """

    override = os.environ.get("D810_SPEEDUPS_DIR")
    if override:
        return Path(override).expanduser().resolve()
    return DEFAULT_SPEEDUPS_DIR.expanduser().resolve()


def _path_already_on_sys_path(path: str) -> bool:
    """Return True if *path* is already represented on ``sys.path``.

    Resolves each entry before comparing so we do not end up with two
    copies of the same directory on ``sys.path`` (one absolute, one
    relative, one with a trailing slash, ...).
    """
    target = str(Path(path).resolve())
    for entry in sys.path:
        try:
            if str(Path(entry).resolve()) == target:
                return True
        except OSError:
            continue
    return False


def _looks_dangerous(speedups_dir: Path) -> bool:
    """Refuse to prepend obviously dangerous paths to ``sys.path``."""
    text = str(speedups_dir)
    return any(text == p.rstrip("/") or text.startswith(p) for p in _DENY_PATH_PREFIXES)


def ensure_speedups_on_path() -> bool:
    """Prepend the speedups directory to ``sys.path`` if it exists.

    The function is now:

    * Idempotent: repeated calls do not duplicate ``sys.path`` entries.
    * Resolves the configured directory before comparing so symlink
      shenanigans cannot bypass the duplicate check.
    * Refuses to prepend paths under well-known dangerous locations
      (``/etc``, ``~/.ssh``, system ``lib/python`` trees, ...).
    * Logs a warning when the operator-selected path is unsafe, instead
      of silently mutating ``sys.path``.

    Returns:
        ``True`` when ``sys.path`` was modified (or already contained
        the resolved directory), ``False`` when the directory does not
        exist or was rejected as unsafe.
    """
    speedups_dir = get_speedups_dir()
    if not speedups_dir.is_dir():
        return False
    if _looks_dangerous(speedups_dir):
        logger.warning(
            "Refusing to prepend D810_SPEEDUPS_DIR=%s to sys.path: "
            "the path is under a sensitive location.",
            speedups_dir,
        )
        return False
    path_str = str(speedups_dir)
    if _path_already_on_sys_path(path_str):
        return True
    sys.path.insert(0, path_str)
    import builtins
    speedups_z3_lib = speedups_dir / "z3" / "lib"
    if speedups_z3_lib.is_dir():
        # Force z3core.py to search our isolated lib dir first,
        # before falling back to cwd (which is IDA's install dir) or PATH.
        # z3core.py checks builtins.Z3_LIB_DIRS and uses it to override
        # the default search order when loading libz3.{dll,dylib,so}.
        # Only set the global if the operator has not already configured
        # one; replacing an explicit value silently is surprising.
        if not hasattr(builtins, "Z3_LIB_DIRS"):
            builtins.Z3_LIB_DIRS = [str(speedups_z3_lib)]
    return True

