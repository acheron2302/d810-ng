"""Installer for isolated optional speedups dependencies."""

from __future__ import annotations

import logging
import subprocess
import sys

from d810.speedups import bootstrap

__all__ = [
    "get_speedups_dir",
    "ensure_speedups_on_path",
    "install_speedups",
]

SPEEDUPS_PACKAGES = ["z3-solver>=4.13,<4.15.5"]

get_speedups_dir = bootstrap.get_speedups_dir
ensure_speedups_on_path = bootstrap.ensure_speedups_on_path

logger = logging.getLogger(__name__)


def install_speedups(packages: list[str] | None = None) -> None:
    """Install optional dependencies into the private speedups directory.

    The pip invocation now passes ``--no-input``, ``--disable-pip-version-check``
    and ``--no-cache-dir`` so the installer is non-interactive, deterministic,
    and does not write a pip cache under the operator's home directory.
    Failures surface a meaningful error that includes the failing command
    and the captured stderr/stdout instead of being silently swallowed by
    ``subprocess.run`` defaults.
    """

    speedups_dir = get_speedups_dir()
    speedups_dir.mkdir(parents=True, exist_ok=True)
    pkg_list = packages or SPEEDUPS_PACKAGES
    cmd = [
        sys.executable,
        "-m",
        "pip",
        "install",
        "--no-input",
        "--disable-pip-version-check",
        "--no-cache-dir",
        "--target",
        str(speedups_dir),
        *pkg_list,
    ]
    logger.info("Installing d810 speedups into %s", speedups_dir)
    try:
        completed = subprocess.run(
            cmd,
            check=True,
            capture_output=True,
            text=True,
        )
    except subprocess.CalledProcessError as exc:
        logger.error(
            "pip install failed (exit %d) for command: %s\n"
            "stdout:\n%s\nstderr:\n%s",
            exc.returncode,
            " ".join(cmd),
            exc.stdout or "",
            exc.stderr or "",
        )
        raise


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    install_speedups()


if __name__ == "__main__":
    main()
