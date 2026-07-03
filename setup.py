"""Optional Cython extension builder for D810.

By default, D810 installs as a pure Python package.
To build with Cython speedups:

    D810_BUILD_SPEEDUPS=1 pip install -e .[speedups]

The IDA SDK will be auto-downloaded from GitHub if not found.
Set IDA_SDK env var to use a custom location.

This setup.py only handles ext_modules; all other config is in pyproject.toml.
"""

import os
import pathlib
import platform
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request

from setuptools import setup

BUILD_SPEEDUPS = os.environ.get("D810_BUILD_SPEEDUPS", "0") == "1"

# Default SDK location (in build directory)
DEFAULT_SDK_DIR = pathlib.Path(__file__).parent / ".ida-sdk"
IDA_SDK_REPO = "https://github.com/HexRaysSA/ida-sdk.git"
# Pin the SDK to a known ref instead of tracking ``main`` so we get
# deterministic builds.  Override with IDA_SDK_BRANCH if you need a
# different ref.  The default SHA-256 below is the pinned commit; if
# you bump IDA_SDK_PINNED_SHA you MUST also update
# IDA_SDK_PINNED_SHA256 with the new tarball's digest.
IDA_SDK_BRANCH = os.environ.get("IDA_SDK_BRANCH", "main")
IDA_SDK_PINNED_SHA = os.environ.get("IDA_SDK_PINNED_SHA", "")
# sha256 of the ``refs/heads/<branch>`` tarball.  Empty means "do not
# verify" (acceptable when overriding the branch via env).
IDA_SDK_PINNED_SHA256 = os.environ.get("IDA_SDK_PINNED_SHA256", "")

# Platform detection
OSTYPE = platform.system()
ARCH = platform.processor() or platform.machine()
x64 = platform.architecture()[0] == "64bit"
DEBUG = os.environ.get("DEBUG") == "1"

# Determine library variant
if ARCH in ("ppc64le", "aarch64"):
    LIBRARY = ARCH
elif ARCH in ("arm", "arm64"):
    LIBRARY = "arm64"
else:
    LIBRARY = "amd64" if x64 else "intel32"


def _sdk_has_includes(path: pathlib.Path) -> bool:
    """Check if an SDK path has the include directory (either layout)."""
    return ((path / "src" / "include").exists() or
            (path / "include").exists())


def _sdk_include_dir(sdk_path: pathlib.Path) -> pathlib.Path:
    """Return the include directory for the SDK, handling both layouts.

    GitHub SDK clone: sdk/src/include/
    User IDA SDK:     sdk/include/
    """
    if (sdk_path / "src" / "include").exists():
        return sdk_path / "src" / "include"
    return sdk_path / "include"


def _sdk_lib_dir(sdk_path: pathlib.Path, *sub: str) -> pathlib.Path:
    """Return a library directory for the SDK, handling both layouts.

    The Hex-Rays public SDK ships a ``src/lib/x64_win_64`` layout while
    older / vendor layouts use names like ``x64_win_vc_64``.  When *sub*
    points at a directory that does not exist, fall back to scanning the
    lib tree for a sibling whose name starts with the same arch+os prefix
    (``x64_win``, ``x64_linux``, ``arm64_linux``, ...), so the linker
    finds ``ida.lib`` and ``idalib.lib`` regardless of which SDK
    revision is installed.  Among siblings the directory containing
    ``ida.lib`` is preferred; otherwise we prefer the 64-bit variant
    (``_64``) over 32-bit.
    """
    base = sdk_path / "src" / "lib"
    if not base.exists():
        base = sdk_path / "lib"
    target = base / pathlib.Path(*sub) if sub else base
    if sub and not target.exists():
        prefix_tokens = sub[0].split("_")[:2]
        prefix = "_".join(prefix_tokens)
        siblings = [
            c for c in base.iterdir()
            if c.is_dir() and c.name.startswith(prefix)
        ]

        def _score(candidate: pathlib.Path) -> tuple:
            name = candidate.name
            # Prefer directories that actually contain ida.lib so we do
            # not silently link against an empty shell.
            has_ida = (candidate / "ida.lib").exists()
            # Prefer 64-bit over 32-bit.
            is_64 = "_64" in name
            return (has_ida, is_64, name)

        if siblings:
            siblings.sort(key=_score, reverse=True)
            return siblings[0]
    return target


def get_ida_sdk_version(sdk_path: pathlib.Path) -> int:
    """Read the IDA SDK version number from pro.h.

    Returns the SDK version (e.g. 920 for IDA 9.2), or 0 if not found.
    """
    pro_h = _sdk_include_dir(sdk_path) / "pro.h"
    if pro_h.exists():
        with pro_h.open("r", encoding="utf-8") as f:
            for line in f:
                if line.strip().startswith("#define IDA_SDK_VERSION"):
                    parts = line.strip().split()
                    if len(parts) >= 3 and parts[2].isdigit():
                        return int(parts[2])
    return 0


def ensure_ida_sdk(sdk_path: pathlib.Path) -> pathlib.Path:
    """Ensure IDA SDK is available, downloading if necessary."""
    # If SDK exists, use it (GitHub SDK has include under src/,
    # user-provided SDK may have include/ at root)
    if sdk_path.exists() and _sdk_has_includes(sdk_path):
        print(f"Using IDA SDK at: {sdk_path}", file=sys.stderr)
        return sdk_path

    # Check cached SDK
    if DEFAULT_SDK_DIR.exists() and _sdk_has_includes(DEFAULT_SDK_DIR):
        print(f"Using cached IDA SDK at: {DEFAULT_SDK_DIR}", file=sys.stderr)
        return DEFAULT_SDK_DIR

    # Download SDK from GitHub
    print(f"IDA SDK not found. Downloading from {IDA_SDK_REPO}...", file=sys.stderr)

    # Clean up partial/corrupt SDK directory (exists but missing includes)
    if DEFAULT_SDK_DIR.exists() and not _sdk_has_includes(DEFAULT_SDK_DIR):
        print(f"Removing partial SDK directory: {DEFAULT_SDK_DIR}", file=sys.stderr)
        shutil.rmtree(DEFAULT_SDK_DIR)

    # Try git clone first (faster, gets only latest)
    if shutil.which("git"):
        clone_cmd = ["git", "clone", "--depth=1"]
        if IDA_SDK_BRANCH:
            clone_cmd.extend(["--branch", IDA_SDK_BRANCH])
        if IDA_SDK_PINNED_SHA:
            # When the user provides a pinned SHA, switch to a full
            # clone so we can check out the exact commit deterministically.
            clone_cmd = ["git", "clone", IDA_SDK_REPO, str(DEFAULT_SDK_DIR)]
            try:
                subprocess.run(
                    clone_cmd,
                    check=True,
                    capture_output=True,
                )
                subprocess.run(
                    ["git", "-C", str(DEFAULT_SDK_DIR), "checkout", IDA_SDK_PINNED_SHA],
                    check=True,
                    capture_output=True,
                )
                print(
                    f"IDA SDK pinned to {IDA_SDK_PINNED_SHA} at: {DEFAULT_SDK_DIR}",
                    file=sys.stderr,
                )
                return DEFAULT_SDK_DIR
            except subprocess.CalledProcessError as e:
                print(f"git clone (pinned) failed: {e.stderr.decode()}", file=sys.stderr)
                if DEFAULT_SDK_DIR.exists():
                    shutil.rmtree(DEFAULT_SDK_DIR)
        else:
            clone_cmd.extend([IDA_SDK_REPO, str(DEFAULT_SDK_DIR)])
            try:
                subprocess.run(
                    clone_cmd,
                    check=True,
                    capture_output=True,
                )
                print(f"IDA SDK downloaded to: {DEFAULT_SDK_DIR}", file=sys.stderr)
                return DEFAULT_SDK_DIR
            except subprocess.CalledProcessError as e:
                print(f"git clone failed: {e.stderr.decode()}", file=sys.stderr)
                # Clean up partial clone before tarball fallback
                if DEFAULT_SDK_DIR.exists() and not _sdk_has_includes(DEFAULT_SDK_DIR):
                    shutil.rmtree(DEFAULT_SDK_DIR)

    # Fallback: download tarball
    try:
        tarball_url = f"https://github.com/HexRaysSA/ida-sdk/archive/refs/heads/{IDA_SDK_BRANCH}.tar.gz"
        print(f"Downloading {tarball_url}...", file=sys.stderr)

        with tempfile.NamedTemporaryFile(suffix=".tar.gz", delete=False) as tmp:
            urllib.request.urlretrieve(tarball_url, tmp.name)

            # Optional SHA-256 verification when the caller pinned the
            # build to a known digest.
            if IDA_SDK_PINNED_SHA256:
                import hashlib

                h = hashlib.sha256()
                with open(tmp.name, "rb") as fh:
                    for chunk in iter(lambda: fh.read(65536), b""):
                        h.update(chunk)
                digest = h.hexdigest()
                if digest.lower() != IDA_SDK_PINNED_SHA256.lower():
                    os.unlink(tmp.name)
                    raise RuntimeError(
                        f"IDA SDK tarball SHA-256 mismatch: "
                        f"got {digest}, expected {IDA_SDK_PINNED_SHA256}"
                    )
                print(f"IDA SDK tarball SHA-256 OK ({digest})", file=sys.stderr)

            with tarfile.open(tmp.name, "r:gz") as tar:
                with tempfile.TemporaryDirectory() as tmpdir:
                    # Python 3.12+ supports ``filter="data"`` to refuse
                    # absolute paths and dangerous members; on older
                    # interpreters we must validate members manually
                    # because the older ``tar.extractall`` accepts any
                    # path the tarball specifies (CVE-2007-4559 class).
                    try:
                        tar.extractall(tmpdir, filter="data")
                    except TypeError:
                        # Python <3.12: refuse anything that tries to
                        # escape the destination directory.
                        dest_root = pathlib.Path(tmpdir).resolve()
                        for member in tar.getmembers():
                            member_path = (dest_root / member.name).resolve()
                            if (
                                not str(member_path).startswith(str(dest_root))
                                or member_path == dest_root
                                and member.name == ".."
                            ):
                                raise RuntimeError(
                                    f"Refusing unsafe tar member: {member.name!r}"
                                )
                        tar.extractall(tmpdir)
                    extracted = next(pathlib.Path(tmpdir).iterdir())
                    shutil.move(str(extracted), str(DEFAULT_SDK_DIR))

            os.unlink(tmp.name)

        print(f"IDA SDK downloaded to: {DEFAULT_SDK_DIR}", file=sys.stderr)
        return DEFAULT_SDK_DIR

    except Exception as e:
        raise RuntimeError(
            f"Failed to download IDA SDK: {e}\n"
            f"Please manually clone: git clone {IDA_SDK_REPO} {DEFAULT_SDK_DIR}\n"
            f"Or set IDA_SDK environment variable to your SDK location."
        )


def get_compile_args():
    """Return platform-specific compilation arguments."""
    if OSTYPE == "Windows":
        return ["/TP", "/EHa", "/Zc:offsetof-", "/std:c++17"] + (["/Z7", "/Od"] if DEBUG else [])
    elif OSTYPE == "Linux":
        base = ["-Wno-stringop-truncation", "-Wno-catch-value", "-Wno-unused-variable"]
        return base + (["-g", "-O0"] if DEBUG else [])
    elif OSTYPE == "Darwin":
        warnings = [
            "-Wno-unused-variable", "-Wno-nullability-completeness",
            "-Wno-sign-compare", "-Wno-varargs", "-Wno-c99-extensions",
        ]
        base = ["-mmacosx-version-min=10.9"] + warnings
        return base + (["-g", "-O0", "-fno-omit-frame-pointer"] if DEBUG else [])
    return []


def get_link_args():
    """Return platform-specific linker arguments."""
    if OSTYPE == "Darwin":
        return ["-Wl,-headerpad_max_install_names,-rpath,@loader_path/lib"]
    elif OSTYPE == "Linux":
        return ["-Wl,-rpath,$ORIGIN/lib"]
    return []


def get_ext_modules():
    """Build Cython extensions if D810_BUILD_SPEEDUPS=1, else return empty list."""
    # Re-check at call time (not just module-load time) so subprocess
    # invocations by pip/setuptools always see the current env.
    want_speedups = os.environ.get("D810_BUILD_SPEEDUPS", "0") == "1"
    if not want_speedups:
        return []

    try:
        from Cython.Build import cythonize
        from setuptools import Extension
    except ImportError:
        raise ImportError(
            "Cython is required to build speedups. "
            "Install with: pip install 'd810[speedups]'"
        )

    # Get IDA SDK (download if needed)
    sdk_env = os.environ.get("IDA_SDK")
    sdk_path = pathlib.Path(sdk_env) if sdk_env else DEFAULT_SDK_DIR
    IDA_SDK = ensure_ida_sdk(sdk_path)

    sdk_version = get_ida_sdk_version(IDA_SDK)
    print(f"IDA SDK version: {sdk_version}", file=sys.stderr)

    include_dirs = [
        str(_sdk_include_dir(IDA_SDK)),
        str(pathlib.Path(__file__).parent / "src" / "include"),
    ]
    library_dirs = [str(_sdk_lib_dir(IDA_SDK))]

    # Platform-specific library paths
    runtime_library_dirs = []
    if OSTYPE == "Windows":
        library_dirs.extend([
            str(_sdk_lib_dir(IDA_SDK, "x64_win_vc_64")),
            str(_sdk_lib_dir(IDA_SDK, "x64_win_qt")),
        ])
        # Qt6 for IDA 9.2+ (SDK >= 920), Qt5 for older
        if sdk_version >= 920:
            qt_ver = "Qt6"
        else:
            qt_ver = "Qt5"
        libraries = [f"{qt_ver}Core", f"{qt_ver}Gui", f"{qt_ver}Widgets", "ida", "idalib"]
    elif OSTYPE == "Darwin":
        subdir = "arm64_mac_clang_64" if LIBRARY == "arm64" else "x64_mac_clang_64"
        library_dirs.append(str(_sdk_lib_dir(IDA_SDK, subdir)))
        libraries = []
    else:  # Linux
        linux_lib_dir = str(_sdk_lib_dir(IDA_SDK, "x64_linux_gcc_64"))
        library_dirs.append(linux_lib_dir)
        libraries = ["ida"]
        runtime_library_dirs = [linux_lib_dir]

    macros = [("__EA64__", "1")] if x64 else []
    if DEBUG:
        macros.extend([("CYTHON_TRACE", "1"), ("CYTHON_CLINE_IN_TRACEBACK", "1")])

    return cythonize(
        Extension(
            "*",
            ["src/d810/speedups/**/*.pyx"],
            language="c++",
            include_dirs=include_dirs,
            library_dirs=library_dirs,
            libraries=libraries,
            runtime_library_dirs=runtime_library_dirs,
            extra_compile_args=get_compile_args(),
            extra_link_args=get_link_args(),
            define_macros=macros,
        ),
        compiler_directives={
            "language_level": "3",
            "binding": True,
            "embedsignature": True,
            "boundscheck": False,
            "wraparound": False,
            "profile": DEBUG,
            "linetrace": DEBUG,
        },
        annotate=DEBUG,
    )


# Minimal setup() - everything else comes from pyproject.toml
#
# NOTE: The previous Windows-only ``install.run`` post-install hook that
# copied plugin files into ``%APPDATA%\\Hex-Rays\\IDA Pro\\plugins`` has been
# removed. It was unreliable (its monkey patch was defined after the
# ``setup()`` call) and produced a descriptor mismatch because it copied the
# ``ida-plugin.json`` whose ``entryPoint`` only matches a ``src/`` layout.
#
# Plugin registration is now handled by the explicit symlink installer:
#
#     python -m d810.install_plugin
#
# See README.md for details.
setup(ext_modules=get_ext_modules())
