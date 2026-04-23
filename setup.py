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
IDA_SDK_BRANCH = "main"

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
    """Return a library directory for the SDK, handling both layouts."""
    if (sdk_path / "src" / "lib").exists():
        return sdk_path / "src" / "lib" / pathlib.Path(*sub) if sub else sdk_path / "src" / "lib"
    return sdk_path / "lib" / pathlib.Path(*sub) if sub else sdk_path / "lib"


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
        try:
            subprocess.run(
                ["git", "clone", "--depth=1", "--branch", IDA_SDK_BRANCH,
                 IDA_SDK_REPO, str(DEFAULT_SDK_DIR)],
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

            with tarfile.open(tmp.name, "r:gz") as tar:
                with tempfile.TemporaryDirectory() as tmpdir:
                    try:
                        tar.extractall(tmpdir, filter="data")
                    except TypeError:
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
setup(ext_modules=get_ext_modules())


# -----------------------------------------------------------------------------
# IDA Plugin Auto-Installation (Windows)
# -----------------------------------------------------------------------------
# Post-install hook to copy plugin files to IDA Pro's plugins directory.
# This ensures the plugin is available to IDA regardless of which Python
# interpreter IDA uses.
#
# To disable auto-install: set D810_INSTALL_IDA_PLUGIN=0 environment variable

if sys.platform == "win32" and "bdist_wheel" not in sys.argv:
    from setuptools.command.install import install
    import shutil
    import pathlib

    _original_install = install.run

    def _ida_plugin_install_run(self):
        result = _original_install(self)
        if os.environ.get("D810_INSTALL_IDA_PLUGIN", "1") != "0":
            _install_to_ida_plugins()
        return result

    def _install_to_ida_plugins():
        """Copy plugin files to IDA Pro's Windows plugins directory."""
        try:
            appdata = os.environ.get("APPDATA")
            if not appdata:
                print("Warning: APPDATA not set, skipping IDA plugin install")
                return

            ida_plugins_dir = pathlib.Path(appdata) / "Hex-Rays" / "IDA Pro" / "plugins"
            project_root = pathlib.Path(__file__).parent

            # Files/directories to copy for the plugin
            items_to_copy = [
                ("src/d810ng.py", "d810ng.py"),
                ("src/d810", "d810"),
                ("ida-plugin.json", "ida-plugin.json"),
            ]
            resource_items = [
                ("resources", "resources"),
            ]

            # Create plugin directory
            ida_plugins_dir.mkdir(parents=True, exist_ok=True)

            # Copy main plugin files
            for src_rel, dst_name in items_to_copy:
                src = project_root / src_rel
                dst = ida_plugins_dir / dst_name
                if src.exists():
                    if src.is_dir():
                        if dst.exists():
                            shutil.rmtree(dst)
                        shutil.copytree(src, dst)
                    else:
                        shutil.copy2(src, dst)
                    print(f"Copied {src_rel} -> {dst}")

            # Copy resources directory
            for src_rel, dst_name in resource_items:
                src = project_root / src_rel
                dst = ida_plugins_dir.parent / dst_name  # resources alongside plugin folder
                if src.exists() and not dst.exists():
                    shutil.copytree(src, dst)
                    print(f"Copied {src_rel} -> {dst}")

            print(f"\nD810-ng installed to: {ida_plugins_dir}")
            print("Restart IDA Pro to load the plugin.")

        except Exception as e:
            print(f"Warning: Failed to install to IDA plugins: {e}")
            print("Manual installation: copy plugin files to %APPDATA%\\Hex-Rays\\IDA Pro\\plugins")

    install.run = _ida_plugin_install_run
