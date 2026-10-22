"""Build script for CyberOpsSuite (revised).

Creates a Windows bundle using PyInstaller:

* ``dist/CyberOpsSuite/CyberOpsSuite.exe``           - Dashboard launcher
* ``dist/CyberOpsSuite/modules/<Name>/<Name>.exe``   - 7 standalone modules

What changed compared to the previous version
---------------------------------------------
1. Every sub-module of the project packages is listed as a hidden import
   (found by walking the folders). Listing only the package name bundles
   just its ``__init__`` - dynamically imported tabs/plugins were missing.
2. ``.spec`` files live in ``build/specs`` - separate from PyInstaller's
   work path, so ``--clean`` can never delete the spec it is about to read.
3. The dashboard is built in a staging folder and copied over
   ``dist/CyberOpsSuite`` WITHOUT touching ``modules/``. Before, building the
   dashboard with ``--noconfirm`` wiped the already built modules.
4. ``uac_admin=True`` (default) - firewall / event log / VPN need admin.
   Modules started from the elevated dashboard inherit the rights.
5. A runtime hook is bundled into every exe:
   - fixes ``sys.stdout/stderr = None`` crashes of windowed (no console) exes
   - writes unhandled errors (also Tk callback errors) to
     ``%LOCALAPPDATA%\\CyberOpsSuite\\logs\\<exe>_crash.log``
6. ``--console`` builds with a console window for easy debugging.

Usage::

    python build.py                    # build everything
    python build.py dashboard          # dashboard only (modules are kept)
    python build.py modules            # the 7 modules only
    python build.py --clean            # clean dist/ and build/ first
    python build.py --console          # debug build, shows a console window
    python build.py --no-admin         # do not request administrator rights
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path


# ---------------------------------------------------------------- paths

PROJECT_ROOT = Path(__file__).resolve().parent
DIST_DIR = PROJECT_ROOT / "dist"
BUILD_DIR = PROJECT_ROOT / "build"
SPEC_DIR = BUILD_DIR / "specs"      # kept apart from PyInstaller's workpath
WORK_DIR = BUILD_DIR / "work"
STAGE_DIR = BUILD_DIR / "stage"
APP_NAME = "CyberOpsSuite"
ICON_PATH = PROJECT_ROOT / "assets" / "icons" / "cyberopssuite.ico"

#: Set from the command line in main().
OPTIONS = {"console": False, "admin": True}


# ---------------------------------------------------------------- modules

#: Each entry: (exe_name, module_path, friendly_name)
MODULES = [
    ("FirewallManager", "firewall_manager.gui.main", "Firewall Manager"),
    ("EventLogAnalyzer", "event_log_analyzer.gui.main", "Event Log Analyzer"),
    ("NetworkMapper", "network_mapper.gui.main", "Network Mapper"),
    ("DHCPLeaseViewer", "dhcp_lease_viewer.gui.main", "DHCP Lease Viewer"),
    ("ServerMonitor", "server_monitor.gui.main", "Server Monitor"),
    ("VPNManager", "vpn_manager.gui.main", "VPN Manager"),
    ("IPRotator", "ip_rotator.gui.main", "IP Rotator"),
]


# ---------------------------------------------------------------- packages

#: Top-level project packages. Every .py file inside is added as hidden import.
PROJECT_PACKAGES = [
    "core",
    "dashboard",
    "firewall_manager",
    "event_log_analyzer",
    "network_mapper",
    "dhcp_lease_viewer",
    "server_monitor",
    "vpn_manager",
    "ip_rotator",
]

#: Third-party packages that PyInstaller may miss.
THIRD_PARTY_PACKAGES = [
    "customtkinter",
    "PIL",
    "PIL.Image",
    "PIL.ImageTk",
    "psutil",
    "numpy",
]

#: Data folders bundled with every executable.
#: NOTE: PyInstaller 6+ puts them in ``<exe folder>/_internal`` (sys._MEIPASS),
#: NOT next to the exe. Read-only resources must be located via sys._MEIPASS.
DATA_FOLDERS = ("assets", "bin", "data")


# ---------------------------------------------------------------- runtime hook

RUNTIME_HOOK = '''\
"""Runtime hook added by build.py (runs before the application code)."""
import datetime
import os
import sys
import threading
import traceback

# Windowed exes have no console: sys.stdout / sys.stderr are None and any
# print() or library that writes to them can crash.
for _name in ("stdout", "stderr"):
    if getattr(sys, _name, None) is None:
        setattr(sys, _name, open(os.devnull, "w", encoding="utf-8"))
if getattr(sys, "stdin", None) is None:
    sys.stdin = open(os.devnull, "r", encoding="utf-8")


def _log_exception(exc_type, exc, tb):
    try:
        base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
        folder = os.path.join(base, "CyberOpsSuite", "logs")
        os.makedirs(folder, exist_ok=True)
        exe = os.path.splitext(os.path.basename(sys.executable))[0]
        with open(os.path.join(folder, exe + "_crash.log"), "a",
                  encoding="utf-8") as fh:
            fh.write("\\n--- %s ---\\n" % datetime.datetime.now())
            traceback.print_exception(exc_type, exc, tb, file=fh)
    except Exception:
        pass


_orig_excepthook = sys.excepthook


def _excepthook(exc_type, exc, tb):
    _log_exception(exc_type, exc, tb)
    _orig_excepthook(exc_type, exc, tb)


sys.excepthook = _excepthook

_orig_thread_hook = getattr(threading, "excepthook", None)


def _thread_hook(args):
    _log_exception(args.exc_type, args.exc_value, args.exc_traceback)
    if _orig_thread_hook:
        _orig_thread_hook(args)


if _orig_thread_hook:
    threading.excepthook = _thread_hook

# Errors inside Tk/customtkinter callbacks never reach sys.excepthook.
try:
    import tkinter

    _orig_cb = tkinter.Tk.report_callback_exception

    def _report_callback_exception(self, exc, val, tb):
        _log_exception(exc, val, tb)
        _orig_cb(self, exc, val, tb)

    tkinter.Tk.report_callback_exception = _report_callback_exception
except Exception:
    pass
'''


# ---------------------------------------------------------------- helpers

def _run(cmd: list[str]) -> int:
    print(f"\n$ {' '.join(cmd)}\n")
    return subprocess.call(cmd)


def _clean() -> None:
    for path in (BUILD_DIR, DIST_DIR):
        if path.exists():
            print(f"  Removing: {path}")
            shutil.rmtree(path, ignore_errors=True)
    print("  Cleaned.")


def _check_pyinstaller() -> bool:
    try:
        import PyInstaller  # noqa: F401
        print(f"  PyInstaller: {PyInstaller.__version__}")
        return True
    except ImportError:
        print("ERROR: PyInstaller is not installed.")
        print("Install it with:  pip install pyinstaller")
        return False


def _clean_pycache() -> None:
    for path in PROJECT_ROOT.rglob("__pycache__"):
        shutil.rmtree(path, ignore_errors=True)


def _discover_modules(package: str) -> list[str]:
    """Return the dotted names of every module inside a project package.

    Walks the folder instead of importing anything, so nothing is executed.
    """
    root = PROJECT_ROOT / package
    if not root.is_dir():
        print(f"  WARNING: package folder not found: {root}")
        return []

    names = [package]
    for py in sorted(root.rglob("*.py")):
        parts = list(py.relative_to(PROJECT_ROOT).with_suffix("").parts)
        if any(p in ("__pycache__", "tests", "test") for p in parts):
            continue
        if parts[-1] == "__init__":
            parts = parts[:-1]
        elif parts[-1] == "__main__":
            continue
        if not parts or not all(p.isidentifier() for p in parts):
            continue
        names.append(".".join(parts))
    return list(dict.fromkeys(names))


def _write_runtime_hook() -> Path:
    SPEC_DIR.mkdir(parents=True, exist_ok=True)
    hook = SPEC_DIR / "rthook_cyberops.py"
    hook.write_text(RUNTIME_HOOK, encoding="utf-8")
    return hook


# ---------------------------------------------------------------- spec

def _write_spec(exe_name: str, entry_path: Path) -> Path:
    """Generate a PyInstaller .spec file with an explicit pathex."""
    SPEC_DIR.mkdir(parents=True, exist_ok=True)
    spec_path = SPEC_DIR / f"{exe_name}.spec"
    hook = _write_runtime_hook()

    datas_entries = [
        (str(PROJECT_ROOT / folder), folder)
        for folder in DATA_FOLDERS
        if (PROJECT_ROOT / folder).is_dir()
    ]

    hidden: list[str] = []
    for pkg in PROJECT_PACKAGES:
        hidden.extend(_discover_modules(pkg))
    hidden.extend(THIRD_PARTY_PACKAGES)
    hidden = list(dict.fromkeys(hidden))

    datas_lines = ",\n        ".join(f"({s!r}, {d!r})" for s, d in datas_entries)
    hidden_lines = ",\n        ".join(repr(m) for m in hidden)
    icon = str(ICON_PATH) if ICON_PATH.is_file() else None

    spec_content = f'''# -*- mode: python ; coding: utf-8 -*-
"""Auto-generated by build.py - do not edit by hand."""

import sys

PROJECT_ROOT = {str(PROJECT_ROOT)!r}

# Make sure the project root is importable before analysis starts.
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

a = Analysis(
    [{str(entry_path)!r}],
    pathex=[PROJECT_ROOT],
    binaries=[],
    datas=[
        {datas_lines}
    ],
    hiddenimports=[
        {hidden_lines}
    ],
    hookspath=[],
    hooksconfig={{}},
    runtime_hooks=[{str(hook)!r}],
    excludes=[],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name={exe_name!r},
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console={OPTIONS["console"]!r},
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    uac_admin={OPTIONS["admin"]!r},
    icon={icon!r},
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name={exe_name!r},
)
'''
    spec_path.write_text(spec_content, encoding="utf-8")
    return spec_path


def _pyinstaller(spec_path: Path, distpath: Path, workpath: Path) -> int:
    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--noconfirm",
        "--clean",
        "--distpath", str(distpath),
        "--workpath", str(workpath),
        str(spec_path),
    ]
    return _run(cmd)


# ---------------------------------------------------------------- builds

def _install_dashboard(built: Path) -> None:
    """Copy the dashboard output into dist/CyberOpsSuite, keeping modules/."""
    target = DIST_DIR / APP_NAME
    target.mkdir(parents=True, exist_ok=True)

    for item in target.iterdir():
        if item.name == "modules":
            continue
        if item.is_dir():
            shutil.rmtree(item, ignore_errors=True)
        else:
            item.unlink(missing_ok=True)

    shutil.copytree(built, target, dirs_exist_ok=True)


def build_dashboard() -> int:
    print("\n" + "=" * 60)
    print("  Building Dashboard: CyberOpsSuite.exe")
    print("=" * 60)

    entry = PROJECT_ROOT / "dashboard" / "main.py"
    if not entry.is_file():
        print(f"ERROR: entry not found: {entry}")
        return 1

    spec_path = _write_spec(APP_NAME, entry)
    print(f"  Spec written: {spec_path}")

    stage = STAGE_DIR / "dashboard"
    shutil.rmtree(stage, ignore_errors=True)
    stage.mkdir(parents=True, exist_ok=True)

    rc = _pyinstaller(spec_path, stage, WORK_DIR / APP_NAME)
    if rc != 0:
        return rc

    built = stage / APP_NAME
    if not built.is_dir():
        print(f"ERROR: PyInstaller output not found: {built}")
        return 1

    _install_dashboard(built)
    return 0


def build_module(exe_name: str, module_path: str, friendly: str) -> int:
    print("\n" + "=" * 60)
    print(f"  Building Module: {friendly} ({exe_name}.exe)")
    print("=" * 60)

    entry = PROJECT_ROOT / Path(*module_path.split(".")).with_suffix(".py")
    if not entry.is_file():
        print(f"ERROR: entry not found: {entry}")
        return 1

    modules_dir = DIST_DIR / APP_NAME / "modules"
    modules_dir.mkdir(parents=True, exist_ok=True)

    stale = modules_dir / exe_name
    if stale.exists():
        shutil.rmtree(stale, ignore_errors=True)

    spec_path = _write_spec(exe_name, entry)
    print(f"  Spec written: {spec_path}")

    return _pyinstaller(spec_path, modules_dir, WORK_DIR / exe_name)


def build_all_modules() -> int:
    rc = 0
    for exe_name, module_path, friendly in MODULES:
        r = build_module(exe_name, module_path, friendly)
        if r != 0:
            rc = r
    return rc


# ---------------------------------------------------------------- summary

def _verify() -> list[str]:
    """Return a list of problems found in the finished bundle."""
    problems: list[str] = []
    root = DIST_DIR / APP_NAME

    if not (root / f"{APP_NAME}.exe").is_file():
        problems.append(f"missing {APP_NAME}.exe")
    for exe_name, _, _ in MODULES:
        if not (root / "modules" / exe_name / f"{exe_name}.exe").is_file():
            problems.append(f"missing modules/{exe_name}/{exe_name}.exe")
    return problems


def _print_summary() -> None:
    print("\n" + "=" * 60)
    print("  BUILD COMPLETE")
    print("=" * 60)

    target = DIST_DIR / APP_NAME
    if not target.is_dir():
        print(f"  WARNING: output not found: {target}")
        return

    print(f"\n  Output: {target}\n")

    for item in sorted(target.iterdir()):
        if item.is_file():
            mb = item.stat().st_size / (1024 * 1024)
            print(f"    [FILE] {item.name}  ({mb:.1f} MB)")
        elif item.name == "modules":
            print("    [DIR]  modules/")
            for sub in sorted(item.iterdir()):
                if sub.is_dir():
                    exe_file = sub / f"{sub.name}.exe"
                    if exe_file.is_file():
                        mb = exe_file.stat().st_size / (1024 * 1024)
                        print(f"           - {sub.name}/{sub.name}.exe  ({mb:.1f} MB)")
                    else:
                        print(f"           - {sub.name}/")
        else:
            count = sum(1 for _ in item.rglob("*") if _.is_file())
            print(f"    [DIR]  {item.name}/  ({count} files)")

    problems = _verify()
    if problems:
        print("\n  PROBLEMS:")
        for p in problems:
            print(f"    - {p}")

    print(
        "\n  Reminder: bundled data (assets/bin/data) is inside each exe's"
        "\n  '_internal' folder. Locate it with sys._MEIPASS, and keep"
        "\n  writable data (profiles, settings, logs) in %APPDATA%."
        "\n  Crash logs: %LOCALAPPDATA%\\CyberOpsSuite\\logs"
    )


# ---------------------------------------------------------------- main

def main() -> int:
    parser = argparse.ArgumentParser(
        prog="build.py",
        description="Build CyberOpsSuite executables.",
    )
    parser.add_argument(
        "target",
        nargs="?",
        choices=["all", "dashboard", "modules"],
        default="all",
    )
    parser.add_argument("--clean", action="store_true")
    parser.add_argument(
        "--console", action="store_true",
        help="debug build: keep a console window open",
    )
    parser.add_argument(
        "--no-admin", action="store_true",
        help="do not request administrator rights (uac_admin)",
    )
    args = parser.parse_args()

    OPTIONS["console"] = args.console
    OPTIONS["admin"] = not args.no_admin

    print("=" * 60)
    print("  CyberOpsSuite Build Script")
    print("=" * 60)
    print(f"  Python:    {sys.version.split()[0]}")
    print(f"  Platform:  {sys.platform}")
    print(f"  Project:   {PROJECT_ROOT}")
    print(f"  Target:    {args.target}")
    print(f"  Console:   {OPTIONS['console']}")
    print(f"  Admin:     {OPTIONS['admin']}")

    if not _check_pyinstaller():
        return 1

    if args.clean:
        print("\n[Clean] Removing old build artifacts...")
        _clean()
        _clean_pycache()

    rc = 0

    if args.target in ("all", "dashboard"):
        rc = build_dashboard() or rc

    if args.target in ("all", "modules"):
        rc = build_all_modules() or rc

    _print_summary()

    if rc == 0:
        print("\n  Build succeeded!")
    else:
        print("\n  Build failed (see output above).")

    return rc


if __name__ == "__main__":
    raise SystemExit(main())