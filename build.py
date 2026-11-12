"""Build script for CyberOpsSuite (final - installer wizard).

Creates:
  * dist/CyberOpsSuite/CyberOpsSuite.exe           - Dashboard launcher
  * dist/CyberOpsSuite/modules/<Name>/<Name>.exe   - 7 standalone modules
  * dist/installer/CyberOpsSuite_Setup_<ver>.exe   - Windows installer (wizard)

Usage::

    python build.py                    # build everything + installer
    python build.py dashboard          # dashboard only (modules are kept)
    python build.py modules            # the 7 modules only
    python build.py --clean            # clean dist/ and build/ first
    python build.py --console          # debug build, shows a console window
    python build.py --no-admin         # do not request administrator rights
    python build.py --skip-installer   # build exes but no installer
    python build.py --installer-only   # only build the installer
    python build.py --version 1.2.3    # set installer version

Requires:
    pip install pyinstaller
    Inno Setup 6 or 7  ->  https://jrsoftware.org/isdl.php
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path


# ---------------------------------------------------------------- paths

PROJECT_ROOT = Path(__file__).resolve().parent
DIST_DIR = PROJECT_ROOT / "dist"
BUILD_DIR = PROJECT_ROOT / "build"
SPEC_DIR = BUILD_DIR / "specs"
WORK_DIR = BUILD_DIR / "work"
STAGE_DIR = BUILD_DIR / "stage"
APP_NAME = "CyberOpsSuite"
APP_PUBLISHER = "LorinBuilds"
APP_URL = "https://github.com/LorinBuilds/CyberOpsSuite"
ICON_PATH = PROJECT_ROOT / "assets" / "icons" / "cyberopssuite.ico"

INSTALLER_DIR = DIST_DIR / "installer"
INSTALLER_ISS = PROJECT_ROOT / "installer.iss"

OPTIONS = {
    "console": False,
    "admin": True,
    "version": "1.0.0",
    "build_installer": True,
}


# ---------------------------------------------------------------- modules

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

THIRD_PARTY_PACKAGES = [
    "customtkinter",
    "PIL",
    "PIL.Image",
    "PIL.ImageTk",
    "psutil",
    "numpy",
]

DATA_FOLDERS = ("assets", "bin", "data")

#: Files copied next to the exe (not inside _internal) for MIT compliance
#: and so the user sees LICENSE.txt in the install folder.
BUNDLE_ROOT_FILES = ("LICENSE.txt", "README.md", "README.FA.md")


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


def _copy_bundle_root_files(target_dir: Path) -> None:
    """Copy LICENSE + README next to the exe (MIT compliance)."""
    for fname in BUNDLE_ROOT_FILES:
        src = PROJECT_ROOT / fname
        if src.is_file():
            try:
                shutil.copy2(src, target_dir / fname)
            except Exception as exc:
                print(f"  WARNING: could not copy {fname}: {exc}")


# ---------------------------------------------------------------- spec

def _write_spec(exe_name: str, entry_path: Path) -> Path:
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
    _copy_bundle_root_files(target)


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

    rc = _pyinstaller(spec_path, modules_dir, WORK_DIR / exe_name)
    if rc == 0:
        _copy_bundle_root_files(modules_dir / exe_name)
    return rc


def build_all_modules() -> int:
    rc = 0
    for exe_name, module_path, friendly in MODULES:
        r = build_module(exe_name, module_path, friendly)
        if r != 0:
            rc = r
    return rc


# ---------------------------------------------------------------- installer (Inno Setup)

# NOTE: Inno Setup uses "{{" for literal braces, so all Inno preprocessor
# directives (which start with #) and all Inno constants (which use {}) are
# escaped with {{ }} in this Python f-string template. Do not remove them.

INSTALLER_ISS_TEMPLATE = '''\
; Auto-generated by build.py - do not edit by hand.
; Regenerate with:  python build.py --installer-only

#define MyAppName "{app_name}"
#define MyAppVersion "{app_version}"
#define MyAppPublisher "{app_publisher}"
#define MyAppURL "{app_url}"
#define MyAppExeName "{app_exe}"

[Setup]
AppId={{{{D3A7B9C1-4F2E-4A8B-9C6D-1E5F7A9B2C4D}}}}
AppName={{#MyAppName}}
AppVersion={{#MyAppVersion}}
AppVerName={{#MyAppName}} {{#MyAppVersion}}
AppPublisher={{#MyAppPublisher}}
AppPublisherURL={{#MyAppURL}}
AppSupportURL={{#MyAppURL}}
AppUpdatesURL={{#MyAppURL}}
DefaultDirName={{autopf}}\\{{#MyAppName}}
DefaultGroupName={{#MyAppName}}
DisableProgramGroupPage=yes
LicenseFile={license_file}
OutputDir={output_dir}
OutputBaseFilename={output_base}
SetupIconFile={setup_icon}
UninstallDisplayIcon={{app}}\\{{#MyAppExeName}}
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern dynamic
PrivilegesRequired=admin
PrivilegesRequiredOverridesAllowed=dialog
ArchitecturesInstallIn64BitMode=x64compatible
VersionInfoVersion={{#MyAppVersion}}
VersionInfoCompany={{#MyAppPublisher}}
VersionInfoDescription={{#MyAppName}} Setup

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{{cm:CreateDesktopIcon}}"; GroupDescription: "{{cm:AdditionalIcons}}"
Name: "quicklaunchicon"; Description: "{{cm:CreateQuickLaunchIcon}}"; GroupDescription: "{{cm:AdditionalIcons}}"; Flags: unchecked

[Files]
; Main program files
Source: "{source_dir}\\*"; DestDir: "{{app}}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
; Start Menu
Name: "{{group}}\\{{#MyAppName}}"; Filename: "{{app}}\\{{#MyAppExeName}}"; WorkingDir: "{{app}}"
Name: "{{group}}\\Uninstall {{#MyAppName}}"; Filename: "{{uninstallexe}}"
; Desktop
Name: "{{autodesktop}}\\{{#MyAppName}}"; Filename: "{{app}}\\{{#MyAppExeName}}"; WorkingDir: "{{app}}"; Tasks: desktopicon
; Quick Launch
Name: "{{userappdata}}\\Microsoft\\Internet Explorer\\Quick Launch\\{{#MyAppName}}"; Filename: "{{app}}\\{{#MyAppExeName}}"; WorkingDir: "{{app}}"; Tasks: quicklaunchicon

[Run]
Filename: "{{app}}\\{{#MyAppExeName}}"; Description: "{{cm:LaunchProgram,{{#StringChange(MyAppName, '&', '&&')}}}}"; Flags: nowait postinstall skipifsilent

[UninstallDelete]
Type: filesandordirs; Name: "{{app}}"

[Code]
var
  DataPage: TInputDirWizardPage;
  DataDir: String;

function GetDefaultDataDir(Param: String): String;
begin
  // %LOCALAPPDATA%\\CyberOpsSuite  by default
  Result := ExpandConstant('{{localappdata}}\\CyberOpsSuite');
end;

procedure InitializeWizard;
begin
  // Custom page: choose where the app stores user data (profiles, logs, db)
  DataPage := CreateInputDirPage(wpSelectDir,
    'Data Folder',
    'Where should {{#MyAppName}} store user data (profiles, logs, database)?',
    'Select a folder for writable data. This is separate from the program ' +
    'folder, which is read-only after install. If unsure, keep the default.',
    False, '');
  DataPage.Add('');
  DataPage.Values[0] := GetDefaultDataDir('');
end;

function NextButtonClick(CurPageID: Integer): Boolean;
begin
  Result := True;
  if CurPageID = DataPage.ID then
  begin
    if DataPage.Values[0] = '' then
    begin
      MsgBox('Please select a data folder.', mbError, MB_OK);
      Result := False;
    end
    else
      DataDir := DataPage.Values[0];
  end;
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  ConfigPath: String;
  ConfigLines: TStringList;
begin
  if CurStep = ssPostInstall then
  begin
    // Write a small config.ini next to the exe that tells the app
    // where its writable data lives. The app reads this on startup.
    if DataDir = '' then
      DataDir := GetDefaultDataDir('');

    ConfigPath := ExpandConstant('{{app}}\\config.ini');
    ConfigLines := TStringList.Create;
    try
      ConfigLines.Add('[paths]');
      ConfigLines.Add('data_dir=' + DataDir);
      ConfigLines.Add('logs_dir=' + ExpandConstant('{{localappdata}}\\CyberOpsSuite\\logs'));
      ConfigLines.Add('version={{#MyAppVersion}}');
      ConfigLines.SaveToFile(ConfigPath);
    finally
      ConfigLines.Free;
    end;

    // Create the data folder
    ForceDirectories(DataDir);
  end;
end;
'''


def _find_inno_setup() -> str | None:
    """Locate ISCC.exe (Inno Setup Compiler). Returns path or None.

    Searches, in order:
      1. PATH (if user added it)
      2. Inno Setup 7 — user-scope (%LOCALAPPDATA%\\Programs\\Inno Setup 7)
      3. Inno Setup 7 — machine-scope (Program Files / Program Files (x86))
      4. Inno Setup 6 — machine-scope
      5. Inno Setup 5 — machine-scope
    """
    found = shutil.which("iscc") or shutil.which("ISCC")
    if found:
        return found

    localappdata = os.environ.get("LOCALAPPDATA") or str(
        Path.home() / "AppData" / "Local"
    )
    program_files = os.environ.get("ProgramFiles", r"C:\Program Files")
    program_files_x86 = os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")

    candidates = [
        # Inno Setup 7 — user-scope (most common when installed for current user)
        Path(localappdata) / "Programs" / "Inno Setup 7" / "ISCC.exe",
        # Inno Setup 7 — machine-scope
        Path(program_files_x86) / "Inno Setup 7" / "ISCC.exe",
        Path(program_files) / "Inno Setup 7" / "ISCC.exe",
        # Inno Setup 6
        Path(program_files_x86) / "Inno Setup 6" / "ISCC.exe",
        Path(program_files) / "Inno Setup 6" / "ISCC.exe",
        # Inno Setup 5
        Path(program_files_x86) / "Inno Setup 5" / "ISCC.exe",
        Path(program_files) / "Inno Setup 5" / "ISCC.exe",
    ]
    for c in candidates:
        if c.is_file():
            print(f"  Found Inno Setup: {c}")
            return str(c)
    return None


def _write_installer_iss() -> Path | None:
    source_dir = DIST_DIR / APP_NAME
    if not source_dir.is_dir():
        print(f"  ERROR: bundle not found: {source_dir}")
        print("  Run 'python build.py' first (without --installer-only).")
        return None

    INSTALLER_DIR.mkdir(parents=True, exist_ok=True)

    setup_icon = ICON_PATH if ICON_PATH.is_file() else Path("")
    license_file = PROJECT_ROOT / "LICENSE.txt"
    if not license_file.is_file():
        license_file = PROJECT_ROOT / "LICENSE"
    output_base = f"{APP_NAME}_Setup_{OPTIONS['version']}"

    iss = INSTALLER_ISS_TEMPLATE.format(
        app_name=APP_NAME,
        app_version=OPTIONS["version"],
        app_publisher=APP_PUBLISHER,
        app_url=APP_URL,
        app_exe=f"{APP_NAME}.exe",
        source_dir=str(source_dir),
        output_dir=str(INSTALLER_DIR),
        output_base=output_base,
        setup_icon=str(setup_icon) if setup_icon.is_file() else "",
        license_file=str(license_file) if license_file.is_file() else "",
    )

    INSTALLER_ISS.write_text(iss, encoding="utf-8")
    print(f"  Installer script: {INSTALLER_ISS}")
    return INSTALLER_ISS


def build_installer() -> int:
    print("\n" + "=" * 60)
    print(f"  Building Installer: {APP_NAME}_Setup_{OPTIONS['version']}.exe")
    print("=" * 60)

    iscc = _find_inno_setup()
    if not iscc:
        print("  WARNING: Inno Setup (ISCC.exe) not found.")
        print("  Download: https://jrsoftware.org/isdl.php")
        print("  Skipping installer step.")
        return 0

    iss_path = _write_installer_iss()
    if not iss_path:
        return 1

    return _run([iscc, str(iss_path)])


# ---------------------------------------------------------------- summary

def _verify(installer_expected: bool) -> list[str]:
    problems: list[str] = []
    root = DIST_DIR / APP_NAME

    if not (root / f"{APP_NAME}.exe").is_file():
        problems.append(f"missing {APP_NAME}.exe")
    for exe_name, _, _ in MODULES:
        if not (root / "modules" / exe_name / f"{exe_name}.exe").is_file():
            problems.append(f"missing modules/{exe_name}/{exe_name}.exe")

    if installer_expected:
        setup = INSTALLER_DIR / f"{APP_NAME}_Setup_{OPTIONS['version']}.exe"
        if not setup.is_file():
            problems.append(f"missing installer: {setup.name}")
    return problems


def _print_summary(installer_expected: bool) -> None:
    print("\n" + "=" * 60)
    print("  BUILD COMPLETE")
    print("=" * 60)

    target = DIST_DIR / APP_NAME
    if target.is_dir():
        print(f"\n  Bundle:    {target}\n")
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
                count = sum(1 for _ in item.rglob("*") if _.is_file())
                print(f"    [DIR]  {item.name}/  ({count} files)")
    else:
        print(f"  WARNING: output not found: {target}")

    setup = INSTALLER_DIR / f"{APP_NAME}_Setup_{OPTIONS['version']}.exe"
    if setup.is_file():
        mb = setup.stat().st_size / (1024 * 1024)
        print(f"\n  Installer: {setup}  ({mb:.1f} MB)")

    problems = _verify(installer_expected)
    if problems:
        print("\n  PROBLEMS:")
        for p in problems:
            print(f"    - {p}")

    print(
        "\n  Reminder: bundled data (assets/bin/data) is inside each exe's"
        "\n  '_internal' folder. Locate it with sys._MEIPASS, and keep"
        "\n  writable data in the folder chosen in the installer."
        "\n  Crash logs: %LOCALAPPDATA%\\CyberOpsSuite\\logs"
    )


# ---------------------------------------------------------------- version

def _read_version_file() -> str | None:
    vf = PROJECT_ROOT / "VERSION"
    if vf.is_file():
        v = vf.read_text(encoding="utf-8").strip()
        if re.fullmatch(r"\d+(\.\d+){1,3}", v):
            return v
    return None


def _normalize_version(v: str) -> str:
    parts = v.strip().split(".")
    while len(parts) < 4:
        parts.append("0")
    return ".".join(parts[:4])


# ---------------------------------------------------------------- main

def main() -> int:
    parser = argparse.ArgumentParser(
        prog="build.py",
        description="Build CyberOpsSuite executables and installer.",
    )
    parser.add_argument(
        "target",
        nargs="?",
        choices=["all", "dashboard", "modules"],
        default="all",
    )
    parser.add_argument("--clean", action="store_true")
    parser.add_argument("--console", action="store_true",
                        help="debug build: keep a console window open")
    parser.add_argument("--no-admin", action="store_true",
                        help="do not request administrator rights (uac_admin)")
    parser.add_argument("--skip-installer", action="store_true",
                        help="build the exes but do not create the installer")
    parser.add_argument("--installer-only", action="store_true",
                        help="only (re)build the installer")
    parser.add_argument("--version", default=None,
                        help="installer version, e.g. 1.2.3")
    args = parser.parse_args()

    OPTIONS["console"] = args.console
    OPTIONS["admin"] = not args.no_admin

    if args.version:
        OPTIONS["version"] = _normalize_version(args.version)
    else:
        file_ver = _read_version_file()
        OPTIONS["version"] = _normalize_version(file_ver or "1.0.0")

    if args.skip_installer:
        OPTIONS["build_installer"] = False

    print("=" * 60)
    print("  CyberOpsSuite Build Script")
    print("=" * 60)
    print(f"  Python:    {sys.version.split()[0]}")
    print(f"  Platform:  {sys.platform}")
    print(f"  Project:   {PROJECT_ROOT}")
    print(f"  Target:    {args.target}")
    print(f"  Console:   {OPTIONS['console']}")
    print(f"  Admin:     {OPTIONS['admin']}")
    print(f"  Version:   {OPTIONS['version']}")
    print(f"  Installer: {'yes' if OPTIONS['build_installer'] else 'no'}")

    if not _check_pyinstaller():
        return 1

    if args.clean:
        print("\n[Clean] Removing old build artifacts...")
        _clean()
        _clean_pycache()

    rc = 0

    if args.installer_only:
        rc = build_installer() or rc
        _print_summary(installer_expected=True)
        if rc == 0:
            print("\n  Installer build succeeded!")
        else:
            print("\n  Installer build failed (see output above).")
        return rc

    if args.target in ("all", "dashboard"):
        rc = build_dashboard() or rc

    if args.target in ("all", "modules"):
        rc = build_all_modules() or rc

    installer_expected = False
    if OPTIONS["build_installer"] and args.target == "all" and rc == 0:
        installer_expected = True
        irc = build_installer()
        rc = irc or rc

    _print_summary(installer_expected=installer_expected)

    if rc == 0:
        print("\n  Build succeeded!")
    else:
        print("\n  Build failed (see output above).")

    return rc


if __name__ == "__main__":
    raise SystemExit(main())