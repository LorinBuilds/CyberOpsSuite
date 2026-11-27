"""Manage ThreatGuard auto-start on Windows (per-user, no admin required)."""
from __future__ import annotations

import os
import platform
import sys
from pathlib import Path

APP_NAME = "ThreatGuard"


def _is_windows() -> bool:
    return platform.system() == "Windows"


def _startup_folder() -> Path:
    """%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"""
    appdata = os.environ.get("APPDATA")
    if not appdata:
        raise RuntimeError("APPDATA is not set")
    return Path(appdata) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"


def _launch_command() -> str:
    """
    Return the command Windows should run on login.

    Prefer pythonw.exe (no console window) + the module entry point.
    Falls back to sys.executable if pythonw is missing.
    """
    exe = Path(sys.executable)
    pythonw = exe.with_name("pythonw.exe")
    launcher = pythonw if pythonw.exists() else exe
    return f'"{launcher}" -m threat_guard.gui.main --guard'


# ---------- Startup folder (recommended) ----------

def is_enabled_startup_folder() -> bool:
    if not _is_windows():
        return False
    return (_startup_folder() / f"{APP_NAME}.bat").exists()


def enable_startup_folder() -> Path:
    """Create a tiny .bat in the Startup folder."""
    target = _startup_folder()
    target.mkdir(parents=True, exist_ok=True)
    bat = target / f"{APP_NAME}.bat"
    # The module is found relative to the folder that contains threat_guard/, so
    # the startup script must switch there first (it starts in System32 otherwise).
    project_root = Path(__file__).resolve().parents[2]
    bat.write_text(
        "@echo off\r\n"
        f"cd /d \"{project_root}\"\r\n"
        f"start \"\" {_launch_command()}\r\n",
        encoding="utf-8",
    )
    return bat


def disable_startup_folder() -> bool:
    bat = _startup_folder() / f"{APP_NAME}.bat"
    if bat.exists():
        bat.unlink()
        return True
    return False


# ---------- Registry (alternative) ----------

def is_enabled_registry() -> bool:
    if not _is_windows():
        return False
    try:
        import winreg
    except ImportError:
        return False
    key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path) as key:
            winreg.QueryValueEx(key, APP_NAME)
            return True
    except OSError:
        return False


def enable_registry() -> None:
    import winreg
    key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, key_path) as key:
        winreg.SetValueEx(key, APP_NAME, 0, winreg.REG_SZ, _launch_command())


def disable_registry() -> bool:
    import winreg
    key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE) as key:
            winreg.DeleteValue(key, APP_NAME)
        return True
    except OSError:
        return False