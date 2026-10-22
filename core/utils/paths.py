"""Platform-specific paths shared by all CyberOpsSuite modules.

Every module stores its per-user data under a single root directory:

* Windows: ``%APPDATA%\\CyberOpsSuite\\<Module>\\``
* Linux:   ``$XDG_CONFIG_HOME/CyberOpsSuite/<Module>/``
            (``~/.config/CyberOpsSuite/<Module>/`` if unset)

Only Windows and Linux are officially supported. macOS is not a
target platform, but the Linux branch is used as a safe fallback.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path


#: Top-level folder shared by every module.
SUITE_DIR_NAME = "CyberOpsSuite"


def config_root(module_name: str) -> Path:
    """Return (and create) the per-user config directory for *module_name*.

    Parameters
    ----------
    module_name:
        Module folder name, e.g. ``"VpnManager"`` or ``"ServerMonitor"``.
        Must be a plain folder name; nested paths are not supported.

    Returns
    -------
    Path
        The module's config directory, guaranteed to exist.
    """
    base = _platform_base()
    path = base / SUITE_DIR_NAME / module_name
    path.mkdir(parents=True, exist_ok=True)
    return path


def config_root_quiet(module_name: str) -> Path:
    """Same as :func:`config_root` but does not create the directory.

    Useful for read-only checks (e.g. showing the path in About dialogs)
    or for tests that only need the path string.
    """
    return _platform_base() / SUITE_DIR_NAME / module_name


def _platform_base() -> Path:
    """Return the platform-specific base directory for user config."""
    if os.name == "nt":
        # Windows: %APPDATA% (Roaming), with a sensible fallback.
        return Path(os.environ.get("APPDATA") or Path.home())

    # Linux and other POSIX systems: respect the XDG spec.
    xdg = os.environ.get("XDG_CONFIG_HOME")
    if xdg:
        return Path(xdg)
    return Path.home() / ".config"


def is_frozen() -> bool:
    """Return True when running inside a PyInstaller bundle."""
    return bool(getattr(sys, "frozen", False))


def project_root() -> Path:
    """Return the project root, working both in source and frozen (PyInstaller).

    * Source checkout: two levels above this file (``core/utils/paths.py``).
    * Frozen bundle:   the directory that contains the ``.exe`` file,
                       i.e. ``dist/CyberOpsSuite/modules/<Name>/`` — NOT
                       the temporary ``_MEIPASS`` folder. This makes it
                       possible to ship seed data (JSON, assets) next to
                       the executable.
    """
    if is_frozen():
        # In a PyInstaller onedir bundle, sys.executable is the real
        # path to the .exe. Its parent is the folder containing the
        # bundle, which is where we expect user-visible seed files.
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parents[2]


def bundle_root() -> Path:
    """Return the temporary PyInstaller extraction folder (``_MEIPASS``).

    Falls back to :func:`project_root` when not frozen. Use this when
    you need a path to *bundled* read-only resources (assets, icons,
    templates) rather than user-editable data.
    """
    if is_frozen():
        meipass = getattr(sys, "_MEIPASS", None)
        if meipass:
            return Path(meipass)
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parents[2]


def exports_dir() -> Path:
    """Return the project-level ``exports/`` directory (created if missing).

    In a frozen bundle this resolves next to the executable, so the
    user can find the files without digging into ``_MEIPASS``.
    """
    path = project_root() / "exports"
    try:
        path.mkdir(parents=True, exist_ok=True)
    except OSError:
        # If the install folder is read-only, fall back to user config.
        path = config_root("exports")
    return path


def logs_dir() -> Path:
    """Return ``exports/logs/`` (created if missing)."""
    path = exports_dir() / "logs"
    try:
        path.mkdir(parents=True, exist_ok=True)
    except OSError:
        path = config_root("logs")
    return path


def assets_dir() -> Path:
    """Return the ``assets/`` directory (read-only, bundled)."""
    candidate = project_root() / "assets"
    if candidate.is_dir():
        return candidate
    # Fall back to the bundled copy inside _MEIPASS.
    return bundle_root() / "assets"


def bin_dir() -> Path:
    """Return the ``bin/`` directory (read-only, bundled)."""
    candidate = project_root() / "bin"
    if candidate.is_dir():
        return candidate
    return bundle_root() / "bin"