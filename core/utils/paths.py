"""Platform-specific paths shared by all CyberOpsSuite modules.

Two locations are used:

1. **Data root** (writable) — profiles, settings, logs, exports.
   Default location:

   * Windows: ``%APPDATA%\\CyberOpsSuite\\``
   * Linux:   ``$XDG_CONFIG_HOME/CyberOpsSuite/``
                (``~/.config/CyberOpsSuite/`` if unset)

   The installer can override this by writing a ``config.ini`` next to
   the executable:

   .. code-block:: ini

       [paths]
       data_dir=D:\\CyberOpsData
       logs_dir=D:\\CyberOpsData\\logs
       version=1.0.0.0

   When running from a source checkout (not frozen), the ``config.ini``
   is ignored and the platform default is used.

2. **Bundle root** (read-only) — assets, icons, binaries (``bin/``).
   In a frozen PyInstaller build, this is the ``_MEIPASS`` folder.
   In a source checkout, this is the project root.

Only Windows and Linux are officially supported. macOS is not a
target platform, but the Linux branch is used as a safe fallback.
"""

from __future__ import annotations

import configparser
import os
import sys
from pathlib import Path


#: Top-level folder shared by every module.
SUITE_DIR_NAME = "CyberOpsSuite"


# ---------------------------------------------------------------- frozen / root

def is_frozen() -> bool:
    """Return True when running inside a PyInstaller bundle."""
    return bool(getattr(sys, "frozen", False))


def app_dir() -> Path:
    """Return the directory that contains the running ``.exe``.

    * Frozen bundle: the folder holding ``CyberOpsSuite.exe``
      (i.e. ``C:\\Program Files\\CyberOpsSuite\\`` after install).
    * Source checkout: the project root (two levels above this file).
    """
    if is_frozen():
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parents[2]


def project_root() -> Path:
    """Backwards-compatible alias for :func:`app_dir`."""
    return app_dir()


def bundle_root() -> Path:
    """Return the temporary PyInstaller extraction folder (``_MEIPASS``).

    Falls back to :func:`app_dir` when not frozen. Use this for
    *bundled* read-only resources (assets, icons, templates, ``bin/``).
    """
    if is_frozen():
        meipass = getattr(sys, "_MEIPASS", None)
        if meipass:
            return Path(meipass)
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parents[2]


# ---------------------------------------------------------------- config.ini

def _read_config_ini() -> dict[str, str]:
    """Return the ``[paths]`` section of ``config.ini``, if present.

    Only honoured when running as a frozen bundle — in a source
    checkout we always use the platform default so developers don't
    accidentally write into the install folder.
    """
    if not is_frozen():
        return {}

    cfg_path = app_dir() / "config.ini"
    if not cfg_path.is_file():
        return {}

    parser = configparser.ConfigParser()
    try:
        parser.read(cfg_path, encoding="utf-8")
    except (OSError, configparser.Error):
        return {}

    if "paths" not in parser:
        return {}
    return dict(parser["paths"])


# ---------------------------------------------------------------- data root

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


def data_root() -> Path:
    """Return (and create) the writable data root.

    Priority:

    1. ``config.ini`` -> ``[paths] data_dir``  (only when frozen)
    2. ``%APPDATA%\\CyberOpsSuite``             (Windows)
    3. ``~/.config/CyberOpsSuite``             (Linux)

    Guaranteed to exist and be writable.
    """
    cfg = _read_config_ini()

    candidates: list[Path] = []
    if cfg.get("data_dir"):
        candidates.append(Path(cfg["data_dir"]))
    candidates.append(_platform_base() / SUITE_DIR_NAME)

    for path in candidates:
        try:
            path.mkdir(parents=True, exist_ok=True)
            # Verify we can actually write there.
            probe = path / ".write_probe"
            probe.write_text("ok", encoding="utf-8")
            probe.unlink(missing_ok=True)
            return path
        except OSError:
            continue

    # Last resort: temp dir. Should never be reached in practice.
    import tempfile
    fallback = Path(tempfile.gettempdir()) / SUITE_DIR_NAME
    fallback.mkdir(parents=True, exist_ok=True)
    return fallback


def logs_root() -> Path:
    """Return (and create) the writable logs root.

    Uses ``config.ini`` -> ``[paths] logs_dir`` when available,
    otherwise ``<data_root>/logs``.
    """
    cfg = _read_config_ini()
    if cfg.get("logs_dir"):
        path = Path(cfg["logs_dir"])
    else:
        path = data_root() / "logs"
    try:
        path.mkdir(parents=True, exist_ok=True)
    except OSError:
        path = data_root() / "logs"
        path.mkdir(parents=True, exist_ok=True)
    return path


# ---------------------------------------------------------------- per-module

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
    path = data_root() / module_name
    path.mkdir(parents=True, exist_ok=True)
    return path


def config_root_quiet(module_name: str) -> Path:
    """Same as :func:`config_root` but does not create the directory.

    Useful for read-only checks (e.g. showing the path in About dialogs)
    or for tests that only need the path string.
    """
    cfg = _read_config_ini()
    if cfg.get("data_dir"):
        base = Path(cfg["data_dir"])
    else:
        base = _platform_base() / SUITE_DIR_NAME
    return base / module_name


# ---------------------------------------------------------------- exports / logs

def exports_dir() -> Path:
    """Return the writable ``exports/`` directory (created if missing).

    Lives under the data root, so it works after install even when the
    program folder (``C:\\Program Files\\...``) is read-only.
    """
    path = data_root() / "exports"
    path.mkdir(parents=True, exist_ok=True)
    return path


def logs_dir() -> Path:
    """Return the writable ``logs/`` directory (created if missing)."""
    path = logs_root()
    path.mkdir(parents=True, exist_ok=True)
    return path


# ---------------------------------------------------------------- bundled resources

def assets_dir() -> Path:
    """Return the ``assets/`` directory (read-only, bundled).

    Prefers ``_MEIPASS/assets`` when frozen, otherwise the source
    checkout's ``assets/`` folder.
    """
    if is_frozen():
        bundled = bundle_root() / "assets"
        if bundled.is_dir():
            return bundled
    candidate = app_dir() / "assets"
    if candidate.is_dir():
        return candidate
    return bundle_root() / "assets"


def bin_dir() -> Path:
    """Return the ``bin/`` directory (read-only, bundled).

    Prefers ``_MEIPASS/bin`` when frozen (PyInstaller 6+ puts data
    folders inside ``_internal/``, which is what ``_MEIPASS`` points
    to), otherwise the source checkout's ``bin/`` folder.
    """
    if is_frozen():
        bundled = bundle_root() / "bin"
        if bundled.is_dir():
            return bundled
    candidate = app_dir() / "bin"
    if candidate.is_dir():
        return candidate
    return bundle_root() / "bin"


def data_dir() -> Path:
    """Return the ``data/`` directory (read-only seed data, bundled).

    This is for *seed* files shipped with the program (e.g. default
    profiles). Writable user data must go through :func:`data_root`.
    """
    if is_frozen():
        bundled = bundle_root() / "data"
        if bundled.is_dir():
            return bundled
    candidate = app_dir() / "data"
    if candidate.is_dir():
        return candidate
    return bundle_root() / "data"


# ---------------------------------------------------------------- module exe

def module_exe(module_name: str) -> Path:
    """Return the path to a bundled module executable.

    Layout after install::

        C:\\Program Files\\CyberOpsSuite\\
            CyberOpsSuite.exe
            modules\\
                FirewallManager\\FirewallManager.exe
                ...

    In a source checkout this points to a non-existent path; the
    dashboard falls back to ``python -m`` in that case.
    """
    return app_dir() / "modules" / module_name / f"{module_name}.exe"


# ---------------------------------------------------------------- misc

def is_frozen_pyinstaller() -> bool:
    """Alias for :func:`is_frozen` kept for backwards compatibility."""
    return is_frozen()