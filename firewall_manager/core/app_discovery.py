"""Cross-platform discovery of installed applications with icons.

Performance notes (v2):
* Windows: ONE PowerShell process resolves every Start-Menu shortcut and ONE
  more extracts every missing icon (the old code spawned one process per app).
* Data is exchanged through UTF-8 temp files, so non-ASCII app names and paths
  with quotes/apostrophes no longer break the scan.
* Linux: the icon index is built once instead of an ``rglob`` per application.
* A rescan keeps the Allow/Block policies the user already set.
"""

from __future__ import annotations

import base64
import hashlib
import json
import ntpath
import os
import platform
import re
import shlex
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, asdict, fields
from datetime import datetime
from pathlib import Path
from typing import Iterable

from core.utils.paths import config_root


APP_DIR_NAME = "FirewallManager"
CACHE_FILE = "apps_cache.json"
ICON_CACHE_DIR = "app_icons"
CACHE_VERSION = 3          # bump -> old caches trigger an automatic rescan

_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


# ------------------------------------------------------------------ model

@dataclass
class AppEntry:
    app_id: str
    name: str
    executable: str
    icon_path: str = ""
    source: str = ""
    policy: str = "default"
    enabled: bool = True

    def to_dict(self) -> dict:
        return asdict(self)


_ENTRY_FIELDS = {f.name for f in fields(AppEntry)}


def _entry_from_dict(item: dict) -> AppEntry | None:
    """Build an AppEntry from a cache row, ignoring unknown/missing keys."""
    if not isinstance(item, dict):
        return None
    clean = {k: v for k, v in item.items() if k in _ENTRY_FIELDS}
    if not clean.get("app_id") or not clean.get("executable"):
        return None
    clean.setdefault("name", Path(str(clean["executable"])).stem)
    try:
        entry = AppEntry(**clean)
    except TypeError:
        return None
    if entry.policy not in ("default", "allow", "block"):   # "ask" was removed
        entry.policy = "default"
    return entry


# ------------------------------------------------------------------ helpers

def _cache_dir() -> Path:
    d = config_root(APP_DIR_NAME) / ICON_CACHE_DIR
    d.mkdir(parents=True, exist_ok=True)
    return d


def _cache_file() -> Path:
    return config_root(APP_DIR_NAME) / CACHE_FILE


def _stable_id(exe: str) -> str:
    return hashlib.sha1(exe.lower().encode("utf-8", "ignore")).hexdigest()[:16]


# --------------------------------------------------------------- Windows
#
# Sources (in priority order, de-duplicated by executable path):
#   1. Start-Menu shortcuts   (resolved with ONE PowerShell process)
#   2. Registry "Uninstall"   (friendly DisplayName + DisplayIcon exe)
#   3. Registry "App Paths"   (chrome.exe, firefox.exe, ...)
# The registry sources need no PowerShell, so the list is never empty just
# because PowerShell is blocked / slow on a given machine.

# Filled by every scan; shown in the GUI when nothing was found.
LAST_SCAN: dict = {}


def scan_summary() -> str:
    d = LAST_SCAN
    if not d:
        return "No scan has run yet."
    parts = [
        f"Start Menu shortcuts: {d.get('lnk_found', 0)} "
        f"(usable .exe: {d.get('lnk_exe', 0)})",
        f"registry apps: {d.get('registry', 0)}",
        f"program folders: {d.get('folders', 0)}",
    ]
    if d.get("ps_error"):
        parts.append(f"PowerShell problem: {d['ps_error']}")
    return " | ".join(parts)


_PS_RESOLVE_LNK = r"""
$ErrorActionPreference = 'SilentlyContinue'
$paths = @(Get-Content -LiteralPath $env:FWM_IN -Raw -Encoding UTF8 | ConvertFrom-Json)
$shell = New-Object -ComObject WScript.Shell
$out = New-Object System.Collections.ArrayList
foreach ($p in $paths) {
    try {
        $s = $shell.CreateShortcut([string]$p)
        [void]$out.Add(@{ path = [string]$p; target = [string]$s.TargetPath })
    } catch { }
}
$json = ConvertTo-Json -InputObject @($out) -Compress -Depth 3
[System.IO.File]::WriteAllText($env:FWM_OUT, $json, (New-Object System.Text.UTF8Encoding($false)))
"""

_PS_EXTRACT_ICONS = r"""
$ErrorActionPreference = 'SilentlyContinue'
Add-Type -AssemblyName System.Drawing
$items = @(Get-Content -LiteralPath $env:FWM_IN -Raw -Encoding UTF8 | ConvertFrom-Json)
foreach ($i in $items) {
    try {
        $icon = [System.Drawing.Icon]::ExtractAssociatedIcon([string]$i.exe)
        if ($icon) {
            $bmp = $icon.ToBitmap()
            $bmp.Save([string]$i.out, [System.Drawing.Imaging.ImageFormat]::Png)
            $bmp.Dispose()
            $icon.Dispose()
        }
    } catch { }
}
"""


def _run_powershell(script: str, env_extra: dict[str, str],
                    timeout: int) -> tuple[bool, str]:
    """Run a script through -EncodedCommand (not affected by the script
    execution policy).  Paths travel in environment variables.

    Returns (ok, short_error_text).
    """
    encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    env = os.environ.copy()
    env.update(env_extra)
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive",
             "-EncodedCommand", encoded],
            capture_output=True, timeout=timeout,
            creationflags=_NO_WINDOW, env=env,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return False, f"{type(exc).__name__}: {exc}"

    if result.returncode == 0:
        return True, ""
    err = result.stderr.decode("utf-8", "replace").strip()
    return False, (err or f"exit code {result.returncode}")[:300]


def _batch_resolve_lnks(lnk_paths: list[str]) -> dict[str, str]:
    """Resolve many .lnk files in ONE PowerShell call -> {lnk_path: target}."""
    with tempfile.TemporaryDirectory(prefix="fwm_") as tmp:
        in_file = Path(tmp) / "in.json"
        out_file = Path(tmp) / "out.json"
        in_file.write_text(json.dumps(lnk_paths), encoding="utf-8")

        ok, err = _run_powershell(
            _PS_RESOLVE_LNK,
            {"FWM_IN": str(in_file), "FWM_OUT": str(out_file)},
            timeout=120,
        )
        if not ok:
            LAST_SCAN["ps_error"] = err
            return {}
        try:
            data = json.loads(out_file.read_text(encoding="utf-8-sig"))
        except (OSError, ValueError) as exc:
            LAST_SCAN["ps_error"] = f"no/invalid result file ({exc})"
            return {}

    if isinstance(data, dict):
        data = [data]
    result: dict[str, str] = {}
    for item in data or []:
        if isinstance(item, dict) and item.get("path"):
            result[item["path"]] = item.get("target") or ""
    return result


def _batch_extract_icons(pairs: list[tuple[str, Path]]) -> None:
    """Extract many icons in ONE PowerShell call. pairs = [(exe, out_png)]."""
    if not pairs:
        return
    with tempfile.TemporaryDirectory(prefix="fwm_") as tmp:
        in_file = Path(tmp) / "icons.json"
        in_file.write_text(
            json.dumps([{"exe": exe, "out": str(out)} for exe, out in pairs]),
            encoding="utf-8",
        )
        _run_powershell(_PS_EXTRACT_ICONS, {"FWM_IN": str(in_file)}, timeout=180)


# ---- registry ------------------------------------------------------------

def _clean_path(value) -> str:
    """'"C:\\x\\a.exe",0' / 'C:\\x\\a.exe /S' / '%ProgramFiles%\\a.ico' -> path."""
    if not value:
        return ""
    v = os.path.expandvars(str(value).strip())
    if v.startswith('"'):
        end = v.find('"', 1)
        v = v[1:end] if end > 0 else v[1:]
    else:
        m = re.match(r"(.+?\.(?:exe|ico|dll))(?=$|[\s,])", v, re.I)
        v = m.group(1) if m else re.sub(r",\s*-?\d+$", "", v)
    return v.strip().strip('"')


def _clean_exe(value) -> str:
    v = _clean_path(value)
    return os.path.normpath(v) if v.lower().endswith(".exe") else ""


_NOISE_EXE = re.compile(
    r"^(unins\w*|uninstall\w*|setup\w*|install\w*|vc_?redist\S*|vcredist\S*|"
    r"dxsetup|crashpad\w*|crashreport\w*|\w*updater|update|notification_helper)$",
    re.I,
)
_SKIP_DIRS = {
    "common files", "windowsapps", "windows defender", "windows nt",
    "reference assemblies", "dotnet", "package cache", "installer",
    "node_modules", "__pycache__", "$recycle.bin", "windows mail",
    "windows photo viewer", "windows media player", "internet explorer",
}


def _bad_dir(path: str) -> bool:
    low = path.lower().replace("/", "\\")
    return any(x in low for x in ("\\windows\\", "\\package cache", "\\installer"))


def _pick_exe(dirs: list[str], name: str) -> str:
    """Best guess for an app's main exe inside its install folder(s)."""
    want = re.sub(r"[^a-z0-9]", "", name.lower())
    best: tuple[int, int, str] | None = None
    for d in dirs:
        if not d or not os.path.isdir(d) or _bad_dir(d):
            continue
        candidates: list[str] = []
        try:
            with os.scandir(d) as it:
                subdirs = []
                for e in it:
                    if e.is_file() and e.name.lower().endswith(".exe"):
                        candidates.append(e.path)
                    elif e.is_dir() and e.name.lower() in ("bin", "app", "x64", "win64"):
                        subdirs.append(e.path)
            if not candidates:                       # e.g. <install>\bin\app.exe
                for sd in subdirs:
                    with os.scandir(sd) as it:
                        candidates += [e.path for e in it
                                       if e.is_file() and e.name.lower().endswith(".exe")]
        except OSError:
            continue
        for path in candidates:
            stem = ntpath.basename(path)[:-4]
            if _NOISE_EXE.match(stem):
                continue
            norm = re.sub(r"[^a-z0-9]", "", stem.lower())
            match = 1 if (len(norm) >= 3 and (norm in want or want in norm)) else 0
            try:
                size = os.path.getsize(path)
            except OSError:
                size = 0
            key = (match, size, path)
            if best is None or key[:2] > best[:2]:
                best = key
    return best[2] if best else ""


def _discover_registry() -> list[tuple[str, str, str, list[str]]]:
    """Return [(name, exe_or_empty, source, candidate_install_dirs)]."""
    try:
        import winreg
    except ImportError:
        return []

    def open_key(hive, path, view):
        try:
            return winreg.OpenKey(hive, path, 0, winreg.KEY_READ | view)
        except OSError:
            return None

    def subkeys(key):
        i = 0
        while True:
            try:
                yield winreg.EnumKey(key, i)
            except OSError:
                return
            i += 1

    def value(key, name):
        try:
            return winreg.QueryValueEx(key, name)[0]
        except OSError:
            return None

    base = r"SOFTWARE\Microsoft\Windows\CurrentVersion"
    uninstall_rows: list[tuple[str, str, str, list[str]]] = []
    app_path_rows: list[tuple[str, str, str, list[str]]] = []

    for hive in (winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER):
        for view in (winreg.KEY_WOW64_64KEY, winreg.KEY_WOW64_32KEY):
            root = open_key(hive, base + r"\Uninstall", view)
            if root is not None:
                with root:
                    for sub in subkeys(root):
                        sk = open_key(hive, base + "\\Uninstall\\" + sub, view)
                        if sk is None:
                            continue
                        with sk:
                            name = value(sk, "DisplayName")
                            if (not name or value(sk, "SystemComponent") == 1
                                    or value(sk, "ParentKeyName")):
                                continue
                            icon = _clean_path(value(sk, "DisplayIcon"))
                            exe = os.path.normpath(icon) if icon.lower().endswith(".exe") else ""
                            dirs: list[str] = []
                            loc = _clean_path(value(sk, "InstallLocation"))
                            if loc:
                                dirs.append(loc)
                            if icon:
                                dirs.append(ntpath.dirname(icon))
                            unins = _clean_path(value(sk, "UninstallString"))
                            if unins.lower().endswith(".exe") and "msiexec" not in unins.lower():
                                dirs.append(ntpath.dirname(unins))
                            uninstall_rows.append((str(name), exe, "uninstall", dirs))

            root = open_key(hive, base + r"\App Paths", view)
            if root is not None:
                with root:
                    for sub in subkeys(root):
                        if not sub.lower().endswith(".exe"):
                            continue
                        sk = open_key(hive, base + "\\App Paths\\" + sub, view)
                        if sk is None:
                            continue
                        with sk:
                            exe = _clean_exe(value(sk, ""))
                            if exe:
                                stem = sub[:-4]
                                app_path_rows.append(
                                    (stem[:1].upper() + stem[1:], exe, "apppaths", [])
                                )

    return uninstall_rows + app_path_rows


# ---- folder crawl ----------------------------------------------------------

def _scan_folders(limit: int = 4000, max_depth: int = 3) -> list[str]:
    """Every non-noise .exe under Program Files & friends (depth-limited)."""
    roots: list[str] = []
    for var in ("ProgramFiles", "ProgramW6432", "ProgramFiles(x86)"):
        v = os.environ.get(var)
        if v:
            roots.append(v)
    local = os.environ.get("LOCALAPPDATA")
    if local:
        roots.append(os.path.join(local, "Programs"))

    seen_roots: set[str] = set()
    found: list[str] = []
    for root in roots:
        key = root.lower().rstrip("\\/")
        if key in seen_roots or not os.path.isdir(root):
            continue
        seen_roots.add(key)
        base_depth = root.rstrip("\\/").count(os.sep)
        for dirpath, dirnames, filenames in os.walk(root):
            depth = dirpath.rstrip("\\/").count(os.sep) - base_depth
            if depth >= max_depth:
                dirnames[:] = []
            else:
                dirnames[:] = [d for d in dirnames if d.lower() not in _SKIP_DIRS]
            for fname in filenames:
                if fname.lower().endswith(".exe") and not _NOISE_EXE.match(fname[:-4]):
                    found.append(os.path.join(dirpath, fname))
            if len(found) >= limit:
                return found
    return found


def _discover_windows() -> list[AppEntry]:
    LAST_SCAN.clear()
    entries: list[AppEntry] = []
    seen: set[str] = set()

    def add(name: str, target: str, source: str) -> bool:
        if not target:
            return False
        base = ntpath.basename(target).lower()
        if (not base.endswith(".exe") or base.startswith("unins")
                or name.lower().startswith("uninstall")):
            return False
        key = target.lower()
        if key in seen or not os.path.isfile(target):
            return False
        seen.add(key)
        entries.append(AppEntry(
            app_id=_stable_id(target),
            name=name.strip() or ntpath.basename(target),
            executable=target, source=source,
        ))
        return True

    # 1) Start-Menu shortcuts
    roots = [
        Path(os.environ.get("ProgramData", r"C:\ProgramData"))
        / "Microsoft" / "Windows" / "Start Menu" / "Programs",
    ]
    appdata = os.environ.get("APPDATA")
    if appdata:
        roots.append(
            Path(appdata) / "Microsoft" / "Windows" / "Start Menu" / "Programs"
        )
    lnk_paths: list[str] = []
    for root in roots:
        if root.exists():
            lnk_paths.extend(str(p) for p in root.rglob("*.lnk"))

    LAST_SCAN["lnk_found"] = len(lnk_paths)
    LAST_SCAN["lnk_exe"] = 0
    if lnk_paths:
        for lnk_path, target in _batch_resolve_lnks(lnk_paths).items():
            if add(Path(lnk_path).stem, target, "startmenu"):
                LAST_SCAN["lnk_exe"] += 1

    # 2) registry: Uninstall (friendly names) + App Paths
    LAST_SCAN["registry"] = 0
    try:
        for name, exe, source, dirs in _discover_registry():
            if (not exe or ntpath.basename(exe).lower().startswith("unins")
                    or not os.path.isfile(exe)):
                exe = _pick_exe(dirs, name) if dirs else ""
            if add(name, exe, source):
                LAST_SCAN["registry"] += 1
    except Exception as exc:                      # noqa: BLE001
        LAST_SCAN["ps_error"] = (LAST_SCAN.get("ps_error", "")
                                 + f" registry: {exc}").strip()

    # 3) crawl the program folders: catches everything the above missed
    LAST_SCAN["folders"] = 0
    try:
        for path in _scan_folders():
            stem = ntpath.basename(path)[:-4]
            parent = ntpath.basename(ntpath.dirname(path))
            label = stem if (not parent or parent.lower() == stem.lower()) else f"{stem} ({parent})"
            if add(label, path, "folder"):
                LAST_SCAN["folders"] += 1
    except Exception as exc:                      # noqa: BLE001
        LAST_SCAN["ps_error"] = (LAST_SCAN.get("ps_error", "")
                                 + f" folders: {exc}").strip()

    entries.sort(key=lambda e: e.name.lower())
    return entries


# ----------------------------------------------------------------- Linux

_FIELD_CODE = re.compile(r"%[a-zA-Z%]")


def _discover_linux() -> list[AppEntry]:
    entries: list[AppEntry] = []
    seen: set[str] = set()

    data_dirs = os.environ.get(
        "XDG_DATA_DIRS", "/usr/share:/usr/local/share"
    ).split(":")
    dirs = [Path(d) / "applications" for d in data_dirs if d]
    user_apps = Path.home() / ".local" / "share" / "applications"
    if user_apps.exists():
        dirs.insert(0, user_apps)

    for apps_dir in dirs:
        if not apps_dir.exists():
            continue
        for desktop in apps_dir.rglob("*.desktop"):
            try:
                info = _parse_desktop(desktop)
            except Exception:
                continue
            if not info or not info.get("exec"):
                continue
            exe = info["exec"]
            if exe in seen:
                continue
            seen.add(exe)
            entries.append(AppEntry(
                app_id=_stable_id(exe),
                name=info.get("name") or desktop.stem,
                executable=exe,
                icon_path=info.get("icon", ""),
                source="desktop",
            ))

    entries.sort(key=lambda e: e.name.lower())
    return entries


def _parse_desktop(path: Path) -> dict:
    name = exec_line = icon = ""
    hidden = False
    app_type = "Application"
    in_entry = False

    for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw.strip()
        if line == "[Desktop Entry]":
            in_entry = True
            continue
        if line.startswith("["):
            in_entry = False
        if not in_entry or "=" not in line:
            continue
        k, _, v = line.partition("=")
        if k == "Name" and not name:
            name = v
        elif k == "Exec" and not exec_line:
            exec_line = v
        elif k == "Icon" and not icon:
            icon = v
        elif k in ("NoDisplay", "Hidden") and v.strip().lower() == "true":
            hidden = True
        elif k == "Type":
            app_type = v.strip()

    if hidden or app_type != "Application" or not exec_line:
        return {}

    try:
        parts = shlex.split(_FIELD_CODE.sub("", exec_line))
    except ValueError:
        parts = _FIELD_CODE.sub("", exec_line).split()
    if not parts:
        return {}

    exe = parts[0]
    resolved = shutil.which(exe)
    return {"name": name, "exec": resolved or exe, "icon": icon}


_ICON_INDEX: dict[str, str] | None = None


def _icon_score(dirpath: str) -> int:
    """Prefer icon sizes close to 48px."""
    m = re.search(r"(\d+)x\d+", dirpath)
    return -abs(int(m.group(1)) - 48) if m else -10


def _build_icon_index() -> dict[str, str]:
    index: dict[str, str] = {}
    rank: dict[str, int] = {}
    roots = [
        Path.home() / ".local" / "share" / "icons",
        Path("/usr/share/icons"),
        Path("/usr/share/pixmaps"),
    ]
    for base in roots:
        if not base.exists():
            continue
        for dirpath, _dirs, files in os.walk(base):
            score = _icon_score(dirpath)
            for fname in files:
                if not fname.endswith(".png"):   # PIL can't read svg/xpm
                    continue
                stem = fname[:-4]
                if score > rank.get(stem, -10_000):
                    rank[stem] = score
                    index[stem] = os.path.join(dirpath, fname)
    return index


def _extract_icon_linux(icon_name: str, app_id: str) -> str:
    global _ICON_INDEX
    if not icon_name:
        return ""
    if icon_name.startswith("/"):
        return icon_name if icon_name.endswith(".png") and Path(icon_name).is_file() else ""
    if _ICON_INDEX is None:
        _ICON_INDEX = _build_icon_index()
    return _ICON_INDEX.get(icon_name, "")


# --------------------------------------------------------------- public

def _read_cache() -> tuple[list[AppEntry] | None, int]:
    cache = _cache_file()
    if not cache.exists():
        return None, 0
    try:
        data = json.loads(cache.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return None, 0
        rows = data.get("apps", [])
        apps = [e for e in (_entry_from_dict(r) for r in rows) if e]
        return apps, int(data.get("version", 1))
    except (OSError, ValueError, TypeError):
        return None, 0


def load_cached_apps() -> list[AppEntry] | None:
    """Return cached apps, or None when there is no usable cache."""
    return _read_cache()[0]


def discover_apps(*, use_cache: bool = True) -> list[AppEntry]:
    previous, version = _read_cache()
    # An old-format cache is still used for its policies, but triggers a rescan.
    if use_cache and previous and version >= CACHE_VERSION:
        return previous

    system = platform.system().lower()
    if system == "windows":
        entries = _discover_windows()
        icon_dir = _cache_dir()
        missing: list[tuple[str, Path]] = []
        for e in entries:
            png = icon_dir / f"{e.app_id}.png"
            if not png.exists():
                missing.append((e.executable, png))
        _batch_extract_icons(missing)          # one process for all icons
        for e in entries:
            png = icon_dir / f"{e.app_id}.png"
            e.icon_path = str(png) if png.exists() else ""
    elif system == "linux":
        entries = _discover_linux()
        for e in entries:
            e.icon_path = _extract_icon_linux(e.icon_path, e.app_id)
    else:
        entries = []

    # Keep the policies the user already set (a rescan must not wipe them).
    if previous:
        old = {a.app_id: a for a in previous}
        new_ids = set()
        for e in entries:
            new_ids.add(e.app_id)
            prev = old.get(e.app_id)
            if prev:
                e.policy, e.enabled = prev.policy, prev.enabled
        # Apps that disappeared from the Start Menu but still carry a rule.
        for app_id, prev in old.items():
            if app_id not in new_ids and prev.policy in ("allow", "block"):
                entries.append(prev)
        entries.sort(key=lambda e: e.name.lower())

    if entries:
        _save_cache(entries)
    return entries


def _save_cache(entries: Iterable[AppEntry]) -> None:
    payload = {
        "version": CACHE_VERSION,
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "apps": [e.to_dict() for e in entries],
    }
    target = _cache_file()
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_suffix(".tmp")
    tmp.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    os.replace(tmp, target)
