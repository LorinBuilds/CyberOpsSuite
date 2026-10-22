"""Window icon helpers shared by all CyberOpsSuite GUIs.

Every module can call :func:`apply_window_icon` to set its taskbar and
title-bar icon. Missing icon files are silently ignored so the app
still runs during development.

Icon lookup order
-----------------
1. ``assets/icons/<name>.ico`` — Windows multi-resolution ICO.
2. ``assets/icons/<name>_<size>.png`` — PNGs in every available size.
3. ``assets/icons/<name>.png`` — single fallback PNG.

Both ``lowercase`` and ``PascalCase`` filenames are accepted, so the
existing ``cyberopssuite.ico`` and ``CyberOpsSuite_16x16.png`` both work.
"""

from __future__ import annotations

import sys
from pathlib import Path


#: Preferred icon sizes, largest first.
_PREFERRED_SIZES: tuple[int, ...] = (256, 128, 64, 48, 32, 16)


def _project_root() -> Path:
    """Return the project root regardless of how the app is launched."""
    if getattr(sys, "frozen", False):
        # PyInstaller: everything is unpacked under _MEIPASS.
        return Path(getattr(sys, "_MEIPASS", Path(sys.executable).parent))
    return Path(__file__).resolve().parents[2]


def _icon_dir() -> Path:
    """Return the assets/icons directory, or an empty path if missing."""
    candidates = [
        _project_root() / "assets" / "icons",
        Path(__file__).resolve().parents[2] / "assets" / "icons",
    ]
    for candidate in candidates:
        if candidate.is_dir():
            return candidate
    return candidates[0]


def _find_files(base: Path, name: str, suffix: str) -> list[Path]:
    """Find every icon file matching *name* with *suffix*.

    Accepts both ``name`` and ``Name`` capitalisations so that existing
    mixed-case assets (``CyberOpsSuite_16x16.png``) continue to work.
    """
    patterns = {
        f"{name}{suffix}",
        f"{name.capitalize()}{suffix}",
        f"{name.upper()}{suffix}",
    }
    found: list[Path] = []
    for pattern in patterns:
        try:
            found.extend(base.glob(pattern))
        except OSError:
            continue

    # De-duplicate while preserving order.
    seen: set[Path] = set()
    unique: list[Path] = []
    for path in found:
        if path not in seen:
            seen.add(path)
            unique.append(path)
    return unique


def _sorted_pngs(base: Path, name: str) -> list[Path]:
    """Return PNG files for *name*, largest first, by parsing size hints."""
    files = _find_files(base, name, "*.png")

    def size_key(path: Path) -> int:
        stem = path.stem
        # Match "…_16x16" / "…16x16" / "…-16x16".
        for token in stem.replace("-", "_").split("_"):
            if "x" in token:
                left, _, right = token.partition("x")
                if left.isdigit() and right.isdigit():
                    return max(int(left), int(right))
        if stem.lower() == name.lower():
            return 512  # plain "<name>.png" — treat as the largest.
        return 0

    return sorted(files, key=size_key, reverse=True)


def apply_window_icon(window, name: str = "cyberopssuite") -> None:
    """Set *window*'s icon to the best available assets/icons entry.

    On Windows the ICO is applied first (multi-resolution taskbar icon),
    then every PNG is applied through ``iconphoto`` as a fallback because
    CustomTkinter sometimes ignores ``iconbitmap`` alone.

    All errors are swallowed: a missing icon must never prevent the app
    from starting.
    """
    try:
        import tkinter as tk
    except Exception:
        return

    try:
        base = _icon_dir()
        if not base.is_dir():
            return

        # Keep strong references on the window so Tk does not garbage-
        # collect the PhotoImage objects.
        refs: list = getattr(window, "_icon_refs", [])
        if not isinstance(refs, list):
            refs = []
        window._icon_refs = refs

        # 1) ICO — Windows multi-resolution, used by the taskbar.
        for ico in _find_files(base, name, ".ico"):
            try:
                window.iconbitmap(str(ico))
                break
            except Exception:
                continue

        # 2) Every PNG, largest first (Tk uses the first one it accepts).
        for png in _sorted_pngs(base, name):
            try:
                photo = tk.PhotoImage(file=str(png))
            except Exception:
                continue
            try:
                window.iconphoto(True, photo)
                refs.append(photo)
            except Exception:
                continue

        window._icon_refs = refs
    except Exception:
        # Never let an icon problem break the application.
        pass