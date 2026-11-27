"""Theme and icon helpers.

Inside CyberOpsSuite the real ``core.theme`` / ``core.utils`` modules are used.
When ThreatGuard runs on its own (no ``core`` package next to it) these
built-in equivalents are used, so the program starts either way.
"""
from __future__ import annotations

try:  # running inside CyberOpsSuite
    from core.theme import Colors, Fonts, Spacing  # type: ignore
    from core.utils.icons import apply_window_icon  # type: ignore
    try:
        from core.utils.window_icons import apply_dialog_icon  # type: ignore
    except Exception:  # older installs without the helper
        apply_dialog_icon = apply_window_icon
    STANDALONE = False
except Exception:  # standalone
    STANDALONE = True

    class Colors:  # noqa: D101 - simple palette
        bg = "#0b1220"
        bg_alt = "#0f172a"
        surface = "#111c30"
        surface_alt = "#1e293b"
        border = "#263247"
        text = "#e2e8f0"
        text_soft = "#cbd5e1"
        text_muted = "#94a3b8"
        text_dim = "#64748b"
        text_strong = "#f8fafc"
        primary = "#2563eb"
        primary_hover = "#1d4ed8"
        neutral = "#334155"
        neutral_hover = "#475569"
        info = "#38bdf8"
        success = "#10b981"
        success_hover = "#059669"
        success_text = "#34d399"
        danger = "#dc2626"
        danger_hover = "#b91c1c"
        danger_text = "#f87171"
        warning_text = "#fbbf24"

    class Fonts:  # noqa: D101 - tuples are accepted by every Tk / CustomTkinter widget
        @staticmethod
        def title(size: int = 20, bold: bool = True):
            return ("Segoe UI", size, "bold" if bold else "normal")

        @staticmethod
        def badge(size: int = 10, bold: bool = True):
            return ("Segoe UI", size, "bold" if bold else "normal")

        @staticmethod
        def label(size: int = 11, bold: bool = False):
            return ("Segoe UI", size, "bold" if bold else "normal")

        @staticmethod
        def mono(size: int = 11, bold: bool = False):
            return ("Consolas", size, "bold" if bold else "normal")

    class Spacing:  # noqa: D101
        PAGE_PADX = 22
        PAGE_PADY = 18
        RADIUS_CARD = 12
        RADIUS_INPUT = 8
        RADIUS_BUTTON = 8
        INPUT_HEIGHT = 38
        BUTTON_HEIGHT = 38

    def apply_window_icon(_window) -> None:
        return None

    def apply_dialog_icon(_window) -> None:
        return None
