"""Unified visual theme for CyberOpsSuite."""

from __future__ import annotations


class Colors:
    # --------------------------------------------------------------- surfaces
    bg = "#0B0F14"
    bg_alt = "#0F172A"           # alias used by firewall_manager
    surface = "#111827"
    surface_alt = "#1E293B"
    surface_raised = "#172033"

    # ---------------------------------------------------------------- borders
    border = "#263449"
    border_light = "#334155"

    # ------------------------------------------------------------------- text
    text = "#E5E7EB"
    text_strong = "#F8FAFC"      # for important headings
    text_soft = "#CBD5E1"        # between text and muted
    text_very_soft = "#D1D5DB"   # slightly lighter than soft
    text_muted = "#94A3B8"
    text_dim = "#64748B"
    text_faint = "#9CA3AF"       # for footers

    # ---------------------------------------------------------------- accents
    # Primary
    primary = "#1D4ED8"
    primary_hover = "#2563EB"
    primary_active = "#1E40AF"

    # Success
    success = "#15803D"
    success_hover = "#166534"
    success_text = "#86EFAC"
    success_dark = "#0F766E"

    # Danger
    danger = "#B91C1C"
    danger_hover = "#991B1B"
    danger_text = "#FCA5A5"
    danger_light = "#F87171"

    # Warning
    warning = "#F59E0B"
    warning_text = "#FBBF24"
    warning_hover = "#D97706"

    # Info
    info = "#38BDF8"
    info_bg = "#10263A"
    info_soft = "#60A5FA"
    info_light = "#7DD3FC"
    info_lighter = "#BFDBFE"
    info_pale = "#93C5FD"

    # Neutral
    neutral = "#475569"
    neutral_hover = "#334155"
    neutral_dark = "#374151"
    neutral_dark_hover = "#4B5563"
    neutral_scroll = "#303846"
    neutral_scroll_hover = "#465365"

    # Treeview
    tree_bg = "#111827"
    tree_header_bg = "#1F2937"
    tree_header_fg = "#F9FAFB"
    tree_selected_bg = "#1D4ED8"
    tree_selected_fg = "#FFFFFF"

    # -------------------------------------------------------------- semantic
    online = success_text
    offline = text_dim
    allow = success_text
    block = danger_text
    enabled = success_text
    disabled = text_dim


class Fonts:
    FAMILY_UI = "Segoe UI"
    FAMILY_MONO = "Consolas"

    @staticmethod
    def title(size=24): return (Fonts.FAMILY_UI, size, "bold")
    @staticmethod
    def heading(size=16): return (Fonts.FAMILY_UI, size, "bold")
    @staticmethod
    def label(size=11, bold=False): return (Fonts.FAMILY_UI, size, "bold" if bold else "normal")
    @staticmethod
    def badge(size=10): return (Fonts.FAMILY_UI, size, "bold")
    @staticmethod
    def mono(size=10, bold=False): return (Fonts.FAMILY_MONO, size, "bold" if bold else "normal")


class Spacing:
    PAGE_PAD = (24, 20, 24, 16)
    PAGE_PADX = 24
    PAGE_PADY = 20
    SECTION_GAP = 14
    CARD_PAD = (18, 16)
    CARD_GAP = 10
    INPUT_HEIGHT = 38
    BUTTON_HEIGHT = 38
    BADGE_PAD = (10, 5)
    TREE_ROW_HEIGHT = 34
    RADIUS_CARD = 12
    RADIUS_INPUT = 8
    RADIUS_BADGE = 10
    RADIUS_BUTTON = 8