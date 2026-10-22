"""Shared ttk.Treeview styling for CyberOpsSuite GUIs.

Every module that uses a ``ttk.Treeview`` needs the same dark theme
configuration. This module centralises that configuration so it can be
applied consistently across the suite.

Usage
-----
::

    from core.gui.treeview_style import apply_treeview_style

    class MyGUI(ctk.CTk):
        def __init__(self):
            super().__init__()
            apply_treeview_style(self)
            # ... build UI ...
"""

from __future__ import annotations

from tkinter import ttk

from core.theme import Colors, Fonts, Spacing


#: Name of the ttk style applied to every CyberOpsSuite treeview.
STYLE_NAME = "Cyber.Treeview"


def apply_treeview_style(root, *, selection_color: str | None = None) -> None:
    """Apply the CyberOpsSuite dark theme to ``ttk.Treeview`` widgets.

    Parameters
    ----------
    root:
        Any Tk/CTk widget (usually the main window). The style is
        registered globally on this widget's Tk interpreter.
    selection_color:
        Optional override for the selected-row background. Defaults to
        :data:`core.theme.Colors.primary_active`.
    """
    style = ttk.Style(root)
    try:
        style.theme_use("clam")
    except Exception:
        pass

    selected_bg = selection_color or Colors.primary_active

    # ----- Body -----
    style.configure(
        STYLE_NAME,
        background=Colors.surface,
        fieldbackground=Colors.surface,
        foreground=Colors.text,
        rowheight=Spacing.TREE_ROW_HEIGHT,
        borderwidth=0,
        relief="flat",
        font=Fonts.label(10),
    )

    # ----- Heading -----
    style.configure(
        f"{STYLE_NAME}.Heading",
        background=Colors.surface_alt,
        foreground=Colors.text_muted,
        relief="flat",
        borderwidth=0,
        font=Fonts.badge(10),
        padding=(10, 9),
    )

    # ----- Selected row -----
    style.map(
        STYLE_NAME,
        background=[("selected", selected_bg)],
        foreground=[("selected", "#FFFFFF")],
    )
    style.map(
        f"{STYLE_NAME}.Heading",
        background=[("active", Colors.surface_raised)],
    )

    # ----- Scrollbars (used alongside treeviews) -----
    style.configure(
        "Vertical.TScrollbar",
        background=Colors.neutral_scroll,
        troughcolor=Colors.bg,
        bordercolor=Colors.bg,
        arrowcolor=Colors.text_very_soft,
        relief="flat",
    )
    style.map(
        "Vertical.TScrollbar",
        background=[("active", Colors.neutral_scroll_hover)],
    )
    style.configure(
        "Horizontal.TScrollbar",
        background=Colors.neutral_scroll,
        troughcolor=Colors.bg,
        bordercolor=Colors.bg,
        arrowcolor=Colors.text_very_soft,
        relief="flat",
    )
    style.map(
        "Horizontal.TScrollbar",
        background=[("active", Colors.neutral_scroll_hover)],
    )