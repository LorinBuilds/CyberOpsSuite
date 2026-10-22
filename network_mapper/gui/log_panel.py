"""Scrolling log panel for CyberOpsSuite Network Mapper.

A minimal append-only text view. The panel is read-only: callers use
:meth:`LogPanel.log` to append a line, and :meth:`LogPanel.clear` to wipe
the history. All colors come from :mod:`core.theme` so the panel looks the
same across every module in the suite.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import customtkinter as ctk

from core.theme import Colors, Fonts, Spacing

if TYPE_CHECKING:
    # Avoid a runtime import cycle: parent is only used for typing.
    from tkinter import Misc


class LogPanel(ctk.CTkFrame):
    """Read-only scrolling log view.

    Parameters
    ----------
    parent:
        Tk/CTk parent widget.
    height:
        Height of the text area in pixels. The panel is not resizable by
        the user; the caller decides how much vertical space to give it.
    """

    def __init__(self, parent: "Misc", height: int = 140) -> None:
        super().__init__(
            parent,
            fg_color=Colors.surface,
            corner_radius=Spacing.RADIUS_CARD,
        )

        self._text = ctk.CTkTextbox(
            self,
            height=height,
            fg_color=Colors.bg,
            text_color=Colors.text_muted,
            border_color=Colors.border,
            border_width=1,
            corner_radius=Spacing.RADIUS_INPUT,
            font=Fonts.mono(10),
            wrap="word",
            activate_scrollbars=True,
        )
        self._text.pack(fill="both", expand=True, padx=6, pady=6)

        # CTkTextbox does not have a built-in "read-only" flag, so we
        # toggle the underlying state around every write.
        self._text.configure(state="disabled")

    # ------------------------------------------------------------------ API

    def log(self, message: str) -> None:
        """Append *message* as a new bulleted line and scroll to the bottom."""
        text = self._text
        text.configure(state="normal")
        text.insert("end", f"• {message}\n")
        text.see("end")
        text.configure(state="disabled")

    def clear(self) -> None:
        """Remove every line from the panel."""
        text = self._text
        text.configure(state="normal")
        text.delete("1.0", "end")
        text.configure(state="disabled")

    def lines(self) -> list[str]:
        """Return the current contents split into non-empty lines.

        Mostly useful for tests and debugging; the GUI never reads the log
        back from the widget.
        """
        raw = self._text.get("1.0", "end")
        return [line for line in raw.splitlines() if line.strip()]