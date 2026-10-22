"""Scan settings dialog for CyberOpsSuite Network Mapper.

A small ``CTkToplevel`` that lets the user edit the TCP ports the scanner
will probe. The dialog validates the input, refuses to overwrite a running
scan without confirmation, and writes the new ports back to the parent
scanner instance.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import customtkinter as ctk

from core.theme import Colors, Fonts, Spacing

if TYPE_CHECKING:
    # Only used for typing; avoids a runtime import cycle with the main app.
    from .main import NetworkMapperGUI


#: Upper bound on how many ports a single scan may probe. Keeps the parallel
#: port pool from being flooded and the scan time predictable.
MAX_PORTS = 128


class SettingsWindow(ctk.CTkToplevel):
    """Modal dialog for editing the TCP port list.

    Parameters
    ----------
    parent:
        The :class:`NetworkMapperGUI` instance. Its ``scanner.ports`` and
        ``log_panel`` are used to apply and confirm the change.
    """

    def __init__(self, parent: "NetworkMapperGUI") -> None:
        super().__init__(parent)
        self.parent = parent

        self.title("Scan settings | CyberOpsSuite")
        self.geometry("460x300")
        self.resizable(False, False)
        self.configure(fg_color=Colors.bg)
        self.transient(parent)
        self.grab_set()

        self._build_ui()
        self._center_on_parent()

    # ------------------------------------------------------------------ UI

    def _build_ui(self) -> None:
        card = ctk.CTkFrame(
            self,
            fg_color=Colors.surface,
            corner_radius=Spacing.RADIUS_CARD,
            border_width=1,
            border_color=Colors.border,
        )
        card.pack(fill="both", expand=True, padx=18, pady=18)

        ctk.CTkLabel(
            card,
            text="Scan settings",
            font=Fonts.heading(16),
            text_color=Colors.text,
        ).pack(anchor="w", padx=18, pady=(18, 2))

        ctk.CTkLabel(
            card,
            text=f"Comma-separated TCP ports (1–65535), up to {MAX_PORTS} ports.",
            font=Fonts.label(11),
            text_color=Colors.text_muted,
        ).pack(anchor="w", padx=18, pady=(0, 12))

        self.port_entry = ctk.CTkEntry(
            card,
            height=Spacing.INPUT_HEIGHT,
            fg_color=Colors.bg,
            text_color=Colors.text,
            border_color=Colors.border,
            placeholder_text="22, 80, 443, 3389",
        )
        self.port_entry.pack(fill="x", padx=18)
        self.port_entry.insert(0, ", ".join(map(str, self.parent.scanner.ports)))
        self.port_entry.bind("<Return>", lambda _event: self.apply())

        actions = ctk.CTkFrame(card, fg_color="transparent")
        actions.pack(fill="x", padx=18, pady=(18, 18))

        ctk.CTkButton(
            actions,
            text="Cancel",
            width=100,
            height=Spacing.BUTTON_HEIGHT,
            fg_color=Colors.neutral,
            hover_color=Colors.neutral_hover,
            command=self.destroy,
        ).pack(side="right", padx=(8, 0))

        ctk.CTkButton(
            actions,
            text="Apply settings",
            width=140,
            height=Spacing.BUTTON_HEIGHT,
            fg_color=Colors.primary,
            hover_color=Colors.primary_hover,
            command=self.apply,
        ).pack(side="right")

        self.port_entry.focus_set()

    def _center_on_parent(self) -> None:
        """Place the dialog at the center of the parent window."""
        self.update_idletasks()
        parent = self.parent
        x = parent.winfo_rootx() + (parent.winfo_width() - self.winfo_width()) // 2
        y = parent.winfo_rooty() + (parent.winfo_height() - self.winfo_height()) // 2
        self.geometry(f"+{max(0, x)}+{max(0, y)}")

    # --------------------------------------------------------------- actions

    def apply(self) -> None:
        """Validate the port list and write it back to the parent scanner."""
        try:
            ports = sorted({
                int(piece.strip())
                for piece in self.port_entry.get().split(",")
                if piece.strip()
            })
        except ValueError:
            self._error("Ports must be whole numbers separated by commas.")
            return

        if not ports:
            self._error("Enter at least one port.")
            return

        if any(port < 1 or port > 65535 for port in ports):
            self._error("Each port must be between 1 and 65535.")
            return

        if len(ports) > MAX_PORTS:
            self._error(f"At most {MAX_PORTS} ports are allowed.")
            return

        parent = self.parent
        if getattr(parent, "scan_running", False):
            if not self._confirm(
                "A scan is currently running. The new ports will apply to the "
                "next scan, not the current one.\n\nContinue?"
            ):
                return

        parent.scanner.ports = ports
        if hasattr(parent, "log_panel"):
            parent.log_panel.log(f"Scan ports updated: {ports}")
        self.destroy()

    # ------------------------------------------------------------- helpers

    def _error(self, message: str) -> None:
        from tkinter import messagebox
        messagebox.showerror("Invalid ports", message, parent=self)

    def _confirm(self, message: str) -> bool:
        from tkinter import messagebox
        return messagebox.askyesno("Scan in progress", message, parent=self)