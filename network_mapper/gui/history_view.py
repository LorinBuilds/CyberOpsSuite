"""Scan history viewer for CyberOpsSuite Network Mapper."""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING

import customtkinter as ctk
from tkinter import ttk, messagebox

from core.theme import Colors, Fonts, Spacing
from core.gui.treeview_style import apply_treeview_style
from core.utils.icons import apply_window_icon

if TYPE_CHECKING:
    from .main import NetworkMapperGUI


class HistoryWindow(ctk.CTkToplevel):
    """Dialog listing saved scan sessions with a two-way compare tool.

    Parameters
    ----------
    parent:
        The :class:`NetworkMapperGUI` instance.
    path:
        Path to the JSON file that stores the scan history.
    """

    def __init__(self, parent: "NetworkMapperGUI", path: Path) -> None:
        super().__init__(parent)
        self.parent = parent
        self.path = path
        self.sessions: list[dict] = []

        self.title("Scan History & Comparison | CyberOpsSuite")
        self.geometry("980x640")
        self.minsize(780, 500)
        self.configure(fg_color=Colors.bg)
        self.transient(parent)

        # Window icon.
        apply_window_icon(self)

        # Apply the shared dark theme to all Treeviews.
        apply_treeview_style(self)

        self._build_ui()
        self.load()

    # ------------------------------------------------------------------ UI

    def _build_ui(self) -> None:
        wrap = ctk.CTkFrame(self, fg_color="transparent")
        wrap.pack(fill="both", expand=True, padx=20, pady=20)

        header = ctk.CTkFrame(wrap, fg_color="transparent")
        header.pack(fill="x", pady=(0, 12))

        ctk.CTkLabel(
            header,
            text="SCAN HISTORY",
            font=Fonts.heading(16),
            text_color=Colors.info,
        ).pack(side="left")

        ctk.CTkButton(
            header,
            text="Refresh",
            width=100,
            height=Spacing.BUTTON_HEIGHT,
            fg_color=Colors.neutral,
            hover_color=Colors.neutral_hover,
            command=self.load,
        ).pack(side="right")

        ctk.CTkLabel(
            wrap,
            text=(
                "History is stored locally on this computer. "
                "Select two sessions to compare host and port changes."
            ),
            font=Fonts.label(10),
            text_color=Colors.text_muted,
        ).pack(anchor="w", pady=(0, 12))

        self._build_table(wrap)
        self._build_footer(wrap)

    def _build_table(self, parent: ctk.CTkFrame) -> None:
        frame = ctk.CTkFrame(
            parent,
            fg_color=Colors.surface,
            corner_radius=Spacing.RADIUS_CARD,
            border_width=1,
            border_color=Colors.border,
        )
        frame.pack(fill="both", expand=True)

        columns = ("time", "target", "scanned", "responded", "ports", "status")
        self.tree = ttk.Treeview(
            frame,
            columns=columns,
            show="headings",
            selectmode="extended",
            style="Cyber.Treeview",
        )

        headings = {
            "time": "Finished / started",
            "target": "Target",
            "scanned": "Hosts",
            "responded": "Responded",
            "ports": "Open ports",
            "status": "Result",
        }
        widths = {
            "time": 200, "target": 190, "scanned": 80,
            "responded": 100, "ports": 100, "status": 100,
        }
        for col in columns:
            self.tree.heading(col, text=headings[col])
            self.tree.column(
                col,
                width=widths[col],
                minwidth=70,
                anchor="w" if col in ("time", "target") else "center",
                stretch=True,
            )

        scrollbar = ttk.Scrollbar(
            frame, orient="vertical", style="Vertical.TScrollbar",
            command=self.tree.yview,
        )
        self.tree.configure(yscrollcommand=scrollbar.set)
        self.tree.pack(side="left", fill="both", expand=True, padx=(10, 0), pady=10)
        scrollbar.pack(side="right", fill="y", padx=(0, 10), pady=10)

    def _build_footer(self, parent: ctk.CTkFrame) -> None:
        footer = ctk.CTkFrame(parent, fg_color="transparent")
        footer.pack(fill="x", pady=(14, 0))

        self.summary = ctk.CTkLabel(
            footer,
            text="Select two sessions and click Compare.",
            font=Fonts.label(10),
            text_color=Colors.text_muted,
            justify="left",
            anchor="w",
            wraplength=680,
        )
        self.summary.pack(side="left", fill="x", expand=True)

        ctk.CTkButton(
            footer,
            text="Compare selected",
            width=160,
            height=Spacing.BUTTON_HEIGHT,
            fg_color=Colors.primary,
            hover_color=Colors.primary_hover,
            command=self.compare,
        ).pack(side="right")

    # ------------------------------------------------------------- loading

    def load(self) -> None:
        """Read the history file from disk and populate the table."""
        try:
            if self.path.exists():
                self.sessions = json.loads(self.path.read_text(encoding="utf-8"))
            else:
                self.sessions = []
            if not isinstance(self.sessions, list):
                self.sessions = []
        except (OSError, ValueError) as exc:
            messagebox.showerror("History read failed", str(exc), parent=self)
            self.sessions = []

        self.tree.delete(*self.tree.get_children())
        for index, session in reversed(list(enumerate(self.sessions))):
            stamp = session.get("finished_at") or session.get("started_at", "Unknown time")
            status = "Stopped" if session.get("stopped") else "Complete"
            self.tree.insert(
                "",
                "end",
                iid=str(index),
                values=(
                    stamp,
                    session.get("target", "—"),
                    session.get("hosts_scanned", 0),
                    session.get("responded", 0),
                    session.get("open_ports", 0),
                    status,
                ),
            )

        self.summary.configure(
            text=f"{len(self.sessions)} session(s) saved · latest 100 sessions are retained."
        )

    # ------------------------------------------------------------ compare

    def compare(self) -> None:
        """Compare two selected sessions and summarise the differences."""
        chosen = self.tree.selection()
        if len(chosen) != 2:
            messagebox.showinfo(
                "Select two scans",
                "Select exactly two scan sessions (Ctrl-click to select the second).",
                parent=self,
            )
            return

        a, b = (self.sessions[int(i)] for i in chosen)
        ar = {x.get("ip"): x for x in a.get("results", [])}
        br = {x.get("ip"): x for x in b.get("results", [])}

        added = sorted(set(br) - set(ar))
        removed = sorted(set(ar) - set(br))
        became_online = sorted(
            ip for ip in set(ar) & set(br)
            if not ar[ip].get("online") and br[ip].get("online")
        )
        became_unresponsive = sorted(
            ip for ip in set(ar) & set(br)
            if ar[ip].get("online") and not br[ip].get("online")
        )

        opened: list[tuple[str, int]] = []
        closed: list[tuple[str, int]] = []
        for ip in set(ar) & set(br):
            old = set(ar[ip].get("open_ports", []))
            new = set(br[ip].get("open_ports", []))
            opened.extend((ip, port) for port in sorted(new - old))
            closed.extend((ip, port) for port in sorted(old - new))

        parts = [
            f"hosts: {len(ar)} → {len(br)}",
            self._brief("new IPs", added),
            self._brief("missing IPs", removed),
            self._brief("became responsive", became_online),
            self._brief("no longer responsive", became_unresponsive),
            self._brief("new open ports", opened),
            self._brief("ports no longer open", closed),
        ]
        self.summary.configure(
            text="Comparison · selected first scan → second scan\n" + "  |  ".join(parts)
        )

    @staticmethod
    def _brief(label: str, values: list) -> str:
        """Return a short human-readable summary of a diff list."""
        if not values:
            return f"{label}: none"
        if isinstance(values[0], tuple):
            sample = ", ".join(f"{ip}:{port}" for ip, port in values[:8])
        else:
            sample = ", ".join(map(str, values[:8]))
        suffix = "…" if len(values) > 8 else ""
        return f"{label}: {len(values)} ({sample}{suffix})"