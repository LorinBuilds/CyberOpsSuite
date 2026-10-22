"""Network topology viewer for CyberOpsSuite Network Mapper.

Renders a simple host overview on a Tkinter canvas. Online and offline
hosts are colour-coded; lines only group scan targets and do not
represent verified physical connections.
"""

from __future__ import annotations

import tkinter as tk
from typing import TYPE_CHECKING

import customtkinter as ctk

from core.theme import Colors, Fonts, Spacing
from core.utils.icons import apply_window_icon

if TYPE_CHECKING:
    from .main import NetworkMapperGUI


#: Maximum number of hosts drawn individually. Beyond this, a "+N more"
#: label is shown to keep the canvas readable.
MAX_DRAWN_HOSTS = 40


class GraphWindow(ctk.CTkToplevel):
    """Visual host overview dialog.

    Parameters
    ----------
    parent:
        The :class:`NetworkMapperGUI` instance.
    results:
        List of :class:`HostResult` objects from the last scan.
    """

    def __init__(self, parent: "NetworkMapperGUI", results) -> None:
        super().__init__(parent)
        self._results = list(results)

        self.title("Network topology | CyberOpsSuite")
        self.geometry("880x600")
        self.minsize(680, 460)
        self.configure(fg_color=Colors.bg)
        self.transient(parent)

        # Window icon.
        apply_window_icon(self)

        self._build_ui()
        self.after(60, self._redraw)

    # ------------------------------------------------------------------ UI

    def _build_ui(self) -> None:
        outer = ctk.CTkFrame(self, fg_color="transparent")
        outer.pack(fill="both", expand=True, padx=20, pady=20)

        self._build_header(outer)
        self._build_canvas(outer)
        self._build_legend(outer)

    def _build_header(self, parent: ctk.CTkFrame) -> None:
        header = ctk.CTkFrame(parent, fg_color="transparent")
        header.pack(fill="x", pady=(0, 14))

        ctk.CTkLabel(
            header,
            text="NETWORK OVERVIEW",
            font=Fonts.heading(15),
            text_color=Colors.info,
        ).pack(side="left")

        online = sum(1 for r in self._results if r.online)
        total_ports = sum(len(r.open_ports) for r in self._results)
        summary = (
            f"{len(self._results)} hosts  ·  {online} responded  ·  "
            f"{total_ports} open-port observations"
        )
        ctk.CTkLabel(
            header,
            text=summary,
            font=Fonts.label(10),
            text_color=Colors.text_muted,
        ).pack(side="right")

    def _build_canvas(self, parent: ctk.CTkFrame) -> None:
        panel = ctk.CTkFrame(
            parent,
            fg_color=Colors.surface,
            corner_radius=Spacing.RADIUS_CARD,
            border_width=1,
            border_color=Colors.border,
        )
        panel.pack(fill="both", expand=True)

        # tk.Canvas has no CustomTkinter equivalent; keep the raw widget and
        # paint it in the theme background so it blends in visually.
        self.canvas = tk.Canvas(
            panel,
            bg=Colors.surface,
            highlightthickness=0,
            borderwidth=0,
        )
        self.canvas.pack(fill="both", expand=True, padx=10, pady=10)
        self.canvas.bind("<Configure>", self._redraw)

    def _build_legend(self, parent: ctk.CTkFrame) -> None:
        legend = ctk.CTkFrame(parent, fg_color="transparent")
        legend.pack(fill="x", pady=(12, 0))

        ctk.CTkLabel(
            legend,
            text="● Responded",
            font=Fonts.label(10),
            text_color=Colors.success_text,
        ).pack(side="left", padx=(2, 14))

        ctk.CTkLabel(
            legend,
            text="● No response",
            font=Fonts.label(10),
            text_color=Colors.text_dim,
        ).pack(side="left", padx=(0, 14))

        ctk.CTkLabel(
            legend,
            text="Lines group scan targets; they do not represent verified physical connections.",
            font=Fonts.label(9),
            text_color=Colors.text_dim,
        ).pack(side="right")

    # ------------------------------------------------------------- drawing

    def _redraw(self, _event=None) -> None:
        canvas = self.canvas
        canvas.delete("all")

        width = max(canvas.winfo_width(), 360)
        height = max(canvas.winfo_height(), 260)
        cx, cy = width / 2, height / 2

        self._draw_center(canvas, cx, cy)
        self._draw_hosts(canvas, cx, cy, width, height)

    def _draw_center(self, canvas: tk.Canvas, cx: float, cy: float) -> None:
        canvas.create_oval(
            cx - 68, cy - 32, cx + 68, cy + 32,
            fill=Colors.surface_raised,
            outline=Colors.info,
            width=2,
        )
        canvas.create_text(
            cx, cy - 5,
            text="SCAN SCOPE",
            fill=Colors.text,
            font=Fonts.label(10, bold=True),
        )
        canvas.create_text(
            cx, cy + 12,
            text=f"{len(self._results)} targets",
            fill=Colors.text_muted,
            font=Fonts.label(9),
        )

    def _draw_hosts(
        self,
        canvas: tk.Canvas,
        cx: float,
        cy: float,
        width: int,
        height: int,
    ) -> None:
        if not self._results:
            canvas.create_text(
                cx, cy + 58,
                text="No hosts in this scan",
                fill=Colors.text_muted,
                font=Fonts.label(11),
            )
            return

        # Responded hosts first, then the rest.
        ordered = sorted(self._results, key=lambda r: not r.online)
        shown = ordered[:MAX_DRAWN_HOSTS]
        half = max(1, (len(shown) + 1) // 2)
        left = shown[:half]
        right = shown[half:]

        for side, hosts in ((-1, left), (1, right)):
            rows = max(1, len(hosts))
            for row, result in enumerate(hosts):
                y = max(28, height / (rows + 1) * (row + 1))
                x = cx + side * min(width * 0.32, 245)
                self._draw_host(canvas, cx, cy, x, y, side, result)

        hidden = len(self._results) - len(shown)
        if hidden > 0:
            canvas.create_text(
                cx, height - 12,
                text=f"+ {hidden} more hosts",
                fill=Colors.text_muted,
                font=Fonts.label(10),
            )

    def _draw_host(
        self,
        canvas: tk.Canvas,
        cx: float,
        cy: float,
        x: float,
        y: float,
        side: int,
        result,
    ) -> None:
        color = Colors.success_text if result.online else Colors.text_dim

        # Connector: grouping, not physical link.
        canvas.create_line(
            cx + side * 68, cy, x - side * 55, y,
            fill=Colors.border,
            width=1,
        )
        canvas.create_rectangle(
            x - 58, y - 16, x + 58, y + 16,
            fill=Colors.surface_raised,
            outline=color,
            width=1,
        )
        canvas.create_text(
            x, y - 3,
            text=result.ip,
            fill=Colors.text,
            font=Fonts.mono(9),
        )

        if result.open_ports:
            detail = f"{len(result.open_ports)} open port(s)"
        elif result.online:
            detail = "responsive"
        else:
            detail = "no response"

        canvas.create_text(
            x, y + 8,
            text=detail,
            fill=color,
            font=Fonts.label(8),
        )