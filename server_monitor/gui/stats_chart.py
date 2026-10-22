"""Simple donut chart widget drawn with Tkinter Canvas."""

from __future__ import annotations

import tkinter as tk

import customtkinter as ctk

from core.theme import Colors


class StatsChart(ctk.CTkFrame):
    """A donut chart showing running vs stopped services."""

    def __init__(self, parent, **kwargs) -> None:
        super().__init__(
            parent,
            fg_color=Colors.surface,
            corner_radius=12,
            **kwargs,
        )
        self._running = 0
        self._stopped = 0
        self._total = 0

        self.canvas = tk.Canvas(
            self, width=160, height=160,
            bg=Colors.surface, highlightthickness=0,
        )
        self.canvas.pack(pady=(8, 4), padx=8)

        self.center_label = ctk.CTkLabel(
            self,
            text="0%",
            font=("Segoe UI", 18, "bold"),
            text_color=Colors.success_text,
        )
        self.center_label.place(in_=self.canvas, relx=0.5, rely=0.5, anchor="center")

        self.legend = ctk.CTkLabel(
            self,
            text="Running: 0    Stopped: 0",
            font=("Segoe UI", 10),
            text_color=Colors.text_muted,
        )
        self.legend.pack(pady=(0, 8))

    def update_chart(self, running: int, stopped: int) -> None:
        """Redraw the donut chart with new values."""
        self._running = running
        self._stopped = stopped
        self._total = running + stopped

        self.canvas.delete("all")

        if self._total == 0:
            self.center_label.configure(text="—", text_color=Colors.text_muted)
            self.legend.configure(text="No services")
            return

        pct = int((running / self._total) * 100)
        self.center_label.configure(
            text=f"{pct}%",
            text_color=(
                Colors.success_text if pct >= 90
                else Colors.warning_text if pct >= 70
                else Colors.danger_text
            ),
        )
        self.legend.configure(
            text=f"Running: {running}    Stopped: {stopped}"
        )

        # Draw donut
        start_angle = 90
        extent_running = -(running / self._total) * 360

        # Running slice (green)
        if running > 0:
            self.canvas.create_arc(
                15, 15, 145, 145,
                start=start_angle,
                extent=extent_running,
                fill=Colors.success_text,
                outline=Colors.surface,
                width=2,
                style="pieslice",
            )

        # Stopped slice (red)
        if stopped > 0:
            self.canvas.create_arc(
                15, 15, 145, 145,
                start=start_angle + extent_running,
                extent=(stopped / self._total) * 360,
                fill=Colors.danger_text,
                outline=Colors.surface,
                width=2,
                style="pieslice",
            )

        # Inner circle (donut hole)
        self.canvas.create_oval(
            50, 50, 110, 110,
            fill=Colors.surface,
            outline=Colors.surface,
        )