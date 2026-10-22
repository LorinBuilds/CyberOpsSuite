"""CyberOpsSuite CyberOpsSuite Dashboard.

A CustomTkinter launcher for every CyberOpsSuite module. This version
uses a standard Tkinter Canvas to provide smooth, reliable scrolling
with both mouse and touchpad on Windows 11.

The dashboard includes:
- A live status bar.
- Global stats cards.
- A 2-column grid of tool cards.
- Recent activity feed.
- A How to Use guide for the dashboard itself.
"""

from __future__ import annotations

import os
import platform
import queue
import subprocess
import sys
import tempfile
import threading
import time
import tkinter as tk
from datetime import datetime
from pathlib import Path

import customtkinter as ctk
from tkinter import messagebox

from core.theme import Colors, Fonts, Spacing
from core.utils.icons import apply_window_icon

# Optional imports for live stats
try:
    from ip_rotator.core.ip_logger import IPLogger
    HAS_IP_LOGGER = True
except ImportError:
    HAS_IP_LOGGER = False

try:
    from firewall_manager.core.firewall import FirewallManager
    HAS_FIREWALL = True
except ImportError:
    HAS_FIREWALL = False

try:
    from server_monitor.core.service_checker import get_service_details
    HAS_SERVER_MONITOR = True
except ImportError:
    HAS_SERVER_MONITOR = False


APP_VERSION = "1.5.7"

TOOLS = [
    ("🛡", "Firewall Manager",
     "Manage Windows Firewall rules and profiles.",
     "firewall_manager.gui.main", "NETWORK DEFENSE", "#EF4444"),
    ("📋", "Event Log Analyzer",
     "Review Windows events, Linux journal, or log files.",
     "event_log_analyzer.gui.main", "INVESTIGATION", "#F59E0B"),
    ("🗺", "Network Mapper",
     "Explore devices and hosts on your network.",
     "network_mapper.gui.main", "NETWORK VISIBILITY", "#22C55E"),
    ("📡", "DHCP Lease Viewer",
     "Inspect local and remote DHCP leases.",
     "dhcp_lease_viewer.gui.main", "NETWORK SERVICES", "#3B82F6"),
    ("🖥", "Server Monitor",
     "Monitor local service health on Windows and Linux.",
     "server_monitor.gui.main", "INFRASTRUCTURE", "#A855F7"),
    ("🔒", "VPN Manager",
     "Manage VLESS/VMess profiles and the local Xray proxy.",
     "vpn_manager.gui.main", "VPN CONNECTIVITY", "#06B6D4"),
    ("🌐", "IP Rotator",
     "Change your public IP via the Tor network.",
     "ip_rotator.gui.main", "PRIVACY", "#8B5CF6"),
]

MODULE_TO_EXE = {
    "firewall_manager.gui.main": "FirewallManager",
    "event_log_analyzer.gui.main": "EventLogAnalyzer",
    "network_mapper.gui.main": "NetworkMapper",
    "dhcp_lease_viewer.gui.main": "DHCPLeaseViewer",
    "server_monitor.gui.main": "ServerMonitor",
    "vpn_manager.gui.main": "VPNManager",
    "ip_rotator.gui.main": "IPRotator",
}

CRITICAL_SERVICES = ("RpcSs", "DcomLaunch", "Winmgmt", "EventLog", "Schedule")


class Dashboard(ctk.CTk):
    """Main application window for the CyberOpsSuite Dashboard."""

    def __init__(self) -> None:
        super().__init__()

        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("dark-blue")

        self.title("CyberOpsSuite |  CyberOpsSuite Dashboard")
        self.geometry("1280x820")
        self.minsize(1000, 680)
        self.configure(fg_color=Colors.bg)

        apply_window_icon(self)

        self._ip_address = "Checking..."
        self._firewall_status = "Checking..."
        self._service_status = "Checking..."
        self._last_scan = "Never"
        self._internet_online = False
        self._activity_log: list[tuple[str, str, str]] = []
        self._stats_queue: queue.Queue = queue.Queue()
        self._poll_after_id: str | None = None
        self._time_after_id: str | None = None

        self._build_layout()
        self._start_background_stats()
        self._tick_clock()

    # ============================================================= layout

    def _build_layout(self) -> None:
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self._build_sidebar()

        self.canvas = tk.Canvas(
            self, bg=Colors.bg, highlightthickness=0, bd=0,
        )
        self.canvas.grid(row=0, column=1, sticky="nsew", padx=(18, 0), pady=16)

        self.scrollbar = ctk.CTkScrollbar(
            self, command=self.canvas.yview,
            fg_color=Colors.bg, button_color=Colors.surface_alt,
            button_hover_color=Colors.primary,
        )
        self.scrollbar.grid(row=0, column=2, sticky="ns", padx=(0, 10), pady=16)

        self.canvas.configure(yscrollcommand=self.scrollbar.set)

        self.content = ctk.CTkFrame(self.canvas, fg_color=Colors.bg, corner_radius=0)
        self.canvas_window = self.canvas.create_window(
            (0, 0), window=self.content, anchor="nw", tags="self.content"
        )

        self.content.grid_columnconfigure(0, weight=1)

        self.content.bind("<Configure>", self._on_frame_configure)
        self.canvas.bind("<Configure>", self._on_canvas_configure)

        self._build_topbar(self.content)
        self._build_live_status_bar(self.content)
        self._build_global_stats(self.content)
        self._build_tools_grid(self.content)
        self._build_recent_activity(self.content)
        self._build_footer(self.content)

        self.after(100, self._bind_scroll_events)

    def _on_frame_configure(self, event=None):
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))

    def _on_canvas_configure(self, event):
        self.canvas.itemconfig(self.canvas_window, width=event.width)

    def _bind_scroll_events(self):
        self._bind_wheel(self.canvas)
        self._bind_wheel(self.content)
        for child in self.content.winfo_children():
            self._bind_wheel_recursive(child)

    def _bind_wheel_recursive(self, widget):
        self._bind_wheel(widget)
        for child in widget.winfo_children():
            self._bind_wheel_recursive(child)

    def _bind_wheel(self, widget):
        try:
            widget.bind("<MouseWheel>", self._on_mousewheel, add="+")
            widget.bind("<Button-4>", self._on_linux_scroll_up, add="+")
            widget.bind("<Button-5>", self._on_linux_scroll_down, add="+")
        except Exception:
            pass

    def _on_mousewheel(self, event):
        delta = event.delta
        if delta == 0:
            return
        if abs(delta) >= 120:
            self.canvas.yview_scroll(int(-1 * (delta / 120)), "units")
        else:
            self.canvas.yview_scroll(-1 if delta > 0 else 1, "units")

    def _on_linux_scroll_up(self, event):
        self.canvas.yview_scroll(-1, "units")

    def _on_linux_scroll_down(self, event):
        self.canvas.yview_scroll(1, "units")

    # ---------------------------------------------------------- sidebar

    def _build_sidebar(self) -> None:
        sidebar = ctk.CTkFrame(
            self, width=240, corner_radius=0, fg_color=Colors.bg_alt, border_width=0,
        )
        sidebar.grid(row=0, column=0, sticky="nsew")
        sidebar.grid_propagate(False)

        brand = ctk.CTkFrame(sidebar, fg_color="transparent")
        brand.pack(fill="x", padx=22, pady=(27, 30))

        ctk.CTkLabel(
            brand, text="◈", font=ctk.CTkFont(family="Arial", size=32, weight="bold"),
            text_color=Colors.primary,
        ).pack(side="left", padx=(0, 10))

        brand_text = ctk.CTkFrame(brand, fg_color="transparent")
        brand_text.pack(side="left", fill="x", expand=True)

        ctk.CTkLabel(
            brand_text, text="CyberOpsSuite", anchor="w",
            font=Fonts.heading(17), text_color=Colors.text,
        ).pack(fill="x")

        ctk.CTkLabel(
            brand_text, text="SECURITY CENTER", anchor="w",
            font=Fonts.badge(9), text_color=Colors.text_muted,
        ).pack(fill="x", pady=(3, 0))

        status_card = ctk.CTkFrame(
            sidebar, fg_color=Colors.surface, corner_radius=Spacing.RADIUS_CARD,
            border_width=1, border_color=Colors.border,
        )
        status_card.pack(fill="x", padx=14, pady=(0, 0))

        ctk.CTkLabel(
            status_card, text="SYSTEM STATUS", anchor="w",
            font=Fonts.badge(9), text_color=Colors.text_dim,
        ).pack(fill="x", padx=14, pady=(12, 6))

        self._status_row(status_card, "●  Ready", Colors.success_text)
        self._status_row(status_card, f"Modules: {len(TOOLS)}", Colors.text_muted)
        self._status_row(
            status_card, f"Version {APP_VERSION}", Colors.text_muted, last=True,
        )

        ctk.CTkLabel(
            sidebar, text="SHORTCUTS", anchor="w",
            font=Fonts.badge(9), text_color=Colors.text_dim,
        ).pack(fill="x", padx=14, pady=(20, 6))

        shortcuts = [
            ("🛡  Firewall", "firewall_manager.gui.main"),
            ("🖥  Server", "server_monitor.gui.main"),
            ("🗺  Network", "network_mapper.gui.main"),
            ("🌐  IP Rotator", "ip_rotator.gui.main"),
        ]
        for label, module in shortcuts:
            ctk.CTkButton(
                sidebar,
                text=label,
                command=lambda m=module: self.run_module(m),
                fg_color="transparent",
                hover_color=Colors.surface,
                border_width=0,
                corner_radius=Spacing.RADIUS_BUTTON,
                height=32,
                font=Fonts.label(11),
                text_color=Colors.text_muted,
                anchor="w",
            ).pack(fill="x", padx=14, pady=1)

        footer = ctk.CTkFrame(sidebar, fg_color="transparent")
        footer.pack(side="bottom", fill="x", padx=20, pady=22)

        ctk.CTkFrame(footer, height=1, fg_color=Colors.border).pack(fill="x", pady=(0, 14))

        ctk.CTkLabel(
            footer, text="Local security toolkit", anchor="w",
            text_color=Colors.text_muted, font=Fonts.label(10),
        ).pack(fill="x")

    @staticmethod
    def _status_row(parent, text, color, last=False):
        ctk.CTkLabel(
            parent, text=text, anchor="w",
            text_color=color, font=Fonts.label(10),
        ).pack(fill="x", padx=14, pady=(0, 12 if last else 4))

    # ----------------------------------------------------------- topbar

    def _build_topbar(self, content):
        topbar = ctk.CTkFrame(content, fg_color="transparent")
        topbar.grid(row=0, column=0, sticky="ew", pady=(0, 14))
        topbar.grid_columnconfigure(0, weight=1)

        brand = ctk.CTkFrame(topbar, fg_color="transparent")
        brand.grid(row=0, column=0, sticky="w")

        ctk.CTkLabel(
            brand, text=" CyberOpsSuite Dashboard", anchor="w",
            font=Fonts.title(27), text_color=Colors.text,
        ).pack(anchor="w")

        ctk.CTkLabel(
            brand, text="Live overview of your local security posture.",
            anchor="w", text_color=Colors.text_muted, font=Fonts.label(12),
        ).pack(anchor="w", pady=(5, 0))

        actions = ctk.CTkFrame(topbar, fg_color="transparent")
        actions.grid(row=0, column=1, sticky="e", pady=4)

        self.help_btn = ctk.CTkButton(
            actions, text="❓ Help", width=90, height=34,
            corner_radius=Spacing.RADIUS_BUTTON,
            fg_color=Colors.info_bg, hover_color=Colors.info,
            text_color=Colors.info_light, font=Fonts.label(11, bold=True),
            command=self._show_page_help,
        )
        self.help_btn.pack(side="right", padx=(0, 8))

        ctk.CTkButton(
            actions, text="About", width=90, height=34,
            corner_radius=Spacing.RADIUS_BUTTON,
            fg_color=Colors.surface_alt, hover_color=Colors.primary,
            text_color=Colors.text, font=Fonts.label(11, bold=True),
            command=self._show_about,
        ).pack(side="right")

    # ------------------------------------------------------- Live Status

    def _build_live_status_bar(self, content):
        bar = ctk.CTkFrame(
            content, fg_color=Colors.surface_alt,
            corner_radius=Spacing.RADIUS_CARD,
            border_width=1, border_color=Colors.border,
        )
        bar.grid(row=1, column=0, sticky="ew", pady=(0, 16))
        bar.grid_columnconfigure((0, 1, 2, 3), weight=1)

        self._internet_label = self._status_item(
            bar, "🌐  INTERNET", "Checking...", "Checking...", 0
        )
        self._firewall_label = self._status_item(
            bar, "🛡  FIREWALL", "Checking...", "Checking...", 1
        )
        self._services_label = self._status_item(
            bar, "🖥  SERVICES", "Checking...", "Checking...", 2
        )
        self._clock_label = self._status_item(
            bar, "🕐  SYSTEM TIME", "Loading...", "Loading...", 3
        )

    def _status_item(self, parent, title, value, subtitle, column):
        frame = ctk.CTkFrame(parent, fg_color="transparent")
        frame.grid(row=0, column=column, sticky="ew", padx=10, pady=10)

        ctk.CTkLabel(
            frame, text=title, anchor="w",
            font=Fonts.badge(9), text_color=Colors.text_dim,
        ).pack(fill="x")

        value_label = ctk.CTkLabel(
            frame, text=value, anchor="w",
            font=Fonts.heading(14), text_color=Colors.text,
        )
        value_label.pack(fill="x", pady=(2, 0))

        ctk.CTkLabel(
            frame, text=subtitle, anchor="w",
            font=Fonts.label(9), text_color=Colors.text_muted,
        ).pack(fill="x")

        return value_label

    def _tick_clock(self):
        try:
            self._clock_label.configure(text=datetime.now().strftime("%H:%M:%S"))
            self._time_after_id = self.after(1000, self._tick_clock)
        except Exception:
            pass

    # ------------------------------------------------------- Global Stats

    def _build_global_stats(self, content):
        stats = ctk.CTkFrame(content, fg_color="transparent")
        stats.grid(row=2, column=0, sticky="ew", pady=(0, 16))
        stats.grid_columnconfigure((0, 1, 2, 3), weight=1, uniform="stats")

        self._stat_ip = self._stat_card(
            stats, 0, "🌐  YOUR PUBLIC IP", "Checking...", Colors.info,
        )
        self._stat_firewall = self._stat_card(
            stats, 1, "🛡  FIREWALL STATUS", "Checking...", Colors.warning_text,
        )
        self._stat_services = self._stat_card(
            stats, 2, "🖥  CRITICAL SERVICES", "Checking...", Colors.success_text,
        )
        self._stat_scans = self._stat_card(
            stats, 3, "🗺  LAST NETWORK SCAN", "Never", Colors.primary,
        )

    def _stat_card(self, parent, column, title, value, color):
        card = ctk.CTkFrame(
            parent, fg_color=Colors.surface,
            corner_radius=Spacing.RADIUS_CARD,
            border_width=1, border_color=Colors.border,
        )
        card.grid(row=0, column=column, sticky="ew", padx=(0, 8) if column < 3 else 0)

        ctk.CTkLabel(
            card, text=title, anchor="w",
            font=Fonts.badge(9), text_color=Colors.text_dim,
        ).pack(fill="x", padx=14, pady=(12, 2))

        value_label = ctk.CTkLabel(
            card, text=value, anchor="w",
            font=Fonts.title(18), text_color=color,
        )
        value_label.pack(fill="x", padx=14, pady=(0, 14))

        return value_label

    # ------------------------------------------------------- tools grid

    def _build_tools_grid(self, content):
        header = ctk.CTkFrame(content, fg_color="transparent")
        header.grid(row=3, column=0, sticky="ew", pady=(0, 8))

        ctk.CTkLabel(
            header, text="🛠  AVAILABLE TOOLS", anchor="w",
            font=Fonts.heading(14), text_color=Colors.text,
        ).pack(side="left")

        ctk.CTkLabel(
            header, text=f"{len(TOOLS)} modules", anchor="e",
            font=Fonts.label(10), text_color=Colors.text_muted,
        ).pack(side="right")

        cards_frame = ctk.CTkFrame(content, fg_color="transparent")
        cards_frame.grid(row=4, column=0, sticky="nsew", pady=(0, 12))
        cards_frame.grid_columnconfigure((0, 1), weight=1, uniform="toolcards")

        for index, (symbol, name, desc, module, category, accent) in enumerate(TOOLS):
            row, col = divmod(index, 2)
            self._create_tool_card(
                cards_frame, row, col,
                symbol, name, desc, module, category, accent,
            )

    def _create_tool_card(
        self, parent, row, col, symbol, name, description,
        module_name, category, accent,
    ):
        card = ctk.CTkFrame(
            parent, fg_color=Colors.surface,
            corner_radius=Spacing.RADIUS_CARD,
            border_width=1, border_color=Colors.border,
        )
        card.grid(
            row=row, column=col, sticky="nsew",
            padx=(0, 10) if col == 0 else (10, 0),
            pady=7,
        )
        
        card.grid_columnconfigure(0, weight=1)
        card.grid_rowconfigure(2, weight=1)

        head = ctk.CTkFrame(card, fg_color="transparent")
        head.grid(row=0, column=0, sticky="ew", padx=16, pady=(16, 10))

        icon_label = ctk.CTkLabel(
            head, text=symbol,
            width=52, height=52,
            corner_radius=12,
            fg_color=self._tint(accent, 0.15),
            text_color=accent,
            font=ctk.CTkFont(size=26, weight="bold"),
        )
        icon_label.pack(side="left")

        ctk.CTkLabel(
            head, text=category, text_color=accent, font=Fonts.badge(9),
        ).pack(side="right")

        ctk.CTkLabel(
            card, text=name, anchor="w",
            text_color=Colors.text, font=Fonts.heading(15),
        ).grid(row=1, column=0, sticky="ew", padx=17, pady=(0, 5))

        ctk.CTkLabel(
            card, text=description, anchor="w", justify="left",
            wraplength=310, text_color=Colors.text_muted, font=Fonts.label(11),
        ).grid(row=2, column=0, sticky="nsew", padx=17, pady=(0, 14))

        button = ctk.CTkButton(
            card, text="Open module  ↗",
            height=34, corner_radius=Spacing.RADIUS_BUTTON,
            fg_color=accent, hover_color=self._darken(accent),
            text_color="#FFFFFF", font=Fonts.label(12, bold=True),
            command=lambda: self.run_module(module_name),
        )
        button.grid(row=3, column=0, sticky="ew", padx=16, pady=(0, 16))

        def on_enter(_event=None):
            try:
                card.configure(border_color=accent)
            except Exception:
                pass

        def on_leave(_event=None):
            try:
                card.configure(border_color=Colors.border)
            except Exception:
                pass

        for widget in (card, head, icon_label, button):
            widget.bind("<Enter>", on_enter, add="+")
            widget.bind("<Leave>", on_leave, add="+")

    # --------------------------------------------------- Recent Activity

    def _build_recent_activity(self, content):
        header = ctk.CTkFrame(content, fg_color="transparent")
        header.grid(row=5, column=0, sticky="ew", pady=(12, 8))

        ctk.CTkLabel(
            header, text="📋  RECENT ACTIVITY", anchor="w",
            font=Fonts.heading(14), text_color=Colors.text,
        ).pack(side="left")

        self._activity_clear_btn = ctk.CTkButton(
            header, text="Clear", width=70, height=26,
            fg_color=Colors.surface_alt, hover_color=Colors.danger,
            font=Fonts.label(10),
            command=self._clear_activity,
        )
        self._activity_clear_btn.pack(side="right")

        self._activity_card = ctk.CTkFrame(
            content, fg_color=Colors.surface,
            corner_radius=Spacing.RADIUS_CARD,
            border_width=1, border_color=Colors.border,
        )
        self._activity_card.grid(row=6, column=0, sticky="ew", pady=(0, 16))
        self._activity_card.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            self._activity_card,
            text="No activity yet. Open a module to start.",
            font=Fonts.label(11), text_color=Colors.text_muted,
        ).pack(pady=20)

    def _log_activity(self, icon: str, message: str) -> None:
        timestamp = datetime.now().strftime("%H:%M")
        self._activity_log.insert(0, (timestamp, icon, message))
        self._activity_log = self._activity_log[:8]
        self._render_activity()

    def _render_activity(self) -> None:
        if not hasattr(self, "_activity_card"):
            return

        for widget in self._activity_card.winfo_children():
            widget.destroy()

        if not self._activity_log:
            ctk.CTkLabel(
                self._activity_card,
                text="No activity yet. Open a module to start.",
                font=Fonts.label(11), text_color=Colors.text_muted,
            ).pack(pady=20)
            return

        for timestamp, icon, message in self._activity_log:
            row = ctk.CTkFrame(self._activity_card, fg_color="transparent")
            row.pack(fill="x", padx=14, pady=3)

            ctk.CTkLabel(
                row, text=timestamp, width=60,
                font=Fonts.mono(10), text_color=Colors.text_dim, anchor="w",
            ).pack(side="left")

            ctk.CTkLabel(
                row, text=icon, width=30,
                font=ctk.CTkFont(size=14), anchor="w",
            ).pack(side="left")

            ctk.CTkLabel(
                row, text=message, anchor="w",
                font=Fonts.label(11), text_color=Colors.text,
            ).pack(side="left", fill="x", expand=True)

    def _clear_activity(self):
        self._activity_log = []
        self._render_activity()

    # ----------------------------------------------------------- footer

    def _build_footer(self, content):
        footer = ctk.CTkFrame(content, fg_color="transparent")
        footer.grid(row=7, column=0, sticky="ew", pady=(20, 0))

        ctk.CTkLabel(
            footer,
            text=f"CyberOpsSuite v{APP_VERSION}  •  Modular security workspace",
            anchor="w", text_color=Colors.text_dim, font=Fonts.label(10),
        ).pack(side="left")

        ctk.CTkLabel(
            footer, text="READY", anchor="e",
            text_color=Colors.success_text, font=Fonts.label(10, bold=True),
        ).pack(side="right")

    # ===================================================== background stats

    def _start_background_stats(self) -> None:
        self._poll_after_id = self.after(200, self._poll_stats)
        self._refresh_ip_stats()
        self._refresh_firewall_stats()
        self._refresh_service_stats()
        self._load_last_scan()
        self.after(30_000, self._periodic_refresh)

    def _periodic_refresh(self):
        self._refresh_firewall_stats()
        self._refresh_service_stats()
        self.after(30_000, self._periodic_refresh)

    def _refresh_ip_stats(self) -> None:
        def worker():
            ip = "Unknown"
            try:
                if HAS_IP_LOGGER:
                    logger = IPLogger()
                    ip = logger.get_real_ip()
                else:
                    import urllib.request
                    with urllib.request.urlopen(
                        "https://api.ipify.org?format=text", timeout=5
                    ) as r:
                        ip = r.read().decode("utf-8").strip()
            except Exception:
                ip = "Offline"
            self._stats_queue.put(("ip", ip))

        threading.Thread(target=worker, daemon=True).start()

    def _refresh_firewall_stats(self) -> None:
        def worker():
            status = "Unknown"
            try:
                if HAS_FIREWALL:
                    fw = FirewallManager()
                    scan = fw.quick_scan()
                    fs = scan.get("firewall_status", "Unknown")
                    rules = scan.get("total_rules", 0)
                    status = f"{fs} ({rules} rules)"
                else:
                    status = "N/A"
            except Exception:
                status = "Error"
            self._stats_queue.put(("firewall", status))

        threading.Thread(target=worker, daemon=True).start()

    def _refresh_service_stats(self) -> None:
        def worker():
            try:
                running = 0
                total = len(CRITICAL_SERVICES)
                if HAS_SERVER_MONITOR:
                    for svc in CRITICAL_SERVICES:
                        info = get_service_details(svc, timeout=3)
                        if info.is_running:
                            running += 1
                status = f"{running}/{total} Running"
            except Exception:
                status = "Error"
            self._stats_queue.put(("services", status))

        threading.Thread(target=worker, daemon=True).start()

    def _load_last_scan(self) -> None:
        try:
            from core.utils.paths import config_root
            import json
            path = config_root("NetworkMapper") / "scan_history.json"
            if path.exists():
                history = json.loads(path.read_text(encoding="utf-8"))
                if history and isinstance(history, list):
                    last = history[-1]
                    finished = last.get("finished_at", "")
                    if finished:
                        dt = datetime.fromisoformat(finished)
                        delta = datetime.now(dt.tzinfo) - dt
                        minutes = int(delta.total_seconds() / 60)
                        if minutes < 1:
                            text = "Just now"
                        elif minutes < 60:
                            text = f"{minutes}m ago"
                        elif minutes < 1440:
                            text = f"{minutes // 60}h ago"
                        else:
                            text = f"{minutes // 1440}d ago"
                        self._stats_queue.put(("last_scan", text))
                        return
            self._stats_queue.put(("last_scan", "Never"))
        except Exception:
            self._stats_queue.put(("last_scan", "Unknown"))

    def _poll_stats(self) -> None:
        try:
            while True:
                kind, value = self._stats_queue.get_nowait()
                self._apply_stat(kind, value)
        except queue.Empty:
            pass

        try:
            if self.winfo_exists():
                self._poll_after_id = self.after(200, self._poll_stats)
        except Exception:
            pass

    def _apply_stat(self, kind: str, value: str) -> None:
        try:
            if kind == "ip":
                if hasattr(self, "_stat_ip"):
                    self._stat_ip.configure(text=value)
                if hasattr(self, "_internet_label"):
                    is_online = value not in ("Offline", "Unknown", "Error")
                    self._internet_label.configure(
                        text="🟢 Online" if is_online else "🔴 Offline",
                        text_color=Colors.success_text if is_online else Colors.danger_text,
                    )
                    self._internet_online = is_online

            elif kind == "firewall":
                if hasattr(self, "_stat_firewall"):
                    self._stat_firewall.configure(text=value)
                if hasattr(self, "_firewall_label"):
                    is_on = "On" in value or "enabled" in value.lower()
                    self._firewall_label.configure(
                        text=value.split("(")[0].strip(),
                        text_color=Colors.success_text if is_on else Colors.danger_text,
                    )

            elif kind == "services":
                if hasattr(self, "_stat_services"):
                    self._stat_services.configure(text=value)
                if hasattr(self, "_services_label"):
                    try:
                        running, total = value.split("/")
                        running = int(running.split()[-1])
                        total = int(total.split()[0])
                        is_ok = running == total
                        self._services_label.configure(
                            text=value,
                            text_color=Colors.success_text if is_ok else Colors.warning_text,
                        )
                    except Exception:
                        self._services_label.configure(text=value)

            elif kind == "last_scan":
                if hasattr(self, "_stat_scans"):
                    self._stat_scans.configure(text=value)
        except Exception:
            pass

    # ------------------------------------------------------- page help

    def _show_page_help(self):
        """Show help for the Dashboard page."""
        dialog = ctk.CTkToplevel(self)
        dialog.title("How to Use | CyberOpsSuite Dashboard")
        dialog.geometry("650x600")
        dialog.minsize(550, 450)
        dialog.configure(fg_color=Colors.bg)
        dialog.transient(self)
        dialog.grab_set()

        apply_window_icon(dialog)

        outer = ctk.CTkScrollableFrame(
            dialog, fg_color=Colors.surface,
            corner_radius=Spacing.RADIUS_CARD,
        )
        outer.pack(fill="both", expand=True, padx=18, pady=18)

        ctk.CTkLabel(
            outer, text="❓  HOW TO USE",
            font=Fonts.badge(11), text_color=Colors.info,
        ).pack(anchor="w", padx=28, pady=(24, 0))

        ctk.CTkLabel(
            outer, text=" CyberOpsSuite Dashboard",
            font=Fonts.title(24), text_color=Colors.text_strong,
        ).pack(anchor="w", padx=28, pady=(6, 2))

        ctk.CTkFrame(outer, height=1, fg_color=Colors.border).pack(
            fill="x", padx=28, pady=16
        )

        help_text = (
            "Welcome to the CyberOpsSuite  CyberOpsSuite Dashboard!\n\n"
            "This page gives you a live overview of your system's security posture.\n\n"
            "1️⃣  LIVE STATUS BAR\n"
            "•  🌐 Internet: Shows if you are online or offline.\n"
            "•  🛡 Firewall: Shows if the firewall is active.\n"
            "•  🖥 Services: Shows how many critical services are running.\n"
            "•  🕐 System Time: Live clock.\n\n"
            "2️⃣  GLOBAL STATS CARDS\n"
            "•  Your Public IP: Your current external IP address.\n"
            "•  Firewall Status: Number of active firewall rules.\n"
            "•  Critical Services: Summary of essential Windows services.\n"
            "•  Last Network Scan: When you last ran a network scan.\n\n"
            "3️⃣  AVAILABLE TOOLS\n"
            "Click 'Open module ↗' on any card to launch that module.\n"
            "Hover over a card to highlight it.\n\n"
            "4️⃣  RECENT ACTIVITY\n"
            "Every time you open a module, it is logged here.\n"
            "You can click 'Clear' to remove the history.\n\n"
            "5️⃣  SCROLLING\n"
            "Use your mouse wheel or touchpad to scroll up and down.\n"
            "On touchpads, use two-finger scrolling."
        )

        ctk.CTkLabel(
            outer, text=help_text,
            font=Fonts.label(11), text_color=Colors.text,
            justify="left", anchor="w", wraplength=580,
        ).pack(fill="x", padx=28, pady=(0, 20))

        ctk.CTkButton(
            outer, text="Got it", width=160, height=40,
            corner_radius=Spacing.RADIUS_BUTTON,
            fg_color=Colors.primary, hover_color=Colors.primary_hover,
            font=Fonts.label(12, bold=True),
            command=dialog.destroy,
        ).pack(anchor="e", padx=28, pady=(0, 22))

        dialog.bind("<Escape>", lambda _e: dialog.destroy())

    # ------------------------------------------------------- about

    def _show_about(self):
        dialog = ctk.CTkToplevel(self)
        dialog.title("About CyberOpsSuite")
        dialog.geometry("780x820")
        dialog.minsize(680, 700)
        dialog.resizable(True, True)
        dialog.configure(fg_color=Colors.bg)
        dialog.transient(self)
        dialog.grab_set()

        apply_window_icon(dialog)

        outer = ctk.CTkScrollableFrame(
            dialog, fg_color=Colors.surface,
            corner_radius=Spacing.RADIUS_CARD,
            scrollbar_button_color=Colors.surface_alt,
            scrollbar_button_hover_color=Colors.border_light,
        )
        outer.pack(fill="both", expand=True, padx=18, pady=18)

        ctk.CTkLabel(
            outer, text="◈  CYBEROPSSUITE",
            font=Fonts.badge(11), text_color=Colors.primary,
        ).pack(anchor="w", padx=28, pady=(24, 0))

        ctk.CTkLabel(
            outer, text="CyberOpsSuite Dashboard",
            font=Fonts.title(24), text_color=Colors.text_strong,
        ).pack(anchor="w", padx=28, pady=(6, 2))

        ctk.CTkLabel(
            outer,
            text=f"Version {APP_VERSION}  ·  Modular security workspace",
            font=Fonts.label(10), text_color=Colors.text_muted,
        ).pack(anchor="w", padx=28)

        ctk.CTkFrame(outer, height=1, fg_color=Colors.border).pack(
            fill="x", padx=28, pady=16
        )

        os_name = f"{platform.system()} {platform.release()}"
        py_version = platform.python_version()

        info_frame = ctk.CTkFrame(
            outer, fg_color=Colors.bg,
            corner_radius=Spacing.RADIUS_INPUT,
            border_width=1, border_color=Colors.border,
        )
        info_frame.pack(fill="x", padx=28, pady=(0, 16))

        info_text = (
            f"Platform:  {os_name}\n"
            f"Python:    {py_version}\n"
            f"Modules:   {len(TOOLS)}\n"
            f"Status:    Live dashboard with real-time stats"
        )
        ctk.CTkLabel(
            info_frame, text=info_text,
            font=Fonts.mono(10), text_color=Colors.text_soft,
            justify="left", anchor="w",
        ).pack(fill="x", padx=14, pady=10)

        self._about_section(outer, "🎯  OVERVIEW", (
            "CyberOpsSuite is a modular desktop security toolkit designed for "
            "system administrators and IT professionals. It bundles seven "
            "independent modules under a single, consistent dashboard.\n\n"
            "The dashboard now shows live system status, global statistics, "
            "and a real-time activity feed, giving you a command-center view "
            "of your security posture."
        ))

        self._about_section(outer, "🆕  NEW IN v1.5.7", (
            "•  Added a 'How to Use' guide specific to the Dashboard\n"
            "•  Replaced CTkScrollableFrame with a standard Tkinter Canvas\n"
            "•  Smooth, reliable scrolling with both mouse and touchpad\n"
            "•  Fixed scroll conflict between dashboard and dialogs\n"
            "•  Recent Activity feed is back"
        ))

        self._about_modules(outer, TOOLS)

        self._about_section(outer, "✨  KEY FEATURES", (
            "•  Unified dark theme across all modules\n"
            "•  Thread-based operations — the UI never freezes\n"
            "•  JSON / CSV / HTML export in reporting modules\n"
            "•  Modular architecture — add your own tool in minutes\n"
            "•  No telemetry, no external calls except where requested"
        ))

        self._about_section(outer, "🌐  PLATFORM SUPPORT", (
            "•  Windows 10 / 11 / Server 2019+    —  full support\n"
            "•  Linux (systemd-based)             —  most modules supported\n"
            "•  macOS                             —  not supported"
        ))

        warning = ctk.CTkFrame(
            outer, fg_color="#2A1D17",
            corner_radius=Spacing.RADIUS_CARD,
            border_width=1, border_color="#7C2D12",
        )
        warning.pack(fill="x", padx=28, pady=(16, 8))

        ctk.CTkLabel(
            warning, text="⚠  RESPONSIBLE USE",
            font=Fonts.badge(11), text_color="#FDBA74", anchor="w",
        ).pack(fill="x", padx=16, pady=(12, 4))

        ctk.CTkLabel(
            warning,
            text=(
                "Use CyberOpsSuite only on systems you own or have explicit "
                "permission to assess. Scanning, firewall modification, and "
                "log analysis can have legal and operational consequences on "
                "networks you do not administer."
            ),
            wraplength=660, justify="left", text_color="#FED7AA",
            font=Fonts.label(11), anchor="w",
        ).pack(fill="x", padx=16, pady=(0, 14))

        ctk.CTkButton(
            outer, text="Close", width=160, height=40,
            corner_radius=Spacing.RADIUS_BUTTON,
            fg_color=Colors.primary, hover_color=Colors.primary_hover,
            font=Fonts.label(12, bold=True),
            command=dialog.destroy,
        ).pack(anchor="e", padx=28, pady=(0, 22))

        dialog.bind("<Escape>", lambda _e: dialog.destroy())
        dialog.update_idletasks()
        x = self.winfo_rootx() + (self.winfo_width() - dialog.winfo_width()) // 2
        y = self.winfo_rooty() + (self.winfo_height() - dialog.winfo_height()) // 2
        dialog.geometry(f"+{max(0, x)}+{max(0, y)}")

    def _about_section(self, parent, title, text):
        wrapper = ctk.CTkFrame(parent, fg_color="transparent")
        wrapper.pack(fill="x", pady=(4, 12), padx=28)

        ctk.CTkLabel(
            wrapper, text=title, font=Fonts.badge(11),
            text_color=Colors.primary, anchor="w",
        ).pack(fill="x", pady=(0, 6))

        ctk.CTkLabel(
            wrapper, text=text, font=Fonts.label(11),
            text_color=Colors.text_soft, justify="left",
            anchor="w", wraplength=660,
        ).pack(fill="x")

    def _about_modules(self, parent, modules):
        wrapper = ctk.CTkFrame(parent, fg_color="transparent")
        wrapper.pack(fill="x", pady=(4, 12), padx=28)

        ctk.CTkLabel(
            wrapper, text="📦  INCLUDED MODULES",
            font=Fonts.badge(11), text_color=Colors.primary, anchor="w",
        ).pack(fill="x", pady=(0, 8))

        for symbol, name, description, _module, _category, accent in modules:
            row = ctk.CTkFrame(
                wrapper, fg_color=Colors.bg_alt,
                corner_radius=Spacing.RADIUS_INPUT,
                border_width=1, border_color=Colors.border,
            )
            row.pack(fill="x", pady=3)

            ctk.CTkLabel(
                row, text=symbol, font=ctk.CTkFont(size=18),
                text_color=accent, width=36,
            ).pack(side="left", padx=(10, 4), pady=8)

            text_frame = ctk.CTkFrame(row, fg_color="transparent")
            text_frame.pack(side="left", fill="x", expand=True, padx=(0, 12), pady=8)

            ctk.CTkLabel(
                text_frame, text=name, font=Fonts.label(12, bold=True),
                text_color=Colors.text, anchor="w",
            ).pack(fill="x")

            ctk.CTkLabel(
                text_frame, text=description, font=Fonts.label(10),
                text_color=Colors.text_muted, anchor="w",
                justify="left", wraplength=520,
            ).pack(fill="x", pady=(2, 0))

    # --------------------------------------------------------- helpers

    @staticmethod
    def _tint(hex_color: str, amount: float) -> str:
        try:
            r = int(hex_color[1:3], 16)
            g = int(hex_color[3:5], 16)
            b = int(hex_color[5:7], 16)
            bg = (0x11, 0x18, 0x27)
            r = int(r * amount + bg[0] * (1 - amount))
            g = int(g * amount + bg[1] * (1 - amount))
            b = int(b * amount + bg[2] * (1 - amount))
            return f"#{r:02X}{g:02X}{b:02X}"
        except Exception:
            return hex_color

    @staticmethod
    def _darken(hex_color: str, factor: float = 0.75) -> str:
        try:
            r = int(hex_color[1:3], 16)
            g = int(hex_color[3:5], 16)
            b = int(hex_color[5:7], 16)
            r = int(r * factor)
            g = int(g * factor)
            b = int(b * factor)
            return f"#{r:02X}{g:02X}{b:02X}"
        except Exception:
            return hex_color

    # ===================================================== module launch

    def run_module(self, module_name: str) -> None:
        self._log_activity("▶", f"Opening {module_name.split('.')[0]}")
        if getattr(sys, "frozen", False):
            self._run_module_exe(module_name)
        else:
            self._run_module_subprocess(module_name)

    def _run_module_exe(self, module_name: str) -> None:
        exe_base = MODULE_TO_EXE.get(module_name)
        if exe_base is None:
            messagebox.showerror(
                "Module not found",
                f"No standalone EXE is registered for:\n{module_name}",
                parent=self,
            )
            return

        install_dir = Path(sys.executable).resolve().parent
        exe_path = install_dir / "modules" / exe_base / f"{exe_base}.exe"

        if not exe_path.is_file():
            legacy_path = install_dir / "modules" / f"{exe_base}.exe"
            if legacy_path.is_file():
                exe_path = legacy_path
            else:
                candidates = [
                    install_dir / "modules" / exe_base / f"{exe_base}.exe",
                    install_dir / "modules" / f"{exe_base}.exe",
                    install_dir / f"{exe_base}.exe",
                ]
                tried = "\n".join(f"  • {c}" for c in candidates)
                messagebox.showerror(
                    "Module EXE not found",
                    f"Could not find the standalone executable for:\n"
                    f"  {exe_base}\n\n"
                    f"Tried the following locations:\n{tried}",
                    parent=self,
                )
                return

        try:
            subprocess.Popen([str(exe_path)], cwd=str(exe_path.parent))
        except (OSError, subprocess.SubprocessError) as exc:
            messagebox.showerror(
                "Unable to launch module",
                f"Could not start {exe_base}.exe\n\nDetails: {exc}",
                parent=self,
            )

    def _run_module_subprocess(self, module_name: str) -> None:
        python = sys.executable
        project_root = str(Path(__file__).resolve().parents[1])

        module_file = os.path.join(project_root, *module_name.split(".")) + ".py"

        if not os.path.isfile(module_file):
            messagebox.showerror(
                "Module not found",
                f"Could not find the module file:\n{module_file}",
                parent=self,
            )
            return

        env = os.environ.copy()
        existing_pythonpath = env.get("PYTHONPATH", "")
        env["PYTHONPATH"] = (
            project_root
            + (os.pathsep + existing_pythonpath if existing_pythonpath else "")
        )

        log_handle = None
        log_path = None
        try:
            log_handle = tempfile.NamedTemporaryFile(
                mode="w", encoding="utf-8", suffix=".log",
                prefix="cyberopssuite_", delete=False,
            )
            log_path = log_handle.name

            process = subprocess.Popen(
                [python, "-u", "-m", module_name],
                cwd=project_root,
                env=env,
                stdout=log_handle,
                stderr=subprocess.STDOUT,
            )
            log_handle.close()
            log_handle = None
            self.after(
                1500,
                lambda: self._check_module_startup(process, module_name, log_path),
            )
        except (OSError, subprocess.SubprocessError) as exc:
            if log_handle is not None:
                log_handle.close()
            if log_path and os.path.exists(log_path):
                try:
                    os.remove(log_path)
                except OSError:
                    pass
            messagebox.showerror(
                "Unable to launch module",
                f"Could not start {module_name}.\n\nDetails: {exc}\n\n"
                f"Expected project folder: {project_root}",
                parent=self,
            )

    def _check_module_startup(self, process, module_name: str, log_path: str) -> None:
        if process.poll() is None:
            try:
                os.remove(log_path)
            except OSError:
                pass
            return

        try:
            with open(log_path, "r", encoding="utf-8", errors="replace") as log_file:
                details = log_file.read().strip()
        except OSError:
            details = "No startup details were captured."
        finally:
            try:
                os.remove(log_path)
            except OSError:
                pass

        if not details:
            details = "The module process closed immediately without printing an error."

        messagebox.showerror(
            "Module did not start",
            f"{module_name} exited during startup.\n\n{details}",
            parent=self,
        )


def main() -> None:
    app = Dashboard()
    app.mainloop()


if __name__ == "__main__":
    main()