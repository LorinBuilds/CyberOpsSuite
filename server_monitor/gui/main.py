"""Server Monitor GUI for CyberOpsSuite.

Monitors the status of a configurable list of local services on Windows
or Linux. Uses CustomTkinter for the interface. Now includes:
- Logging to AppData
- Desktop notifications for critical services
- Health score
- Donut chart
- Service history (uptime)
- Category column
- How to Use guide
"""

from __future__ import annotations

import csv
import logging
import os
import platform
import queue
import sys
import threading
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

import customtkinter as ctk

# ------------------------------------------------------------------
# Logging setup (must be before any other imports)
# ------------------------------------------------------------------
APP_NAME = "Server Monitor"
APP_VERSION = "1.7.0"
APP_SUITE = "CyberOpsSuite"

log_dir = Path(os.getenv("LOCALAPPDATA", Path.home() / ".config")) / "ServerMonitor"
log_dir.mkdir(parents=True, exist_ok=True)
logging.basicConfig(
    filename=log_dir / "server_monitor.log",
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)
logger.info(f"--- Starting {APP_NAME} v{APP_VERSION} ---")

# Always resolve imports from the project root.
PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core.theme import Colors, Fonts, Spacing
from core.gui.treeview_style import apply_treeview_style
from core.utils.icons import apply_window_icon
from core.utils.paths import config_root_quiet

from server_monitor.core.config_store import (
    PRESETS,
    ServiceConfig,
    load_config,
    save_config,
)
from server_monitor.core.service_checker import (
    ServiceInfo,
    get_service_details,
    restart_service,
    start_service,
    stop_service,
)
from server_monitor.core.notification_manager import NotificationManager
from server_monitor.core.health_score import calculate_health_score
from server_monitor.core.service_history import ServiceHistory
from server_monitor.gui.stats_chart import StatsChart


#: Auto-refresh interval (milliseconds).
AUTO_REFRESH_MS = 30_000


class ServerMonitor(ctk.CTk):
    """Main window for the Server Monitor."""

    def __init__(self) -> None:
        super().__init__()

        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("dark-blue")

        self.title(f"{APP_SUITE} | {APP_NAME}")
        self.configure(fg_color=Colors.bg_alt)

        self.update_idletasks()
        screen_w = self.winfo_screenwidth()
        screen_h = self.winfo_screenheight()
        win_w = min(1200, screen_w - 60)
        win_h = min(780, screen_h - 120)
        x = max(0, (screen_w - win_w) // 2)
        y = max(0, (screen_h - win_h) // 2)
        self.geometry(f"{win_w}x{win_h}+{x}+{y}")
        self.minsize(900, 600)

        apply_window_icon(self)
        apply_treeview_style(self)

        # Config
        self._config: ServiceConfig = load_config()

        # State
        self._loading: bool = False
        self._last_scan: str = "Not refreshed yet"
        self._results: queue.Queue = queue.Queue()
        self._poll_after_id: str | None = None
        self._auto_refresh_job: str | None = None
        self._about_open = False

        # Managers
        self._notifier = NotificationManager()
        self._history = ServiceHistory()
        self._last_health_score = 100

        # Observable variables
        self._auto_refresh_var = ctk.BooleanVar(value=False)
        self.total_var = ctk.StringVar(value=str(len(self._config.services())))
        self.running_var = ctk.StringVar(value="—")
        self.stopped_var = ctk.StringVar(value="—")
        self.health_var = ctk.StringVar(value="100")
        self.last_scan_var = ctk.StringVar(value=self._last_scan)
        self.message_var = ctk.StringVar(value="Ready")
        self.preset_var = ctk.StringVar(value=self._config.active_preset)

        self._build_ui()

        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self.bind("<F5>", lambda _event: self.refresh())

        self._poll_after_id = self.after(100, self._poll_results)
        self.after(500, self.refresh)

    # ------------------------------------------------------------------ UI

    def _build_ui(self) -> None:
        outer = ctk.CTkScrollableFrame(
            self, fg_color="transparent",
            scrollbar_button_color=Colors.surface_alt,
            scrollbar_button_hover_color=Colors.border_light,
        )
        outer.pack(fill="both", expand=True, padx=20, pady=20)

        self._build_header(outer)
        self._build_stats_row(outer)
        self._build_table(outer)
        self._build_footer(outer)

    def _build_header(self, parent: ctk.CTkFrame) -> None:
        header = ctk.CTkFrame(parent, fg_color="transparent")
        header.pack(fill="x", pady=(0, 16))

        # Fixed columns for stable positioning:
        # col 0: brand (takes remaining space), col 1: Help, col 2: About
        header.columnconfigure(0, weight=1)
        header.columnconfigure(1, weight=0)
        header.columnconfigure(2, weight=0)

        brand = ctk.CTkFrame(header, fg_color="transparent")
        brand.grid(row=0, column=0, sticky="w")

        ctk.CTkLabel(
            brand, text="Server Monitor",
            font=Fonts.title(24), text_color=Colors.text_strong,
        ).pack(anchor="w")

        self.subtitle_label = ctk.CTkLabel(
            brand, text=f"Preset: {self._config.active_preset}",
            font=Fonts.label(11), text_color=Colors.text_muted,
        )
        self.subtitle_label.pack(anchor="w", pady=(4, 0))

        # Help button (col 1) - always visible
        ctk.CTkButton(
            header, text="❓ How to Use", width=110, height=34,
            corner_radius=Spacing.RADIUS_BUTTON,
            fg_color=Colors.info_bg, hover_color=Colors.info,
            text_color=Colors.info_light, font=Fonts.label(11, bold=True),
            command=self._show_how_to_use,
        ).grid(row=0, column=1, sticky="ne", padx=(0, 8), pady=8)

        # About button (col 2) - always visible
        ctk.CTkButton(
            header, text="About", width=90, height=34,
            corner_radius=Spacing.RADIUS_BUTTON,
            fg_color=Colors.neutral_dark, hover_color=Colors.neutral_dark_hover,
            font=Fonts.label(10), command=self._show_about,
        ).grid(row=0, column=2, sticky="ne", pady=8)

    def _build_stats_row(self, parent: ctk.CTkFrame) -> None:
        row = ctk.CTkFrame(parent, fg_color="transparent")
        row.pack(fill="x", pady=(0, 16))
        row.columnconfigure(0, weight=1)

        stats = ctk.CTkFrame(row, fg_color="transparent")
        stats.grid(row=0, column=0, sticky="nsew", padx=(0, 12))

        specs = [
            ("MONITORED", self.total_var, Colors.info),
            ("RUNNING", self.running_var, Colors.success_text),
            ("STOPPED", self.stopped_var, Colors.danger_text),
            ("HEALTH SCORE", self.health_var, Colors.success_text),
        ]
        for index, (title, var, color) in enumerate(specs):
            card = ctk.CTkFrame(
                stats, fg_color=Colors.surface,
                corner_radius=Spacing.RADIUS_CARD,
                border_width=1, border_color=Colors.border,
            )
            padx = (0, 10) if index < len(specs) - 1 else 0
            card.pack(side="left", fill="both", expand=True, padx=padx)

            ctk.CTkLabel(
                card, text=title,
                font=Fonts.badge(9), text_color=Colors.text_muted,
            ).pack(anchor="w", padx=14, pady=(14, 2))

            self._stat_labels = getattr(self, "_stat_labels", {})
            label = ctk.CTkLabel(
                card, textvariable=var,
                font=Fonts.title(22), text_color=color,
            )
            label.pack(anchor="w", padx=14, pady=(0, 14))
            self._stat_labels[title] = label

        self.chart = StatsChart(row, width=220, height=220)
        self.chart.grid(row=0, column=1, sticky="e", padx=(0, 4))

    def _build_table(self, parent: ctk.CTkFrame) -> None:
        card = ctk.CTkFrame(
            parent, fg_color=Colors.surface,
            corner_radius=Spacing.RADIUS_CARD,
            border_width=1, border_color=Colors.border,
        )
        card.pack(fill="both", expand=True, pady=(0, 16))
        card.rowconfigure(1, weight=1)
        card.columnconfigure(0, weight=1)

        top = ctk.CTkFrame(card, fg_color="transparent")
        top.grid(row=0, column=0, sticky="ew", padx=16, pady=(14, 8))
        top.columnconfigure(0, weight=1)

        ctk.CTkLabel(
            top, text="SERVICE STATUS",
            font=Fonts.badge(10), text_color=Colors.text_muted,
        ).grid(row=0, column=0, sticky="w")

        right = ctk.CTkFrame(top, fg_color="transparent")
        right.grid(row=0, column=1, sticky="e")

        ctk.CTkLabel(
            right, textvariable=self.last_scan_var,
            font=Fonts.label(10), text_color=Colors.text_muted,
        ).pack(side="left", padx=(0, 12))

        ctk.CTkCheckBox(
            right, text="Auto-refresh (30 s)",
            variable=self._auto_refresh_var,
            command=self._toggle_auto_refresh,
            font=Fonts.label(10), text_color=Colors.text,
            fg_color=Colors.primary, hover_color=Colors.primary_hover,
            border_color=Colors.border_light,
        ).pack(side="left")

        table_frame = ctk.CTkFrame(card, fg_color="transparent")
        table_frame.grid(row=1, column=0, sticky="nsew", padx=12, pady=(0, 8))
        table_frame.rowconfigure(0, weight=1)
        table_frame.columnconfigure(0, weight=1)

        columns = ("service", "display", "category", "status", "start_type", "uptime", "pid")
        headings = {
            "service": "SERVICE NAME", "display": "DISPLAY NAME",
            "category": "CATEGORY", "status": "STATUS",
            "start_type": "START TYPE", "uptime": "LAST CHANGE", "pid": "PID",
        }
        widths = {
            "service": 140, "display": 200, "category": 100,
            "status": 110, "start_type": 110, "uptime": 120, "pid": 70,
        }

        self.tree = ttk.Treeview(
            table_frame, columns=columns, show="headings",
            selectmode="browse", style="Cyber.Treeview",
        )
        for col in columns:
            self.tree.heading(col, text=headings[col], anchor="w")
            self.tree.column(
                col, width=widths[col], minwidth=60,
                anchor="w" if col in ("service", "display") else "center",
                stretch=(col == "display"),
            )

        self.tree.tag_configure("running", foreground=Colors.success_text)
        self.tree.tag_configure("stopped", foreground=Colors.danger_text)
        self.tree.tag_configure("unknown", foreground=Colors.text_dim)

        yscroll = ttk.Scrollbar(
            table_frame, orient="vertical", style="Vertical.TScrollbar",
            command=self.tree.yview,
        )
        self.tree.configure(yscrollcommand=yscroll.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        yscroll.grid(row=0, column=1, sticky="ns")

        actions = ctk.CTkFrame(card, fg_color="transparent")
        actions.grid(row=2, column=0, sticky="ew", padx=12, pady=(0, 12))

        self.action_label = ctk.CTkLabel(
            actions, text="Select a service to control it.",
            font=Fonts.label(10), text_color=Colors.text_muted,
        )
        self.action_label.pack(side="left", padx=(4, 0))

        self.stop_btn = ctk.CTkButton(
            actions, text="■  Stop", width=100, height=Spacing.BUTTON_HEIGHT,
            fg_color=Colors.danger, hover_color=Colors.danger_hover,
            font=Fonts.label(10, bold=True),
            command=self._on_stop_service, state="disabled",
        )
        self.stop_btn.pack(side="right", padx=(6, 0))

        self.start_btn = ctk.CTkButton(
            actions, text="▶  Start", width=100, height=Spacing.BUTTON_HEIGHT,
            fg_color=Colors.success, hover_color=Colors.success_hover,
            font=Fonts.label(10, bold=True),
            command=self._on_start_service, state="disabled",
        )
        self.start_btn.pack(side="right", padx=(6, 0))

        self.restart_btn = ctk.CTkButton(
            actions, text="↻  Restart", width=110, height=Spacing.BUTTON_HEIGHT,
            fg_color=Colors.neutral_dark, hover_color=Colors.neutral_dark_hover,
            font=Fonts.label(10),
            command=self._on_restart_service, state="disabled",
        )
        self.restart_btn.pack(side="right", padx=(6, 0))

        self.tree.bind("<<TreeviewSelect>>", self._on_tree_select)

    def _build_footer(self, parent: ctk.CTkFrame) -> None:
        footer = ctk.CTkFrame(parent, fg_color="transparent")
        footer.pack(fill="x")
        footer.columnconfigure(0, weight=1)

        ctk.CTkLabel(
            footer, textvariable=self.message_var,
            font=Fonts.label(10), text_color=Colors.text_muted,
        ).grid(row=0, column=0, sticky="w")

        self.export_btn = ctk.CTkButton(
            footer, text="📥  Export CSV",
            width=140, height=Spacing.BUTTON_HEIGHT,
            font=Fonts.label(11),
            fg_color=Colors.neutral_dark, hover_color=Colors.neutral_dark_hover,
            command=self._export_csv,
        )
        self.export_btn.grid(row=0, column=1, sticky="e", padx=(0, 8))

        self.settings_btn = ctk.CTkButton(
            footer, text="⚙  Settings",
            width=140, height=Spacing.BUTTON_HEIGHT,
            font=Fonts.label(11),
            fg_color=Colors.neutral_dark, hover_color=Colors.neutral_dark_hover,
            command=self._open_settings,
        )
        self.settings_btn.grid(row=0, column=2, sticky="e", padx=(0, 8))

        self.refresh_btn = ctk.CTkButton(
            footer, text="↻  Refresh Status",
            width=170, height=Spacing.BUTTON_HEIGHT,
            font=Fonts.label(11, bold=True),
            fg_color=Colors.primary, hover_color=Colors.primary_hover,
            command=self.refresh,
        )
        self.refresh_btn.grid(row=0, column=3, sticky="e")

    # ------------------------------------------------------------- How to Use

    def _show_how_to_use(self):
        """Show help for the Server Monitor."""
        dialog = ctk.CTkToplevel(self)
        dialog.title("How to Use | Server Monitor")
        dialog.geometry("700x750")
        dialog.minsize(600, 600)
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
            outer, text="Server Monitor",
            font=Fonts.title(24), text_color=Colors.text_strong,
        ).pack(anchor="w", padx=28, pady=(6, 2))

        ctk.CTkFrame(outer, height=1, fg_color=Colors.border).pack(
            fill="x", padx=28, pady=16
        )

        help_text = (
            "Welcome to Server Monitor!\n\n"
            "1️⃣  OVERVIEW\n"
            "•  Monitored: Number of services in the current preset.\n"
            "•  Running: Services that are active.\n"
            "•  Stopped: Services that are stopped or failed.\n"
            "•  Health Score: 0–100 based on running vs stopped services.\n"
            "•  Donut Chart: Visual representation of running vs stopped.\n\n"
            "2️⃣  SERVICE TABLE\n"
            "•  SERVICE NAME: Internal service name.\n"
            "•  DISPLAY NAME: Friendly description.\n"
            "•  CATEGORY: Functional group (Network, Security, etc.).\n"
            "•  STATUS: Running, Stopped, Failed, etc.\n"
            "•  START TYPE: Automatic, Manual, Disabled.\n"
            "•  LAST CHANGE: How long since the status last changed.\n"
            "•  PID: Process ID (if running).\n\n"
            "3️⃣  SERVICE CONTROL\n"
            "•  Select a service row to enable Start/Stop/Restart buttons.\n"
            "•  Start: Only if stopped.\n"
            "•  Stop: Only if running (requires admin).\n"
            "•  Restart: Stop then start.\n"
            "⚠  Requires Administrator privileges on Windows.\n\n"
            "4️⃣  SETTINGS\n"
            "•  Choose a Preset (Domain Controller, File Server, etc.)\n"
            "•  Or browse all installed services to build a custom list.\n\n"
            "5️⃣  AUTO-REFRESH\n"
            "•  Enable to check services every 30 seconds.\n"
            "•  Disable to refresh manually with F5 or the Refresh button.\n\n"
            "6️⃣  EXPORT\n"
            "•  Export CSV: Save current status to a CSV file."
        )

        ctk.CTkLabel(
            outer, text=help_text,
            font=Fonts.label(11), text_color=Colors.text,
            justify="left", anchor="w", wraplength=620,
        ).pack(fill="x", padx=28, pady=(0, 20))

        ctk.CTkButton(
            outer, text="Got it", width=160, height=40,
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

    # --------------------------------------------------------------- About

    def _show_about(self) -> None:
        if self._about_open:
            return
        self._about_open = True

        # IMPORTANT: We do NOT hide the Help button here.
        # Both Help and About stay in the header at all times.

        dialog = ctk.CTkToplevel(self)
        dialog.title("About Server Monitor")
        dialog.geometry("680x720")
        dialog.resizable(False, False)
        dialog.configure(fg_color=Colors.bg)
        dialog.transient(self)
        dialog.grab_set()

        apply_window_icon(dialog)

        def on_close():
            dialog.destroy()
            self._about_open = False

        dialog.protocol("WM_DELETE_WINDOW", on_close)

        card = ctk.CTkFrame(
            dialog, fg_color=Colors.surface,
            corner_radius=Spacing.RADIUS_CARD,
            border_width=1, border_color=Colors.border,
        )
        card.pack(fill="both", expand=True, padx=18, pady=18)

        ctk.CTkLabel(
            card, text="◈  CYBEROPSSUITE",
            font=Fonts.badge(11), text_color=Colors.info,
        ).pack(anchor="w", padx=26, pady=(24, 0))

        ctk.CTkLabel(
            card, text="Server Monitor",
            font=Fonts.title(22), text_color=Colors.text,
        ).pack(anchor="w", padx=26, pady=(6, 2))

        ctk.CTkLabel(
            card,
            text=f"{APP_SUITE}  •  Version {APP_VERSION}",
            font=Fonts.label(10), text_color=Colors.text_muted,
        ).pack(anchor="w", padx=26)

        ctk.CTkFrame(card, fg_color=Colors.border, height=1).pack(
            fill="x", padx=26, pady=14
        )

        os_name = f"{platform.system()} {platform.release()}"
        py_version = platform.python_version()
        cfg_path = config_root_quiet("ServerMonitor")

        info_frame = ctk.CTkFrame(
            card, fg_color=Colors.bg,
            corner_radius=Spacing.RADIUS_INPUT,
            border_width=1, border_color=Colors.border,
        )
        info_frame.pack(fill="x", padx=26, pady=(0, 12))

        info_text = (
            f"Platform:  {os_name}\n"
            f"Python:    {py_version}\n"
            f"Config:    {cfg_path}\n"
            f"Log file:  {log_dir / 'server_monitor.log'}"
        )
        ctk.CTkLabel(
            info_frame, text=info_text,
            font=Fonts.mono(10), text_color=Colors.text_soft,
            justify="left", anchor="w",
        ).pack(fill="x", padx=14, pady=10)

        description = (
            "A lightweight desktop utility for monitoring and controlling "
            "local system services on Windows and Linux.\n\n"
            "FEATURES\n"
            "• Configurable service list with presets\n"
            "• Cross-platform: Windows (sc) and Linux (systemctl)\n"
            "• Detailed view: status, start type, PID, category\n"
            "• Start, Stop, and Restart services\n"
            "• Auto-refresh every 30 seconds\n"
            "• Export the current status to CSV\n"
            "• Thread-based operations — the UI never freezes\n"
            "• Health score and donut chart\n"
            "• Service uptime (last change)\n"
            "• Desktop notifications for critical failures\n"
            "• Detailed logging to server_monitor.log\n\n"
            "REQUIREMENTS\n"
            "• Windows: Administrator privileges for Start/Stop/Restart\n"
            "• Linux:   root or polkit authorization for control actions\n"
            "• Optional: 'plyer' for desktop notifications\n\n"
            "SUPPORTED PLATFORMS\n"
            "• Windows 10 / 11 / Server 2019+\n"
            "• Linux (systemd-based distributions)\n"
            "• macOS is not supported."
        )
        ctk.CTkLabel(
            card, text=description,
            font=Fonts.label(11), text_color=Colors.text,
            justify="left", anchor="w", wraplength=580,
        ).pack(fill="x", padx=26)

        footer = ctk.CTkFrame(card, fg_color="transparent")
        footer.pack(side="bottom", fill="x", padx=26, pady=(20, 22))

        ctk.CTkButton(
            footer, text="Close", width=160, height=40,
            corner_radius=Spacing.RADIUS_BUTTON,
            fg_color=Colors.primary, hover_color=Colors.primary_hover,
            font=Fonts.label(12, bold=True), command=on_close,
        ).pack(side="right")

        ctk.CTkLabel(
            footer, text="CyberOpsSuite · Local security toolkit",
            font=Fonts.label(10), text_color=Colors.text_muted,
        ).pack(side="left")

        dialog.bind("<Escape>", lambda _e: on_close())
        dialog.update_idletasks()
        x = self.winfo_rootx() + (self.winfo_width() - dialog.winfo_width()) // 2
        y = self.winfo_rooty() + (self.winfo_height() - dialog.winfo_height()) // 2
        dialog.geometry(f"+{max(0, x)}+{max(0, y)}")

    # ------------------------------------------------------------- settings

    def _open_settings(self) -> None:
        from server_monitor.gui.settings_dialog import SettingsDialog
        SettingsDialog(self, on_saved=self._on_settings_saved)

    def _on_settings_saved(self, config) -> None:
        self._config = config
        self.subtitle_label.configure(text=f"Preset: {config.active_preset}")
        self.total_var.set(str(len(config.services())))
        self.message_var.set("Settings saved")
        logger.info(f"Settings saved (preset={config.active_preset})")
        self.refresh()

    # -------------------------------------------------------------- refresh

    def refresh(self) -> None:
        if self._loading:
            return
        self._set_busy(True, "Checking local services…")
        threading.Thread(
            target=self._worker_refresh,
            args=(self._config.services(),),
            daemon=True,
        ).start()

    def _worker_refresh(self, services: list[str]) -> None:
        results = []
        for name in services:
            try:
                info = get_service_details(name)
            except Exception:
                info = ServiceInfo(name=name, status="Unknown")
            results.append(info)
        self._results.put((self._apply_results, (results,)))

    def _apply_results(self, results: list) -> None:
        self.tree.delete(*self.tree.get_children())

        running = 0
        critical_stopped = 0
        current_states: dict[str, str] = {}

        critical_names = set(PRESETS.get("Domain Controller", ()))
        critical_names.update(PRESETS.get("DHCP Server", ()))

        for info in results:
            if info.is_running:
                running += 1
                tag = "running"
            elif info.status in ("Not found", "Unknown"):
                tag = "unknown"
            else:
                tag = "stopped"

            if info.status == "Stopped" and info.name in critical_names:
                critical_stopped += 1

            self._history.update(info.name, info.status)
            uptime_text = self._history.format_change(info.name, info.status)

            current_states[info.name] = info.status

            display = info.display_name or "—"
            start_type = info.start_type or "—"
            pid_text = str(info.pid) if info.pid else "—"
            category = getattr(info, "category", "") or "—"

            self.tree.insert(
                "", "end",
                values=(
                    info.name, display, category, info.status,
                    start_type, uptime_text, pid_text,
                ),
                tags=(tag,),
            )

        total = len(results)
        self.total_var.set(str(total))
        self.running_var.set(str(running))
        self.stopped_var.set(str(total - running))

        score = calculate_health_score(total, running, critical_stopped)
        self.health_var.set(str(score))
        self._last_health_score = score

        self.chart.update_chart(running, total - running)

        try:
            alerts = self._notifier.check_transitions(
                current_states, list(critical_names)
            )
            for service, old, new in alerts:
                logger.warning(
                    f"CRITICAL: {service} went {old} -> {new}"
                )
                self._notifier.notify(
                    "Critical Service Stopped",
                    f"{service} is no longer running!",
                )
        except Exception as exc:
            logger.warning(f"Notification check failed: {exc}")

        self._last_scan = datetime.now().strftime("Updated at %H:%M:%S")
        self.last_scan_var.set(self._last_scan)
        self._set_busy(False, "Refresh complete")
        logger.info(
            f"Refresh complete: {running}/{total} running, "
            f"health={score}, critical_stopped={critical_stopped}"
        )

    def _set_busy(self, busy: bool, message: str | None) -> None:
        self._loading = busy
        state = "disabled" if busy else "normal"
        self.refresh_btn.configure(state=state)
        self.settings_btn.configure(state=state)
        self.export_btn.configure(state=state)
        if message:
            self.message_var.set(message)

    # -------------------------------------------------- service actions

    def _on_tree_select(self, _event=None) -> None:
        selection = self.tree.selection()
        if not selection:
            self.action_label.configure(text="Select a service to control it.")
            self.start_btn.configure(state="disabled")
            self.stop_btn.configure(state="disabled")
            self.restart_btn.configure(state="disabled")
            return

        values = self.tree.item(selection[0], "values")
        name = values[0] if values else ""
        status = values[3] if len(values) > 3 else ""
        self.action_label.configure(text=f"Selected: {name} ({status})")

        is_running = status == "Running"
        is_stopped = status in ("Stopped", "Failed")

        self.start_btn.configure(state="normal" if is_stopped else "disabled")
        self.stop_btn.configure(state="normal" if is_running else "disabled")
        self.restart_btn.configure(
            state="normal" if (is_running or is_stopped) else "disabled"
        )

    def _selected_service_name(self) -> str | None:
        selection = self.tree.selection()
        if not selection:
            return None
        values = self.tree.item(selection[0], "values")
        return values[0] if values else None

    def _on_start_service(self) -> None:
        self._control_selected_service("start")

    def _on_stop_service(self) -> None:
        self._control_selected_service("stop")

    def _on_restart_service(self) -> None:
        self._control_selected_service("restart")

    def _control_selected_service(self, action: str) -> None:
        name = self._selected_service_name()
        if not name:
            return

        fn = {"start": start_service, "stop": stop_service}.get(action, restart_service)

        if action in ("stop", "restart"):
            if not messagebox.askyesno(
                f"Confirm {action}",
                f"Are you sure you want to {action} the service:\n\n"
                f"  {name}\n\nThis may interrupt running applications.",
                parent=self,
            ):
                return

        logger.info(f"User requested {action} on '{name}'")
        self._set_busy(True, f"{action.capitalize()}ing {name}…")

        def worker():
            try:
                success, msg = fn(name)
            except Exception as exc:
                success, msg = False, str(exc)
            self._results.put((self._apply_action_result, (name, action, success, msg)))

        threading.Thread(target=worker, daemon=True).start()

    def _apply_action_result(self, name: str, action: str, success: bool, message: str) -> None:
        self._set_busy(False, None)
        if success:
            logger.info(f"{action.capitalize()} '{name}' succeeded")
            self.message_var.set(f"{action.capitalize()} '{name}' — OK")
        else:
            logger.error(f"{action.capitalize()} '{name}' failed: {message}")
            self.message_var.set(f"{action.capitalize()} '{name}' — failed")
            messagebox.showerror(
                f"{action.capitalize()} failed",
                f"Could not {action} '{name}':\n\n{message}",
                parent=self,
            )
        self.refresh()

    # ---------------------------------------------------------- export

    def _export_csv(self) -> None:
        rows = [self.tree.item(item, "values") for item in self.tree.get_children()]
        if not rows:
            messagebox.showinfo("Export CSV", "There are no rows to export.", parent=self)
            return

        path = filedialog.asksaveasfilename(
            parent=self, title="Export service status",
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
            initialfile="server_monitor.csv",
        )
        if not path:
            return

        headers = ("Service Name", "Display Name", "Category", "Status",
                   "Start Type", "Last Change", "PID")
        try:
            with open(path, "w", newline="", encoding="utf-8-sig") as handle:
                writer = csv.writer(handle)
                writer.writerow(headers)
                writer.writerows(rows)
            logger.info(f"Exported {len(rows)} rows to {path}")
            self.message_var.set(f"Exported {len(rows)} rows to {path}")
            messagebox.showinfo("Export CSV", f"Exported {len(rows)} row(s).", parent=self)
        except OSError as exc:
            logger.error(f"Export failed: {exc}")
            messagebox.showerror("Export failed", str(exc), parent=self)

    # ------------------------------------------------------- auto-refresh

    def _toggle_auto_refresh(self) -> None:
        if self._auto_refresh_var.get():
            self._schedule_auto_refresh()
            self.message_var.set("Auto-refresh enabled (every 30 s)")
            logger.info("Auto-refresh enabled")
        elif self._auto_refresh_job is not None:
            try:
                self.after_cancel(self._auto_refresh_job)
            except Exception:
                pass
            self._auto_refresh_job = None
            self.message_var.set("Auto-refresh disabled")
            logger.info("Auto-refresh disabled")

    def _schedule_auto_refresh(self) -> None:
        if self._auto_refresh_var.get():
            self._auto_refresh_job = self.after(AUTO_REFRESH_MS, self._auto_refresh)

    def _auto_refresh(self) -> None:
        self._auto_refresh_job = None
        if self._auto_refresh_var.get():
            self.refresh()
            self._schedule_auto_refresh()

    # -------------------------------------------------------- worker polling

    def _poll_results(self) -> None:
        try:
            while True:
                callback, args = self._results.get_nowait()
                callback(*args)
        except queue.Empty:
            pass
        try:
            if self.winfo_exists():
                self._poll_after_id = self.after(100, self._poll_results)
        except Exception:
            return

    # -------------------------------------------------------------- closing

    def _on_close(self) -> None:
        logger.info("--- Shutting down ---")
        for after_id in (self._poll_after_id, self._auto_refresh_job):
            if after_id is not None:
                try:
                    self.after_cancel(after_id)
                except Exception:
                    pass
        self.destroy()


def main() -> None:
    try:
        app = ServerMonitor()
        app.mainloop()
    except Exception:
        logger.exception("Fatal error in main loop")
        raise


if __name__ == "__main__":
    main()