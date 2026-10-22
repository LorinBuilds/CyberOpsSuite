"""Event Log Analyzer GUI for CyberOpsSuite.

Reads local Windows Application/System/Security event logs through
PowerShell, or the Linux systemd journal through ``journalctl``, or a
JSON Lines log file. Run it from the repository root with::

    python -m event_log_analyzer.gui.main
"""

from __future__ import annotations

import os
import platform
import queue
import sys
import threading
import time
import tkinter as tk
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

import customtkinter as ctk

# Always resolve imports from the project root, regardless of
# the directory from which this file is launched.
PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core.theme import Colors, Fonts, Spacing
from core.gui.treeview_style import apply_treeview_style
from core.utils.icons import apply_window_icon
from core.utils.paths import config_root_quiet

from event_log_analyzer import __version__
from event_log_analyzer.core import bookmarks
from event_log_analyzer.core.exporters import write_csv
from event_log_analyzer.core.filters import ALL_SEARCH_FIELDS, filter_entries
from event_log_analyzer.core.levels import FILTER_LEVELS, normalize_level
from event_log_analyzer.core.parser import LogEntry, LogParser
from event_log_analyzer.core.windows_events import (
    MAX_EVENTS,
    MIN_EVENTS,
    SYSTEM_LOGS,
    EventLogError,
    find_powershell,
    read_windows_events,
)
from event_log_analyzer.core.linux_events import (
    SYSTEM_JOURNALS,
    JournalError,
    find_journalctl,
    read_linux_journal,
)


LEVELS = list(FILTER_LEVELS)

#: Source modes.
SOURCE_WINDOWS = "Windows Event Logs"
SOURCE_LINUX = "Linux Journal"
SOURCE_FILE = "Log File"


class EventLogGUI(ctk.CTk):
    """Main application window for Event Log Analyzer."""

    def __init__(self) -> None:
        super().__init__()

        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("dark-blue")

        self._setup_state()
        self._setup_window()

        apply_window_icon(self)
        apply_treeview_style(self)

        self._build_ui()
        self._bind_shortcuts()

        self.after(250, self._center_window_on_screen)
        self.after(150, self._check_backends)
        self._auto_refresh_after_id = self.after(1000, self._auto_refresh_tick)
        self._poll_after_id = self.after(100, self._poll_results)

    # --------------------------------------------------------------- setup

    def _setup_state(self) -> None:
        self.logs: list[LogEntry] = []
        self.visible_logs: list[LogEntry] = []
        self.log_file: str | None = None
        self._loading: bool = False

        if os.name == "nt":
            default_source = SOURCE_WINDOWS
        elif platform.system() == "Linux":
            default_source = SOURCE_LINUX
        else:
            default_source = SOURCE_FILE

        self.source_mode = tk.StringVar(value=default_source)
        self.system_source = tk.StringVar(value="System")
        self.limit_var = tk.StringVar(value="300")
        self.level_var = tk.StringVar(value="ALL")
        self.search_var = tk.StringVar(value="")
        self.status_var = tk.StringVar(value="Ready — choose a log source.")
        self.auto_refresh_var = tk.BooleanVar(value=False)
        self.refresh_interval_var = tk.StringVar(value="10")
        self.last_refresh_var = tk.StringVar(value="Last refresh: never")
        
        self.show_bookmarks_only = tk.BooleanVar(value=False)

        self._next_auto_refresh: float | None = None
        self._auto_refresh_after_id: str | None = None
        self._poll_after_id: str | None = None

        self._results: queue.Queue = queue.Queue()

    def _setup_window(self) -> None:
        self.title("CyberOpsSuite | Event Log Analyzer")

        self.update_idletasks()
        screen_width = self.winfo_screenwidth()
        screen_height = self.winfo_screenheight()

        window_width = min(1440, max(800, screen_width - 80))
        window_height = min(900, max(600, screen_height - 100))
        window_width = min(window_width, screen_width)
        window_height = min(window_height, screen_height)

        x = max(0, (screen_width - window_width) // 2)
        y = max(0, (screen_height - window_height) // 2)
        self.geometry(f"{window_width}x{window_height}+{x}+{y}")
        self.minsize(min(1050, screen_width), min(680, screen_height))
        self.configure(fg_color=Colors.bg)

        self._set_dark_title_bar()

    def _set_dark_title_bar(self) -> None:
        if os.name != "nt":
            return
        try:
            import ctypes
            hwnd = ctypes.windll.user32.GetParent(self.winfo_id())
            value = ctypes.c_int(1)
            result = ctypes.windll.dwmapi.DwmSetWindowAttribute(
                hwnd, 20, ctypes.byref(value), ctypes.sizeof(value)
            )
            if result != 0:
                ctypes.windll.dwmapi.DwmSetWindowAttribute(
                    hwnd, 19, ctypes.byref(value), ctypes.sizeof(value)
                )
        except Exception:
            pass

    def _center_window_on_screen(self) -> None:
        self.update_idletasks()
        screen_width = self.winfo_screenwidth()
        screen_height = self.winfo_screenheight()

        width = self.winfo_width()
        height = self.winfo_height()
        if width <= 1:
            width = min(1440, screen_width - 80)
        if height <= 1:
            height = min(900, screen_height - 100)

        width = min(width, max(640, screen_width - 40))
        height = min(height, max(420, screen_height - 80))
        x = max(0, (screen_width - width) // 2)
        y = max(0, (screen_height - height) // 2)
        self.geometry(f"{width}x{height}+{x}+{y}")

    def _bind_shortcuts(self) -> None:
        shortcuts = {
            "<F5>": self._on_f5,
            "<Control-r>": self._on_f5, "<Control-R>": self._on_f5,
            "<Control-o>": self._on_ctrl_o, "<Control-O>": self._on_ctrl_o,
            "<Control-e>": self._on_ctrl_e, "<Control-E>": self._on_ctrl_e,
            "<Control-f>": self._on_ctrl_f, "<Control-F>": self._on_ctrl_f,
            "<Control-l>": self._on_ctrl_l, "<Control-L>": self._on_ctrl_l,
            "<F1>": self._on_f1,
        }
        for sequence, handler in shortcuts.items():
            self.bind_all(sequence, handler)

        self.protocol("WM_DELETE_WINDOW", self._on_close)

    # ------------------------------------------------------------- build UI

    def _build_ui(self) -> None:
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(3, weight=1)

        self._build_header()
        self._build_controls()
        self._build_filters()
        self._build_table()
        self._build_footer()

    def _build_header(self) -> None:
        header = ctk.CTkFrame(self, corner_radius=0, fg_color=Colors.surface)
        header.grid(row=0, column=0, sticky="ew")
        header.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            header, text="EVENT LOG ANALYZER",
            font=Fonts.title(25), text_color=Colors.text_strong,
        ).grid(row=0, column=0, sticky="w", padx=24, pady=(18, 2))

        ctk.CTkLabel(
            header, text="Inspect Windows event logs, the Linux journal, or a log file",
            font=Fonts.label(12), text_color=Colors.text_muted,
        ).grid(row=1, column=0, sticky="w", padx=25, pady=(0, 16))

        # Add buttons
        actions = ctk.CTkFrame(header, fg_color="transparent")
        actions.grid(row=0, column=1, rowspan=2, sticky="e", padx=24, pady=16)

        ctk.CTkButton(
            actions, text="❓ How to Use", width=110, height=34,
            corner_radius=Spacing.RADIUS_BUTTON,
            fg_color=Colors.info_bg, hover_color=Colors.info,
            text_color=Colors.info_light, font=Fonts.label(11, bold=True),
            command=self._show_how_to_use,
        ).pack(side="right", padx=(0, 8))

        ctk.CTkButton(
            actions, text="About", width=90, height=34,
            corner_radius=Spacing.RADIUS_BUTTON,
            fg_color=Colors.surface_alt, hover_color=Colors.primary,
            text_color=Colors.text, font=Fonts.label(11, bold=True),
            command=self.show_about,
        ).pack(side="right")

    def _build_controls(self) -> None:
        controls = ctk.CTkFrame(
            self, corner_radius=Spacing.RADIUS_CARD,
            fg_color=Colors.surface,
            border_width=1, border_color=Colors.border,
        )
        controls.grid(row=1, column=0, sticky="ew", padx=18, pady=(14, 10))
        controls.grid_columnconfigure(8, weight=1)

        ctk.CTkLabel(
            controls, text="Source",
            font=Fonts.label(12), text_color=Colors.text,
        ).grid(row=0, column=0, padx=(12, 6), pady=12)

        ctk.CTkOptionMenu(
            controls, variable=self.source_mode,
            values=[SOURCE_WINDOWS, SOURCE_LINUX, SOURCE_FILE],
            width=170,
            fg_color=Colors.primary, button_color=Colors.primary_hover,
            button_hover_color=Colors.primary_active,
            dropdown_fg_color=Colors.surface,
            dropdown_hover_color=Colors.primary,
            command=self._source_changed,
        ).grid(row=0, column=1, padx=5, pady=12)

        ctk.CTkLabel(
            controls, text="Log",
            font=Fonts.label(12), text_color=Colors.text,
        ).grid(row=0, column=2, padx=(10, 5), pady=12)

        self.system_menu = ctk.CTkOptionMenu(
            controls, variable=self.system_source,
            values=list(SYSTEM_LOGS),
            width=125,
            fg_color=Colors.primary, button_color=Colors.primary_hover,
            button_hover_color=Colors.primary_active,
            dropdown_fg_color=Colors.surface,
            dropdown_hover_color=Colors.primary,
        )
        self.system_menu.grid(row=0, column=3, padx=5, pady=12)

        ctk.CTkLabel(
            controls, text="Max events",
            font=Fonts.label(12), text_color=Colors.text,
        ).grid(row=0, column=4, padx=(10, 5), pady=12)

        ctk.CTkOptionMenu(
            controls, variable=self.limit_var,
            values=["100", "300", "500", "1000", "2000"],
            width=90,
            fg_color=Colors.primary, button_color=Colors.primary_hover,
            button_hover_color=Colors.primary_active,
            dropdown_fg_color=Colors.surface,
            dropdown_hover_color=Colors.primary,
        ).grid(row=0, column=5, padx=5, pady=12)

        self.load_button = ctk.CTkButton(
            controls, text="Refresh Now",
            command=self.refresh_now,
            width=115, height=Spacing.BUTTON_HEIGHT,
            fg_color=Colors.primary, hover_color=Colors.primary_hover,
        )
        self.load_button.grid(row=0, column=6, padx=(10, 6), pady=12)

        ctk.CTkButton(
            controls, text="Open File…",
            command=self.open_file,
            width=105, height=Spacing.BUTTON_HEIGHT,
            fg_color=Colors.neutral_dark,
            hover_color=Colors.neutral_dark_hover,
        ).grid(row=0, column=7, padx=6, pady=12)

        ctk.CTkButton(
            controls, text="Export CSV",
            command=self.export_csv,
            width=105, height=Spacing.BUTTON_HEIGHT,
            fg_color=Colors.neutral,
            hover_color=Colors.neutral_hover,
        ).grid(row=0, column=9, padx=(6, 12), pady=12)

        self.auto_refresh_check = ctk.CTkCheckBox(
            controls, text="Auto refresh",
            variable=self.auto_refresh_var,
            command=self._auto_refresh_changed,
            font=Fonts.label(11),
            text_color=Colors.text,
            fg_color=Colors.primary, hover_color=Colors.primary_hover,
            border_color=Colors.border_light,
        )
        self.auto_refresh_check.grid(
            row=1, column=0, columnspan=2, sticky="w", padx=12, pady=(0, 12),
        )

        ctk.CTkLabel(
            controls, text="Every (sec)",
            font=Fonts.label(11), text_color=Colors.text,
        ).grid(row=1, column=2, padx=(10, 5), pady=(0, 12))

        self.refresh_interval_menu = ctk.CTkOptionMenu(
            controls, variable=self.refresh_interval_var,
            values=["5", "10", "15", "30", "60"],
            width=90,
            fg_color=Colors.primary, button_color=Colors.primary_hover,
            button_hover_color=Colors.primary_active,
            dropdown_fg_color=Colors.surface,
            dropdown_hover_color=Colors.primary,
            command=self._refresh_interval_changed,
        )
        self.refresh_interval_menu.grid(row=1, column=3, sticky="w", padx=5, pady=(0, 12))

        ctk.CTkLabel(
            controls, textvariable=self.last_refresh_var,
            text_color=Colors.text_muted, font=Fonts.label(11),
        ).grid(row=1, column=4, columnspan=6, sticky="e", padx=12, pady=(0, 12))

    # ------------------------------------------------------------- filters

    def _build_filters(self) -> None:
        filters = ctk.CTkFrame(self, fg_color="transparent")
        filters.grid(row=2, column=0, sticky="new", padx=18, pady=(0, 8))
        filters.grid_columnconfigure(3, weight=1)

        ctk.CTkLabel(
            filters, text="Level:",
            font=Fonts.label(12), text_color=Colors.text,
        ).grid(row=0, column=0, padx=(2, 6), pady=4)

        ctk.CTkOptionMenu(
            filters, variable=self.level_var, values=LEVELS, width=140,
            fg_color=Colors.primary, button_color=Colors.primary_hover,
            button_hover_color=Colors.primary_active,
            dropdown_fg_color=Colors.surface,
            dropdown_hover_color=Colors.primary,
            command=lambda _v: self.apply_filters(),
        ).grid(row=0, column=1, padx=(0, 16), pady=4)

        ctk.CTkLabel(
            filters, text="Search:",
            font=Fonts.label(12), text_color=Colors.text,
        ).grid(row=0, column=2, padx=(0, 6), pady=4)

        self.search_entry = ctk.CTkEntry(
            filters, textvariable=self.search_var,
            placeholder_text="Search message, provider, event ID…",
            height=Spacing.INPUT_HEIGHT,
            fg_color=Colors.bg,
            text_color=Colors.text,
            border_color=Colors.border_light,
        )
        self.search_entry.grid(row=0, column=3, sticky="ew", padx=(0, 8), pady=4)
        self.search_entry.bind("<KeyRelease>", lambda _e: self.apply_filters())

        ctk.CTkButton(
            filters, text="Clear", width=75,
            height=Spacing.BUTTON_HEIGHT,
            fg_color=Colors.neutral_dark,
            hover_color=Colors.neutral_dark_hover,
            command=self._clear_filters,
        ).grid(row=0, column=4, pady=4)

        self.show_bookmarks_only = tk.BooleanVar(value=False)
        ctk.CTkCheckBox(
            filters, text="Only Bookmarked", variable=self.show_bookmarks_only,
            command=self.apply_filters, font=Fonts.label(11),
            text_color=Colors.text, fg_color=Colors.warning, hover_color=Colors.warning_text,
        ).grid(row=0, column=5, padx=(15, 0), pady=4)

    def _build_table(self) -> None:
        table_frame = ctk.CTkFrame(
            self, corner_radius=Spacing.RADIUS_CARD,
            fg_color=Colors.surface,
            border_width=1, border_color=Colors.border,
        )
        table_frame.grid(row=3, column=0, sticky="nsew", padx=18, pady=(0, 10))
        table_frame.grid_rowconfigure(0, weight=1)
        table_frame.grid_columnconfigure(0, weight=1)

        columns = ("action", "time", "level", "event_id", "source", "message")
        headings = {
            "action": "★", "time": "Timestamp", "level": "Level", 
            "event_id": "Event ID", "source": "Provider / Source", "message": "Message",
        }
        widths = {"action": 60, "time": 180, "level": 110, "event_id": 90, "source": 240, "message": 600}

        self.tree = ttk.Treeview(
            table_frame, columns=columns, show="headings",
            selectmode="browse", style="Cyber.Treeview",
        )
        for col in columns:
            self.tree.heading(col, text=headings[col])
            self.tree.column(
                col, width=widths[col],
                minwidth=60 if col == "action" else 65,
                anchor="center" if col == "action" else "w",
                stretch=(col == "message"),
            )

        yscroll = ttk.Scrollbar(
            table_frame, orient="vertical", style="Vertical.TScrollbar",
            command=self.tree.yview,
        )
        self.tree.configure(yscrollcommand=yscroll.set)
        self.tree.grid(row=0, column=0, sticky="nsew", padx=(8, 0), pady=(8, 0))
        yscroll.grid(row=0, column=1, sticky="ns", pady=(8, 0), padx=(0, 8))

        # Tag colors for log levels
        self.tree.tag_configure("CRITICAL", foreground=Colors.danger_text)
        self.tree.tag_configure("ERROR", foreground=Colors.danger_light)
        self.tree.tag_configure("WARNING", foreground=Colors.warning_text)
        
        # Tag color for bookmarked entries
        self.tree.tag_configure("bookmarked", foreground=Colors.warning)

        self.tree.bind("<Double-1>", self.show_details)
        self.tree.bind("<Return>", self.show_details)
        self.tree.bind("<Button-1>", self._on_tree_click)
        self.tree.bind("<MouseWheel>", self._on_tree_mousewheel)
        self.tree.bind("<Button-4>", lambda _e: self.tree.yview_scroll(-3, "units"))
        self.tree.bind("<Button-5>", lambda _e: self.tree.yview_scroll(3, "units"))

    def _build_footer(self) -> None:
        footer = ctk.CTkFrame(self, corner_radius=0, fg_color=Colors.surface)
        footer.grid(row=4, column=0, sticky="ew")
        footer.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            footer, textvariable=self.status_var, anchor="w",
            text_color=Colors.text_very_soft, font=Fonts.label(11),
        ).grid(row=0, column=0, sticky="ew", padx=18, pady=9)

        ctk.CTkLabel(
            footer, text="Double-click an event for details  •  Click ▢/■ to bookmark",
            text_color=Colors.text_muted, font=Fonts.label(10),
        ).grid(row=0, column=1, padx=18, pady=9)

    def _on_tree_mousewheel(self, event) -> str:
        delta = int(-event.delta / 120) if event.delta else 0
        if delta == 0 and event.delta:
            delta = -1 if event.delta > 0 else 1
        self.tree.yview_scroll(delta * 3, "units")
        return "break"

    def _on_tree_click(self, event):
        """Handle clicks on the bookmark column."""
        region = self.tree.identify_region(event.x, event.y)
        if region != "cell":
            return
            
        column = self.tree.identify_column(event.x)
        if column != "#1":
            return
            
        item = self.tree.identify_row(event.y)
        if not item:
            return
            
        try:
            entry = self.visible_logs[int(item)]
        except (ValueError, IndexError):
            return

        # Read current state from the tree view
        current_values = self.tree.item(item, "values")
        current_marker = current_values[0]

        if current_marker == "■":
            # Filled -> empty (remove bookmark)
            bookmarks.remove_bookmark_by_timestamp(
                entry.timestamp, 
                entry.event_id, 
                entry.source, 
                entry.message
            )
            new_marker = "▢"
            new_tags = [t for t in self.tree.item(item, "tags") if t != "bookmarked"]
        else:
            # Empty -> filled (add bookmark)
            bookmarks.add_bookmark({
                "timestamp": entry.timestamp,
                "level": entry.level,
                "source": entry.source,
                "event_id": entry.event_id,
                "message": entry.message,
            })
            new_marker = "■"
            new_tags = list(self.tree.item(item, "tags")) + ["bookmarked"]

        # Update the specific row
        new_values = list(current_values)
        new_values[0] = new_marker
        self.tree.item(item, values=new_values, tags=new_tags)
        
        # If "Only Bookmarked" filter is active and we removed the bookmark, delete the row
        if getattr(self, "show_bookmarks_only", None) and self.show_bookmarks_only.get():
            if current_marker == "■": 
                self.tree.delete(item)
                self.apply_filters(keep_status="Bookmark removed.")

    # ------------------------------------------------------------- how to use

    def _show_how_to_use(self):
        """Show help for the Event Log Analyzer."""
        dialog = ctk.CTkToplevel(self)
        dialog.title("How to Use | Event Log Analyzer")
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
            outer, text="Event Log Analyzer",
            font=Fonts.title(24), text_color=Colors.text_strong,
        ).pack(anchor="w", padx=28, pady=(6, 2))

        ctk.CTkFrame(outer, height=1, fg_color=Colors.border).pack(
            fill="x", padx=28, pady=16
        )

        help_text = (
            "Welcome to Event Log Analyzer!\n\n"
            "1️⃣  SOURCE MODES\n"
            "•  Windows Event Logs: Reads Application, System, or Security logs.\n"
            "•  Linux Journal: Reads System, User, or Kernel journal.\n"
            "•  Log File: Parses a JSON Lines file (.log, .txt, .jsonl, .json).\n\n"
            "2️⃣  CONTROLS\n"
            "•  Log: Choose the specific log (System, Security, etc.).\n"
            "•  Max events: How many recent entries to request (1–5000).\n"
            "•  Refresh Now: Reload the current source (F5).\n"
            "•  Open File: Select a JSON Lines file.\n"
            "•  Export CSV: Save the currently visible events.\n"
            "•  Auto refresh: Reload every 5–60 seconds.\n\n"
            "3️⃣  FILTERS\n"
            "•  Level: Filter by severity (CRITICAL, ERROR, WARNING, INFO, DEBUG).\n"
            "•  Search: Match text across message, provider, event ID, etc.\n"
            "•  Clear: Reset all filters (Ctrl+L).\n"
            "•  Only Bookmarked: Show only saved events.\n\n"
            "4️⃣  TABLE\n"
            "•  Click ▢/■ to bookmark an event.\n"
            "•  Double-click a row (or press Enter) to see full details.\n"
            "•  Use mouse wheel or touchpad to scroll.\n\n"
            "5️⃣  KEYBOARD SHORTCUTS\n"
            "F5 / Ctrl+R  - Refresh\n"
            "Ctrl+O       - Open file\n"
            "Ctrl+F       - Focus search\n"
            "Ctrl+L       - Clear filters\n"
            "Ctrl+E       - Export CSV\n"
            "F1           - About\n"
            "Enter        - Event details"
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

    # ------------------------------------------------------------- about

    def show_about(self) -> None:
        win = ctk.CTkToplevel(self)
        win.title("About CyberOpsSuite | Event Log Analyzer")
        win.geometry("660x740")
        win.minsize(560, 600)
        win.configure(fg_color=Colors.bg)
        win.transient(self)
        win.grab_set()
        win.grid_columnconfigure(0, weight=1)
        win.grid_rowconfigure(2, weight=1)

        apply_window_icon(win)

        ctk.CTkLabel(
            win, text="CyberOpsSuite",
            font=Fonts.title(27), text_color=Colors.info_pale,
        ).grid(row=0, column=0, padx=24, pady=(22, 3))

        ctk.CTkLabel(
            win, text=f"Event Log Analyzer  •  Version {__version__}",
            font=Fonts.label(13, bold=True), text_color=Colors.text,
        ).grid(row=1, column=0, padx=24, pady=(0, 12))

        info = ctk.CTkTextbox(
            win, wrap="word", font=Fonts.label(12),
            fg_color=Colors.surface, text_color=Colors.text,
            border_color=Colors.border, border_width=1,
        )
        info.grid(row=2, column=0, sticky="nsew", padx=20, pady=(0, 14))

        os_name = f"{platform.system()} {platform.release()}"
        py_version = platform.python_version()
        cfg_path = config_root_quiet("EventLogAnalyzer")

        about_text = (
            "OVERVIEW\n"
            "Inspect Windows event logs, the Linux systemd journal, or a "
            "structured JSON Lines log file — in read-only mode.\n\n"
            f"Platform:  {os_name}\n"
            f"Python:    {py_version}\n"
            f"Config:    {cfg_path}\n\n"
            "SOURCE MODES\n"
            "• Windows Event Logs  —  Application / System / Security\n"
            "  Reads via PowerShell (Get-WinEvent). Requires Windows.\n\n"
            "• Linux Journal  —  System / User / Kernel\n"
            "  Reads via journalctl -o json. Requires systemd.\n"
            "  Add your user to the 'systemd-journal' group, or use sudo.\n\n"
            "• Log File  —  JSON Lines (.log, .txt, .jsonl, .json)\n"
            "  Parses one JSON object per line.\n\n"
            "FEATURES & OPTIONS\n"
            "• Max events: how many recent entries to request (1–5000).\n"
            "• Refresh Now: reload the current source.\n"
            "• Open File: parse a JSON Lines file.\n"
            "• Level: filter by severity, or choose ALL.\n"
            "• Search: match text across timestamp, level, event ID, "
            "source, message and log name.\n"
            "• Clear: reset the level and text filters.\n"
            "• Event details: double-click a row, or press Enter.\n"
            "• Export CSV: save the currently visible events.\n"
            "• Auto refresh: reload Windows / Linux events on a 5–60 s "
            "interval.\n"
            "• Bookmark: click ▢/■ next to any log to save it.\n"
            "• Only Bookmarked: toggle the filter to see saved logs.\n\n"

            "SUPPORTED PLATFORMS\n"
            "• Windows 10 / 11 / Server 2019+\n"
            "• Linux (systemd-based distributions)\n"
            "• macOS is not supported.\n\n"
            "NOTES\n"
            "This tool reads logs; it does not change event records or the "
            "systemd journal in any way."
        )
        info.insert("1.0", about_text)
        info.configure(state="disabled")

        ctk.CTkButton(
            win, text="Close", width=160,
            height=40,
            corner_radius=Spacing.RADIUS_BUTTON,
            fg_color=Colors.primary, hover_color=Colors.primary_hover,
            font=Fonts.label(12, bold=True),
            command=win.destroy,
        ).grid(row=3, column=0, pady=(0, 18))

    # --------------------------------------------------------- shortcuts

    def _on_f1(self, _event=None):
        self.show_about()
        return "break"

    def _on_ctrl_o(self, _event=None):
        self.open_file()
        return "break"

    def _on_ctrl_e(self, _event=None):
        self.export_csv()
        return "break"

    def _on_ctrl_f(self, _event=None):
        self.search_entry.focus_set()
        self.search_entry.select_range(0, "end")
        return "break"

    def _on_ctrl_l(self, _event=None):
        self._clear_filters()
        return "break"

    def _on_f5(self, _event=None):
        self.refresh_now()
        return "break"

    # ---------------------------------------------------------- refresh

    def refresh_now(self) -> None:
        source = self.source_mode.get()
        if source == SOURCE_FILE and not self.log_file:
            self.status_var.set("Choose a log file first, then press F5 to reload it.")
            return
        self.load_logs()

    def _refresh_interval_changed(self, _value=None) -> None:
        if self.auto_refresh_var.get():
            self._next_auto_refresh = (
                time.monotonic() + int(self.refresh_interval_var.get())
            )

    def _auto_refresh_changed(self) -> None:
        if self.auto_refresh_var.get():
            self._next_auto_refresh = (
                time.monotonic() + int(self.refresh_interval_var.get())
            )
            self.status_var.set(
                f"Auto refresh enabled: every {self.refresh_interval_var.get()} seconds."
            )
        else:
            self._next_auto_refresh = None
            self.status_var.set("Auto refresh disabled.")

    def _auto_refresh_tick(self) -> None:
        try:
            if not self.winfo_exists():
                return
            if self.auto_refresh_var.get() and self._next_auto_refresh is not None:
                if time.monotonic() >= self._next_auto_refresh and not self._loading:
                    self._next_auto_refresh = (
                        time.monotonic() + int(self.refresh_interval_var.get())
                    )
                    if self.source_mode.get() != SOURCE_FILE or self.log_file:
                        self.load_logs()
            self._auto_refresh_after_id = self.after(1000, self._auto_refresh_tick)
        except tk.TclError:
            return

    # ---------------------------------------------------------- cleanup

    def _on_close(self) -> None:
        for after_id in (self._auto_refresh_after_id, self._poll_after_id):
            if after_id is not None:
                try:
                    self.after_cancel(after_id)
                except tk.TclError:
                    pass
        self.destroy()

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
        except tk.TclError:
            return

    def _check_backends(self) -> None:
        ps = find_powershell()
        jc = find_journalctl()
        notes: list[str] = []
        if not ps and os.name == "nt":
            notes.append("PowerShell not found.")
        if not jc and platform.system() == "Linux":
            notes.append("journalctl not found.")
        if notes:
            self.status_var.set(" ".join(notes) + " File analysis is still available.")

    # ---------------------------------------------------------- load flow

    def _source_changed(self, value: str | None = None) -> None:
        source = value if value is not None else self.source_mode.get()
        is_windows = source == SOURCE_WINDOWS
        is_linux = source == SOURCE_LINUX

        if is_windows:
            self.system_menu.configure(values=list(SYSTEM_LOGS), state="normal")
            if self.system_source.get() not in SYSTEM_LOGS:
                self.system_source.set(SYSTEM_LOGS[0])
        elif is_linux:
            self.system_menu.configure(values=list(SYSTEM_JOURNALS), state="normal")
            if self.system_source.get() not in SYSTEM_JOURNALS:
                self.system_source.set(SYSTEM_JOURNALS[0])
        else:
            self.system_menu.configure(state="disabled")

        self.load_button.configure(text="Refresh Now")

    def _set_busy(self, busy: bool, message: str | None = None) -> None:
        self._loading = busy
        self.load_button.configure(state="disabled" if busy else "normal")
        if message:
            self.status_var.set(message)

    def load_logs(self) -> None:
        if self._loading:
            return

        source = self.source_mode.get()

        if source == SOURCE_FILE:
            if not self.log_file:
                self.open_file()
            else:
                self._load_file(self.log_file)
            return

        try:
            limit = int(self.limit_var.get())
        except (TypeError, ValueError):
            messagebox.showwarning(
                "Invalid event limit",
                f"Enter a whole number between {MIN_EVENTS} and {MAX_EVENTS}.",
                parent=self,
            )
            return

        if not MIN_EVENTS <= limit <= MAX_EVENTS:
            messagebox.showwarning(
                "Invalid event limit",
                f"The event limit must be between {MIN_EVENTS} and {MAX_EVENTS}.",
                parent=self,
            )
            return

        log_name = self.system_source.get()

        if source == SOURCE_WINDOWS:
            if log_name not in SYSTEM_LOGS:
                messagebox.showwarning(
                    "Invalid event source",
                    "Choose Application, System, or Security.",
                    parent=self,
                )
                return
            self._set_busy(True, f"Reading {log_name} event log…")
            threading.Thread(
                target=self._read_windows_events,
                args=(log_name, limit),
                daemon=True,
            ).start()
            return

        if source == SOURCE_LINUX:
            if log_name not in SYSTEM_JOURNALS:
                messagebox.showwarning(
                    "Invalid journal",
                    "Choose System, User, or Kernel.",
                    parent=self,
                )
                return
            self._set_busy(True, f"Reading {log_name} journal…")
            threading.Thread(
                target=self._read_linux_journal,
                args=(log_name, limit),
                daemon=True,
            ).start()
            return

    def _read_windows_events(self, source: str, limit: int) -> None:
        try:
            entries = read_windows_events(source, limit)
        except EventLogError as exc:
            self._results.put((self._load_failed, (str(exc),)))
            return
        except Exception as exc:
            self._results.put((self._load_failed, (f"Unexpected error: {exc}",)))
            return

        self._results.put((
            self._load_succeeded,
            (entries, f"Loaded {len(entries)} events from {source}."),
        ))

    def _read_linux_journal(self, source: str, limit: int) -> None:
        try:
            entries = read_linux_journal(source, limit)
        except JournalError as exc:
            self._results.put((self._load_failed, (str(exc),)))
            return
        except Exception as exc:
            self._results.put((self._load_failed, (f"Unexpected error: {exc}",)))
            return

        self._results.put((
            self._load_succeeded,
            (entries, f"Loaded {len(entries)} events from the {source} journal."),
        ))

    def open_file(self) -> None:
        path = filedialog.askopenfilename(
            title="Select a log file",
            filetypes=[
                ("Log and JSON files", "*.log *.txt *.jsonl *.json"),
                ("All files", "*.*"),
            ],
        )
        if not path:
            return

        self.log_file = path
        self.source_mode.set(SOURCE_FILE)
        self._source_changed(SOURCE_FILE)
        self._load_file(path)

    def _load_file(self, path: str) -> None:
        self._set_busy(True, f"Parsing {os.path.basename(path)}…")
        threading.Thread(
            target=self._parse_file_worker,
            args=(path,),
            daemon=True,
        ).start()

    def _parse_file_worker(self, path: str) -> None:
        try:
            parser = LogParser(path)
            entries = parser.parse()
        except Exception as exc:
            self._results.put((self._load_failed, (f"Could not parse file: {exc}",)))
            return

        message = f"Parsed {len(entries)} records from {os.path.basename(path)}."
        if parser.errors:
            message += f" {len(parser.errors)} invalid line(s) skipped."
        self._results.put((self._load_succeeded, (entries, message)))

    # ---------------------------------------------------------- callbacks

    def _load_succeeded(self, entries: list[LogEntry], message: str) -> None:
        self.logs = entries
        self.last_refresh_var.set(
            "Last refresh: " + datetime.now().strftime("%H:%M:%S")
        )
        self._set_busy(False, message)
        self.apply_filters(keep_status=message)

    def _load_failed(self, error: str) -> None:
        self._set_busy(False, "Could not load events.")
        messagebox.showerror("Event Log Analyzer", error, parent=self)

    def _clear_filters(self) -> None:
        self.level_var.set("ALL")
        self.search_var.set("")
        self.show_bookmarks_only.set(False)
        self.apply_filters()

    def apply_filters(self, keep_status: str | None = None) -> None:
        self.visible_logs = filter_entries(
            self.logs,
            level=self.level_var.get(),
            search=self.search_var.get(),
            fields=ALL_SEARCH_FIELDS,
        )
        
        if getattr(self, "show_bookmarks_only", None) and self.show_bookmarks_only.get():
            bms = bookmarks.load_bookmarks()
            bookmarked_keys = {
                (bm.get("timestamp"), bm.get("event_id"), bm.get("source"), bm.get("message")) 
                for bm in bms
            }
            self.visible_logs = [
                e for e in self.visible_logs 
                if (e.timestamp, e.event_id, e.source, e.message) in bookmarked_keys
            ]
        
        self.update_tree(self.visible_logs)

        if keep_status:
            self.status_var.set(keep_status)
            return

        suffix = ""
        if self.log_file and self.source_mode.get() == SOURCE_FILE:
            suffix = f" • {os.path.basename(self.log_file)}"
        self.status_var.set(
            f"Showing {len(self.visible_logs)} of {len(self.logs)} events{suffix}"
        )

    def update_tree(self, entries: list[LogEntry]) -> None:
        self.tree.delete(*self.tree.get_children())
        
        bms = bookmarks.load_bookmarks()
        bookmarked_keys = {
            (bm.get("timestamp"), bm.get("event_id"), bm.get("source"), bm.get("message")) 
            for bm in bms
        }
        
        for index, entry in enumerate(entries):
            level = normalize_level(entry.level)
            message = " ".join(str(entry.message).split())
            if len(message) > 240:
                message = message[:237] + "…"
            
            is_bm = (entry.timestamp, entry.event_id, entry.source, entry.message) in bookmarked_keys
            marker = "■" if is_bm else "▢"
            
            self.tree.insert(
                "", "end", iid=str(index),
                values=(
                    marker, entry.timestamp, level, entry.event_id,
                    entry.source, message,
                ),
                tags=(level, "bookmarked") if is_bm else (level,),
            )

    def show_details(self, _event=None) -> None:
        selected = self.tree.selection()
        if not selected:
            return

        try:
            entry = self.visible_logs[int(selected[0])]
        except (ValueError, IndexError):
            return

        win = ctk.CTkToplevel(self)
        win.title(f"Event Details — {entry.event_id}")
        win.geometry("760x520")
        win.minsize(520, 350)
        win.configure(fg_color=Colors.bg)
        win.transient(self)
        win.grid_columnconfigure(0, weight=1)
        win.grid_rowconfigure(1, weight=1)

        apply_window_icon(win)

        ctk.CTkLabel(
            win, text=f"{entry.level}  |  Event ID {entry.event_id}",
            font=Fonts.heading(18), anchor="w", text_color=Colors.text,
        ).grid(row=0, column=0, sticky="ew", padx=18, pady=(18, 8))

        text = ctk.CTkTextbox(
            win, wrap="word", font=Fonts.label(12),
            fg_color=Colors.surface, text_color=Colors.text,
            border_color=Colors.border, border_width=1,
        )
        text.grid(row=1, column=0, sticky="nsew", padx=18, pady=(0, 12))

        details = [
            f"Timestamp: {entry.timestamp}",
            f"Source: {entry.source}",
            f"Log: {entry.log_name}",
            f"Machine: {entry.machine}",
            "",
            "Message:",
            entry.message,
        ]
        text.insert("1.0", "\n".join(details))
        text.configure(state="disabled")

        ctk.CTkButton(
            win, text="Close", width=120,
            height=Spacing.BUTTON_HEIGHT,
            fg_color=Colors.primary, hover_color=Colors.primary_hover,
            command=win.destroy,
        ).grid(row=2, column=0, sticky="e", padx=18, pady=(0, 16))

    def export_csv(self) -> None:
        if not self.visible_logs:
            messagebox.showinfo(
                "Export CSV",
                "There are no visible events to export.",
                parent=self,
            )
            return

        path = filedialog.asksaveasfilename(
            title="Export events",
            defaultextension=".csv",
            filetypes=[("CSV file", "*.csv")],
            initialfile="event_logs.csv",
        )
        if not path:
            return

        try:
            with open(path, "w", newline="", encoding="utf-8-sig") as handle:
                count = write_csv(self.visible_logs, handle)
            self.status_var.set(
                f"Exported {count} events to {os.path.basename(path)}"
            )
        except OSError as exc:
            messagebox.showerror("Export failed", str(exc), parent=self)


def main() -> None:
    app = EventLogGUI()
    app.mainloop()


if __name__ == "__main__":
    main()