"""CyberOpsSuite VPN Manager GUI.

A CustomTkinter desktop client for managing VLESS/VMess profiles and
running an Xray-core process as a local SOCKS5/HTTP proxy. Profiles
are imported from links or subscription URLs, stored via
:mod:`vpn_manager.core.xray_manager`, and started/stopped through the
same module. All network work runs on a worker thread so the UI never
freezes.
"""

from __future__ import annotations

import os
import platform
import queue
import sys
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

import customtkinter as ctk

from vpn_manager.core.xray_manager import (
    DEFAULT_SOCKS_PORT,
    VPNError,
    XrayManager,
    xray_log_path,
)

# Always resolve imports from the project root.
PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core.theme import Colors, Fonts, Spacing
from core.gui.treeview_style import apply_treeview_style
from core.utils.icons import apply_window_icon
from core.utils.paths import config_root_quiet


APP_NAME = "VPN Manager"
APP_VERSION = "1.9.1"
APP_SUITE = "CyberOpsSuite"

#: Default local proxy ports (SOCKS5 and HTTP).
DEFAULT_HTTP_PORT = DEFAULT_SOCKS_PORT + 1

#: Log refresh interval (ms).
LOG_REFRESH_MS = 2_000

#: Status refresh interval (ms) while connected.
STATUS_REFRESH_MS = 3_000

#: Speed test interval (ms) while connected.
SPEED_REFRESH_MS = 10_000

#: Speed test duration (seconds).
SPEED_DURATION = 5.0

#: Ping thresholds (ms).
PING_GOOD_MS = 100
PING_OK_MS = 200


class VPNManagerApp(ctk.CTk):
    """Main window for the VPN Manager."""

    def __init__(self) -> None:
        super().__init__()

        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("dark-blue")

        self.title(f"{APP_SUITE} | {APP_NAME}")
        self.configure(fg_color=Colors.bg_alt)

        self.update_idletasks()
        screen_w = self.winfo_screenwidth()
        screen_h = self.winfo_screenheight()
        win_w = min(1280, screen_w - 60)
        win_h = min(800, screen_h - 100)
        x = max(0, (screen_w - win_w) // 2)
        y = max(0, (screen_h - win_h) // 2)
        self.geometry(f"{win_w}x{win_h}+{x}+{y}")
        self.minsize(1000, 650)

        apply_window_icon(self)
        apply_treeview_style(self)

        self.manager = XrayManager()
        self.xray_path: str = ""
        self._about_open = False

        # State.
        self.selected: str | None = None
        self._loading: bool = False
        self._ping_results: dict[str, float | None] = {}
        self._ping_in_progress = False
        self._verifying = False
        self._speed_testing = False
        self._auto_connect = False
        self._results: queue.Queue = queue.Queue()
        self._poll_after_id: str | None = None
        self._log_after_id: str | None = None
        self._status_after_id: str | None = None
        self._speed_after_id: str | None = None

        # Smart Auto-Switch State
        self._auto_switch_enabled = False
        self._auto_switch_interval = 60
        self._auto_switch_after_id: str | None = None
        self._is_switching = False

        # Observable variables.
        self.status_var = ctk.StringVar(value="●  DISCONNECTED")
        self.info_var = ctk.StringVar(value="Select a profile to connect.")
        self.down_var = ctk.StringVar(value="Down:  —")
        self.up_var = ctk.StringVar(value="Up:    —")
        self.selected_var = tk.StringVar(value="")

        self._build_ui()
        self._refresh_profiles()
        self._bind_shortcuts()

        self.protocol("WM_DELETE_WINDOW", self._on_close)

        self._poll_after_id = self.after(100, self._poll_results)
        self._log_after_id = self.after(LOG_REFRESH_MS, self._refresh_log)

    # ------------------------------------------------------------------ UI

    def _build_ui(self) -> None:
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self._build_sidebar()

        self.content = ctk.CTkFrame(self, fg_color="transparent")
        self.content.grid(row=0, column=1, sticky="nsew", padx=16, pady=14)
        self.content.columnconfigure(0, weight=1)
        self.content.rowconfigure(2, weight=1)

        self._build_header()
        self._build_import_bar()
        self._build_profiles_table()
        self._build_auto_switch_bar()
        self._build_log_panel()
        self._build_footer()

    def _bind_shortcuts(self) -> None:
        self.bind("<F5>", lambda e: self._refresh_profiles())
        self.bind("<Delete>", lambda e: self._remove_selected())
        self.bind("<Return>", lambda e: self._connect())

    def _build_sidebar(self) -> None:
        sidebar = ctk.CTkFrame(
            self, width=210, corner_radius=0, fg_color=Colors.bg,
        )
        sidebar.grid(row=0, column=0, sticky="nsew")
        sidebar.grid_propagate(False)

        ctk.CTkLabel(sidebar, text="◈", font=Fonts.title(32), text_color=Colors.info).pack(anchor="w", padx=20, pady=(20, 0))
        ctk.CTkLabel(sidebar, text="CyberOpsSuite", font=Fonts.heading(17), text_color=Colors.text).pack(anchor="w", padx=20, pady=(0, 2))
        ctk.CTkLabel(sidebar, text="VPN MANAGER", font=Fonts.badge(10), text_color=Colors.text_muted).pack(anchor="w", padx=21, pady=(0, 22))
        ctk.CTkLabel(sidebar, text="LOCAL PROXY", font=Fonts.badge(9), text_color=Colors.text_muted).pack(anchor="w", padx=20, pady=(8, 4))
        ctk.CTkLabel(sidebar, text=f"SOCKS5  127.0.0.1:{DEFAULT_SOCKS_PORT}\nHTTP     127.0.0.1:{DEFAULT_HTTP_PORT}", justify="left", text_color=Colors.info_soft, font=Fonts.mono(10)).pack(anchor="w", padx=20)

        self.sidebar_status = ctk.CTkLabel(sidebar, textvariable=self.status_var, font=Fonts.badge(10), text_color=Colors.warning_text)
        self.sidebar_status.pack(side="bottom", anchor="w", padx=20, pady=(0, 4))

        speed_box = ctk.CTkFrame(sidebar, fg_color="transparent")
        speed_box.pack(side="bottom", anchor="w", padx=20, pady=(0, 18))
        ctk.CTkLabel(speed_box, textvariable=self.down_var, font=Fonts.mono(9), text_color=Colors.text_muted).pack(anchor="w")
        ctk.CTkLabel(speed_box, textvariable=self.up_var, font=Fonts.mono(9), text_color=Colors.text_muted).pack(anchor="w")

    def _build_header(self) -> None:
        header = ctk.CTkFrame(self.content, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        header.columnconfigure(0, weight=1)

        brand = ctk.CTkFrame(header, fg_color="transparent")
        brand.grid(row=0, column=0, sticky="w")

        ctk.CTkLabel(brand, text="VPN Manager", font=Fonts.title(24), text_color=Colors.text_strong).pack(anchor="w")
        ctk.CTkLabel(brand, text="VLESS  /  VMess  /  Xray-core", font=Fonts.label(10), text_color=Colors.text_muted).pack(anchor="w", pady=(3, 0))

        actions = ctk.CTkFrame(header, fg_color="transparent")
        actions.grid(row=0, column=1, sticky="ne", pady=4)
        actions.grid_columnconfigure(0, weight=0)
        actions.grid_columnconfigure(1, weight=0)
        actions.grid_columnconfigure(2, weight=0)

        # Help button (col 0) - hidden on About page
        self.help_btn = ctk.CTkButton(
            actions, text="❓ How to Use", width=110, height=32,
            corner_radius=Spacing.RADIUS_BUTTON,
            fg_color=Colors.info_bg, hover_color=Colors.info,
            text_color=Colors.info_light, font=Fonts.label(10, bold=True),
            command=self._show_how_to_use,
        )
        self.help_btn.grid(row=0, column=0, padx=(0, 6))

        ctk.CTkButton(actions, text="About", width=90, height=32, fg_color=Colors.neutral_dark, hover_color=Colors.neutral_dark_hover, font=Fonts.label(10), command=self._show_about).grid(row=0, column=1, padx=(0, 6))

        self.best_btn = ctk.CTkButton(actions, text="🚀  Connect to Best", width=160, height=32, fg_color=Colors.primary, hover_color=Colors.primary_hover, font=Fonts.label(10, bold=True), command=self._connect_to_best)
        self.best_btn.grid(row=0, column=2)

    def _build_import_bar(self) -> None:
        card = ctk.CTkFrame(self.content, fg_color=Colors.surface, corner_radius=Spacing.RADIUS_CARD, border_width=1, border_color=Colors.border)
        card.grid(row=1, column=0, sticky="ew", pady=(0, 10))

        row = ctk.CTkFrame(card, fg_color="transparent")
        row.pack(fill="x", padx=14, pady=10)
        row.columnconfigure(0, weight=1)

        self.link_input = ctk.CTkEntry(row, placeholder_text="Paste a VLESS / VMess link or subscription URL…", height=36, fg_color=Colors.bg, text_color=Colors.text, border_color=Colors.border_light, font=Fonts.mono(10))
        self.link_input.grid(row=0, column=0, sticky="ew", padx=(0, 8))

        ctk.CTkButton(row, text="Paste", width=90, height=36, fg_color=Colors.neutral_dark, hover_color=Colors.neutral_dark_hover, font=Fonts.label(10), command=self._paste_clipboard).grid(row=0, column=1, padx=(0, 6))
        ctk.CTkButton(row, text="Import", width=110, height=36, fg_color=Colors.primary, hover_color=Colors.primary_hover, font=Fonts.label(10, bold=True), command=self._import_from_input).grid(row=0, column=2)

    def _build_profiles_table(self) -> None:
        card = ctk.CTkFrame(self.content, fg_color=Colors.surface, corner_radius=Spacing.RADIUS_CARD, border_width=1, border_color=Colors.border)
        card.grid(row=2, column=0, sticky="nsew", pady=(0, 10))
        card.rowconfigure(1, weight=1)
        card.columnconfigure(0, weight=1)

        top = ctk.CTkFrame(card, fg_color="transparent")
        top.grid(row=0, column=0, sticky="ew", padx=14, pady=(10, 6))
        top.columnconfigure(0, weight=1)

        ctk.CTkLabel(top, text="SERVER PROFILES", font=Fonts.badge(10), text_color=Colors.text_muted).grid(row=0, column=0, sticky="w")
        ctk.CTkButton(top, text="⚡  Ping All", width=110, height=28, fg_color=Colors.info, hover_color=Colors.primary_hover, font=Fonts.label(10, bold=True), command=self._ping_all).grid(row=0, column=1, sticky="e", padx=(0, 6))
        ctk.CTkButton(top, text="Remove", width=90, height=28, fg_color=Colors.danger, hover_color=Colors.danger_hover, font=Fonts.label(10), command=self._remove_selected).grid(row=0, column=2, sticky="e")

        table_frame = ctk.CTkFrame(card, fg_color="transparent")
        table_frame.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 10))
        table_frame.rowconfigure(0, weight=1)
        table_frame.columnconfigure(0, weight=1)

        columns = ("name", "protocol", "address", "port", "ping")
        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings", selectmode="browse", style="Cyber.Treeview")
        headings = {"name": "NAME", "protocol": "PROTOCOL", "address": "ADDRESS", "port": "PORT", "ping": "PING (ms)"}
        widths = {"name": 260, "protocol": 100, "address": 260, "port": 80, "ping": 100}
        for col in columns:
            self.tree.heading(col, text=headings[col], anchor="w")
            self.tree.column(col, width=widths[col], minwidth=70, anchor="w" if col in ("name", "address") else "center", stretch=(col == "name"))

        yscroll = ttk.Scrollbar(table_frame, orient="vertical", style="Vertical.TScrollbar", command=self.tree.yview)
        self.tree.configure(yscrollcommand=yscroll.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        yscroll.grid(row=0, column=1, sticky="ns")

        self.tree.tag_configure("ping_good", foreground="#22C55E")
        self.tree.tag_configure("ping_ok", foreground=Colors.warning_text)
        self.tree.tag_configure("ping_bad", foreground=Colors.danger_text)
        self.tree.bind("<<TreeviewSelect>>", self._on_tree_select)

    def _build_auto_switch_bar(self) -> None:
        """این کادر رو دقیقاً زیر جدول و بالای لاگ می‌سازیم."""
        bar = ctk.CTkFrame(self.content, fg_color=Colors.surface, corner_radius=Spacing.RADIUS_CARD, border_width=1, border_color=Colors.border)
        bar.grid(row=3, column=0, sticky="ew", pady=(0, 10))

        ctk.CTkLabel(bar, text="Auto-Rotate:", font=Fonts.label(11, bold=True), text_color=Colors.text).pack(side="left", padx=(14, 8), pady=10)

        self.auto_switch_var = tk.BooleanVar(value=False)
        self.auto_switch_switch = ctk.CTkSwitch(bar, text="Enable", variable=self.auto_switch_var, command=self._toggle_auto_switch, progress_color=Colors.success, font=Fonts.label(11))
        self.auto_switch_switch.pack(side="left", padx=(0, 15))

        ctk.CTkLabel(bar, text="Interval:", font=Fonts.label(11, bold=True), text_color=Colors.text).pack(side="left", padx=(0, 8))

        self.auto_switch_timer_var = ctk.StringVar(value="1 min")
        self.auto_switch_menu = ctk.CTkOptionMenu(bar, values=["Manual", "1 min", "2 min", "5 min", "10 min"], variable=self.auto_switch_timer_var, width=90, command=self._change_auto_switch_timer, fg_color=Colors.surface_alt, button_color=Colors.surface_alt, font=Fonts.label(10))
        self.auto_switch_menu.pack(side="left")

    def _build_log_panel(self) -> None:
        card = ctk.CTkFrame(self.content, fg_color=Colors.surface, corner_radius=Spacing.RADIUS_CARD, border_width=1, border_color=Colors.border)
        card.grid(row=4, column=0, sticky="ew", pady=(0, 10))

        top = ctk.CTkFrame(card, fg_color="transparent")
        top.pack(fill="x", padx=14, pady=(8, 2))

        ctk.CTkLabel(top, text="XRAY LOG", font=Fonts.badge(10), text_color=Colors.text_muted).pack(side="left")
        ctk.CTkButton(top, text="Clear view", width=80, height=22, fg_color=Colors.neutral_dark, hover_color=Colors.neutral_dark_hover, font=Fonts.label(9), command=lambda: self._set_log_text("")).pack(side="right")

        self.log_text = ctk.CTkTextbox(card, height=90, fg_color=Colors.bg, text_color=Colors.text_muted, border_width=1, border_color=Colors.border, font=Fonts.mono(9), wrap="word")
        self.log_text.pack(fill="x", padx=14, pady=(0, 10))
        self.log_text.configure(state="disabled")

    def _build_footer(self) -> None:
        footer = ctk.CTkFrame(self.content, fg_color="transparent")
        footer.grid(row=5, column=0, sticky="ew")
        footer.columnconfigure(0, weight=1)

        ctk.CTkLabel(footer, textvariable=self.info_var, font=Fonts.label(10), text_color=Colors.text_muted, anchor="w", justify="left", wraplength=600).grid(row=0, column=0, sticky="ew")

        ctk.CTkButton(footer, text="Locate xray", width=140, height=34, fg_color=Colors.neutral_dark, hover_color=Colors.neutral_dark_hover, font=Fonts.label(10), command=self._locate_xray).grid(row=0, column=1, sticky="e", padx=(6, 0))
        self.disconnect_btn = ctk.CTkButton(footer, text="■  Disconnect", width=130, height=34, fg_color=Colors.danger, hover_color=Colors.danger_hover, font=Fonts.label(10, bold=True), command=self._disconnect)
        self.disconnect_btn.grid(row=0, column=2, sticky="e", padx=(6, 0))
        self.connect_btn = ctk.CTkButton(footer, text="▶  Connect", width=130, height=34, fg_color=Colors.success, hover_color=Colors.success_hover, font=Fonts.label(10, bold=True), command=self._connect)
        self.connect_btn.grid(row=0, column=3, sticky="e", padx=(6, 0))

    # ------------------------------------------------------------- How to Use

    def _show_how_to_use(self):
        """Show help for the VPN Manager."""
        dialog = ctk.CTkToplevel(self)
        dialog.title("How to Use | VPN Manager")
        dialog.geometry("750x800")
        dialog.minsize(650, 650)
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
            outer, text="VPN Manager",
            font=Fonts.title(24), text_color=Colors.text_strong,
        ).pack(anchor="w", padx=28, pady=(6, 2))

        ctk.CTkFrame(outer, height=1, fg_color=Colors.border).pack(
            fill="x", padx=28, pady=16
        )

        help_text = (
            "Welcome to VPN Manager!\n\n"
            "1️⃣  IMPORT PROFILES\n"
            "•  Paste a VLESS/VMess link (vless://... or vmess://...) or a\n"
            "   subscription URL into the input box.\n"
            "•  Click 'Import' to add all servers.\n"
            "•  You can also click 'Paste' to load from clipboard.\n\n"
            "2️⃣  SERVER PROFILES\n"
            "•  Each row shows: NAME, PROTOCOL, ADDRESS, PORT, PING.\n"
            "•  Click '⚡ Ping All' to test TCP latency of every profile.\n"
            "•  Green = fast (<100ms), Amber = OK (<200ms), Red = slow/offline.\n"
            "•  Select a profile and press Delete to remove it.\n\n"
            "3️⃣  CONNECT\n"
            "•  Select a profile and click '▶ Connect' (or press Enter).\n"
            "•  Or click '🚀 Connect to Best' to auto-ping and connect to the\n"
            "   fastest server.\n"
            "•  Click '■ Disconnect' to stop the proxy.\n\n"
            "4️⃣  LOCAL PROXY\n"
            "•  SOCKS5: 127.0.0.1:10808\n"
            "•  HTTP:   127.0.0.1:10809\n"
            "•  Point your browser/app at these endpoints.\n\n"
            "5️⃣  SMART AUTO-SWITCH\n"
            "•  Enable the 'Auto-Rotate' switch.\n"
            "•  Choose an interval (1, 2, 5, 10 min).\n"
            "•  The tool will test current connection every interval.\n"
            "•  If the current server fails or another server is >20% faster,\n"
            "   it switches automatically without dropping the connection.\n\n"
            "6️⃣  LIVE MONITORING\n"
            "•  Status badge shows CONNECTED, TIMEOUT, or DISCONNECTED.\n"
            "•  Download/Upload speed is measured every 10 seconds.\n"
            "•  Xray log is refreshed every 2 seconds (bottom panel).\n\n"
            "7️⃣  REQUIREMENTS\n"
            "•  Place the Xray-core binary in the project's bin/ folder:\n"
            "   - Windows: bin/xray.exe\n"
            "   - Linux:   bin/xray\n"
            "•  Or click 'Locate xray' to choose a custom path.\n\n"
            "⌨  SHORTCUTS\n"
            "F5      → Refresh profiles list\n"
            "Enter   → Connect to selected profile\n"
            "Delete  → Remove selected profile\n\n"
            "⚠  NOTE\n"
            "•  The tool does NOT store credentials from your subscription.\n"
            "•  Profiles are stored in your user's config directory.\n"
            "•  Closing the app disconnects the proxy."
        )

        ctk.CTkLabel(
            outer, text=help_text,
            font=Fonts.label(11), text_color=Colors.text,
            justify="left", anchor="w", wraplength=670,
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

    # ------------------------------------------------------------- profiles

    def _refresh_profiles(self) -> None:
        self.tree.delete(*self.tree.get_children())
        for p in self.manager.profiles:
            ping = self._ping_results.get(p["id"])
            self.tree.insert("", "end", iid=p["id"], values=(p.get("name", "—"), str(p.get("protocol", "")).upper(), p.get("address", "—"), p.get("port", "—"), self._format_ping(ping)), tags=(self._tag_for_ping(ping),))

        if not self.manager.profiles:
            self.info_var.set("No profiles yet — paste a VLESS/VMess link above.")
        else:
            self.info_var.set(f"{len(self.manager.profiles)} profile(s) loaded. Press Enter to connect, Delete to remove.")

    @staticmethod
    def _format_ping(ping: float | None) -> str:
        return "—" if ping is None else f"{ping:.0f} ms"

    @staticmethod
    def _tag_for_ping(ping: float | None) -> str:
        if ping is None: return "ping_bad"
        if ping < PING_GOOD_MS: return "ping_good"
        if ping < PING_OK_MS: return "ping_ok"
        return "ping_bad"

    def _on_tree_select(self, _event=None) -> None:
        selection = self.tree.selection()
        self.selected = selection[0] if selection else None

    def _remove_selected(self) -> None:
        if not self.selected:
            messagebox.showinfo("Select profile", "Select a profile first.", parent=self)
            return
        if self.manager.connected():
            messagebox.showwarning("Connected", "Disconnect before removing profiles.", parent=self)
            return
        self.manager.remove(self.selected)
        self._ping_results.pop(self.selected, None)
        self.selected = None
        self._refresh_profiles()

    # ------------------------------------------------------- Smart Auto-Switch

    def _toggle_auto_switch(self):
        self._auto_switch_enabled = self.auto_switch_var.get()
        if self._auto_switch_enabled: self._schedule_auto_switch()
        elif self._auto_switch_after_id:
            self.after_cancel(self._auto_switch_after_id)
            self._auto_switch_after_id = None

    def _change_auto_switch_timer(self, choice):
        mapping = {"Manual": 0, "1 min": 60, "2 min": 120, "5 min": 300, "10 min": 600}
        self._auto_switch_interval = mapping.get(choice, 60)
        if self._auto_switch_enabled:
            if self._auto_switch_after_id: self.after_cancel(self._auto_switch_after_id)
            self._schedule_auto_switch()

    def _schedule_auto_switch(self):
        if self._auto_switch_after_id:
            self.after_cancel(self._auto_switch_after_id)
            self._auto_switch_after_id = None
        if not self._auto_switch_enabled or self.auto_switch_timer_var.get() == "Manual": return
        self._auto_switch_after_id = self.after(self._auto_switch_interval * 1000, self._check_and_switch)

    def _check_and_switch(self):
        self._auto_switch_after_id = None
        if not self._auto_switch_enabled or self._is_switching or not self.manager.connected():
            self._schedule_auto_switch()
            return
        self._is_switching = True

        def worker():
            try: current_ok, _ = self.manager.test_connection(timeout=5.0)
            except: current_ok = False
            if not current_ok:
                self._results.put((self._do_smart_switch, (True,)))
                return
            profiles = list(self.manager.profiles)
            if len(profiles) <= 1:
                self._results.put((self._finish_switch, ()))
                return
            pings = {}
            for p in profiles:
                try: pings[p["id"]] = self.manager.ping_profile(p, timeout=2.0)
                except: pings[p["id"]] = None
            valid_pings = {k: v for k, v in pings.items() if v is not None}
            if not valid_pings:
                self._results.put((self._finish_switch, ()))
                return
            best_id = min(valid_pings, key=valid_pings.get)
            force = pings.get(self.selected) is None
            should_switch = force or (best_id != self.selected and valid_pings[best_id] < pings[self.selected] * 0.8)
            if should_switch: self._results.put((self._do_smart_switch, (force, best_id)))
            else: self._results.put((self._finish_switch, ()))

        threading.Thread(target=worker, daemon=True).start()

    def _do_smart_switch(self, force: bool, best_id: str = None):
        if best_id is None and self.manager.profiles:
            idx = next((i for i, p in enumerate(self.manager.profiles) if p["id"] == self.selected), 0)
            best_id = self.manager.profiles[(idx + 1) % len(self.manager.profiles)]["id"]
        if best_id:
            target = next((p for p in self.manager.profiles if p["id"] == best_id), None)
            if target:
                self.selected = best_id
                self.tree.selection_set(best_id)
                try:
                    self.manager.connect(target, self.xray_path)
                    self.info_var.set(f"Auto-Switched to {target['name']}")
                except Exception as exc: self.info_var.set(f"Auto-Switch failed: {exc}")
        self._finish_switch()

    def _finish_switch(self):
        self._is_switching = False
        self._schedule_auto_switch()

    # ------------------------------------------------------- connect to best

    def _connect_to_best(self) -> None:
        if not self.manager.profiles:
            messagebox.showinfo("No profiles", "Import at least one profile first.", parent=self)
            return
        if self._ping_in_progress: return
        self._auto_connect = True
        self._ping_all()

    # ------------------------------------------------------------- ping

    def _ping_all(self) -> None:
        if self._ping_in_progress or not self.manager.profiles: return
        self._ping_in_progress = True
        self.info_var.set("Pinging all profiles…")
        self.best_btn.configure(state="disabled")
        self.connect_btn.configure(state="disabled")
        profiles = list(self.manager.profiles)

        def worker():
            results: dict[str, float | None] = {}
            for profile in profiles:
                try: latency = self.manager.ping_profile(profile, timeout=3.0)
                except: latency = None
                results[profile["id"]] = latency
            self._results.put((self._apply_ping_results, (results,)))

        threading.Thread(target=worker, daemon=True).start()

    def _apply_ping_results(self, results: dict[str, float | None]) -> None:
        self._ping_results.update(results)
        self._ping_in_progress = False
        self.best_btn.configure(state="normal")
        self.connect_btn.configure(state="normal")
        self._refresh_profiles()
        reachable = {k: v for k, v in results.items() if v is not None}

        if self._auto_connect and reachable:
            self._auto_connect = False
            fastest_id = min(reachable, key=reachable.get)
            name = next((p["name"] for p in self.manager.profiles if p["id"] == fastest_id), fastest_id)
            self.info_var.set(f"Fastest server: {name} ({reachable[fastest_id]:.0f} ms). Connecting…")
            self.selected = fastest_id
            self.tree.selection_set(fastest_id)
            self._connect()
            return

        self._auto_connect = False
        if reachable:
            fastest = min(reachable, key=reachable.get)
            name = next((p["name"] for p in self.manager.profiles if p["id"] == fastest), fastest)
            self.info_var.set(f"Ping complete — {len(reachable)}/{len(results)} reachable. Fastest: {name} ({reachable[fastest]:.0f} ms)")
        else:
            self.info_var.set(f"Ping complete — none of the {len(results)} server(s) responded on their TCP port.")

    # -------------------------------------------------------------- import

    def _import_from_input(self) -> None:
        text = self.link_input.get().strip()
        if not text:
            messagebox.showinfo("Empty input", "Paste a VLESS/VMess link or subscription URL first.", parent=self)
            return
        self._run_import(text)

    def _paste_clipboard(self) -> None:
        try: text = self.clipboard_get()
        except tk.TclError:
            messagebox.showinfo("Clipboard", "Clipboard is empty.", parent=self)
            return
        self.link_input.delete(0, "end")
        self.link_input.insert(0, text)

    def _run_import(self, text: str) -> None:
        if self._loading: return
        self._set_busy(True, "Importing profiles…")

        def worker():
            try: added = self.manager.import_text(text)
            except VPNError as exc:
                self._results.put((self._apply_import_error, (str(exc),)))
                return
            except Exception as exc:
                self._results.put((self._apply_import_error, (str(exc),)))
                return
            self._results.put((self._apply_import_ok, (len(added),)))

        threading.Thread(target=worker, daemon=True).start()

    def _apply_import_ok(self, count: int) -> None:
        self._set_busy(False, None)
        self.link_input.delete(0, "end")
        self._refresh_profiles()
        self.info_var.set(f"Imported {count} profile(s).")

    def _apply_import_error(self, message: str) -> None:
        self._set_busy(False, None)
        messagebox.showerror("Import failed", message, parent=self)

    # ------------------------------------------------------- connect flow

    def _locate_xray(self) -> None:
        path = filedialog.askopenfilename(title="Select Xray-core executable", filetypes=[("Xray executable", "xray.exe xray"), ("All files", "*.*")], parent=self)
        if path:
            self.xray_path = path
            self.info_var.set(f"Xray-core: {path}")

    def _connect(self) -> None:
        if not self.selected:
            messagebox.showinfo("Select profile", "Choose a server profile first.", parent=self)
            return
        profile = next((p for p in self.manager.profiles if p["id"] == self.selected), None)
        if not profile:
            messagebox.showerror("Not found", "Selected profile no longer exists.", parent=self)
            return
        if self._loading: return
        self._stop_live_status()
        self.status_var.set("●  CONNECTING…")
        self.sidebar_status.configure(text_color=Colors.warning_text)
        self.info_var.set(f"Connecting to {profile['name']}…")
        self.down_var.set("Down:  …")
        self.up_var.set("Up:    …")
        self._set_busy(True, None)

        def worker():
            try: self.manager.connect(profile, self.xray_path)
            except VPNError as exc:
                self._results.put((self._apply_connect_error, (str(exc),)))
                return
            except Exception as exc:
                self._results.put((self._apply_connect_error, (str(exc),)))
                return
            try: ok, msg = self.manager.test_connection(timeout=8.0)
            except Exception as exc: ok, msg = False, str(exc)
            self._results.put((self._apply_connect_ok, (profile["name"], ok, msg)))

        threading.Thread(target=worker, daemon=True).start()

    def _apply_connect_ok(self, name: str, verified: bool, message: str) -> None:
        self._set_busy(False, None)
        if verified:
            self.status_var.set("●  CONNECTED (verified)")
            self.sidebar_status.configure(text_color=Colors.success_text)
            self.info_var.set(f"{name} — {message}")
            self._start_live_status()
        else:
            self.status_var.set("●  CONNECTED (unverified)")
            self.sidebar_status.configure(text_color=Colors.warning_text)
            self.info_var.set(f"{name} — {message}")
            self._start_live_status()

    def _apply_connect_error(self, message: str) -> None:
        self._set_busy(False, None)
        self.status_var.set("●  TIMEOUT / FAILED")
        self.sidebar_status.configure(text_color=Colors.danger_text)
        messagebox.showerror("Connection failed", message, parent=self)

    def _disconnect(self) -> None:
        self._stop_live_status()
        try: self.manager.disconnect()
        except Exception as exc:
            messagebox.showerror("Disconnect failed", str(exc), parent=self)
            return
        self.status_var.set("●  DISCONNECTED")
        self.sidebar_status.configure(text_color=Colors.warning_text)
        self.info_var.set("Disconnected.")
        self.down_var.set("Down:  —")
        self.up_var.set("Up:    —")

    # ------------------------------------------------------ live status

    def _start_live_status(self) -> None:
        self._stop_live_status()
        self._status_after_id = self.after(STATUS_REFRESH_MS, self._tick_status)
        self._speed_after_id = self.after(2_000, self._tick_speed)

    def _stop_live_status(self) -> None:
        for attr in ("_status_after_id", "_speed_after_id"):
            after_id = getattr(self, attr, None)
            if after_id is not None:
                try: self.after_cancel(after_id)
                except: pass
                setattr(self, attr, None)

    def _tick_status(self) -> None:
        self._status_after_id = None
        if not self.manager.connected(): return
        if self._verifying:
            self._status_after_id = self.after(STATUS_REFRESH_MS, self._tick_status)
            return
        self._verifying = True

        def worker():
            try: ok, msg = self.manager.test_connection(timeout=6.0)
            except Exception as exc: ok, msg = False, str(exc)
            self._results.put((self._apply_live_status, (ok, msg)))

        threading.Thread(target=worker, daemon=True).start()

    def _apply_live_status(self, ok: bool, message: str) -> None:
        self._verifying = False
        if ok:
            self.status_var.set("●  CONNECTED")
            self.sidebar_status.configure(text_color=Colors.success_text)
            self.info_var.set(message)
        else:
            self.status_var.set("●  TIMEOUT")
            self.sidebar_status.configure(text_color=Colors.danger_text)
            self.info_var.set(message)
        if self.manager.connected():
            self._status_after_id = self.after(STATUS_REFRESH_MS, self._tick_status)

    def _tick_speed(self) -> None:
        self._speed_after_id = None
        if not self.manager.connected(): return
        if self._speed_testing:
            self._speed_after_id = self.after(SPEED_REFRESH_MS, self._tick_speed)
            return
        self._speed_testing = True
        self.down_var.set("Down:  testing…")
        self.up_var.set("Up:    testing…")

        def worker():
            try: down = self.manager.measure_down_speed(duration=SPEED_DURATION)
            except: down = 0.0
            try: up = self.manager.measure_up_speed(duration=SPEED_DURATION)
            except: up = 0.0
            self._results.put((self._apply_speed, (down, up)))

        threading.Thread(target=worker, daemon=True).start()

    def _apply_speed(self, down_mbps: float, up_mbps: float) -> None:
        self._speed_testing = False
        self.down_var.set(f"Down:  {down_mbps:6.2f} Mbps")
        self.up_var.set(f"Up:    {up_mbps:6.2f} Mbps")
        if self.manager.connected():
            self._speed_after_id = self.after(SPEED_REFRESH_MS, self._tick_speed)

    # -------------------------------------------------------------- about

    def _show_about(self) -> None:
        if self._about_open:
            return
        self._about_open = True

        # Hide Help button on About page (grid_remove keeps position)
        self.help_btn.grid_remove()

        dialog = ctk.CTkToplevel(self)
        dialog.title("About VPN Manager")
        dialog.geometry("820x820")
        dialog.minsize(720, 700)
        dialog.resizable(True, True)
        dialog.configure(fg_color=Colors.bg)
        dialog.transient(self)
        dialog.grab_set()
        apply_window_icon(dialog)

        def on_close():
            dialog.destroy()
            # Restore Help button at the SAME grid position
            self.help_btn.grid(row=0, column=0, padx=(0, 6))
            self._about_open = False

        dialog.protocol("WM_DELETE_WINDOW", on_close)

        outer = ctk.CTkScrollableFrame(dialog, fg_color=Colors.surface, corner_radius=Spacing.RADIUS_CARD, scrollbar_button_color=Colors.surface_alt, scrollbar_button_hover_color=Colors.border_light)
        outer.pack(fill="both", expand=True, padx=18, pady=18)

        ctk.CTkLabel(outer, text="◈  CYBEROPSSUITE", font=Fonts.badge(12), text_color=Colors.info).pack(anchor="w", padx=26, pady=(20, 0))
        ctk.CTkLabel(outer, text="VPN Manager", font=Fonts.title(26), text_color=Colors.text).pack(anchor="w", padx=26, pady=(6, 2))
        ctk.CTkLabel(outer, text=f"{APP_SUITE}  •  Version {APP_VERSION}", font=Fonts.label(11), text_color=Colors.text_muted).pack(anchor="w", padx=26)

        ctk.CTkFrame(outer, fg_color=Colors.border, height=1).pack(fill="x", padx=26, pady=14)

        os_name = f"{platform.system()} {platform.release()}"
        py_version = platform.python_version()
        cfg_path = config_root_quiet("VpnManager")

        info_frame = ctk.CTkFrame(outer, fg_color=Colors.bg, corner_radius=Spacing.RADIUS_INPUT, border_width=1, border_color=Colors.border)
        info_frame.pack(fill="x", padx=26, pady=(0, 16))

        info_text = f"Platform:  {os_name}\nPython:    {py_version}\nConfig:    {cfg_path}"
        ctk.CTkLabel(info_frame, text=info_text, font=Fonts.mono(10), text_color=Colors.text_soft, justify="left", anchor="w").pack(fill="x", padx=14, pady=10)

        def add_section(title: str, body: str, color: str = Colors.info) -> None:
            ctk.CTkLabel(outer, text=title, font=Fonts.badge(11), text_color=color).pack(anchor="w", padx=26, pady=(6, 4))
            ctk.CTkLabel(outer, text=body, font=Fonts.label(11), text_color=Colors.text, justify="left", anchor="w", wraplength=720).pack(fill="x", padx=26, pady=(0, 10))

        add_section("OVERVIEW", "A desktop client for managing VLESS and VMess profiles and running an Xray-core instance as a local SOCKS5/HTTP proxy.", Colors.info_soft)

        add_section("FEATURES", "• Import single links or subscription URLs (HTTP / base64)\n• Manage VLESS (incl. REALITY) and VMess profiles\n• One-click Connect to Best (auto-selects fastest server)\n• Smart Auto-Switch: automatically evaluates server latency and switches to the fastest server without dropping the connection\n• TCP latency test for every profile\n• Real tunnel verification (Cloudflare trace)\n• Live downstream / upstream speed display\n• Live Xray log panel\n• Cross-platform (Windows, Linux)", Colors.success_text)

        add_section("LOCAL PROXY ENDPOINTS", f"SOCKS5   127.0.0.1:{DEFAULT_SOCKS_PORT}\nHTTP     127.0.0.1:{DEFAULT_HTTP_PORT}", Colors.warning_text)

        add_section("SUPPORTED PLATFORMS", "• Windows 10 / 11 / Server 2019+\n• Linux (any distribution with Xray binary in bin/)\n• macOS is not supported.", Colors.warning_text)

        add_section("HOW IT WORKS", "1. Import a profile from a link or subscription.\n2. Place the Xray-core binary in the project's bin/ folder\n   (xray.exe on Windows, xray on Linux).\n3. Select a profile and click Connect, or Connect to Best.\n4. Point applications at the local proxy.", Colors.info)

        add_section("⌨  KEYBOARD SHORTCUTS", "F5           → Refresh the profiles list\nEnter        → Connect to the selected profile\nDelete       → Remove the selected profile\nCtrl+Click   → Select a profile without connecting", Colors.info_light)

        add_section("NOTES", "• The tool does not store credentials from your subscription.\n• Profiles are stored under your user's config directory.\n• Closing the app disconnects the proxy.", Colors.text_muted)

        ctk.CTkFrame(outer, fg_color=Colors.border, height=1).pack(fill="x", padx=26, pady=14)

        ctk.CTkButton(outer, text="Close", width=200, height=42, corner_radius=Spacing.RADIUS_BUTTON, fg_color=Colors.primary, hover_color=Colors.primary_hover, font=Fonts.label(13, bold=True), command=on_close).pack(anchor="e", padx=26, pady=(0, 20))

        dialog.bind("<Escape>", lambda _e: on_close())
        dialog.update_idletasks()
        x = self.winfo_rootx() + (self.winfo_width() - dialog.winfo_width()) // 2
        y = self.winfo_rooty() + (self.winfo_height() - dialog.winfo_height()) // 2
        dialog.geometry(f"+{max(0, x)}+{max(0, y)}")

    # --------------------------------------------------------- log panel

    def _refresh_log(self) -> None:
        try:
            if not self.winfo_exists(): return
            tail = self.manager.read_log_tail(4000)
            self._set_log_text(tail)
        except: pass
        try: self._log_after_id = self.after(LOG_REFRESH_MS, self._refresh_log)
        except tk.TclError: return

    def _set_log_text(self, text: str) -> None:
        if not hasattr(self, "log_text"): return
        self.log_text.configure(state="normal")
        self.log_text.delete("1.0", "end")
        self.log_text.insert("1.0", text or "(no log yet)")
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    # ---------------------------------------------------------- status

    def _set_busy(self, busy: bool, message: str | None) -> None:
        self._loading = busy
        self.connect_btn.configure(state="disabled" if busy else "normal")
        self.disconnect_btn.configure(state="disabled" if busy else "normal")
        self.best_btn.configure(state="disabled" if busy else "normal")
        if message: self.info_var.set(message)

    # ------------------------------------------------------ worker polling

    def _poll_results(self) -> None:
        try:
            while True:
                callback, args = self._results.get_nowait()
                callback(*args)
        except queue.Empty: pass
        try:
            if self.winfo_exists(): self._poll_after_id = self.after(100, self._poll_results)
        except tk.TclError: return

    # -------------------------------------------------------------- closing

    def _on_close(self) -> None:
        self._stop_live_status()
        if self._auto_switch_after_id:
            try: self.after_cancel(self._auto_switch_after_id)
            except: pass
        for after_id in (self._poll_after_id, self._log_after_id):
            if after_id is not None:
                try: self.after_cancel(after_id)
                except: pass
        try: self.manager.disconnect()
        except: pass
        self.destroy()

def main() -> None:
    app = VPNManagerApp()
    app.mainloop()


if __name__ == "__main__":
    main()