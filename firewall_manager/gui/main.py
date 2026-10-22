"""CyberOpsSuite Firewall Manager GUI.

A CustomTkinter desktop client for managing Windows Firewall rules. The GUI
is deliberately split into small methods: window setup, sidebar, toolbar,
and individual pages. All colors and fonts come from :mod:`core.theme` so
the tool looks consistent with the rest of the suite.

Includes a page-specific How to Use guide.
"""

from __future__ import annotations

import os
import platform
import subprocess
import sys
from datetime import datetime
from pathlib import Path

import customtkinter as ctk
import tkinter as tk
from tkinter import ttk, messagebox

from core.theme import Colors, Fonts, Spacing
from core.gui.treeview_style import apply_treeview_style
from core.utils.icons import apply_window_icon
from core.utils.paths import config_root_quiet
from core.utils.subprocess_utils import get_no_window_kwargs


PROJECT_ROOT = Path(__file__).resolve().parents[2]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from firewall_manager.core.firewall import FirewallManager


# Dictionary of page-specific help texts
HELP_TEXTS = {
    "dashboard": {
        "title": "Dashboard",
        "content": (
            "The Dashboard provides an overview of your system's security status:\n\n"
            "•  🛡 Firewall: Shows if the firewall is active.\n"
            "•  🌐 Internet: Shows if you are online.\n"
            "•  📋 Total Rules: Number of all saved rules.\n"
            "•  ✅ Enabled Rules: Rules currently active.\n"
            "•  🚫 Blocked Rules: Rules that block traffic.\n"
            "•  🔌 Open Ports: Ports that are open.\n\n"
            "You can also see the Active Profile and Network Status (IP, Gateway, DNS, Latency)."
        )
    },
    "firewall": {
        "title": "Firewall Rules",
        "content": (
            "Here you can manage your custom CyberOpsSuite rules:\n\n"
            "•  To add a rule, click '＋ Add Rule'.\n"
            "•  To remove, enable, or disable a rule, select it and click the respective button.\n"
            "•  Use the search bar and filters to find specific rules.\n"
            "•  Click 'Apply JSON → System' to apply all saved rules to the system.\n\n"
            "Tip: Double-click a rule to see its details."
        )
    },
    "system": {
        "title": "System Rules",
        "content": (
            "This page lists all system firewall rules (read-only).\n\n"
            "•  You can enable or disable system rules by selecting them and clicking the buttons.\n"
            "•  Removing system rules requires Administrator privileges.\n"
            "•  Use the search bar to filter by name, port, or protocol.\n\n"
            "Note: System rules are managed by Windows, not by CyberOpsSuite."
        )
    },
    "modes": {
        "title": "Profile Modes",
        "content": (
            "Choose a security profile to quickly change your firewall policy:\n\n"
            "•  🔐 Secure Mode: Restrictive inbound policy.\n"
            "•  🚫 Lockdown Mode: Blocks all traffic (use with caution).\n"
            "•  🟦 Default Mode: Restores Windows Firewall defaults.\n"
            "•  ⚙ Custom Mode: Applies your saved CyberOpsSuite rules.\n\n"
            "Warning: Some profiles can interrupt network access. Use carefully."
        )
    },
    "network": {
        "title": "Network Monitoring",
        "content": (
            "Shows a live snapshot of all TCP/UDP endpoints:\n\n"
            "•  Uses netstat on Windows, ss on Linux.\n"
            "•  Use the search bar to filter by IP, port, or PID.\n"
            "•  TCP connections are highlighted in blue, UDP in orange.\n"
            "•  Click '↻ Refresh Snapshot' to update.\n\n"
            "Tip: This is a read-only view; you cannot close connections from here."
        )
    },
    "settings": {
        "title": "Settings",
        "content": (
            "Here you can configure the application:\n\n"
            "•  DISPLAY & APPEARANCE: The app uses a fixed Dark Blue theme.\n"
            "•  MAINTENANCE: Refresh firewall status, open logs/exports folders, or clear logs.\n"
            "•  ADVANCED ACTION: Reset Windows Firewall to defaults (use with caution).\n\n"
            "Warning: Resetting the firewall can remove custom rules."
        )
    },
    "about": {
        "title": "About",
        "content": (
            "This page provides information about CyberOpsSuite Firewall Manager:\n\n"
            "•  Version and build details.\n"
            "•  Runtime info (OS, Python version, config path).\n"
            "•  List of features.\n"
            "•  Supported platforms.\n"
            "•  Keyboard shortcuts.\n"
            "•  Responsible use guidelines."
        )
    }
}


class FirewallGUI(ctk.CTk):
    """Main application window for the Firewall Manager."""

    def __init__(self) -> None:
        super().__init__()

        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("dark-blue")

        try:
            self.fw = FirewallManager()
        except Exception as exc:
            messagebox.showerror(
                "Firewall Manager Startup Error",
                f"Could not initialize Firewall Manager.\n\n{exc}",
            )
            self.destroy()
            raise

        self._setup_state()
        self._setup_window()

        apply_window_icon(self)
        apply_treeview_style(self)

        self._build_ui()
        self._bind_shortcuts()

        self.switch_page("dashboard")

    # --------------------------------------------------------------- setup

    def _setup_window(self) -> None:
        self.title("CyberOpsSuite Firewall Manager")
        self.geometry("1280x780")
        self.minsize(1100, 680)
        self.configure(fg_color=Colors.bg)
        self._apply_dark_titlebar()

    def _setup_state(self) -> None:
        self.current_page: str = "dashboard"
        self.last_scan_time: str = "Never"
        self.scan_status: str = "Idle"
        self._firewall_rules: list = []
        self._system_rules: list = []

    def _apply_dark_titlebar(self) -> None:
        if os.name != "nt":
            return
        try:
            import ctypes
            hwnd = ctypes.windll.user32.GetParent(self.winfo_id())
            value = ctypes.c_int(1)
            for attribute in (20, 19):
                result = ctypes.windll.dwmapi.DwmSetWindowAttribute(
                    hwnd, attribute, ctypes.byref(value), ctypes.sizeof(value)
                )
                if result == 0:
                    break
        except Exception:
            pass

    def _build_ui(self) -> None:
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(1, weight=1)

        self._build_sidebar()
        self._build_toolbar()
        self._build_pages()

    def _build_sidebar(self) -> None:
        sidebar = ctk.CTkFrame(
            self, width=230, corner_radius=0, fg_color=Colors.bg_alt,
        )
        sidebar.grid(row=0, column=0, rowspan=2, sticky="ns")
        sidebar.grid_propagate(False)

        ctk.CTkLabel(
            sidebar, text="CyberOpsSuite",
            font=Fonts.heading(20), text_color=Colors.text,
        ).pack(padx=20, pady=(25, 4))

        ctk.CTkLabel(
            sidebar, text="Security Operations",
            font=Fonts.label(11), text_color=Colors.text_muted,
        ).pack(padx=20, pady=(0, 25))

        nav_items = [
            ("🛡️  Dashboard", "dashboard"),
            ("📄  Firewall Rules", "firewall"),
            ("⚙️  System Rules", "system"),
            ("🔐  Profile Modes", "modes"),
            ("🌐  Network Monitoring", "network"),
            ("🔧  Settings", "settings"),
            ("ℹ️  About", "about"),
        ]
        for label, page in nav_items:
            ctk.CTkButton(
                sidebar,
                text=label,
                command=lambda p=page: self.switch_page(p),
                fg_color=Colors.surface_alt,
                hover_color=Colors.primary,
                corner_radius=Spacing.RADIUS_BUTTON,
                height=42,
                anchor="w",
                font=Fonts.label(13),
            ).pack(fill="x", padx=12, pady=5)

        ctk.CTkButton(
            sidebar,
            text="↻  Refresh",
            command=self.refresh_current_page,
            fg_color=Colors.primary,
            hover_color=Colors.primary_hover,
            corner_radius=Spacing.RADIUS_BUTTON,
            height=42,
            anchor="w",
            font=Fonts.label(13, bold=True),
        ).pack(fill="x", padx=12, pady=(12, 5))

    def _build_toolbar(self) -> None:
        toolbar = ctk.CTkFrame(self, height=50, corner_radius=0, fg_color=Colors.bg)
        toolbar.grid(row=0, column=1, sticky="ew")
        toolbar.grid_columnconfigure(0, weight=1)

        self.mode_label = ctk.CTkLabel(
            toolbar, text="Mode: Default",
            font=Fonts.label(13), text_color=Colors.text,
        )
        self.mode_label.grid(row=0, column=0, sticky="w", padx=20, pady=10)

        actions = ctk.CTkFrame(toolbar, fg_color="transparent")
        actions.grid(row=0, column=1, sticky="e", padx=(0, 20), pady=8)

        # Only Help button here, About is in the sidebar
        self.help_btn = ctk.CTkButton(
            actions, text="❓ Help", width=100, height=34,
            corner_radius=Spacing.RADIUS_BUTTON,
            fg_color=Colors.info_bg, hover_color=Colors.info,
            text_color=Colors.info_light, font=Fonts.label(11, bold=True),
            command=self._show_page_help,
        )
        self.help_btn.pack(side="right")

    def _build_pages(self) -> None:
        self.pages = {
            name: ctk.CTkFrame(self, fg_color=Colors.bg_alt)
            for name in (
                "dashboard", "firewall", "system", "modes",
                "network", "settings", "about",
            )
        }
        for page in self.pages.values():
            page.grid(row=1, column=1, sticky="nsew", padx=10, pady=10)

        self.build_dashboard()
        self.build_firewall_page()
        self.build_system_page()
        self.build_modes_page()
        self.build_network_monitor_page()
        self.build_settings()
        self.build_about_page()
        self.tree.bind("<Double-1>", self._on_rule_double_click)
        self.system_tree.bind("<Double-1>", self._on_system_rule_double_click)

    def _bind_shortcuts(self) -> None:
        self.bind_all("<F1>", self.open_about_shortcut)
        self.bind_all("<F5>", lambda _e: self.refresh_current_page())
        self.bind_all("<Escape>", self.escape_key_handler)
        self.bind_all("<Delete>", lambda _e: self.delete_key_handler())
        self.bind("<Return>", self.enter_key_handler)

    # ---------------------------------------------------------- navigation

    def switch_page(self, name: str) -> None:
        for page in self.pages.values():
            page.grid_remove()

        self.pages[name].grid()
        self.current_page = name
        self._update_help_button()
        self.refresh_current_page()

    def _update_help_button(self) -> None:
        """Update the Help button text based on the current page."""
        if self.current_page == "about":
            # Hide the Help button on the About page
            self.help_btn.pack_forget()
        else:
            page_title = HELP_TEXTS.get(self.current_page, {}).get("title", "this page")
            self.help_btn.configure(text=f"❓ Help: {page_title}")
            # Show the Help button again if it was hidden
            self.help_btn.pack(side="right", padx=(0, 8))

    def open_about_shortcut(self, _event=None):
        self.switch_page("about")
        return "break"

    def focus_search(self, _event=None):
        mapping = {
            "firewall": "firewall_search_entry",
            "system": "system_search_entry",
            "network": "monitor_search_entry",
        }
        attr = mapping.get(self.current_page)
        widget = getattr(self, attr, None) if attr else None
        if widget is not None:
            widget.focus_set()
            if hasattr(widget, "select_range"):
                try:
                    widget.select_range(0, "end")
                except Exception:
                    pass
        return "break"

    def escape_key_handler(self, _event=None):
        focused = self.focus_get()
        if focused is not None:
            try:
                if focused.winfo_toplevel() is not self:
                    focused.winfo_toplevel().destroy()
                    return "break"
            except Exception:
                pass

        mapping = {
            "firewall": "firewall_search_var",
            "system": "system_search_var",
            "network": "monitor_search_var",
        }
        var = getattr(self, mapping.get(self.current_page, ""), None)
        if var is not None and var.get():
            var.set("")
            if self.current_page == "firewall":
                self.apply_firewall_filters()
            elif self.current_page == "system":
                self.apply_system_filters()
            elif self.current_page == "network":
                self.apply_network_monitor_filter()
        return "break"

    def enter_key_handler(self, _event=None):
        return None

    def delete_key_handler(self, _event=None):
        if self.current_page == "firewall":
            self.remove_rule()

    def refresh_current_page(self) -> None:
        errors: list[str] = []
        self.scan_status = "Scanning..."

        if hasattr(self, "scan_info_label"):
            self.scan_info_label.configure(text="Security Scan Running...")
        self.update_idletasks()

        try:
            scan = self.fw.quick_scan()
            self.update_dashboard(scan)
        except Exception as exc:
            errors.append(f"Dashboard scan: {exc}")

        try:
            self.load_rules()
        except Exception as exc:
            errors.append(f"Firewall rules: {exc}")

        try:
            self.load_system_rules()
        except Exception as exc:
            errors.append(f"System firewall rules: {exc}")

        try:
            self.update_network_status()
        except Exception as exc:
            errors.append(f"Network status: {exc}")

        if self.current_page == "network" and hasattr(self, "monitor_tree"):
            try:
                self.update_network_monitor()
            except Exception as exc:
                errors.append(f"Network monitor: {exc}")

        self.last_scan_time = datetime.now().strftime("%H:%M:%S")
        self.scan_status = "Completed with errors" if errors else "Completed"

        if hasattr(self, "scan_info_label"):
            self.scan_info_label.configure(
                text=f"Last Scan: {self.last_scan_time} | Status: {self.scan_status}"
            )

        if errors:
            self.log_application_event("Refresh warnings: " + " | ".join(errors))
            messagebox.showerror(
                "Refresh Warnings",
                "Some information could not be refreshed. Details were saved "
                "to exports/logs/firewall_manager.log.\n\n" + "\n".join(errors),
            )

    # ------------------------------------------------------------ logging

    def log_application_event(self, message: str) -> None:
        import logging
        logs_path = PROJECT_ROOT / "exports" / "logs"
        logs_path.mkdir(parents=True, exist_ok=True)

        logger = logging.getLogger("CyberOpsSuite.FirewallManager")
        if not logger.handlers:
            handler = logging.FileHandler(
                logs_path / "firewall_manager.log", encoding="utf-8"
            )
            handler.setFormatter(
                logging.Formatter("%(asctime)s %(levelname)s %(message)s")
            )
            logger.addHandler(handler)
            logger.setLevel(logging.INFO)

        logger.error("%s", message)

    # ------------------------------------------------------------- folders

    @staticmethod
    def _open_folder_in_explorer(path: Path) -> None:
        path.mkdir(parents=True, exist_ok=True)
        try:
            if os.name == "nt":
                os.startfile(str(path))
            elif platform.system() == "Darwin":
                subprocess.Popen(["open", str(path)])
            else:
                subprocess.Popen(["xdg-open", str(path)])
        except OSError as exc:
            messagebox.showerror(
                "Could not open folder",
                f"Failed to open {path}:\n\n{exc}",
            )

    def open_logs_folder(self) -> None:
        self._open_folder_in_explorer(PROJECT_ROOT / "exports" / "logs")

    def open_exports_folder(self) -> None:
        self._open_folder_in_explorer(PROJECT_ROOT / "exports")

    # ------------------------------------------------------------- cleanup

    def clear_application_logs(self) -> None:
        logs_path = PROJECT_ROOT / "exports" / "logs"

        if not logs_path.exists():
            messagebox.showinfo("Logs", "No logs folder found.", parent=self)
            return

        if not messagebox.askyesno(
            "Clear logs",
            "This will permanently delete every log file in the logs folder.\n\n"
            "Continue?",
            parent=self,
        ):
            return

        deleted = 0
        for file in logs_path.iterdir():
            if file.is_file():
                try:
                    file.unlink()
                    deleted += 1
                except OSError:
                    pass

        messagebox.showinfo(
            "Logs",
            f"{deleted} log file(s) cleared.",
            parent=self,
        )

    # ------------------------------------------------------------- firewall

    def reset_windows_firewall(self) -> None:
        confirm = messagebox.askyesno(
            "Reset Windows Firewall",
            "This will restore Windows Firewall to its default configuration.\n\n"
            "Are you sure you want to continue?",
            parent=self,
        )
        if not confirm:
            return

        try:
            success = self.fw.reset_firewall()
        except Exception as exc:
            messagebox.showerror(
                "Firewall Reset",
                f"Error:\n{exc}",
                parent=self,
            )
            return

        if success:
            messagebox.showinfo(
                "Firewall Reset",
                "Windows Firewall was successfully reset.",
                parent=self,
            )
        else:
            messagebox.showerror(
                "Firewall Reset",
                "Failed to reset Windows Firewall.",
                parent=self,
            )

    # ----------------------------------------------------------- dashboard

    def build_dashboard(self) -> None:
        page = self.pages["dashboard"]
        for widget in page.winfo_children():
            widget.destroy()

        self._build_dashboard_header(page)
        self._build_dashboard_cards(page)
        self._build_dashboard_profile(page)
        self._build_dashboard_network(page)

    def _build_dashboard_header(self, parent: ctk.CTkFrame) -> None:
        header = ctk.CTkFrame(parent, fg_color="transparent")
        header.pack(fill="x", padx=25, pady=(20, 10))

        ctk.CTkLabel(
            header,
            text="Security Dashboard",
            font=Fonts.title(28),
            text_color=Colors.text,
        ).pack(anchor="w")

        self.subtitle_label = ctk.CTkLabel(
            header,
            text="CyberOpsSuite • System Security Overview",
            font=Fonts.label(13),
            text_color=Colors.text_muted,
        )
        self.subtitle_label.pack(anchor="w", pady=(3, 0))

        self.scan_info_label = ctk.CTkLabel(
            header,
            text="Last Scan: Never | Status: Idle",
            font=Fonts.label(12),
            text_color=Colors.text_muted,
        )
        self.scan_info_label.pack(anchor="w", pady=(8, 0))

    def _build_dashboard_cards(self, parent: ctk.CTkFrame) -> None:
        cards = ctk.CTkFrame(parent, fg_color="transparent")
        cards.pack(fill="x", padx=20, pady=10)

        for column in range(3):
            cards.grid_columnconfigure(column, weight=1)

        specs = [
            (0, 0, "🛡 Firewall", "card_firewall"),
            (0, 1, "🌐 Internet", "card_internet"),
            (0, 2, "📋 Total Rules", "card_rules"),
            (1, 0, "✅ Enabled Rules", "card_enabled"),
            (1, 1, "🚫 Blocked Rules", "card_blocked"),
            (1, 2, "🔌 Open Ports", "card_open_ports"),
        ]
        for row, column, title, attr_name in specs:
            card, value = self._make_dashboard_card(cards, title)
            card.grid(row=row, column=column, padx=6, pady=6, sticky="nsew")
            setattr(self, attr_name, value)

    def _make_dashboard_card(
        self, parent: ctk.CTkFrame, title: str
    ) -> tuple[ctk.CTkFrame, ctk.CTkLabel]:
        card = ctk.CTkFrame(
            parent,
            fg_color=Colors.surface_alt,
            corner_radius=Spacing.RADIUS_CARD,
        )

        ctk.CTkLabel(
            card,
            text=title,
            font=Fonts.label(14, bold=True),
            text_color=Colors.text,
        ).pack(anchor="w", padx=15, pady=(12, 3))

        value = ctk.CTkLabel(
            card,
            text="Unknown",
            font=Fonts.heading(20),
            text_color=Colors.text,
        )
        value.pack(anchor="w", padx=15, pady=(0, 12))

        return card, value

    def _build_dashboard_profile(self, parent: ctk.CTkFrame) -> None:
        frame = ctk.CTkFrame(
            parent,
            fg_color=Colors.surface_alt,
            corner_radius=Spacing.RADIUS_CARD,
        )
        frame.pack(fill="x", padx=26, pady=(10, 5))

        ctk.CTkLabel(
            frame,
            text="ACTIVE PROFILE",
            font=Fonts.badge(11),
            text_color=Colors.text_muted,
        ).pack(anchor="w", padx=15, pady=(10, 0))

        self.card_mode = ctk.CTkLabel(
            frame,
            text="Current Mode: Default",
            font=Fonts.heading(17),
            text_color=Colors.text,
        )
        self.card_mode.pack(anchor="w", padx=15, pady=(2, 12))

    def _build_dashboard_network(self, parent: ctk.CTkFrame) -> None:
        frame = ctk.CTkFrame(
            parent,
            fg_color=Colors.surface_alt,
            corner_radius=Spacing.RADIUS_CARD,
        )
        frame.pack(fill="x", padx=26, pady=(8, 20))

        ctk.CTkLabel(
            frame,
            text="🌐 Network Status",
            font=Fonts.heading(18),
            text_color=Colors.text,
        ).grid(row=0, column=0, columnspan=2, padx=18, pady=(15, 10), sticky="w")

        frame.grid_columnconfigure(0, weight=1)
        frame.grid_columnconfigure(1, weight=1)

        self.net_status = ctk.CTkLabel(
            frame, text="Internet: Checking...",
            font=Fonts.label(14), text_color=Colors.text,
        )
        self.net_status.grid(row=1, column=0, padx=20, pady=6, sticky="w")

        self.net_ip = ctk.CTkLabel(
            frame, text="IP: ...",
            font=Fonts.label(14), text_color=Colors.text,
        )
        self.net_ip.grid(row=1, column=1, padx=20, pady=6, sticky="w")

        self.net_gateway = ctk.CTkLabel(
            frame, text="Gateway: ...",
            font=Fonts.label(14), text_color=Colors.text,
        )
        self.net_gateway.grid(row=2, column=0, padx=20, pady=6, sticky="w")

        self.net_dns = ctk.CTkLabel(
            frame, text="DNS: ...",
            font=Fonts.label(14), text_color=Colors.text,
        )
        self.net_dns.grid(row=2, column=1, padx=20, pady=6, sticky="w")

        self.net_latency = ctk.CTkLabel(
            frame, text="Latency: ...",
            font=Fonts.label(14), text_color=Colors.text,
        )
        self.net_latency.grid(row=3, column=0, columnspan=2,
                              padx=20, pady=(6, 15), sticky="w")

    # ------------------------------------------------------- dashboard data

    def update_dashboard(self, scan: dict) -> None:
        firewall_status = scan.get("firewall_status", "Unknown")
        internet_status = scan.get("internet_status", "Unknown")

        self.card_firewall.configure(text=firewall_status)
        if str(firewall_status).lower() in {"on", "enabled", "running"}:
            self.card_firewall.configure(text_color=Colors.success_text)
        else:
            self.card_firewall.configure(text_color=Colors.danger_text)

        self.card_internet.configure(text=internet_status)
        if str(internet_status).lower() in {"online", "connected"}:
            self.card_internet.configure(text_color=Colors.success_text)
        else:
            self.card_internet.configure(text_color=Colors.danger_text)

        self.card_rules.configure(
            text=str(scan.get("total_rules", 0)),
            text_color=Colors.text,
        )
        self.card_enabled.configure(
            text=str(scan.get("enabled_rules", 0)),
            text_color=Colors.success_text,
        )
        self.card_blocked.configure(
            text=str(scan.get("blocked_rules", 0)),
            text_color=Colors.danger_text,
        )
        self.card_open_ports.configure(
            text=str(scan.get("open_ports", 0)),
            text_color=Colors.warning_text,
        )

        mode = self.mode_label.cget("text").replace("Mode: ", "")
        self.card_mode.configure(text=f"Current Mode: {mode}")

    # ------------------------------------------------------ firewall rules

    def build_firewall_page(self) -> None:
        page = self.pages["firewall"]
        page.configure(fg_color=Colors.bg_alt)

        self._build_page_title(page, "Firewall Rules", "firewall_badge")

        filters = self._build_filter_bar(
            page,
            search_attr="firewall_search_entry",
            search_var_attr="firewall_search_var",
            action_var_attr="firewall_action_filter",
            status_var_attr="firewall_status_filter",
            on_change=self.apply_firewall_filters,
            placeholder="Search ID, IP, port, protocol...",
        )
        filters.pack(fill="x", padx=16, pady=(0, 10))

        table_frame = ctk.CTkFrame(
            page,
            fg_color=Colors.surface,
            corner_radius=Spacing.RADIUS_CARD,
            border_width=1,
            border_color=Colors.border,
        )
        table_frame.pack(fill="both", expand=True, padx=16, pady=(0, 8))

        columns = ("id", "action", "ip", "port", "protocol", "direction", "enabled")
        headings = {
            "id": "Rule ID", "action": "Action", "ip": "IP Address",
            "port": "Port", "protocol": "Protocol",
            "direction": "Direction", "enabled": "Status",
        }
        widths = {
            "id": 90, "action": 100, "ip": 190, "port": 90,
            "protocol": 110, "direction": 120, "enabled": 100,
        }
        self.tree = self._build_treeview(table_frame, columns, headings, widths)
        self._style_rule_tree(self.tree)

        btn_frame = ctk.CTkFrame(page, fg_color="transparent")
        btn_frame.pack(fill="x", padx=16, pady=(4, 12))

        ctk.CTkButton(
            btn_frame, text="＋ Add Rule", width=120,
            height=Spacing.BUTTON_HEIGHT,
            fg_color=Colors.primary, hover_color=Colors.primary_hover,
            command=self.open_add_rule_window,
        ).pack(side="left", padx=(0, 8))

        ctk.CTkButton(
            btn_frame, text="Remove", width=100,
            height=Spacing.BUTTON_HEIGHT,
            fg_color=Colors.danger, hover_color=Colors.danger_hover,
            command=self.remove_rule,
        ).pack(side="left", padx=4)

        ctk.CTkButton(
            btn_frame, text="Enable", width=90,
            height=Spacing.BUTTON_HEIGHT,
            fg_color=Colors.success, hover_color=Colors.success_hover,
            command=self.enable_rule,
        ).pack(side="left", padx=4)

        ctk.CTkButton(
            btn_frame, text="Disable", width=90,
            height=Spacing.BUTTON_HEIGHT,
            fg_color=Colors.neutral, hover_color=Colors.neutral_hover,
            command=self.disable_rule,
        ).pack(side="left", padx=4)

        ctk.CTkButton(
            btn_frame, text="Apply JSON → System", width=180,
            height=Spacing.BUTTON_HEIGHT,
            fg_color="#6D28D9", hover_color="#5B21B6",
            command=self.apply_json_to_system,
        ).pack(side="right", padx=4)

    # -------------------------------------------------------- system rules

    def build_system_page(self) -> None:
        page = self.pages["system"]
        page.configure(fg_color=Colors.bg_alt)

        self._build_page_title(
            page, "System Firewall Rules", "system_badge",
            initial_text="Active: 0 / 0",
        )

        filters = self._build_filter_bar(
            page,
            search_attr="system_search_entry",
            search_var_attr="system_search_var",
            action_var_attr="system_action_filter",
            status_var_attr="system_status_filter",
            on_change=self.apply_system_filters,
            placeholder="Search rule name, port, protocol...",
        )
        filters.pack(fill="x", padx=16, pady=(0, 10))

        table_frame = ctk.CTkFrame(
            page,
            fg_color=Colors.surface,
            corner_radius=Spacing.RADIUS_CARD,
            border_width=1,
            border_color=Colors.border,
        )
        table_frame.pack(fill="both", expand=True, padx=16, pady=(0, 8))

        columns = ("name", "action", "port", "protocol", "direction", "enabled")
        headings = {
            "name": "Rule Name", "action": "Action", "port": "Port",
            "protocol": "Protocol", "direction": "Direction", "enabled": "Status",
        }
        widths = {
            "name": 360, "action": 100, "port": 100,
            "protocol": 120, "direction": 140, "enabled": 110,
        }
        self.system_tree = self._build_treeview(
            table_frame, columns, headings, widths
        )
        self._style_rule_tree(self.system_tree)

        btn_frame = ctk.CTkFrame(page, fg_color="transparent")
        btn_frame.pack(fill="x", padx=16, pady=(4, 12))

        ctk.CTkButton(
            btn_frame, text="Enable Selected", width=150,
            height=Spacing.BUTTON_HEIGHT,
            fg_color=Colors.success, hover_color=Colors.success_hover,
            command=self.enable_selected_system_rule,
        ).pack(side="left", padx=(0, 8))

        ctk.CTkButton(
            btn_frame, text="Disable Selected", width=150,
            height=Spacing.BUTTON_HEIGHT,
            fg_color=Colors.neutral, hover_color=Colors.neutral_hover,
            command=self.disable_selected_system_rule,
        ).pack(side="left", padx=4)

        ctk.CTkButton(
            btn_frame, text="Remove Selected", width=150,
            height=Spacing.BUTTON_HEIGHT,
            fg_color=Colors.danger, hover_color=Colors.danger_hover,
            command=self.remove_selected_system_rule,
        ).pack(side="left", padx=4)

    # ------------------------------------------------------ shared builders

    def _build_page_title(
        self,
        parent: ctk.CTkFrame,
        title: str,
        badge_attr: str,
        initial_text: str = "● 0 rules",
    ) -> None:
        frame = ctk.CTkFrame(parent, fg_color="transparent")
        frame.pack(fill="x", padx=16, pady=(16, 8))

        ctk.CTkLabel(
            frame, text=title,
            font=Fonts.title(24), text_color=Colors.text_strong,
        ).pack(side="left")

        badge = ctk.CTkLabel(
            frame, text=initial_text,
            font=Fonts.badge(11), text_color=Colors.info,
            fg_color=Colors.info_bg, corner_radius=Spacing.RADIUS_BADGE,
        )
        badge.pack(side="left", padx=14, ipadx=10, ipady=5)
        setattr(self, badge_attr, badge)

    def _build_filter_bar(
        self,
        parent: ctk.CTkFrame,
        *,
        search_attr: str,
        search_var_attr: str,
        action_var_attr: str,
        status_var_attr: str,
        on_change,
        placeholder: str = "Search...",
    ) -> ctk.CTkFrame:
        bar = ctk.CTkFrame(
            parent,
            fg_color=Colors.surface,
            corner_radius=Spacing.RADIUS_CARD,
        )

        search_var = tk.StringVar()
        setattr(self, search_var_attr, search_var)

        action_var = tk.StringVar(value="All actions")
        setattr(self, action_var_attr, action_var)

        status_var = tk.StringVar(value="All statuses")
        setattr(self, status_var_attr, status_var)

        entry = ctk.CTkEntry(
            bar, textvariable=search_var, placeholder_text=placeholder,
            height=Spacing.INPUT_HEIGHT,
            border_color=Colors.border_light,
            fg_color=Colors.bg,
        )
        entry.pack(side="left", padx=(12, 8), pady=10, fill="x", expand=True)
        entry.bind("<KeyRelease>", lambda _e: on_change())
        setattr(self, search_attr, entry)

        ctk.CTkOptionMenu(
            bar, variable=action_var,
            values=["All actions", "Allow", "Block"],
            width=130, height=Spacing.INPUT_HEIGHT,
            fg_color=Colors.primary, button_color=Colors.primary_hover,
            command=lambda _v: on_change(),
        ).pack(side="left", padx=6, pady=10)

        ctk.CTkOptionMenu(
            bar, variable=status_var,
            values=["All statuses", "Enabled", "Disabled"],
            width=140, height=Spacing.INPUT_HEIGHT,
            fg_color=Colors.primary, button_color=Colors.primary_hover,
            command=lambda _v: on_change(),
        ).pack(side="left", padx=(6, 12), pady=10)

        return bar

    def _build_treeview(
        self,
        parent: ctk.CTkFrame,
        columns: tuple[str, ...],
        headings: dict[str, str],
        widths: dict[str, int],
    ) -> ttk.Treeview:
        tree = ttk.Treeview(
            parent, columns=columns, show="headings",
            selectmode="browse", style="Cyber.Treeview",
        )
        for col in columns:
            tree.heading(col, text=headings[col])
            tree.column(
                col, width=widths[col], minwidth=70,
                anchor="w" if col in ("ip", "name", "direction") else "center",
                stretch=True,
            )

        scrollbar = ttk.Scrollbar(
            parent, orient="vertical", style="Vertical.TScrollbar",
            command=tree.yview,
        )
        tree.configure(yscrollcommand=scrollbar.set)
        tree.pack(side="left", fill="both", expand=True, padx=(8, 0), pady=8)
        scrollbar.pack(side="right", fill="y", padx=(0, 8), pady=8)
        return tree

    def _style_rule_tree(self, tree: ttk.Treeview) -> None:
        tree.tag_configure("allow_enabled", foreground=Colors.success_text, background="#10251F")
        tree.tag_configure("block_enabled", foreground=Colors.danger_text, background="#2A171C")
        tree.tag_configure("disabled", foreground=Colors.text_muted, background="#18202D")
        tree.tag_configure("neutral", foreground=Colors.text_soft, background=Colors.surface)

    # -------------------------------------------------------------- filters

    def apply_firewall_filters(self) -> None:
        if not hasattr(self, "tree"):
            return
        visible = self._apply_filters(
            tree=self.tree,
            rules=self._firewall_rules,
            search_var=self.firewall_search_var,
            action_var=self.firewall_action_filter,
            status_var=self.firewall_status_filter,
            extract=lambda r: (
                (r.rule_id, r.action, r.ip, r.port, r.protocol, r.direction,
                 "YES" if r.enabled else "NO"),
                self._tag_for(r.action, r.enabled),
                str(r.rule_id),
            ),
        )
        total = len(self._firewall_rules)
        self.firewall_badge.configure(text=f"● {visible} / {total} rules")

    def apply_system_filters(self) -> None:
        if not hasattr(self, "system_tree"):
            return
        rules = self._system_rules
        visible = self._apply_filters(
            tree=self.system_tree,
            rules=rules,
            search_var=self.system_search_var,
            action_var=self.system_action_filter,
            status_var=self.system_status_filter,
            extract=lambda r: (
                (r.get("name", ""), r.get("action", ""), r.get("port", ""),
                 r.get("protocol", ""), r.get("direction", ""), r.get("enabled", "")),
                self._tag_for(r.get("action", ""), self._is_enabled(r.get("enabled"))),
                None,
            ),
        )
        active = sum(1 for r in rules if self._is_enabled(r.get("enabled")))
        self.system_badge.configure(
            text=f"Active: {active} / {len(rules)}  •  Showing {visible}"
        )

    @staticmethod
    def _is_enabled(value) -> bool:
        return str(value).casefold() in {"yes", "true", "1", "enabled"}

    @staticmethod
    def _tag_for(action: str, enabled: bool) -> str:
        if not enabled:
            return "disabled"
        action = str(action).casefold()
        if action == "allow":
            return "allow_enabled"
        if action == "block":
            return "block_enabled"
        return "neutral"

    def _apply_filters(
        self,
        *,
        tree: ttk.Treeview,
        rules: list,
        search_var: tk.StringVar,
        action_var: tk.StringVar,
        status_var: tk.StringVar,
        extract,
    ) -> int:
        query = search_var.get().strip().casefold()
        action_filter = action_var.get().casefold()
        status_filter = status_var.get().casefold()

        tree.delete(*tree.get_children())
        visible = 0
        for rule in rules:
            values, tag, iid = extract(rule)
            joined = " ".join(str(v) for v in values).casefold()

            if query and query not in joined:
                continue
            if action_filter != "all actions" and str(values[1]).casefold() != action_filter:
                continue

            if isinstance(rule, dict):
                rule_enabled = self._is_enabled(rule.get("enabled"))
            else:
                rule_enabled = getattr(rule, "enabled", True)

            if status_filter == "enabled" and not rule_enabled:
                continue
            if status_filter == "disabled" and rule_enabled:
                continue

            if iid is None:
                tree.insert("", "end", values=values, tags=(tag,))
            else:
                tree.insert("", "end", iid=iid, values=values, tags=(tag,))
            visible += 1
        return visible

    # ---------------------------------------------------------------- load

    def load_rules(self) -> None:
        self._firewall_rules = list(self.fw.list_rules())
        self.apply_firewall_filters()

    def load_system_rules(self) -> None:
        self._system_rules = list(self.fw.get_system_rules())
        self.apply_system_filters()

    # ----------------------------------------------------------- modes page

    def build_modes_page(self) -> None:
        page = self.pages["modes"]
        page.configure(fg_color=Colors.bg_alt)
        for widget in page.winfo_children():
            widget.destroy()

        ctk.CTkLabel(
            page, text="Security Profiles",
            font=Fonts.title(24), text_color=Colors.text_strong,
        ).pack(anchor="w", padx=22, pady=(22, 2))

        ctk.CTkLabel(
            page,
            text="Choose a profile deliberately. Some profiles can change "
                 "connectivity or firewall policy.",
            font=Fonts.label(11), text_color=Colors.text_muted,
            wraplength=820, justify="left",
        ).pack(anchor="w", padx=22, pady=(0, 10))

        grid = ctk.CTkFrame(page, fg_color="transparent")
        grid.pack(fill="both", expand=True, padx=14, pady=4)
        grid.grid_columnconfigure((0, 1), weight=1)
        grid.grid_rowconfigure((0, 1), weight=1)

        profiles = [
            ("🔐", "Secure Mode",
             "Enable the firewall with a restrictive inbound policy.",
             Colors.primary, self.secure_mode),
            ("🚫", "Lockdown Mode",
             "Block inbound and outbound traffic. Connectivity may be interrupted.",
             Colors.danger, self.lockdown_mode),
            ("🟦", "Default Mode",
             "Restore Windows Firewall defaults. Custom settings may be reset.",
             Colors.primary_hover, self.default_mode),
            ("⚙", "Custom Mode",
             "Apply the rules saved in your CyberOpsSuite custom profile.",
             Colors.neutral, self.custom_mode),
        ]
        for index, (symbol, title, description, color, command) in enumerate(profiles):
            self._make_mode_card(
                grid, index, symbol, title, description, color, command
            )

    def _make_mode_card(
        self,
        parent: ctk.CTkFrame,
        index: int,
        symbol: str,
        title: str,
        description: str,
        color: str,
        command,
    ) -> None:
        card = ctk.CTkFrame(
            parent, fg_color=Colors.surface,
            corner_radius=Spacing.RADIUS_CARD,
            border_width=1, border_color=Colors.border,
        )
        card.grid(row=index // 2, column=index % 2, sticky="nsew", padx=6, pady=6)
        card.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            card, text=symbol, font=Fonts.heading(22),
            text_color=Colors.info_light,
        ).grid(row=0, column=0, sticky="w", padx=14, pady=(12, 0))

        ctk.CTkLabel(
            card, text=title, font=Fonts.heading(15),
            text_color=Colors.text,
        ).grid(row=1, column=0, sticky="w", padx=14, pady=(2, 0))

        ctk.CTkLabel(
            card, text=description, font=Fonts.label(11),
            text_color=Colors.text_muted,
            wraplength=340, justify="left",
        ).grid(row=2, column=0, sticky="w", padx=14, pady=4)

        hover = Colors.danger_hover if color == Colors.danger else Colors.primary_hover
        ctk.CTkButton(
            card, text=f"Apply {title}", command=command,
            height=Spacing.BUTTON_HEIGHT,
            fg_color=color, hover_color=hover,
            corner_radius=Spacing.RADIUS_BUTTON,
        ).grid(row=3, column=0, sticky="ew", padx=14, pady=(4, 12))

    # --------------------------------------------------- network monitor page

    def build_network_monitor_page(self) -> None:
        page = self.pages["network"]
        page.configure(fg_color=Colors.bg_alt)
        for widget in page.winfo_children():
            widget.destroy()

        header = ctk.CTkFrame(page, fg_color="transparent")
        header.pack(fill="x", padx=18, pady=(18, 8))
        
        legend = ctk.CTkFrame(page, fg_color="transparent")
        legend.pack(fill="x", padx=20, pady=(0, 8))
        
        ctk.CTkLabel(
            legend, text="■ TCP", text_color="#3B82F6", font=Fonts.label(10)
        ).pack(side="left", padx=(0, 15))
        
        ctk.CTkLabel(
            legend, text="■ UDP", text_color="#F59E0B", font=Fonts.label(10)
        ).pack(side="left")

        ctk.CTkLabel(
            header, text="Network Monitoring",
            font=Fonts.title(24), text_color=Colors.text_strong,
        ).pack(anchor="w")

        ctk.CTkLabel(
            header,
            text="A local snapshot of TCP/UDP endpoints from Windows netstat.",
            font=Fonts.label(11), text_color=Colors.text_muted,
        ).pack(anchor="w", pady=(2, 8))

        controls = ctk.CTkFrame(
            page, fg_color=Colors.surface,
            corner_radius=Spacing.RADIUS_CARD,
        )
        controls.pack(fill="x", padx=18, pady=(0, 8))

        self.monitor_search_var = tk.StringVar()
        self.monitor_search_entry = ctk.CTkEntry(
            controls, textvariable=self.monitor_search_var,
            placeholder_text="Search address, protocol, state or PID…",
            height=Spacing.INPUT_HEIGHT,
            border_color=Colors.border_light, fg_color=Colors.bg,
        )
        self.monitor_search_entry.pack(side="left", fill="x", expand=True, padx=10, pady=9)
        self.monitor_search_entry.bind(
            "<KeyRelease>", lambda _e: self.apply_network_monitor_filter()
        )

        ctk.CTkButton(
            controls, text="↻ Refresh Snapshot",
            command=self.update_network_monitor,
            fg_color=Colors.primary, hover_color=Colors.primary_hover,
            height=Spacing.INPUT_HEIGHT,
        ).pack(side="left", padx=(0, 10), pady=9)

        table_frame = ctk.CTkFrame(
            page, fg_color=Colors.surface,
            corner_radius=Spacing.RADIUS_CARD,
            border_width=1, border_color=Colors.border,
        )
        table_frame.pack(fill="both", expand=True, padx=18, pady=(0, 8))

        columns = ("proto", "local", "remote", "state", "pid")
        headings = {
            "proto": "Protocol", "local": "Local Address",
            "remote": "Remote Address", "state": "State", "pid": "PID",
        }
        widths = {"proto": 90, "local": 220, "remote": 220, "state": 130, "pid": 80}
        self.monitor_tree = self._build_treeview(
            table_frame, columns, headings, widths
        )
        
        self.monitor_tree.tag_configure(
            "tcp", foreground="#3B82F6", background=Colors.surface
        )
        self.monitor_tree.tag_configure(
            "udp", foreground="#F59E0B", background=Colors.surface_alt
        )

        self.monitor_info = ctk.CTkLabel(
            page, text="No snapshot loaded yet.",
            font=Fonts.label(11), text_color=Colors.text_muted,
        )
        self.monitor_info.pack(anchor="w", padx=20, pady=(0, 8))
        self._network_rows: list[tuple] = []

    def update_network_monitor(self) -> None:
        if not hasattr(self, "monitor_tree"):
            return
        
        import sys
        import platform
        
    
        if platform.system() == "Linux":
            cmd = ["ss", "-tulpn"]
        else:
            cmd = ["netstat", "-ano"]
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True, text=True, shell=False,
                timeout=5, check=False,
                **get_no_window_kwargs()
            )
            
            if result.returncode != 0:
                raise RuntimeError(
                    (result.stderr or f"{cmd[0]} returned a non-zero exit code").strip()
                )

            rows: list[tuple] = []
            for raw_line in result.stdout.splitlines():
                parts = raw_line.split()
                if not parts:
                    continue
                
            
                if platform.system() == "Linux":
                
                    if parts[0] not in ("tcp", "udp"):
                        continue
                    proto = parts[0].upper()
                    local = parts[4] if len(parts) > 4 else "—"
                    remote = parts[5] if len(parts) > 5 else "—"
                    state = parts[1] if len(parts) > 1 else "—"
                
                    pid = "—"
                    for p in parts:
                        if "pid=" in p:
                            try:
                                pid = p.split("pid=")[1].split(",")[0]
                            except Exception:
                                pass
                            break
                    rows.append((proto, local, remote, state, pid))
                else:
                    
                    if parts[0].upper() not in ("TCP", "UDP"):
                        continue
                    proto = parts[0].upper()
                    if proto == "TCP" and len(parts) >= 5:
                        local, remote, state, pid = parts[1], parts[2], parts[3], parts[4]
                    elif proto == "UDP" and len(parts) >= 4:
                        local, remote, pid = parts[1], parts[2], parts[3]
                        state = "—"
                    else:
                        continue
                    rows.append((proto, local, remote, state, pid))

            self._network_rows = rows
            self.apply_network_monitor_filter()
            if hasattr(self, "monitor_info"):
                self.monitor_info.configure(
                    text=f"Snapshot updated • {len(rows)} rows • Source: {'ss' if platform.system() == 'Linux' else 'netstat'}"
                )
        except Exception as exc:
            if hasattr(self, "monitor_info"):
                self.monitor_info.configure(text=f"Network monitor unavailable: {exc}")

    def apply_network_monitor_filter(self) -> None:
        if not hasattr(self, "monitor_tree"):
            return

        query = (
            self.monitor_search_var.get().strip().casefold()
            if hasattr(self, "monitor_search_var") else ""
        )
        self.monitor_tree.delete(*self.monitor_tree.get_children())

        visible = 0
        for row in getattr(self, "_network_rows", []):
            if query and query not in " ".join(str(v) for v in row).casefold():
                continue
            tag = "tcp" if row[0] == "TCP" else "udp"
            self.monitor_tree.insert("", "end", values=row, tags=(tag,))
            visible += 1

        if hasattr(self, "monitor_info"):
            total = len(getattr(self, "_network_rows", []))
            self.monitor_info.configure(
                text=f"Showing {visible} of {total} endpoints • TCP in blue / UDP in orange"
            )

    # --------------------------------------------------------- settings page

    def build_settings(self) -> None:
        page = self.pages["settings"]
        page.configure(fg_color=Colors.bg_alt)
        for widget in page.winfo_children():
            widget.destroy()

        header = ctk.CTkFrame(page, fg_color="transparent")
        header.pack(fill="x", padx=20, pady=(20, 8))

        ctk.CTkLabel(
            header, text="⚙️  Settings",
            font=Fonts.title(24), text_color=Colors.text_strong,
        ).pack(anchor="w")

        ctk.CTkLabel(
            header,
            text="Personalize the interface and maintain your local security workspace.",
            font=Fonts.label(11), text_color=Colors.text_muted,
        ).pack(anchor="w", pady=(4, 0))

        appearance = ctk.CTkFrame(
            page, fg_color=Colors.surface,
            corner_radius=Spacing.RADIUS_CARD,
            border_width=1, border_color=Colors.border,
        )
        appearance.pack(fill="x", padx=20, pady=(10, 12))

        ctk.CTkLabel(
            appearance, text="DISPLAY & APPEARANCE",
            font=Fonts.badge(12), text_color=Colors.info,
        ).pack(anchor="w", padx=18, pady=(16, 4))

        ctk.CTkLabel(
            appearance, text="Appearance mode",
            font=Fonts.label(13, bold=True), text_color=Colors.text,
        ).pack(anchor="w", padx=18, pady=(8, 2))

        ctk.CTkLabel(
            appearance,
            text="Dark Blue mode is enabled for a consistent security-focused interface.",
            font=Fonts.label(11), text_color=Colors.text_muted,
        ).pack(anchor="w", padx=18, pady=(0, 4))

        row = ctk.CTkFrame(appearance, fg_color="transparent")
        row.pack(fill="x", padx=18, pady=(8, 16))
        ctk.CTkLabel(
            row, text="●  DARK BLUE",
            text_color=Colors.info_soft,
            fg_color=Colors.info_bg,
            corner_radius=Spacing.RADIUS_BADGE,
            font=Fonts.badge(11), padx=14, pady=8,
        ).pack(side="left")

        maintenance = ctk.CTkFrame(
            page, fg_color=Colors.surface,
            corner_radius=Spacing.RADIUS_CARD,
            border_width=1, border_color=Colors.border,
        )
        maintenance.pack(fill="x", padx=20, pady=8)

        ctk.CTkLabel(
            maintenance, text="MAINTENANCE",
            font=Fonts.badge(12), text_color=Colors.info,
        ).pack(anchor="w", padx=18, pady=(16, 8))

        actions = ctk.CTkFrame(maintenance, fg_color="transparent")
        actions.pack(fill="x", padx=14, pady=(0, 12))
        actions.grid_columnconfigure((0, 1), weight=1)

        action_specs = [
            ("🔄  Refresh Firewall Status", self.refresh_current_page, Colors.primary),
            ("📂  Open Logs Folder", self.open_logs_folder, Colors.neutral),
            ("📁  Open Exports Folder", self.open_exports_folder, Colors.neutral),
            ("🧹  Clear Application Logs", self.clear_application_logs, Colors.neutral_hover),
        ]
        for index, (label, command, color) in enumerate(action_specs):
            ctk.CTkButton(
                actions, text=label, command=command,
                height=40, fg_color=color, hover_color=Colors.primary_hover,
                corner_radius=Spacing.RADIUS_BUTTON,
                font=Fonts.label(12, bold=True),
            ).grid(row=index // 2, column=index % 2, sticky="ew", padx=5, pady=5)

        warning = ctk.CTkFrame(
            page, fg_color="#2A1D17",
            corner_radius=Spacing.RADIUS_CARD,
            border_width=1, border_color="#7C2D12",
        )
        warning.pack(fill="x", padx=20, pady=(4, 16))

        ctk.CTkLabel(
            warning, text="⚠  ADVANCED ACTION",
            font=Fonts.badge(12), text_color="#FDBA74",
        ).pack(anchor="w", padx=15, pady=(12, 3))

        ctk.CTkLabel(
            warning,
            text="Resetting Windows Firewall can remove custom rules. "
                 "Use only when you intend to restore defaults.",
            text_color="#FED7AA", font=Fonts.label(11),
            wraplength=750, justify="left",
        ).pack(anchor="w", padx=15, pady=(0, 8))

        ctk.CTkButton(
            warning, text="Reset Windows Firewall…",
            command=self.reset_windows_firewall,
            fg_color=Colors.danger, hover_color=Colors.danger_hover,
            height=Spacing.BUTTON_HEIGHT,
        ).pack(anchor="w", padx=15, pady=(0, 12))

    def apply_appearance_setting(self, value=None) -> None:
        ctk.set_appearance_mode("dark")

    # ------------------------------------------------------------ about page

    def build_about_page(self) -> None:
        page = self.pages["about"]
        page.configure(fg_color=Colors.bg)
        for widget in page.winfo_children():
            widget.destroy()

        outer = ctk.CTkScrollableFrame(
            page,
            fg_color=Colors.bg,
            scrollbar_button_color=Colors.surface_alt,
            scrollbar_button_hover_color=Colors.border_light,
        )
        outer.pack(fill="both", expand=True, padx=20, pady=20)
        outer.columnconfigure(0, weight=1)

        hero = ctk.CTkFrame(
            outer, fg_color=Colors.info_bg,
            corner_radius=Spacing.RADIUS_CARD,
            border_width=1, border_color="#1E4970",
        )
        hero.pack(fill="x", pady=(0, 16))

        ctk.CTkLabel(
            hero, text="◈", font=("Segoe UI Symbol", 42, "bold"),
            text_color=Colors.info,
        ).pack(pady=(22, 0))

        ctk.CTkLabel(
            hero, text="CyberOpsSuite",
            font=Fonts.title(28), text_color=Colors.text_strong,
        ).pack(pady=(2, 0))

        ctk.CTkLabel(
            hero, text="FIREWALL MANAGER  •  DARK BLUE EDITION",
            font=Fonts.badge(11), text_color=Colors.info_light,
        ).pack(pady=(4, 8))

        ctk.CTkLabel(
            hero,
            text="A focused workspace for reviewing Windows Firewall rules,\n"
                 "security profiles and current network connections.",
            font=Fonts.label(12), text_color=Colors.text_soft,
            justify="center",
        ).pack(pady=(0, 22))

        os_name = f"{platform.system()} {platform.release()}"
        py_version = platform.python_version()
        cfg_path = config_root_quiet("FirewallManager")

        info_frame = ctk.CTkFrame(
            outer, fg_color=Colors.surface,
            corner_radius=Spacing.RADIUS_CARD,
            border_width=1, border_color=Colors.border,
        )
        info_frame.pack(fill="x", pady=(0, 16))

        info_text = (
            f"Platform:  {os_name}\n"
            f"Python:    {py_version}\n"
            f"Config:    {cfg_path}\n"
            f"Rules:     {PROJECT_ROOT / 'exports' / 'json' / 'firewall_rules.json'}"
        )
        ctk.CTkLabel(
            info_frame, text=info_text,
            font=Fonts.mono(10), text_color=Colors.text_soft,
            justify="left", anchor="w",
        ).pack(fill="x", padx=16, pady=12)

        features = ctk.CTkFrame(
            outer, fg_color=Colors.surface,
            corner_radius=Spacing.RADIUS_CARD,
            border_width=1, border_color=Colors.border,
        )
        features.pack(fill="x", pady=(0, 16))

        ctk.CTkLabel(
            features, text="FEATURES",
            font=Fonts.badge(11), text_color=Colors.success_text,
        ).pack(anchor="w", padx=18, pady=(14, 6))

        feature_text = (
            "• Create, edit, enable/disable and delete saved firewall rules\n"
            "• JSON-backed persistence with atomic write + backups\n"
            "• View every system firewall rule (read-only)\n"
            "• Enable/disable system rules by name (admin required)\n"
            "• Profile modes: Secure, Lockdown, Default, Custom\n"
            "• Local netstat snapshot with search\n"
            "• Live network status (ping, IP, gateway, DNS, latency)\n"
            "• CSV export of visible rules\n"
            "• Reset Windows Firewall to defaults"
        )
        ctk.CTkLabel(
            features, text=feature_text,
            font=Fonts.label(11), text_color=Colors.text,
            justify="left", anchor="w", wraplength=760,
        ).pack(fill="x", padx=18, pady=(0, 14))

        platforms = ctk.CTkFrame(
            outer, fg_color=Colors.surface,
            corner_radius=Spacing.RADIUS_CARD,
            border_width=1, border_color=Colors.border,
        )
        platforms.pack(fill="x", pady=(0, 16))

        ctk.CTkLabel(
            platforms, text="SUPPORTED PLATFORMS",
            font=Fonts.badge(11), text_color=Colors.warning_text,
        ).pack(anchor="w", padx=18, pady=(14, 6))

        platform_text = (
            "• Windows 10 / 11 / Server 2019+\n"
            "  Full support (netsh advfirewall + PowerShell).\n"
            "  System rules can be viewed, enabled/disabled, and removed.\n\n"
            "• Linux (Debian/Ubuntu and similar)\n"
            "  Custom rules and profile modes (Secure/Lockdown) work via ufw/nft.\n"
            "  Root privileges are required for firewall changes (run with sudo).\n"
            "  System rules are read-only (Linux has no named rules).\n"
            "  Network Monitoring uses 'ss' instead of 'netstat'.\n"
            "  IP Rotator, Network Mapper, Server Monitor, and VPN Manager\n"
            "  work on Linux without restrictions.\n\n"
            "• macOS is not supported."
        )
        ctk.CTkLabel(
            platforms, text=platform_text,
            font=Fonts.label(11), text_color=Colors.text,
            justify="left", anchor="w", wraplength=760,
        ).pack(fill="x", padx=18, pady=(0, 14))

        shortcuts = ctk.CTkFrame(
            outer, fg_color=Colors.surface,
            corner_radius=Spacing.RADIUS_CARD,
            border_width=1, border_color=Colors.border,
        )
        shortcuts.pack(fill="x", pady=(0, 16))

        ctk.CTkLabel(
            shortcuts, text="⌨  KEYBOARD SHORTCUTS",
            font=Fonts.badge(11), text_color=Colors.info,
        ).pack(anchor="w", padx=18, pady=(14, 6))

        shortcut_rows = [
            ("F1", "Open the About page"),
            ("F5", "Refresh the current page"),
            ("Esc", "Clear search or close a child window"),
            ("Delete", "Request deletion of the selected saved firewall rule"),
        ]
        for key, description in shortcut_rows:
            row = ctk.CTkFrame(shortcuts, fg_color="transparent")
            row.pack(fill="x", padx=16, pady=2)
            ctk.CTkLabel(
                row, text=key, width=105, anchor="w",
                font=Fonts.mono(12, bold=True), text_color=Colors.info_pale,
            ).pack(side="left")
            ctk.CTkLabel(
                row, text=description, anchor="w",
                font=Fonts.label(11), text_color=Colors.text_soft,
            ).pack(side="left", fill="x", expand=True)

        ctk.CTkLabel(
            shortcuts,
            text="Shortcuts are available when the main window is focused.",
            font=Fonts.label(10), text_color=Colors.text_dim,
        ).pack(anchor="w", padx=18, pady=(6, 14))

        warning = ctk.CTkFrame(
            outer, fg_color="#2A1D17",
            corner_radius=Spacing.RADIUS_CARD,
            border_width=1, border_color="#7C2D12",
        )
        warning.pack(fill="x", pady=(0, 16))

        ctk.CTkLabel(
            warning, text="⚠  RESPONSIBLE USE",
            font=Fonts.badge(11), text_color="#FDBA74",
        ).pack(anchor="w", padx=18, pady=(14, 4))

        ctk.CTkLabel(
            warning,
            text=(
                "Changing firewall rules can interrupt network access. "
                "Use this tool only on systems you own or have explicit "
                "permission to administer."
            ),
            wraplength=760, justify="left",
            text_color="#FED7AA", font=Fonts.label(11), anchor="w",
        ).pack(fill="x", padx=18, pady=(0, 14))

        ctk.CTkLabel(
            outer,
            text="CyberOpsSuite  •  Windows Firewall tools",
            font=Fonts.label(10), text_color=Colors.text_dim,
        ).pack(pady=(0, 14))

    # ------------------------------------------------------- page help

    def _show_page_help(self):
        """Show help for the current page."""
        page_data = HELP_TEXTS.get(self.current_page, {
            "title": "Help",
            "content": "No help available for this page."
        })
        
        dialog = ctk.CTkToplevel(self)
        dialog.title(f"Help | {page_data['title']}")
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
            outer, text=page_data["title"],
            font=Fonts.title(24), text_color=Colors.text_strong,
        ).pack(anchor="w", padx=28, pady=(6, 2))

        ctk.CTkFrame(outer, height=1, fg_color=Colors.border).pack(
            fill="x", padx=28, pady=16
        )

        ctk.CTkLabel(
            outer, text=page_data["content"],
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
        dialog.update_idletasks()
        x = self.winfo_rootx() + (self.winfo_width() - dialog.winfo_width()) // 2
        y = self.winfo_rooty() + (self.winfo_height() - dialog.winfo_height()) // 2
        dialog.geometry(f"+{max(0, x)}+{max(0, y)}")

    # ----------------------------------------------------------- profiles

    def secure_mode(self) -> None:
        self.mode_label.configure(text="Mode: Secure")
        self.fw.secure_mode()
        self.update_dashboard(self.fw.quick_scan())
        self.update_network_status()
        messagebox.showinfo("Secure Mode", "Firewall is now in Secure Mode.", parent=self)

    def lockdown_mode(self) -> None:
        if not messagebox.askyesno(
            "Confirm Lockdown Mode",
            "Lockdown may block network access and interrupt active connections.\n\n"
            "Apply this profile?",
            icon="warning", parent=self,
        ):
            return
        self.mode_label.configure(text="Mode: Lockdown")
        self.fw.lockdown_mode()
        self.update_dashboard(self.fw.quick_scan())
        self.update_network_status()
        self.load_rules()
        self.load_system_rules()
        messagebox.showwarning("Lockdown Mode", "Internet access is now blocked.", parent=self)

    def default_mode(self) -> None:
        if not messagebox.askyesno(
            "Confirm Default Mode",
            "This profile resets Windows Firewall settings to defaults and may "
            "change custom rules.\n\nContinue?",
            icon="warning", parent=self,
        ):
            return
        self.mode_label.configure(text="Mode: Default")
        self.fw.reset_firewall()
        self.update_dashboard(self.fw.quick_scan())
        self.update_network_status()
        messagebox.showinfo("Default Mode", "Firewall reset to default settings.", parent=self)

    def custom_mode(self) -> None:
        try:
            rules = getattr(self.fw, "rules", [])
            if not rules:
                messagebox.showwarning(
                    "Custom Mode — No Rules",
                    "Your custom profile is empty, so there is nothing to apply.\n\n"
                    "Add and save at least one rule in Firewall Rules, then try again.",
                    parent=self,
                )
                return

            result = self.fw.custom_mode()
            self.update_dashboard(self.fw.quick_scan())
            self.update_network_status()
            self.mode_label.configure(text="Mode: Custom")

            applied = result.get("applied", 0) if isinstance(result, dict) else len(rules)
            disabled = result.get("disabled", 0) if isinstance(result, dict) else 0
            messagebox.showinfo(
                "Custom Mode Applied",
                f"Custom profile processed successfully.\n\n"
                f"Applied/enabled: {applied}\nDisabled: {disabled}",
                parent=self,
            )
        except Exception as exc:
            messagebox.showerror(
                "Custom Mode Failed",
                "The custom profile could not be applied.\n\n"
                f"{exc}\n\n"
                "Check that the saved rules are valid and run the app as Administrator.",
                parent=self,
            )

    # ------------------------------------------------------ selection helpers

    def get_selected_rule(self) -> tuple | None:
        selected = self.tree.focus()
        if not selected:
            return None
        return selected, self.tree.item(selected)["values"]

    def get_selected_system_rule(self) -> tuple | None:
        selected = self.system_tree.focus()
        if not selected:
            return None
        return self.system_tree.item(selected)["values"]

    # -------------------------------------------------------- add rule dialog

    def open_add_rule_window(self) -> None:
        win = ctk.CTkToplevel(self)
        win.title("Add Firewall Rule | CyberOpsSuite")
        win.geometry("560x680")
        win.resizable(False, False)
        win.configure(fg_color=Colors.bg)
        win.transient(self)
        win.grab_set()

        apply_window_icon(win)

        self._build_rule_dialog_header(win)
        form = self._build_rule_dialog_form(win)
        self._build_rule_dialog_footer(win, form)

        form["ip_entry"].focus_set()

    def _build_rule_dialog_header(self, win: ctk.CTkToplevel) -> None:
        header = ctk.CTkFrame(win, fg_color=Colors.surface, corner_radius=0)
        header.pack(fill="x")

        ctk.CTkLabel(
            header, text="＋", font=Fonts.title(28),
            text_color=Colors.info_soft,
        ).pack(anchor="w", padx=26, pady=(18, 0))

        ctk.CTkLabel(
            header, text="Create Firewall Rule",
            font=Fonts.title(22), text_color=Colors.text_strong,
        ).pack(anchor="w", padx=26, pady=(0, 4))

        ctk.CTkLabel(
            header, text="Define the traffic you want to allow or block.",
            font=Fonts.label(11), text_color=Colors.text_muted,
        ).pack(anchor="w", padx=27, pady=(0, 20))

    def _build_rule_dialog_form(self, win: ctk.CTkToplevel) -> dict:
        form = ctk.CTkFrame(
            win, fg_color=Colors.surface,
            corner_radius=Spacing.RADIUS_CARD,
            border_width=1, border_color=Colors.border,
        )
        form.pack(fill="both", expand=True, padx=22, pady=18)
        form.grid_columnconfigure((0, 1), weight=1, uniform="fields")

        entry_style = {
            "height": Spacing.INPUT_HEIGHT,
            "corner_radius": Spacing.RADIUS_INPUT,
            "fg_color": Colors.bg,
            "border_color": Colors.border_light,
            "text_color": Colors.text,
        }

        self._form_label(form, "IP ADDRESS", 0, colspan=2)
        ip_entry = ctk.CTkEntry(form, placeholder_text="e.g. 192.168.1.10", **entry_style)
        ip_entry.grid(row=1, column=0, columnspan=2, sticky="ew", padx=18)

        self._form_label(form, "PORT", 2, column=0)
        self._form_label(form, "PROTOCOL", 2, column=1)

        port_entry = ctk.CTkEntry(form, placeholder_text="1–65535", **entry_style)
        port_entry.grid(row=3, column=0, sticky="ew", padx=(18, 7))

        protocol = ctk.CTkOptionMenu(
            form, values=["tcp", "udp"],
            height=Spacing.INPUT_HEIGHT,
            corner_radius=Spacing.RADIUS_INPUT,
            fg_color=Colors.primary, button_color=Colors.primary_hover,
            button_hover_color=Colors.primary_active,
            dropdown_fg_color=Colors.surface,
            dropdown_hover_color=Colors.primary,
            text_color="#FFFFFF",
        )
        protocol.set("tcp")
        protocol.grid(row=3, column=1, sticky="ew", padx=(7, 18))

        self._form_label(form, "TRAFFIC DIRECTION", 4, colspan=2)
        direction = ctk.CTkSegmentedButton(
            form, values=["inbound", "outbound"],
            height=Spacing.BUTTON_HEIGHT,
            selected_color=Colors.primary, selected_hover_color=Colors.primary_active,
            unselected_color=Colors.surface_alt, unselected_hover_color=Colors.border_light,
            text_color=Colors.text_soft,
        )
        direction.set("inbound")
        direction.grid(row=5, column=0, columnspan=2, sticky="ew", padx=18)

        self._form_label(form, "RULE ACTION", 6, colspan=2)
        action_row = ctk.CTkFrame(form, fg_color="transparent")
        action_row.grid(row=7, column=0, columnspan=2, sticky="ew", padx=18)
        action_row.grid_columnconfigure((0, 1), weight=1, uniform="actions")

        action = ctk.CTkSegmentedButton(
            action_row, values=["allow", "block"],
            height=Spacing.BUTTON_HEIGHT,
            selected_color=Colors.success, selected_hover_color=Colors.success_hover,
            unselected_color=Colors.surface_alt, unselected_hover_color=Colors.border_light,
            text_color=Colors.text_soft,
        )
        action.set("block")
        action.grid(row=0, column=0, sticky="ew")

        ctk.CTkLabel(
            form,
            text="Tip: double-check the IP, port and direction before saving.",
            font=Fonts.label(11), text_color=Colors.text_muted, anchor="w",
        ).grid(row=8, column=0, columnspan=2, sticky="ew", padx=18, pady=(15, 12))

        return {
            "ip_entry": ip_entry,
            "port_entry": port_entry,
            "protocol": protocol,
            "direction": direction,
            "action": action,
            "form": form,
        }

    def _form_label(
        self,
        parent: ctk.CTkFrame,
        text: str,
        row: int,
        column: int = 0,
        colspan: int = 1,
    ) -> None:
        ctk.CTkLabel(
            parent, text=text,
            font=Fonts.label(12, bold=True),
            text_color=Colors.text_soft, anchor="w",
        ).grid(row=row, column=column, columnspan=colspan,
               sticky="ew", padx=18, pady=(13, 5))

    def _build_rule_dialog_footer(self, win: ctk.CTkToplevel, form: dict) -> None:
        footer = ctk.CTkFrame(win, fg_color="transparent")
        footer.pack(fill="x", padx=22, pady=(0, 18))

        ctk.CTkButton(
            footer, text="Cancel", width=120,
            height=Spacing.BUTTON_HEIGHT,
            fg_color=Colors.surface_alt, hover_color=Colors.border_light,
            border_width=1, border_color=Colors.border_light,
            command=win.destroy,
        ).pack(side="right", padx=(8, 0))

        save = ctk.CTkButton(
            footer, text="✓  Save Rule", width=160,
            height=Spacing.BUTTON_HEIGHT,
            font=Fonts.label(13, bold=True),
            fg_color=Colors.primary, hover_color=Colors.primary_hover,
            command=lambda: self.save_rule(win, form),
        )
        save.pack(side="right")

        for key in ("ip_entry", "port_entry"):
            form[key].bind("<Return>", lambda _e: self.save_rule(win, form))

    def save_rule(self, win: ctk.CTkToplevel, form: dict) -> None:
        ip = form["ip_entry"].get().strip()
        port_text = form["port_entry"].get().strip()
        protocol = form["protocol"].get()
        action = form["action"].get()
        direction = form["direction"].get()

        if not ip:
            messagebox.showerror("Error", "IP cannot be empty.", parent=self)
            return

        if ip.casefold() != "any":
            import ipaddress
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                messagebox.showerror(
                    "Invalid IP",
                    "Enter a valid IPv4/IPv6 address, or use 'Any'.",
                    parent=self,
                )
                return

        if not port_text.isdigit():
            messagebox.showerror("Error", "Port must be a number.", parent=self)
            return

        port = int(port_text)
        if not 1 <= port <= 65535:
            messagebox.showerror("Error", "Port must be between 1 and 65535.", parent=self)
            return

        try:
            rule = self.fw.add_rule(action, ip, port, protocol, direction)
        except Exception as exc:
            self.log_application_event(f"Add firewall rule failed: {exc}")
            messagebox.showerror(
                "Rule Not Added",
                f"Windows Firewall rejected the rule or the operation failed.\n\n{exc}",
                parent=self,
            )
            return

        messagebox.showinfo("Success", f"Rule {rule.rule_id} added.", parent=self)
        self.load_rules()
        try:
            self.update_dashboard(self.fw.quick_scan())
            self.update_network_status()
        except Exception as exc:
            self.log_application_event(f"Post-add refresh failed: {exc}")
        win.destroy()

    # ------------------------------------------------------- rule operations

    def remove_rule(self) -> None:
        selected = self.get_selected_rule()
        if not selected:
            messagebox.showerror("Error", "No rule selected.", parent=self)
            return

        rule_id, _ = selected
        if not messagebox.askyesno(
            "Confirm Delete",
            f"Are you sure you want to delete rule {rule_id}?",
            parent=self,
        ):
            return

        try:
            self.fw.remove_rule(int(rule_id))
        except Exception as exc:
            messagebox.showerror("Remove failed", str(exc), parent=self)
            return

        messagebox.showinfo("Removed", f"Rule {rule_id} removed.", parent=self)
        self._refresh_after_mutation()

    def _toggle_rule(self, enable: bool) -> None:
        selected = self.get_selected_rule()
        if not selected:
            messagebox.showerror("Error", "No rule selected.", parent=self)
            return

        rule_id, _ = selected
        action = "enable" if enable else "disable"
        try:
            getattr(self.fw, f"{action}_rule")(int(rule_id))
        except Exception as exc:
            messagebox.showerror(
                f"{action.capitalize()} failed", str(exc), parent=self
            )
            return

        messagebox.showinfo(
            "Enabled" if enable else "Disabled",
            f"Rule {rule_id} {'enabled' if enable else 'disabled'}.",
            parent=self,
        )
        self._refresh_after_mutation()

    def enable_rule(self) -> None:
        self._toggle_rule(True)

    def disable_rule(self) -> None:
        self._toggle_rule(False)

    def apply_json_to_system(self) -> None:
        if not messagebox.askyesno(
            "Apply JSON",
            "Apply all JSON rules to system firewall?",
            parent=self,
        ):
            return

        try:
            self.fw.apply_all_json_rules()
        except Exception as exc:
            messagebox.showerror("Apply failed", str(exc), parent=self)
            return

        messagebox.showinfo(
            "Applied", "All JSON rules applied to system firewall.", parent=self
        )
        self._refresh_after_mutation()

    # ------------------------------------------------- system rule operations

    def _toggle_system_rule(self, enable: bool) -> None:
        rule = self.get_selected_system_rule()
        if not rule:
            messagebox.showerror("Error", "No system rule selected.", parent=self)
            return

        name = rule[0]
        action = "enable" if enable else "disable"
        try:
            getattr(self.fw, f"{action}_system_rule")(name)
        except Exception as exc:
            messagebox.showerror(
                f"{action.capitalize()} failed", str(exc), parent=self
            )
            return

        messagebox.showinfo(
            "Enabled" if enable else "Disabled",
            f"System rule '{name}' {'enabled' if enable else 'disabled'}.",
            parent=self,
        )
        
        self.load_system_rules()
        self.update_dashboard(self.fw.quick_scan())

    def enable_selected_system_rule(self) -> None:
        self._toggle_system_rule(True)

    def disable_selected_system_rule(self) -> None:
        self._toggle_system_rule(False)

    def remove_selected_system_rule(self) -> None:
        rule = self.get_selected_system_rule()
        if not rule:
            messagebox.showerror("Error", "No system rule selected.", parent=self)
            return

        name = rule[0]
        if not messagebox.askyesno(
            "Confirm Delete",
            f"Delete system rule '{name}'?",
            parent=self,
        ):
            return

        try:
            self.fw.delete_system_rule(name)
        except Exception as exc:
            messagebox.showerror("Delete failed", str(exc), parent=self)
            return

        messagebox.showinfo("Removed", f"System rule '{name}' removed.", parent=self)
        self._refresh_after_mutation()

    def _refresh_after_mutation(self) -> None:
        self.load_rules()
        try:
            self.update_dashboard(self.fw.quick_scan())
        except Exception as exc:
            self.log_application_event(f"Post-mutation dashboard refresh failed: {exc}")
        self.update_network_status()

    # ------------------------------------------------------- network status

    def update_network_status(self) -> None:
        from concurrent.futures import ThreadPoolExecutor

        with ThreadPoolExecutor(max_workers=4) as pool:
            ping_future = pool.submit(self._query_ping)
            ip_future = pool.submit(self._query_ip)
            gw_future = pool.submit(self._query_gateway)
            dns_future = pool.submit(self._query_dns)

        online, latency = ping_future.result()
        ip = ip_future.result()
        gateway = gw_future.result()
        dns_server = dns_future.result()

        self.net_status.configure(text=f"Internet: {online}")
        self.net_ip.configure(text=f"IP: {ip}")
        self.net_gateway.configure(text=f"Gateway: {gateway}")
        self.net_dns.configure(text=f"DNS: {dns_server}")
        self.net_latency.configure(text=f"Latency: {latency}")

    def _query_ping(self) -> tuple[str, str]:
        try:
            if os.name == "nt":
                cmd = ["ping", "-n", "1", "8.8.8.8"]
            else:
                cmd = ["ping", "-c", "1", "-W", "1", "8.8.8.8"]

            result = subprocess.run(
                cmd,
                capture_output=True, text=True, timeout=4,
                **get_no_window_kwargs()
            )
            out = result.stdout

            if "TTL=" in out or "ttl=" in out:
                status = "🟢 Online"
            else:
                status = "🔴 Offline"

            latency = "Unknown"
            for line in out.splitlines():
                if "time=" in line:
                    latency = line.split("time=")[-1].strip()
                    break
            return status, latency
        except Exception:
            return "⚪ Unknown", "Unknown"

    def _query_ip(self) -> str:
        try:
            ipconfig = subprocess.run(
                ["ipconfig"], capture_output=True, text=True, timeout=4,
                **get_no_window_kwargs()
            ).stdout
            line = next((l for l in ipconfig.splitlines() if "IPv4" in l), None)
            return line.split(":")[-1].strip() if line else "Unknown"
        except Exception:
            return "Unknown"

    def _query_gateway(self) -> str:
        try:
            route = subprocess.run(
                ["route", "print"], capture_output=True, text=True, timeout=4,
                **get_no_window_kwargs()
            ).stdout
            line = next(
                (l for l in route.splitlines() if l.strip().startswith("0.0.0.0")),
                None,
            )
            return line.split()[2] if line else "Unknown"
        except Exception:
            return "Unknown"

    def _query_dns(self) -> str:
        try:
            dns = subprocess.run(
                ["nslookup", "8.8.8.8"], capture_output=True, text=True, timeout=4,
                **get_no_window_kwargs()
            ).stdout
            line = next((l for l in dns.splitlines() if "Address:" in l), None)
            return line.split(":")[-1].strip() if line else "Unknown"
        except Exception:
            return "Unknown"

    def _on_rule_double_click(self, event):
        item = self.tree.focus()
        if not item:
            return
        
        values = self.tree.item(item)["values"]
        if not values:
            return
            
        details = (
            f"Rule ID:   {values[0]}\n"
            f"Action:    {values[1]}\n"
            f"IP:        {values[2]}\n"
            f"Port:      {values[3]}\n"
            f"Protocol:  {values[4]}\n"
            f"Direction: {values[5]}\n"
            f"Status:    {values[6]}"
        )
        messagebox.showinfo("Rule Details", details, parent=self)

    def _on_system_rule_double_click(self, event):
        item = self.system_tree.focus()
        if not item:
            return
        
        values = self.system_tree.item(item)["values"]
        if not values:
            return
            
        details = (
            f"Rule Name: {values[0]}\n"
            f"Action:    {values[1]}\n"
            f"Port:      {values[2]}\n"
            f"Protocol:  {values[3]}\n"
            f"Direction: {values[4]}\n"
            f"Status:    {values[5]}"
        )
        messagebox.showinfo("System Rule Details", details, parent=self)

# ------------------------------------------------------------------ entry

def main() -> None:
    app = FirewallGUI()
    app.mainloop()


if __name__ == "__main__":
    main()