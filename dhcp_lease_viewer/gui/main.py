"""CyberOpsSuite DHCP Lease Viewer."""

from __future__ import annotations

import csv
import logging
import os
import platform
import queue
import sys
import threading
import tkinter as tk
from datetime import datetime, timedelta
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

import customtkinter as ctk

# Set up logging BEFORE importing modules that use it
APP_NAME = "DHCP Lease Viewer"
APP_VERSION = "1.7.1"
APP_SUITE = "CyberOpsSuite"

log_dir = Path(os.getenv("LOCALAPPDATA", Path.home() / ".config")) / "DHCPLeaseViewer"
log_dir.mkdir(parents=True, exist_ok=True)
logging.basicConfig(
    filename=log_dir / "app.log",
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logging.info(f"--- Starting {APP_NAME} v{APP_VERSION} ---")

# Always resolve imports from the project root.
PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from dhcp_lease_viewer.core.dhcp_reader import (
    get_network_diagnostics,
    get_remote_diagnostics,
    read_dhcp_leases,
)
from dhcp_lease_viewer.gui.remote_view import RemoteView

from core.theme import Colors, Fonts, Spacing
from core.gui.treeview_style import apply_treeview_style
from core.utils.icons import apply_window_icon
from core.utils.paths import config_root_quiet


# Dictionary of page-specific help texts
HELP_TEXTS = {
    "leases": {
        "title": "DHCP Leases",
        "content": (
            "This page shows the DHCP leases of THIS computer.\n\n"
            "•  IP Address: The assigned IP.\n"
            "•  MAC Address: Physical address.\n"
            "•  Hostname: Name of the device.\n"
            "•  Start Time / End Time: When the lease started and expires.\n"
            "•  Remaining: Time left before expiration.\n"
            "•  Status: Active, Expiring soon, or Expired.\n\n"
            "Use the search bar and status filter to find specific leases.\n"
            "You can click 'Export CSV' to save the visible data."
        )
    },
    "remote": {
        "title": "Remote Server",
        "content": (
            "Here you can query a remote DHCP server (Windows via WinRM, or Linux via SSH).\n\n"
            "1️⃣  Server: Enter the hostname or IP of the remote DHCP server.\n"
            "2️⃣  Backend: Choose Auto, Windows, or Linux.\n"
            "3️⃣  Credentials: If needed, enable 'Use username / password' and enter credentials.\n"
            "4️⃣  SSH Key: For Linux, you can provide the path to a private key.\n"
            "5️⃣  Show inactive: Check to include expired or deleted leases.\n"
            "6️⃣  Connect: Click 'Connect' to fetch the leases.\n\n"
            "Note: This is read-only. No changes are made to the remote server."
        )
    },
    "diagnostics": {
        "title": "Network Diagnostics",
        "content": (
            "This page shows network details for this computer or a remote server.\n\n"
            "•  System: Hostname and OS.\n"
            "•  IP Addresses: Local IPs.\n"
            "•  Default Gateway: The router.\n"
            "•  DNS Servers: Name resolution servers.\n\n"
            "Use the 'Target' toggle to switch between Local and Remote.\n"
            "Click the 📋 icon next to any value to copy it to the clipboard."
        )
    }
}


class DHCPLeaseViewer(ctk.CTk):
    """Main application window for the DHCP Lease Viewer."""

    REFRESH_INTERVAL_MS = 10_000

    def __init__(self) -> None:
        super().__init__()

        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("dark-blue")

        self.title(f"{APP_SUITE} | {APP_NAME}")
        self.geometry("1240x740")
        self.minsize(900, 560)
        self.configure(fg_color=Colors.bg_alt)

        apply_window_icon(self)
        apply_treeview_style(self)

        self.current_page = "leases"
        self.leases: list = []
        self.search_var = tk.StringVar()
        self.status_var = tk.StringVar(value="All statuses")
        self.auto_refresh_var = ctk.BooleanVar(value=False)
        self._auto_refresh_job: str | None = None

        self._results: queue.Queue = queue.Queue()
        self._poll_after_id: str | None = None

        self._build_ui()
        self.load_data()

        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self.bind("<F5>", lambda _event: self.load_data())
        self.bind("<Control-e>", lambda _event: self.export_csv())

        self._poll_after_id = self.after(100, self._poll_results)

    # ------------------------------------------------------------------ UI

    def _build_ui(self) -> None:
        self.columnconfigure(1, weight=1)
        self.rowconfigure(0, weight=1)

        self._build_sidebar()

        self.content = ctk.CTkFrame(self, fg_color="transparent")
        self.content.grid(row=0, column=1, sticky="nsew", padx=22, pady=20)
        self.content.columnconfigure(0, weight=1)
        self.content.rowconfigure(2, weight=1)

        self._build_page_header()
        self._build_toolbar()
        self._build_table()

        self.remote_view = RemoteView(
            self.content, on_status=self._on_remote_status,
        )
        self.remote_view.grid(
            row=1, column=0, rowspan=2, sticky="nsew",
        )
        self.remote_view.grid_remove()

    def _build_sidebar(self) -> None:
        sidebar = ctk.CTkFrame(
            self, width=205, corner_radius=0, fg_color=Colors.bg,
        )
        sidebar.grid(row=0, column=0, sticky="ns")
        sidebar.grid_propagate(False)
        sidebar.columnconfigure(0, weight=1)

        brand = ctk.CTkFrame(sidebar, fg_color="transparent")
        brand.grid(row=0, column=0, sticky="ew", padx=14, pady=(20, 26))
        ctk.CTkLabel(
            brand, text="●", text_color=Colors.info,
            font=Fonts.label(18, bold=True),
        ).grid(row=0, column=0, sticky="w", padx=(0, 7))
        ctk.CTkLabel(
            brand, text="CyberOpsSuite",
            font=Fonts.label(13, bold=True), text_color="#FFFFFF",
        ).grid(row=0, column=1, sticky="w")

        ctk.CTkLabel(
            sidebar, text="NETWORK OPERATIONS",
            font=Fonts.label(10), text_color="#D6E4F5",
        ).grid(row=1, column=0, sticky="w", padx=14, pady=(0, 8))

        nav_specs = [
            ("  DHCP Leases", self._show_leases),
            ("  Remote Server", self._show_remote),
            ("  Network Diagnostics", self._show_diagnostics),
            ("  About", self._show_about),
        ]
        for index, (label, command) in enumerate(nav_specs, start=2):
            ctk.CTkButton(
                sidebar, text=label, command=command,
                height=Spacing.BUTTON_HEIGHT,
                fg_color=Colors.surface_alt,
                hover_color=Colors.primary,
                text_color="#E6EEF9",
                font=Fonts.label(11),
                anchor="w",
            ).grid(row=index, column=0, sticky="ew", padx=8, pady=3)

        sidebar.rowconfigure(6, weight=1)

        ctk.CTkLabel(
            sidebar, text="CyberOpsSuite\nNetwork Operations Tools",
            font=Fonts.label(10), text_color="#D6E4F5",
            justify="left",
        ).grid(row=7, column=0, sticky="w", padx=14, pady=(12, 20))

    def _build_page_header(self) -> None:
        self.page_header = ctk.CTkFrame(self.content, fg_color="transparent")
        self.page_header.grid(row=0, column=0, sticky="ew", pady=(0, 15))
        self.page_header.columnconfigure(0, weight=1)

        self.page_title = ctk.CTkLabel(
            self.page_header, text=APP_NAME,
            font=Fonts.title(22), text_color="#F1F5F9",
        )
        self.page_title.grid(row=0, column=0, sticky="w")

        self.page_subtitle = ctk.CTkLabel(
            self.page_header, text="View and filter DHCP lease assignments",
            font=Fonts.label(10), text_color=Colors.text_muted,
        )
        self.page_subtitle.grid(row=1, column=0, sticky="w", pady=(4, 0))

        # Help button - will update text based on current page
        self.help_btn = ctk.CTkButton(
            self.page_header, text="❓ Help", width=100, height=34,
            corner_radius=Spacing.RADIUS_BUTTON,
            fg_color=Colors.info_bg, hover_color=Colors.info,
            text_color=Colors.info_light, font=Fonts.label(11, bold=True),
            command=self._show_page_help,
        )
        self.help_btn.grid(row=0, column=1, sticky="e", padx=(10, 0))

        self.connection_label = ctk.CTkLabel(
            self.page_header, text="● LOCAL DHCP LEASES",
            font=Fonts.label(10), text_color=Colors.text_muted,
        )
        self.connection_label.grid(row=0, column=2, sticky="e", padx=(10, 0))

    def _update_help_button(self) -> None:
        """Update the Help button text based on the current page."""
        if self.current_page == "about":
            # Hide the Help button on the About page
            self.help_btn.grid_remove()
        else:
            page_title = HELP_TEXTS.get(self.current_page, {}).get("title", "this page")
            self.help_btn.configure(text=f"❓ Help: {page_title}")
            # Show the Help button again if it was hidden
            self.help_btn.grid(row=0, column=1, sticky="e", padx=(10, 0))

    def _build_toolbar(self) -> None:
        self.toolbar = ctk.CTkFrame(
            self.content, fg_color=Colors.surface,
            corner_radius=Spacing.RADIUS_CARD,
        )
        self.toolbar.grid(row=1, column=0, sticky="ew", pady=(0, 12))
        self.toolbar.columnconfigure(1, weight=1)

        ctk.CTkButton(
            self.toolbar, text="↻  Refresh (F5)",
            width=140, height=Spacing.BUTTON_HEIGHT,
            fg_color=Colors.primary, hover_color=Colors.primary_hover,
            font=Fonts.label(11, bold=True),
            command=self.load_data,
        ).grid(row=0, column=0, padx=(12, 10), pady=12)

        self.search_entry = ctk.CTkEntry(
            self.toolbar, textvariable=self.search_var,
            placeholder_text="Search IP, MAC, hostname, DHCP server, adapter…",
            height=Spacing.INPUT_HEIGHT,
            fg_color=Colors.bg, text_color=Colors.text,
            border_color=Colors.border_light,
            font=Fonts.label(11),
        )
        self.search_entry.grid(row=0, column=1, sticky="ew", padx=(0, 10), pady=12)
        self.search_var.trace_add("write", lambda *_: self._render_rows())

        ctk.CTkButton(
            self.toolbar, text="Clear",
            width=80, height=Spacing.BUTTON_HEIGHT,
            fg_color=Colors.neutral_dark,
            hover_color=Colors.neutral_dark_hover,
            font=Fonts.label(10),
            command=lambda: self.search_var.set(""),
        ).grid(row=0, column=2, padx=(0, 10), pady=12)

        self.status_filter = ctk.CTkOptionMenu(
            self.toolbar,
            variable=self.status_var,
            values=["All statuses", "Active", "Expiring soon", "Expired"],
            width=160, height=Spacing.INPUT_HEIGHT,
            fg_color=Colors.primary, button_color=Colors.primary_hover,
            button_hover_color=Colors.primary_active,
            dropdown_fg_color=Colors.surface,
            dropdown_hover_color=Colors.primary,
            font=Fonts.label(10),
            command=lambda _v: self._render_rows(),
        )
        self.status_filter.grid(row=0, column=3, padx=(0, 10), pady=12)

        ctk.CTkButton(
            self.toolbar, text="Export CSV",
            width=120, height=Spacing.BUTTON_HEIGHT,
            fg_color=Colors.neutral_dark,
            hover_color=Colors.neutral_dark_hover,
            font=Fonts.label(11),
            command=self.export_csv,
        ).grid(row=0, column=4, padx=(0, 10), pady=12)

        ctk.CTkCheckBox(
            self.toolbar, text="Auto-refresh",
            variable=self.auto_refresh_var,
            command=self._toggle_auto_refresh,
            font=Fonts.label(10), text_color=Colors.text,
            fg_color=Colors.primary, hover_color=Colors.primary_hover,
            border_color=Colors.border_light,
        ).grid(row=0, column=5, padx=(0, 12), pady=12)

    def _build_table(self) -> None:
        self.table_card = ctk.CTkFrame(
            self.content, fg_color=Colors.surface,
            corner_radius=Spacing.RADIUS_CARD,
        )
        self.table_card.grid(row=2, column=0, sticky="nsew")
        self.table_card.rowconfigure(1, weight=1)
        self.table_card.columnconfigure(0, weight=1)

        ctk.CTkLabel(
            self.table_card, text="Lease assignments",
            font=Fonts.label(11, bold=True), text_color="#E6EEF9",
        ).grid(row=0, column=0, sticky="w", padx=12, pady=(12, 9))

        table_frame = ctk.CTkFrame(self.table_card, fg_color="transparent")
        table_frame.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 10))
        table_frame.rowconfigure(0, weight=1)
        table_frame.columnconfigure(0, weight=1)

        self.columns = ("ip", "mac", "hostname", "start", "end", "remaining", "status")
        self.tree = ttk.Treeview(
            table_frame, columns=self.columns, show="headings",
            selectmode="browse", style="Cyber.Treeview",
        )
        headings = {
            "ip": "IP Address", "mac": "MAC Address", "hostname": "Hostname",
            "start": "Start Time", "end": "End Time", "remaining": "Remaining",
            "status": "Status",
        }
        widths = {
            "ip": 125, "mac": 165, "hostname": 135, "start": 155,
            "end": 155, "remaining": 110, "status": 120,
        }
        for col in self.columns:
            self.tree.heading(col, text=headings[col])
            self.tree.column(
                col, width=widths[col], minwidth=80,
                anchor="w", stretch=(col == "hostname"),
            )

        yscroll = ttk.Scrollbar(
            table_frame, orient="vertical", style="Vertical.TScrollbar",
            command=self.tree.yview,
        )
        self.tree.configure(yscrollcommand=yscroll.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        yscroll.grid(row=0, column=1, sticky="ns")

        self.tree.bind("<MouseWheel>", self._on_mousewheel)
        self.tree.bind("<Button-4>", lambda event: self._on_mousewheel_linux(event, -1))
        self.tree.bind("<Button-5>", lambda event: self._on_mousewheel_linux(event, 1))

        self.tree.tag_configure("active", foreground=Colors.success_text)
        self.tree.tag_configure("expiring", foreground=Colors.warning_text)
        self.tree.tag_configure("expired", foreground=Colors.danger_text)

        self.tree.bind("<Double-1>", self._show_details)

        footer = ctk.CTkFrame(self.table_card, fg_color="transparent")
        footer.grid(row=2, column=0, sticky="ew", padx=12, pady=(10, 12))
        footer.columnconfigure(0, weight=1)

        self.summary_var = tk.StringVar(value="Loading leases…")
        ctk.CTkLabel(
            footer, textvariable=self.summary_var,
            font=Fonts.label(10), text_color=Colors.text_muted,
        ).grid(row=0, column=0, sticky="w")
        ctk.CTkLabel(
            footer,
            text="Green: Active   •   Amber: Expiring soon   •   Red: Expired",
            font=Fonts.label(10), text_color=Colors.text_muted,
        ).grid(row=0, column=1, sticky="e")

    # ------------------------------------------------------------ behavior

    def _on_mousewheel(self, event):
        delta = int(-event.delta / 120) if event.delta else 0
        if delta:
            self.tree.yview_scroll(delta, "units")
        return "break"

    def _on_mousewheel_linux(self, _event, direction):
        self.tree.yview_scroll(direction, "units")
        return "break"

    @staticmethod
    def _status_for(lease) -> tuple[str, str]:
        remaining = lease.remaining
        if remaining is None:
            return "Unknown", "unknown"
        if remaining.total_seconds() <= 0:
            return "Expired", "expired"
        if remaining <= timedelta(hours=1):
            return "Expiring soon", "expiring"
        return "Active", "active"

    @staticmethod
    def _format_remaining(remaining: timedelta | None) -> str:
        if remaining is None:
            return "Unknown"
        seconds = int(remaining.total_seconds())
        if seconds <= 0:
            return "Expired"
        hours, remainder = divmod(seconds, 3600)
        minutes = remainder // 60
        if hours and minutes:
            return f"{hours}h {minutes}m"
        if hours:
            return f"{hours}h"
        return f"{minutes}m"

    @staticmethod
    def _format_datetime(value) -> str:
        if hasattr(value, "strftime"):
            return value.strftime("%Y-%m-%d %H:%M:%S")
        return str(value) if value else "—"

    def load_data(self) -> None:
        try:
            self.leases = list(read_dhcp_leases())
            self.connection_label.configure(text="● LOCAL DHCP LEASES")
            logging.info(f"Loaded {len(self.leases)} local leases.")
            if self.leases:
                servers = sorted({
                    lease.dhcp_server for lease in self.leases
                    if lease.dhcp_server
                })
                source = f" • DHCP server: {', '.join(servers)}" if servers else ""
                self.summary_var.set(
                    f"Loaded {len(self.leases)} local lease(s){source}"
                )
            else:
                self.summary_var.set(
                    "No local IPv4 DHCP lease records were found. "
                    "Check whether this PC uses DHCP."
                )
            self._render_rows()
        except Exception as exc:
            logging.exception("Failed to load local leases.")
            messagebox.showerror(
                "Unable to load leases",
                f"Could not read DHCP lease data.\n\n{exc}",
                parent=self,
            )
            self.summary_var.set("Failed to load lease data")

    def _render_rows(self) -> None:
        if not hasattr(self, "tree"):
            return
        self.tree.delete(*self.tree.get_children())

        query = self.search_var.get().strip().casefold()
        selected_status = self.status_var.get()
        shown = 0

        for lease in self.leases:
            status, tag = self._status_for(lease)
            searchable = " ".join(str(v or "") for v in (
                lease.ip, lease.mac, lease.hostname,
                lease.dhcp_server, lease.adapter,
            )).casefold()

            if query and query not in searchable:
                continue
            if selected_status != "All statuses" and status != selected_status:
                continue

            values = (
                lease.ip,
                lease.mac,
                lease.hostname or "—",
                self._format_datetime(lease.start),
                self._format_datetime(lease.end),
                self._format_remaining(lease.remaining),
                status,
            )
            self.tree.insert("", "end", values=values, tags=(tag,))
            shown += 1

        if self.leases:
            self.summary_var.set(f"Showing {shown} of {len(self.leases)} lease(s)")
        else:
            self.summary_var.set(
                "No local DHCP lease records were found. "
                "This view is not a remote DHCP-server inventory."
            )

    def export_csv(self) -> None:
        rows = [self.tree.item(item, "values") for item in self.tree.get_children()]
        if not rows:
            messagebox.showinfo(
                "Export CSV", "There are no rows to export.", parent=self,
            )
            return

        path = filedialog.asksaveasfilename(
            parent=self, title="Export DHCP leases", defaultextension=".csv",
            filetypes=(("CSV files", "*.csv"), ("All files", "*.*")),
            initialfile="dhcp_leases.csv",
        )
        if not path:
            return

        headers = ("IP Address", "MAC Address", "Hostname", "Start Time",
                   "End Time", "Remaining", "Status")
        try:
            with open(path, "w", newline="", encoding="utf-8-sig") as output:
                writer = csv.writer(output)
                writer.writerow(headers)
                writer.writerows(rows)
            logging.info(f"Exported {len(rows)} local leases to {path}")
            messagebox.showinfo(
                "Export CSV", f"Exported {len(rows)} row(s).", parent=self,
            )
        except OSError as exc:
            logging.error(f"Export failed: {exc}")
            messagebox.showerror("Export failed", str(exc), parent=self)

    def _show_details(self, _event=None) -> None:
        selection = self.tree.selection()
        if not selection:
            return
        values = self.tree.item(selection[0], "values")
        labels = ("IP Address", "MAC Address", "Hostname", "Start Time",
                  "End Time", "Remaining", "Status")
        details = "\n".join(f"{key}: {value}" for key, value in zip(labels, values))

        lease_ip = values[0]
        lease = next((item for item in self.leases if item.ip == lease_ip), None)
        if lease:
            details += (
                f"\nDHCP Server: {lease.dhcp_server or '—'}"
                f"\nNetwork Adapter: {lease.adapter or '—'}"
            )
        messagebox.showinfo("Lease details", details, parent=self)

    # ------------------------------------------------------------ navigation

    def _hide_all_pages(self) -> None:
        for attr in ("about_frame", "diagnostics_frame", "remote_view"):
            widget = getattr(self, attr, None)
            if widget is not None:
                try:
                    widget.grid_remove()
                except Exception:
                    pass

        for widget in (self.toolbar, self.table_card, self.connection_label):
            try:
                widget.grid_remove()
            except Exception:
                pass

    def _show_leases(self) -> None:
        self._hide_all_pages()

        self.current_page = "leases"
        self._update_help_button()

        self.page_title.configure(text=APP_NAME)
        self.page_subtitle.configure(text="View and filter DHCP lease assignments")
        self.toolbar.grid()
        self.table_card.grid()
        self.connection_label.grid()
        self._render_rows()

    def _show_remote(self) -> None:
        self._hide_all_pages()

        self.current_page = "remote"
        self._update_help_button()

        self.page_title.configure(text="Remote DHCP Server")
        self.page_subtitle.configure(
            text="Query a Windows (WinRM) or Linux (SSH) DHCP server — read-only"
        )

        self.remote_view.grid()

    def _on_remote_status(self, message: str) -> None:
        logging.info(message)

    # ------------------------------------------------------------- Diagnostics

    def _show_diagnostics(self) -> None:
        """Show read-only network diagnostics with a modern card layout."""
        self._hide_all_pages()

        self.current_page = "diagnostics"
        self._update_help_button()

        self.page_title.configure(text="Network Diagnostics")
        self.page_subtitle.configure(
            text="Read-only network details for this computer or a remote server"
        )

        if hasattr(self, "diagnostics_frame"):
            self.diagnostics_frame.destroy()

        self.diagnostics_frame = ctk.CTkFrame(
            self.content, fg_color="transparent",
        )
        self.diagnostics_frame.grid(row=1, column=0, rowspan=2, sticky="nsew")
        self.diagnostics_frame.columnconfigure(0, weight=1)
        self.diagnostics_frame.rowconfigure(2, weight=1)

        # Top Controls Bar
        controls = ctk.CTkFrame(
            self.diagnostics_frame, fg_color=Colors.surface,
            corner_radius=Spacing.RADIUS_CARD,
            border_width=1, border_color=Colors.border,
        )
        controls.grid(row=0, column=0, sticky="ew", pady=(0, 12))
        controls.columnconfigure(1, weight=1)

        # Mode Toggle (Local vs Remote)
        ctk.CTkLabel(
            controls, text="Target:",
            font=Fonts.label(10, bold=True), text_color="#D2E1F5",
        ).grid(row=0, column=0, sticky="w", padx=(14, 8), pady=12)

        self.diag_mode = tk.StringVar(value="local")
        ctk.CTkSegmentedButton(
            controls,
            values=["Local (This PC)", "Remote Server"],
            variable=self.diag_mode,
            command=lambda _v: self._on_diag_mode_changed(),
            height=Spacing.BUTTON_HEIGHT, font=Fonts.label(10),
            fg_color=Colors.surface_alt, selected_color=Colors.primary,
            selected_hover_color=Colors.primary_hover,
            unselected_color=Colors.surface_alt,
            unselected_hover_color=Colors.border_light,
            text_color=Colors.text,
        ).grid(row=0, column=1, sticky="w", padx=(0, 12), pady=12)

        # Remote server input (hidden by default)
        self.diag_server_var = tk.StringVar()
        self.diag_username_var = tk.StringVar()
        self.diag_password_var = tk.StringVar()
        self.diag_backend_var = tk.StringVar(value="Auto")

        self.diag_remote_frame = ctk.CTkFrame(controls, fg_color="transparent")
        self.diag_remote_frame.grid(row=1, column=0, columnspan=3, sticky="ew", padx=14, pady=(0, 12))
        self.diag_remote_frame.columnconfigure(1, weight=1)

        ctk.CTkLabel(
            self.diag_remote_frame, text="Server:",
            font=Fonts.label(10, bold=True), text_color="#D2E1F5",
        ).grid(row=0, column=0, sticky="w", padx=(0, 6))

        ctk.CTkEntry(
            self.diag_remote_frame, textvariable=self.diag_server_var,
            placeholder_text="hostname or IP",
            height=Spacing.INPUT_HEIGHT,
            fg_color=Colors.surface_alt, text_color="#E6EEF9",
            border_color=Colors.border_light, font=Fonts.label(10),
        ).grid(row=0, column=1, sticky="ew", padx=(0, 8))

        ctk.CTkLabel(
            self.diag_remote_frame, text="User:",
            font=Fonts.label(10, bold=True), text_color="#D2E1F5",
        ).grid(row=0, column=2, sticky="w", padx=(0, 6))

        ctk.CTkEntry(
            self.diag_remote_frame, textvariable=self.diag_username_var,
            placeholder_text="optional",
            width=140, height=Spacing.INPUT_HEIGHT,
            fg_color=Colors.surface_alt, text_color="#E6EEF9",
            border_color=Colors.border_light, font=Fonts.label(10),
        ).grid(row=0, column=3, sticky="w", padx=(0, 8))

        ctk.CTkLabel(
            self.diag_remote_frame, text="Pass:",
            font=Fonts.label(10, bold=True), text_color="#D2E1F5",
        ).grid(row=0, column=4, sticky="w", padx=(0, 6))

        ctk.CTkEntry(
            self.diag_remote_frame, textvariable=self.diag_password_var,
            placeholder_text="optional", show="•",
            width=120, height=Spacing.INPUT_HEIGHT,
            fg_color=Colors.surface_alt, text_color="#E6EEF9",
            border_color=Colors.border_light, font=Fonts.label(10),
        ).grid(row=0, column=5, sticky="w")

        self.diag_remote_frame.grid_remove()  # hidden until Remote is selected

        # Refresh Button
        self.diag_refresh_btn = ctk.CTkButton(
            controls, text="↻  Refresh",
            width=120, height=Spacing.BUTTON_HEIGHT,
            fg_color=Colors.primary, hover_color=Colors.primary_hover,
            font=Fonts.label(10, bold=True),
            command=self._refresh_diagnostics,
        )
        self.diag_refresh_btn.grid(row=0, column=2, sticky="e", padx=(0, 14), pady=12)

        # Cards Container (scrollable)
        self.diag_cards = ctk.CTkScrollableFrame(
            self.diagnostics_frame, fg_color="transparent",
        )
        self.diag_cards.grid(row=2, column=0, sticky="nsew")
        self.diag_cards.columnconfigure(0, weight=1)

        self._refresh_diagnostics()

    def _on_diag_mode_changed(self) -> None:
        if self.diag_mode.get() == "Remote Server":
            self.diag_remote_frame.grid()
        else:
            self.diag_remote_frame.grid_remove()

    def _refresh_diagnostics(self) -> None:
        if not hasattr(self, "diag_cards") or not self.diag_cards.winfo_exists():
            return

        for widget in self.diag_cards.winfo_children():
            widget.destroy()

        loading = ctk.CTkLabel(
            self.diag_cards, text="⏳ Collecting diagnostics…",
            font=Fonts.label(12), text_color=Colors.text_muted,
        )
        loading.pack(pady=40)

        mode = self.diag_mode.get()
        if mode == "Remote Server":
            server = self.diag_server_var.get().strip()
            if not server:
                for widget in self.diag_cards.winfo_children():
                    widget.destroy()
                ctk.CTkLabel(
                    self.diag_cards, text="⚠  Enter a server name/IP first.",
                    font=Fonts.label(12), text_color=Colors.warning_text,
                ).pack(pady=40)
                return
            threading.Thread(
                target=self._remote_diag_worker,
                args=(
                    server,
                    self.diag_username_var.get().strip() or None,
                    self.diag_password_var.get() or None,
                ),
                daemon=True,
            ).start()
        else:
            threading.Thread(target=self._local_diag_worker, daemon=True).start()

    def _local_diag_worker(self) -> None:
        try:
            data = get_network_diagnostics()
            self._results.put((self._render_diag_cards, (data, None, "local")))
        except Exception as exc:
            self._results.put((self._render_diag_cards, (None, str(exc), "local")))

    def _remote_diag_worker(self, server: str, username, password) -> None:
        try:
            data = get_remote_diagnostics(
                server, username=username, password=password,
                backend=self.diag_backend_var.get().lower() if hasattr(self, "diag_backend_var") else "auto",
            )
            self._results.put((self._render_diag_cards, (data, None, f"remote:{server}")))
        except Exception as exc:
            self._results.put((self._render_diag_cards, (None, str(exc), f"remote:{server}")))

    def _render_diag_cards(self, data: dict | None, error: str | None, target: str) -> None:
        """Render the diagnostics in a modern card layout."""
        if not hasattr(self, "diag_cards") or not self.diag_cards.winfo_exists():
            return

        for widget in self.diag_cards.winfo_children():
            widget.destroy()

        if error is not None:
            card = ctk.CTkFrame(
                self.diag_cards, fg_color=Colors.surface,
                corner_radius=Spacing.RADIUS_CARD,
                border_width=2, border_color=Colors.danger_text,
            )
            card.pack(fill="x", padx=10, pady=6)
            ctk.CTkLabel(
                card, text="⚠  Diagnostics Failed",
                font=Fonts.label(13, bold=True), text_color=Colors.danger_text,
            ).pack(anchor="w", padx=16, pady=(14, 6))
            ctk.CTkLabel(
                card, text=error, justify="left", wraplength=780,
                font=Fonts.label(10), text_color=Colors.text,
            ).pack(anchor="w", padx=16, pady=(0, 14))
            return

        # Helper to build a card
        def build_card(title: str, icon: str, values: list[str], color: str):
            if not values:
                return
            card = ctk.CTkFrame(
                self.diag_cards, fg_color=Colors.surface,
                corner_radius=Spacing.RADIUS_CARD,
                border_width=1, border_color=Colors.border,
            )
            card.pack(fill="x", padx=10, pady=6)

            header = ctk.CTkFrame(card, fg_color="transparent")
            header.pack(fill="x", padx=16, pady=(12, 6))

            ctk.CTkLabel(
                header, text=f"{icon}  {title}",
                font=Fonts.label(12, bold=True), text_color=color,
            ).pack(side="left")

            body = ctk.CTkFrame(card, fg_color="transparent")
            body.pack(fill="x", padx=16, pady=(0, 12))

            for val in values:
                row = ctk.CTkFrame(body, fg_color="transparent")
                row.pack(fill="x", pady=2)

                ctk.CTkLabel(
                    row, text=val,
                    font=Fonts.mono(11), text_color=Colors.text,
                    anchor="w",
                ).pack(side="left", fill="x", expand=True)

                copy_btn = ctk.CTkButton(
                    row, text="📋", width=30, height=24,
                    fg_color="transparent", hover_color=Colors.border_light,
                    text_color=Colors.text_muted,
                    command=lambda v=val: self._copy_to_clipboard(v),
                )
                copy_btn.pack(side="right")

        # Header for the page
        target_label = "THIS COMPUTER" if target == "local" else f"REMOTE: {target.split(':', 1)[1]}"
        ctk.CTkLabel(
            self.diag_cards, text=f"● {target_label}",
            font=Fonts.label(11, bold=True), text_color=Colors.info,
            anchor="w",
        ).pack(fill="x", padx=10, pady=(6, 10))

        # Build cards
        if data.get("hostname") or data.get("os"):
            build_card(
                "System", "💻",
                [v for v in [
                    f"Hostname: {data.get('hostname') or '—'}",
                    f"OS:       {data.get('os') or '—'}",
                ] if "—" not in v],
                Colors.info,
            )

        build_card(
            "IP Addresses", "🌐",
            data.get("addresses") or [],
            Colors.success_text,
        )

        build_card(
            "Default Gateway", "🚪",
            data.get("gateways") or [],
            Colors.warning_text,
        )

        build_card(
            "DNS Servers", "📡",
            data.get("dns") or [],
            Colors.info,
        )

        if data.get("notes"):
            notes_card = ctk.CTkFrame(
                self.diag_cards, fg_color=Colors.surface,
                corner_radius=Spacing.RADIUS_CARD,
                border_width=1, border_color=Colors.warning_text,
            )
            notes_card.pack(fill="x", padx=10, pady=6)
            ctk.CTkLabel(
                notes_card, text="📝  Notes",
                font=Fonts.label(12, bold=True), text_color=Colors.warning_text,
            ).pack(anchor="w", padx=16, pady=(12, 6))
            for note in data["notes"]:
                ctk.CTkLabel(
                    notes_card, text=f"• {note}",
                    font=Fonts.label(10), text_color=Colors.text_muted,
                    justify="left", wraplength=780, anchor="w",
                ).pack(anchor="w", padx=16, pady=1)
            ctk.CTkLabel(notes_card, text="").pack(pady=4)

        if not any([data.get("addresses"), data.get("gateways"), data.get("dns")]):
            ctk.CTkLabel(
                self.diag_cards,
                text="No network information found. Check connectivity.",
                font=Fonts.label(11), text_color=Colors.text_muted,
            ).pack(pady=20)

    def _copy_to_clipboard(self, value: str) -> None:
        try:
            self.clipboard_clear()
            self.clipboard_append(value)
        except Exception:
            pass

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

    # ------------------------------------------------------------ about page

    def _show_about(self) -> None:
        self._hide_all_pages()

        self.current_page = "about"
        self._update_help_button()

        self.page_title.configure(text="About")
        self.page_subtitle.configure(text="Application information and capabilities")

        if hasattr(self, "about_frame"):
            self.about_frame.destroy()

        # Create a scrollable frame for the About page to handle smaller screens
        self.about_frame = ctk.CTkScrollableFrame(
            self.content, fg_color=Colors.surface,
            corner_radius=Spacing.RADIUS_CARD,
            border_width=1, border_color=Colors.border,
        )
        self.about_frame.grid(row=1, column=0, rowspan=2, sticky="nsew")
        self.about_frame.columnconfigure(0, weight=1)

        os_name = f"{platform.system()} {platform.release()}"
        py_version = platform.python_version()
        cfg_path = config_root_quiet("DhcpLeaseViewer")

        ctk.CTkLabel(
            self.about_frame, text="◆  DHCP Lease Viewer",
            font=Fonts.title(20), text_color=Colors.info,
        ).pack(anchor="w", padx=24, pady=(24, 0))

        ctk.CTkLabel(
            self.about_frame,
            text=f"{APP_SUITE}  •  Version {APP_VERSION}",
            font=Fonts.label(10), text_color=Colors.text_muted,
        ).pack(anchor="w", padx=24, pady=(5, 14))

        info_frame = ctk.CTkFrame(
            self.about_frame, fg_color=Colors.bg,
            corner_radius=Spacing.RADIUS_INPUT,
            border_width=1, border_color=Colors.border,
        )
        info_frame.pack(fill="x", padx=24, pady=(0, 16))

        info_text = (
            f"Platform:  {os_name}\n"
            f"Python:    {py_version}\n"
            f"Config:    {cfg_path}"
        )
        ctk.CTkLabel(
            info_frame, text=info_text,
            font=Fonts.mono(10), text_color=Colors.text_soft,
            justify="left", anchor="w",
        ).pack(fill="x", padx=14, pady=10)

        # ---------------- ABOUT THIS TOOL ----------------
        ctk.CTkLabel(
            self.about_frame, text="ABOUT THIS TOOL  /  PURPOSE",
            font=Fonts.badge(10), text_color=Colors.info_soft,
        ).pack(anchor="w", padx=24)

        ctk.CTkLabel(
            self.about_frame,
            text=("A cross-platform desktop utility for viewing locally exposed "
                  "DHCP lease records and querying remote DHCP servers — both "
                  "Windows (via WinRM) and Linux (via SSH) — in read-only mode. "
                  "Supports filtering, searching, and CSV export."),
            wraplength=720, justify="left",
            text_color="#D2E1F5", font=Fonts.label(10),
        ).pack(anchor="w", padx=24, pady=(6, 18))

        # ---------------- RECENT CHANGES ----------------
        ctk.CTkLabel(
            self.about_frame, text="RECENT CHANGES",
            font=Fonts.badge(10), text_color=Colors.warning_text,
        ).pack(anchor="w", padx=24)

        changes_text = (
            "Version 1.7.1\n"
            "• Added a 'How to Use' guide specific to each page.\n"
            "• Improved remote diagnostics error handling.\n"
            "• Fixed minor UI issues.\n\n"
            "Version 1.7.0\n"
            "• Remote: SSH username + key now works; username/password are really used on Windows.\n"
            "• Remote: Windows backend reads every scope through a CIM session.\n"
            "• Remote: ISC dhcpd journal is de-duplicated (latest record per IP, UTC → local).\n"
            "• Remote: added Kea (CSV) support; dnsmasq IPv6 / infinite leases handled.\n"
            "• Remote: password SSH via paramiko; fast port pre-check in Auto mode.\n"
            "• Remote: input validation hardened (no command / option injection).\n\n"
            "Version 1.6.0\n"
            "• Added search and filtering to the Remote Server view.\n"
            "• Added CSV export for remote DHCP leases.\n"
            "• Added double-click details for remote leases.\n"
            "• Added Server Profiles: save and reuse connection details.\n"
            "• Added file-based logging (app.log) for troubleshooting.\n"
            "• Redesigned Network Diagnostics with modern cards.\n"
            "• Added Remote Diagnostics (query a server's IP/GW/DNS).\n"
            "• Added one-click clipboard copy for network values.\n\n"
            "Version 1.5.0\n"
            "• Initial release with local DHCP lease viewer.\n"
            "• Remote query via WinRM (Windows) and SSH (Linux).\n"
            "• Basic search, filtering, and CSV export for local leases.\n"
            "• Network diagnostics (IP, gateway, DNS)."
        )
        ctk.CTkLabel(
            self.about_frame, text=changes_text, justify="left",
            text_color="#D2E1F5", font=Fonts.label(10),
        ).pack(anchor="w", padx=24, pady=(6, 18))

        # ---------------- FEATURES ----------------
        ctk.CTkLabel(
            self.about_frame, text="FEATURES",
            font=Fonts.badge(10), text_color=Colors.success_text,
        ).pack(anchor="w", padx=24)

        features = [
            "• Local view: read this computer's own DHCP leases",
            "• Remote view — Windows: query a Windows DHCP server via WinRM",
            "• Remote view — Linux:   query a Linux DHCP server via SSH",
            "• Auto-detect backend: tries Windows first, then Linux",
            "• Save server profiles for quick reconnection",
            "• Search and filter both local and remote leases",
            "• View IP, MAC, hostname, lease start / end times",
            "• Calculate remaining time and highlight expiring leases",
            "• Export local or remote leases to CSV",
            "• Manual refresh (F5) or 10-second auto-refresh",
            "• Local and remote network diagnostics with copy buttons",
        ]
        ctk.CTkLabel(
            self.about_frame, text="\n".join(features), justify="left",
            text_color="#D2E1F5", font=Fonts.label(10),
        ).pack(anchor="w", padx=24, pady=(7, 18))

        # ---------------- SUPPORTED PLATFORMS ----------------
        ctk.CTkLabel(
            self.about_frame, text="SUPPORTED PLATFORMS",
            font=Fonts.badge(10), text_color=Colors.info,
        ).pack(anchor="w", padx=24)

        ctk.CTkLabel(
            self.about_frame,
            text=("• Windows 10 / 11 / Server 2019+  —  full support\n"
                  "• Linux (systemd-networkd / NetworkManager / ISC / dnsmasq)\n"
                  "• macOS is not supported.\n\n"
                  "This tool is read-only: it never modifies leases, scopes, "
                  "or reservations on any server."),
            wraplength=720, justify="left",
            text_color=Colors.warning_text, font=Fonts.label(10),
        ).pack(anchor="w", padx=24, pady=(6, 18))

        ctk.CTkButton(
            self.about_frame, text="Back to DHCP Leases",
            width=180, height=Spacing.BUTTON_HEIGHT,
            fg_color=Colors.primary, hover_color=Colors.primary_hover,
            font=Fonts.label(11, bold=True),
            command=self._show_leases,
        ).pack(anchor="w", padx=24, pady=(0, 20))

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

    # ------------------------------------------------------- auto refresh

    def _toggle_auto_refresh(self) -> None:
        if self.auto_refresh_var.get():
            self._schedule_auto_refresh()
        elif self._auto_refresh_job is not None:
            try:
                self.after_cancel(self._auto_refresh_job)
            except Exception:
                pass
            self._auto_refresh_job = None

    def _schedule_auto_refresh(self) -> None:
        if self.auto_refresh_var.get():
            self._auto_refresh_job = self.after(
                self.REFRESH_INTERVAL_MS, self._auto_refresh,
            )

    def _auto_refresh(self) -> None:
        self._auto_refresh_job = None
        if self.auto_refresh_var.get():
            self.load_data()
            self._schedule_auto_refresh()

    # -------------------------------------------------------------- closing

    def _on_close(self) -> None:
        logging.info("--- Shutting down ---")
        if hasattr(self, "remote_view"):
            try:
                self.remote_view.shutdown()
            except Exception:
                pass

        for after_id in (self._auto_refresh_job, self._poll_after_id):
            if after_id is not None:
                try:
                    self.after_cancel(after_id)
                except tk.TclError:
                    pass
        self.destroy()


def main() -> None:
    try:
        app = DHCPLeaseViewer()
        app.mainloop()
    except Exception:
        logging.exception("Fatal error in main loop.")
        raise


if __name__ == "__main__":
    main()