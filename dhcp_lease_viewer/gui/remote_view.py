"""Remote DHCP Server view for CyberOpsSuite DHCP Lease Viewer."""

from __future__ import annotations

import csv
import os
import queue
import threading
import tkinter as tk
from datetime import datetime, timedelta
from tkinter import filedialog, messagebox, ttk

import customtkinter as ctk

from dhcp_lease_viewer.core.remote_reader import (
    Backend,
    RemoteDhcpError,
    RemoteLease,
    read_remote_dhcp_leases,
)
from dhcp_lease_viewer.core import profiles

from core.theme import Colors, Fonts, Spacing
from core.utils.icons import apply_window_icon


class RemoteView(ctk.CTkFrame):
    """Full-page view for querying a remote DHCP server."""

    REFRESH_INTERVAL_MS = 30_000

    def __init__(self, parent, *, on_status=None) -> None:
        super().__init__(parent, fg_color=Colors.bg_alt)

        self._on_status = on_status
        self._leases: list[RemoteLease] = []
        self._loading = False
        self._connected_to: str = ""
        self._auto_refresh_job: str | None = None
        self._poll_after_id: str | None = None
        self._results: queue.Queue = queue.Queue()

        # Observable variables.
        self.server_var = tk.StringVar()
        self.username_var = tk.StringVar()
        self.password_var = tk.StringVar()
        self.key_path_var = tk.StringVar()
        self.backend_var = tk.StringVar(value="Auto")
        self.use_credentials_var = tk.BooleanVar(value=False)
        self.auto_refresh_var = tk.BooleanVar(value=False)
        self.show_inactive_var = tk.BooleanVar(value=False)
        self.status_var = tk.StringVar(value="Not connected.")
        self.summary_var = tk.StringVar(value="Enter a server name to begin.")
        self.search_var = tk.StringVar()

        self._build_ui()
        self._on_backend_changed(self.backend_var.get())

        # Load saved profiles into dropdown
        self._refresh_profile_dropdown()

        # Start polling worker results.
        self._poll_after_id = self.after(100, self._poll_results)

    # ------------------------------------------------------------------ UI

    def _build_ui(self) -> None:
        self.columnconfigure(0, weight=1)
        self.rowconfigure(2, weight=1)

        self._build_header()
        self._build_form(row=1)
        self._build_table(row=2)

    def _build_header(self) -> None:
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", pady=(0, 12))
        header.columnconfigure(0, weight=1)

        ctk.CTkLabel(
            header, text="Remote DHCP Server",
            font=Fonts.title(22), text_color="#F1F5F9",
        ).grid(row=0, column=0, sticky="w")

        ctk.CTkLabel(
            header,
            text="Query a Windows (WinRM) or Linux (SSH) DHCP server in read-only mode.",
            font=Fonts.label(10), text_color=Colors.text_muted,
        ).grid(row=1, column=0, sticky="w", pady=(4, 0))

        self.status_label = ctk.CTkLabel(
            header, textvariable=self.status_var,
            font=Fonts.label(10), text_color=Colors.text_muted,
        )
        self.status_label.grid(row=0, column=1, sticky="e", padx=(10, 0))

    def _build_form(self, row: int) -> None:
        form = ctk.CTkFrame(
            self, fg_color=Colors.surface,
            corner_radius=Spacing.RADIUS_CARD,
            border_width=1, border_color=Colors.border,
        )
        form.grid(row=row, column=0, sticky="ew", pady=(0, 12))
        form.columnconfigure(1, weight=1)
        form.columnconfigure(3, weight=1)

        # ---- Row 0: Server Profile Selection ----
        ctk.CTkLabel(
            form, text="Saved Server:",
            font=Fonts.label(10, bold=True), text_color="#D2E1F5",
        ).grid(row=0, column=0, sticky="w", padx=(14, 8), pady=(14, 6))

        self.profile_menu = ctk.CTkOptionMenu(
            form, values=["-- New Connection --"],
            height=Spacing.INPUT_HEIGHT,
            fg_color=Colors.surface_alt, button_color=Colors.border_light,
            button_hover_color=Colors.border,
            dropdown_fg_color=Colors.surface,
            font=Fonts.label(10),
            command=self._on_profile_selected,
        )
        self.profile_menu.grid(row=0, column=1, sticky="ew", padx=(0, 12), pady=(14, 6))
        self.profile_menu.set("-- New Connection --")

        # ---- Row 1: Server & Connect ----
        ctk.CTkLabel(
            form, text="Server:",
            font=Fonts.label(10, bold=True), text_color="#D2E1F5",
        ).grid(row=1, column=0, sticky="w", padx=(14, 8), pady=(2, 6))

        self.server_entry = ctk.CTkEntry(
            form, textvariable=self.server_var,
            placeholder_text="hostname or IP (e.g. dc01 or 192.168.1.10)",
            height=Spacing.INPUT_HEIGHT,
            fg_color=Colors.surface_alt, text_color="#E6EEF9",
            border_color=Colors.border_light, font=Fonts.label(10),
        )
        self.server_entry.grid(row=1, column=1, sticky="ew", padx=(0, 12), pady=(2, 6))

        self.test_button = ctk.CTkButton(
            form, text="Test", width=80, height=Spacing.BUTTON_HEIGHT,
            fg_color=Colors.neutral_dark, hover_color=Colors.neutral_dark_hover,
            command=self._test_connection,
        )
        self.test_button.grid(row=1, column=2, padx=(0, 8), pady=(2, 6))

        self.connect_button = ctk.CTkButton(
            form, text="Connect", width=100, height=Spacing.BUTTON_HEIGHT,
            fg_color=Colors.primary, hover_color=Colors.primary_hover,
            font=Fonts.label(10, bold=True), command=self._connect,
        )
        self.connect_button.grid(row=1, column=3, sticky="w", padx=(0, 14), pady=(2, 6))

        # ---- Row 2: Backend selector ----
        ctk.CTkLabel(
            form, text="Backend:",
            font=Fonts.label(10, bold=True), text_color="#D2E1F5",
        ).grid(row=2, column=0, sticky="w", padx=(14, 8), pady=(2, 6))

        self.backend_selector = ctk.CTkSegmentedButton(
            form, values=["Auto", "Windows", "Linux"],
            variable=self.backend_var, command=self._on_backend_changed,
            height=Spacing.BUTTON_HEIGHT, font=Fonts.label(10),
            fg_color=Colors.surface_alt, selected_color=Colors.primary,
            selected_hover_color=Colors.primary_hover,
            unselected_color=Colors.surface_alt,
            unselected_hover_color=Colors.border_light,
            text_color=Colors.text,
        )
        self.backend_selector.grid(
            row=2, column=1, columnspan=3, sticky="ew",
            padx=(0, 14), pady=(2, 6),
        )

        # ---- Row 3: Credentials ----
        self.use_creds_check = ctk.CTkCheckBox(
            form, text="Use username / password (SSH user, DOMAIN\\user)",
            variable=self.use_credentials_var,
            command=self._toggle_credentials,
            font=Fonts.label(10), text_color="#D2E1F5",
            fg_color=Colors.primary, hover_color=Colors.primary_hover,
            border_color=Colors.border_light,
        )
        self.use_creds_check.grid(row=3, column=0, columnspan=2, sticky="w", padx=14, pady=(2, 6))

        ctk.CTkCheckBox(
            form, text="Show inactive / expired records",
            variable=self.show_inactive_var,
            font=Fonts.label(10), text_color="#D2E1F5",
            fg_color=Colors.primary, hover_color=Colors.primary_hover,
            border_color=Colors.border_light,
        ).grid(row=3, column=2, columnspan=2, sticky="w", padx=(0, 14), pady=(2, 6))

        self.username_entry = ctk.CTkEntry(
            form, textvariable=self.username_var,
            placeholder_text="DOMAIN\\user (Windows) or user (Linux)",
            height=Spacing.INPUT_HEIGHT, fg_color=Colors.surface_alt,
            text_color="#E6EEF9", border_color=Colors.border_light,
            font=Fonts.label(10), state="disabled",
        )
        self.username_entry.grid(
            row=4, column=0, columnspan=2, sticky="ew", padx=(14, 12), pady=(0, 6),
        )

        self.password_entry = ctk.CTkEntry(
            form, textvariable=self.password_var, placeholder_text="Password (empty = SSH key / current user)",
            height=Spacing.INPUT_HEIGHT, fg_color=Colors.surface_alt,
            text_color="#E6EEF9", border_color=Colors.border_light,
            font=Fonts.label(10), show="•", state="disabled",
        )
        self.password_entry.grid(
            row=4, column=2, columnspan=2, sticky="ew", padx=(0, 14), pady=(0, 6),
        )

        # ---- Row 5: SSH key ----
        ctk.CTkLabel(
            form, text="SSH key:",
            font=Fonts.label(10, bold=True), text_color="#D2E1F5",
        ).grid(row=5, column=0, sticky="w", padx=(14, 8), pady=(2, 14))

        self.key_entry = ctk.CTkEntry(
            form, textvariable=self.key_path_var,
            placeholder_text="~/.ssh/id_ed25519 (optional, Linux)",
            height=Spacing.INPUT_HEIGHT, fg_color=Colors.surface_alt,
            text_color="#E6EEF9", border_color=Colors.border_light,
            font=Fonts.label(10),
        )
        self.key_entry.grid(
            row=5, column=1, columnspan=3, sticky="ew", padx=(0, 14), pady=(2, 14),
        )

        # ---- Row 6: auto-refresh + summary ----
        ctk.CTkCheckBox(
            form, text="Auto-refresh (30s)",
            variable=self.auto_refresh_var, command=self._toggle_auto_refresh,
            font=Fonts.label(10), text_color="#D2E1F5",
            fg_color=Colors.primary, hover_color=Colors.primary_hover,
            border_color=Colors.border_light,
        ).grid(row=6, column=0, columnspan=2, sticky="w", padx=14, pady=(0, 14))

        ctk.CTkLabel(
            form, textvariable=self.summary_var,
            font=Fonts.label(10), text_color=Colors.text_muted,
        ).grid(row=6, column=2, columnspan=2, sticky="e", padx=(0, 14), pady=(0, 14))

    def _build_table(self, row: int) -> None:
        table_card = ctk.CTkFrame(
            self, fg_color=Colors.surface,
            corner_radius=Spacing.RADIUS_CARD,
            border_width=1, border_color=Colors.border,
        )
        table_card.grid(row=row, column=0, sticky="nsew")
        table_card.rowconfigure(1, weight=1)
        table_card.columnconfigure(0, weight=1)

        # Table Toolbar
        toolbar = ctk.CTkFrame(table_card, fg_color="transparent")
        toolbar.grid(row=0, column=0, sticky="ew", padx=12, pady=(10, 0))
        toolbar.columnconfigure(1, weight=1)

        ctk.CTkLabel(
            toolbar, text="Remote leases",
            font=Fonts.label(11, bold=True), text_color="#E6EEF9",
        ).grid(row=0, column=0, sticky="w")

        self.search_entry = ctk.CTkEntry(
            toolbar, textvariable=self.search_var,
            placeholder_text="Search IP, MAC, Hostname…",
            height=Spacing.INPUT_HEIGHT, fg_color=Colors.bg,
            text_color=Colors.text, border_color=Colors.border_light,
            font=Fonts.label(10),
        )
        self.search_entry.grid(row=0, column=1, sticky="ew", padx=(20, 10), pady=10)
        self.search_var.trace_add("write", lambda *_: self._render_rows())

        ctk.CTkButton(
            toolbar, text="Export CSV", width=100, height=Spacing.BUTTON_HEIGHT,
            fg_color=Colors.neutral_dark, hover_color=Colors.neutral_dark_hover,
            command=self.export_csv,
        ).grid(row=0, column=2, sticky="e", pady=10)

        table_frame = ctk.CTkFrame(table_card, fg_color="transparent")
        table_frame.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 10))
        table_frame.rowconfigure(0, weight=1)
        table_frame.columnconfigure(0, weight=1)

        self.columns = (
            "ip", "mac", "hostname", "end", "remaining", "scope", "state", "server", "source",
        )
        headings = {
            "ip": "IP Address", "mac": "MAC Address", "hostname": "Hostname",
            "end": "Lease Expires", "remaining": "Remaining", "scope": "Scope",
            "state": "State", "server": "Server", "source": "Source",
        }
        widths = {
            "ip": 120, "mac": 150, "hostname": 140, "end": 150,
            "remaining": 100, "scope": 120, "state": 100, "server": 120, "source": 80,
        }

        self.tree = ttk.Treeview(
            table_frame, columns=self.columns, show="headings",
            selectmode="browse", style="Cyber.Treeview",
        )
        for col in self.columns:
            self.tree.heading(col, text=headings[col])
            self.tree.column(
                col, width=widths[col], minwidth=70,
                anchor="w", stretch=(col == "hostname"),
            )

        yscroll = ttk.Scrollbar(
            table_frame, orient="vertical", style="Vertical.TScrollbar",
            command=self.tree.yview,
        )
        self.tree.configure(yscrollcommand=yscroll.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        yscroll.grid(row=0, column=1, sticky="ns")

        self.tree.tag_configure("active", foreground=Colors.success_text)
        self.tree.tag_configure("expiring", foreground=Colors.warning_text)
        self.tree.tag_configure("expired", foreground=Colors.danger_text)
        self.tree.tag_configure("unknown", foreground=Colors.text_dim)

        self.tree.bind("<Double-1>", self._show_details)

    # --------------------------------------------------------------- events

    def _refresh_profile_dropdown(self) -> None:
        """Load server profiles and update the dropdown."""
        profiles_list = profiles.load_profiles()
        names = [p["server"] for p in profiles_list]
        if names:
            self.profile_menu.configure(values=["-- New Connection --"] + names)
        else:
            self.profile_menu.configure(values=["-- New Connection --"])

    def _on_profile_selected(self, selected: str) -> None:
        if selected == "-- New Connection --":
            self.server_var.set("")
            self.username_var.set("")
            self.password_var.set("")
            self.key_path_var.set("")
            self.backend_var.set("Auto")
            self.use_credentials_var.set(False)
            self._toggle_credentials()
            self._on_backend_changed("Auto")
            return

        profiles_list = profiles.load_profiles()
        for p in profiles_list:
            if p["server"] == selected:
                self.server_var.set(p.get("server", ""))
                self.username_var.set(p.get("username", ""))
                self.key_path_var.set(p.get("key_path", ""))
                self.password_var.set("")
                if p.get("username"):
                    self.use_credentials_var.set(True)
                    self._toggle_credentials()
                else:
                    self.use_credentials_var.set(False)
                    self._toggle_credentials()
                
                backend = p.get("backend", "Auto")
                if backend in ("Auto", "Windows", "Linux"):
                    self.backend_var.set(backend)
                self._on_backend_changed(self.backend_var.get())
                break

    def _on_backend_changed(self, value: str) -> None:
        # The SSH key only matters for Linux/Auto. Credentials stay available
        # for every backend (Linux needs the SSH username too).
        self.key_entry.configure(
            state="disabled" if value == "Windows" else "normal",
        )

    def _toggle_credentials(self) -> None:
        state = "normal" if self.use_credentials_var.get() else "disabled"
        self.username_entry.configure(state=state)
        self.password_entry.configure(state=state)

    def _test_connection(self) -> None:
        self._start_query(timeout=20)

    def _connect(self) -> None:
        self._start_query(timeout=60)

    def _start_query(self, *, timeout: int, silent: bool = False) -> None:
        if self._loading:
            return

        target = self.server_var.get().strip()
        if not target:
            messagebox.showwarning(
                "Server required", "Enter the server name or IP first.", parent=self,
            )
            return

        # Save profile before connecting
        username = self.username_var.get().strip()
        backend = self.backend_var.get()
        profiles.add_profile(
            target, username, backend, self.key_path_var.get().strip(),
        )
        self._refresh_profile_dropdown()

        self._set_busy(True, f"Connecting to {target}…")
        self.status_var.set(f"● Connecting to {target}")
        self.status_label.configure(text_color=Colors.warning_text)

        threading.Thread(
            target=self._worker_query, args=(target, timeout, silent), daemon=True,
        ).start()

    def _worker_query(self, server: str, timeout: int, silent: bool = False) -> None:
        username = None
        password = None
        key_path = None

        if self.use_credentials_var.get():
            username = self.username_var.get().strip() or None
            password = self.password_var.get() or None

        label = self.backend_var.get()
        key_path = self.key_path_var.get().strip() or None
        if label == "Windows":
            key_path = None
        include_inactive = bool(self.show_inactive_var.get())
        backend: Backend = {
            "Auto": "auto", "Windows": "windows", "Linux": "linux",
        }.get(label, "auto")

        try:
            leases = read_remote_dhcp_leases(
                server, username=username, password=password,
                key_path=key_path, backend=backend, timeout=timeout,
                include_inactive=include_inactive,
            )
        except RemoteDhcpError as exc:
            self._results.put((self._apply_result, (None, str(exc), server, silent)))
            return
        except Exception as exc:
            self._results.put((self._apply_result, (None, f"Unexpected error: {exc}", server, silent)))
            return

        self._results.put((self._apply_result, (leases, None, server, silent)))

    def _apply_result(
        self, leases: list[RemoteLease] | None, error: str | None,
        server: str, silent: bool = False,
    ) -> None:
        self._set_busy(False, None)

        if error is not None:
            self.status_var.set(f"● Failed ({server})")
            self.status_label.configure(text_color=Colors.danger_text)
            self.summary_var.set("Connection failed. See the message.")
            if not silent:  # auto-refresh must not spam dialogs
                messagebox.showerror("Remote DHCP error", error, parent=self)
            return

        self._leases = leases or []
        self._connected_to = server
        self.status_var.set(f"● Connected: {server}")
        self.status_label.configure(text_color=Colors.success_text)

        self._render_rows()

        if self._on_status is not None:
            try:
                self._on_status(f"Remote: {len(self._leases)} leases from {server}")
            except Exception:
                pass

    # ------------------------------------------------------------ rendering

    def _render_rows(self) -> None:
        if not hasattr(self, "tree"):
            return
        self.tree.delete(*self.tree.get_children())

        query = self.search_var.get().strip().casefold()
        shown = 0

        for lease in self._leases:
            searchable = " ".join(str(v or "") for v in (
                lease.ip, lease.mac, lease.hostname, lease.scope_id
            )).casefold()

            if query and query not in searchable:
                continue

            values = (
                lease.ip,
                lease.mac,
                lease.hostname or "—",
                self._format_dt(lease.end),
                self._format_remaining(self._remaining(lease)),
                lease.scope_id or "—",
                lease.address_state or "—",
                lease.dhcp_server or "—",
                lease.source or "—",
            )
            self.tree.insert("", "end", values=values, tags=(self._tag_for(lease),))
            shown += 1

        count = len(self._leases)
        if query:
            self.summary_var.set(f"Showing {shown} of {count} lease(s) (Filtered)")
        else:
            self.summary_var.set(f"{count} lease(s) from {self._connected_to}")

    def export_csv(self) -> None:
        rows = [self.tree.item(item, "values") for item in self.tree.get_children()]
        if not rows:
            messagebox.showinfo("Export CSV", "There are no visible rows to export.", parent=self)
            return

        path = filedialog.asksaveasfilename(
            parent=self, title="Export Remote DHCP leases", defaultextension=".csv",
            filetypes=(("CSV files", "*.csv"), ("All files", "*.*")),
            initialfile=f"remote_leases_{self._connected_to}.csv",
        )
        if not path:
            return

        headers = ("IP Address", "MAC Address", "Hostname", "Lease Expires",
                   "Remaining", "Scope", "State", "Server", "Source")
        try:
            with open(path, "w", newline="", encoding="utf-8-sig") as output:
                writer = csv.writer(output)
                writer.writerow(headers)
                writer.writerows(rows)
            messagebox.showinfo("Export CSV", f"Exported {len(rows)} row(s).", parent=self)
        except OSError as exc:
            messagebox.showerror("Export failed", str(exc), parent=self)

    def _show_details(self, _event=None) -> None:
        selection = self.tree.selection()
        if not selection:
            return
        values = self.tree.item(selection[0], "values")
        labels = ("IP Address", "MAC Address", "Hostname", "Lease Expires",
                  "Remaining", "Scope", "State", "Server", "Source")
        
        details = "\n".join(f"{key}: {value}" for key, value in zip(labels, values))
        messagebox.showinfo("Remote Lease Details", details, parent=self)

    # --------------------------------------------------------- helpers

    @staticmethod
    def _remaining(lease: RemoteLease) -> timedelta | None:
        if lease.end is None:
            return None
        return lease.end - datetime.now()

    @staticmethod
    def _tag_for(lease: RemoteLease) -> str:
        if lease.end is None:
            return "unknown"
        delta = lease.end - datetime.now()
        if delta.total_seconds() <= 0:
            return "expired"
        if delta <= timedelta(hours=1):
            return "expiring"
        return "active"

    @staticmethod
    def _format_dt(value) -> str:
        if hasattr(value, "strftime"):
            return value.strftime("%Y-%m-%d %H:%M")
        return str(value) if value else "—"

    @staticmethod
    def _format_remaining(remaining: timedelta | None) -> str:
        if remaining is None:
            return "—"
        seconds = int(remaining.total_seconds())
        if seconds <= 0:
            return "Expired"
        hours, rem = divmod(seconds, 3600)
        minutes = rem // 60
        if hours and minutes:
            return f"{hours}h {minutes}m"
        if hours:
            return f"{hours}h"
        return f"{minutes}m"

    # --------------------------------------------------------- status

    def _set_busy(self, busy: bool, message: str | None) -> None:
        self._loading = busy
        state = "disabled" if busy else "normal"
        self.test_button.configure(state=state)
        self.connect_button.configure(state=state)
        if message:
            self.status_var.set(message)

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
            self._auto_refresh_job = self.after(self.REFRESH_INTERVAL_MS, self._auto_refresh)

    def _auto_refresh(self) -> None:
        self._auto_refresh_job = None
        if self.auto_refresh_var.get() and self._connected_to:
            self._start_query(timeout=60, silent=True)
            self._schedule_auto_refresh()

    # ------------------------------------------------------- worker polling

    def _poll_results(self) -> None:
        try:
            while True:
                callback, args = self._results.get_nowait()
                callback(*args)
        except queue.Empty:
            pass
        except Exception:
            pass

        try:
            if self.winfo_exists():
                self._poll_after_id = self.after(100, self._poll_results)
        except tk.TclError:
            return

    # --------------------------------------------------------- lifecycle

    def shutdown(self) -> None:
        for attr in ("_auto_refresh_job", "_poll_after_id"):
            job = getattr(self, attr, None)
            if job is not None:
                try:
                    self.after_cancel(job)
                except Exception:
                    pass