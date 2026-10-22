"""Network Mapper GUI for CyberOpsSuite."""

from __future__ import annotations

import ipaddress
import json
import os
import platform
import queue
import threading
from datetime import datetime
from pathlib import Path

import customtkinter as ctk
from tkinter import ttk, messagebox, filedialog

from core.theme import Colors, Fonts, Spacing
from core.gui.treeview_style import apply_treeview_style
from core.utils.icons import apply_window_icon
from core.utils.paths import config_root, config_root_quiet

from network_mapper.core.cidr import cidr_to_range, MAX_HOSTS
from network_mapper.core.controller import ScanController
from network_mapper.core.exporter import export_csv, export_html, export_json
from network_mapper.core.scanner import NetworkScanner

from network_mapper.gui.graph_view import GraphWindow
from network_mapper.gui.history_view import HistoryWindow
from network_mapper.gui.log_panel import LogPanel
from network_mapper.gui.settings import SettingsWindow

APP_VERSION = "1.4.0"


class NetworkMapperGUI(ctk.CTk):
    """Main application window for Network Mapper."""

    def __init__(self) -> None:
        super().__init__()

        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("dark-blue")

        self._setup_window()
        self._setup_scanner()
        self._setup_state()

        # Window icon.
        apply_window_icon(self)

        # Shared dark theme for ttk.Treeview widgets.
        apply_treeview_style(self)

        self._build_ui()

        self.after(80, self._apply_dark_titlebar)
        self.after(100, self._poll_scan_queue)

    # ------------------------------------------------------------- setup

    def _setup_window(self) -> None:
        self.title("Network Mapper | CyberOpsSuite")
        self.geometry("1160x780")
        self.minsize(940, 640)
        self.configure(fg_color=Colors.bg)
        self._apply_dark_titlebar()

    def _setup_scanner(self) -> None:
        self.scanner = NetworkScanner(
            max_host_workers=100,
            max_port_workers=8,
            timeout=0.45,
        )
        self.controller = ScanController()

    def _setup_state(self) -> None:
        self.results: list = []
        self.scan_started_at: str | None = None
        self.scan_target: str = ""
        self.scan_queue: queue.Queue = queue.Queue()
        self.scan_running: bool = False
        self._scan_total: int = 0
        self._about_open = False

    def _apply_dark_titlebar(self) -> None:
        """Request a dark native title bar on supported Windows versions."""
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

    # ------------------------------------------------------------- build UI

    def _build_ui(self) -> None:
        outer = ctk.CTkFrame(self, fg_color="transparent")
        outer.pack(fill="both", expand=True, padx=24, pady=(20, 16))

        self._build_header(outer)
        self._build_target_card(outer)
        self._build_metrics(outer)
        self._build_results(outer)
        self._build_footer(outer)

    def _build_header(self, parent: ctk.CTkFrame) -> None:
        header = ctk.CTkFrame(parent, fg_color="transparent")
        header.pack(fill="x", pady=(0, 18))

        brand = ctk.CTkFrame(header, fg_color="transparent")
        brand.pack(side="left", fill="x", expand=True)

        ctk.CTkLabel(
            brand, text="◈  CYBEROPSSUITE",
            font=Fonts.badge(11), text_color=Colors.info,
        ).pack(anchor="w")
        ctk.CTkLabel(
            brand, text="Network Mapper",
            font=Fonts.title(24), text_color=Colors.text,
        ).pack(anchor="w", pady=(3, 0))
        ctk.CTkLabel(
            brand,
            text="Network visibility · TCP reachability · Asset overview",
            font=Fonts.label(10), text_color=Colors.text_muted,
        ).pack(anchor="w", pady=(2, 0))

        actions = ctk.CTkFrame(header, fg_color="transparent")
        actions.pack(side="right", anchor="n", pady=8)
        actions.grid_columnconfigure(0, weight=0)
        actions.grid_columnconfigure(1, weight=0)
        actions.grid_columnconfigure(2, weight=0)

        # Help button (col 0) - hidden on About page
        self.help_btn = ctk.CTkButton(
            actions, text="❓ How to Use", width=110, height=34,
            corner_radius=Spacing.RADIUS_BUTTON,
            fg_color=Colors.info_bg, hover_color=Colors.info,
            text_color=Colors.info_light, font=Fonts.label(11, bold=True),
            command=self._show_how_to_use,
        )
        self.help_btn.grid(row=0, column=0, padx=(0, 8), pady=0)

        # About button (col 1) - always visible
        ctk.CTkButton(
            actions, text="About", width=90, height=34,
            corner_radius=Spacing.RADIUS_BUTTON,
            fg_color=Colors.neutral, hover_color=Colors.neutral_hover,
            command=self.open_about,
        ).grid(row=0, column=1, padx=(0, 10), pady=0)

        # Status badge (col 2)
        self.status_badge = ctk.CTkLabel(
            actions, text="●  READY",
            font=Fonts.badge(10), text_color=Colors.success_text,
            fg_color=Colors.success, corner_radius=Spacing.RADIUS_BADGE,
            padx=14, pady=8,
        )
        self.status_badge.grid(row=0, column=2, pady=0)

    def _build_target_card(self, parent: ctk.CTkFrame) -> None:
        card = ctk.CTkFrame(
            parent, fg_color=Colors.surface,
            corner_radius=Spacing.RADIUS_CARD,
        )
        card.pack(fill="x", pady=(0, 14))

        ctk.CTkLabel(
            card, text="SCAN TARGET",
            font=Fonts.badge(10), text_color=Colors.text_muted,
        ).pack(anchor="w", padx=18, pady=(16, 8))

        controls = ctk.CTkFrame(card, fg_color="transparent")
        controls.pack(fill="x", padx=18)

        self.target_entry = ctk.CTkEntry(
            controls, height=Spacing.INPUT_HEIGHT,
            fg_color=Colors.bg, text_color=Colors.text,
            border_color=Colors.border, placeholder_text="192.168.1.0/24",
        )
        self.target_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))
        self.target_entry.insert(0, "192.168.1.0/24")
        self.target_entry.bind("<Return>", lambda _e: self.start_scan())

        self.scan_button = ctk.CTkButton(
            controls, text="▶  Start scan", width=140,
            height=Spacing.INPUT_HEIGHT,
            fg_color=Colors.primary, hover_color=Colors.primary_hover,
            command=self.start_scan,
        )
        self.scan_button.pack(side="left", padx=(0, 7))

        self.pause_button = ctk.CTkButton(
            controls, text="Ⅱ  Pause", width=110,
            height=Spacing.INPUT_HEIGHT,
            fg_color=Colors.neutral, hover_color=Colors.neutral_hover,
            command=self.toggle_pause, state="disabled",
        )
        self.pause_button.pack(side="left", padx=(0, 7))

        self.stop_button = ctk.CTkButton(
            controls, text="■  Stop", width=100,
            height=Spacing.INPUT_HEIGHT,
            fg_color=Colors.danger, hover_color=Colors.danger_hover,
            command=self.stop_scan, state="disabled",
        )
        self.stop_button.pack(side="left")

        self.progress = ctk.CTkProgressBar(
            card, height=7,
            fg_color=Colors.surface_alt, progress_color=Colors.primary,
        )
        self.progress.pack(fill="x", padx=18, pady=(14, 0))
        self.progress.set(0)

        self.progress_label = ctk.CTkLabel(
            card,
            text="Only scan networks you own or have permission to assess.",
            font=Fonts.label(10), text_color=Colors.text_muted,
        )
        self.progress_label.pack(anchor="w", padx=18, pady=(8, 16))

    def _build_metrics(self, parent: ctk.CTkFrame) -> None:
        metrics = ctk.CTkFrame(parent, fg_color="transparent")
        metrics.pack(fill="x", pady=(0, 14))

        specs = [
            ("hosts", "🖥  HOSTS SCANNED", "0", Colors.text),
            ("online", "✅  RESPONDED", "0", Colors.success_text),
            ("ports", "🔌  OPEN TCP PORTS", "0", Colors.warning_text),
            ("coverage", "📊  SCAN PROGRESS", "0%", Colors.info),
        ]
        self.metric_values: dict[str, ctk.CTkLabel] = {}

        for index, (key, title, initial, color) in enumerate(specs):
            card = ctk.CTkFrame(
                metrics, fg_color=Colors.surface,
                corner_radius=Spacing.RADIUS_CARD,
            )
            padx = (0, Spacing.CARD_GAP) if index < len(specs) - 1 else 0
            card.pack(side="left", fill="both", expand=True, padx=padx)

            ctk.CTkLabel(
                card, text=title,
                font=Fonts.badge(9), text_color=Colors.text_muted,
            ).pack(anchor="w", padx=16, pady=(14, 2))

            value = ctk.CTkLabel(
                card, text=initial,
                font=Fonts.title(22), text_color=color,
            )
            value.pack(anchor="w", padx=16, pady=(0, 14))
            self.metric_values[key] = value

    def _build_results(self, parent: ctk.CTkFrame) -> None:
        card = ctk.CTkFrame(
            parent, fg_color=Colors.surface,
            corner_radius=Spacing.RADIUS_CARD,
        )
        card.pack(fill="both", expand=True, pady=(0, 14))

        toolbar = ctk.CTkFrame(card, fg_color="transparent")
        toolbar.pack(fill="x", padx=16, pady=(14, 10))

        ctk.CTkLabel(
            toolbar, text="DISCOVERED ASSETS",
            font=Fonts.heading(11), text_color=Colors.text,
        ).pack(side="left")

        self.result_count = ctk.CTkLabel(
            toolbar, text="0 records",
            font=Fonts.label(10), text_color=Colors.text_muted,
        )
        self.result_count.pack(side="left", padx=12)

        ctk.CTkButton(
            toolbar, text="Settings", width=90,
            height=Spacing.BUTTON_HEIGHT,
            fg_color=Colors.neutral, hover_color=Colors.neutral_hover,
            command=self.open_settings,
        ).pack(side="right", padx=(7, 0))

        ctk.CTkButton(
            toolbar, text="History / Compare", width=150,
            height=Spacing.BUTTON_HEIGHT,
            fg_color=Colors.neutral, hover_color=Colors.neutral_hover,
            command=self.open_history,
        ).pack(side="right", padx=(7, 0))

        ctk.CTkButton(
            toolbar, text="Topology", width=100,
            height=Spacing.BUTTON_HEIGHT,
            fg_color=Colors.neutral, hover_color=Colors.neutral_hover,
            command=self.open_graph,
        ).pack(side="right")

        table_frame = ctk.CTkFrame(card, fg_color="transparent")
        table_frame.pack(fill="both", expand=True, padx=16, pady=(0, 16))

        columns = ("ip", "status", "ports", "services")
        self.tree = ttk.Treeview(
            table_frame, columns=columns, show="headings",
            selectmode="browse", style="Cyber.Treeview",
        )
        headings = {
            "ip": "IP ADDRESS", "status": "STATUS",
            "ports": "OPEN TCP PORTS", "services": "SERVICE HINTS",
        }
        widths = {"ip": 200, "status": 150, "ports": 230, "services": 420}
        for col in columns:
            self.tree.heading(col, text=headings[col])
            self.tree.column(
                col, width=widths[col], minwidth=90,
                anchor="w", stretch=(col == "services"),
            )

        self.tree.tag_configure("online", foreground=Colors.success_text)
        self.tree.tag_configure("offline", foreground=Colors.text_dim)

        scrollbar = ttk.Scrollbar(
            table_frame, orient="vertical", style="Vertical.TScrollbar",
            command=self.tree.yview,
        )
        self.tree.configure(yscrollcommand=scrollbar.set)
        self.tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

    def _build_footer(self, parent: ctk.CTkFrame) -> None:
        footer = ctk.CTkFrame(parent, fg_color="transparent")
        footer.pack(fill="x")

        self.log_panel = LogPanel(footer, height=140)
        self.log_panel.pack(side="left", fill="both", expand=True)

        exports = ctk.CTkFrame(footer, fg_color="transparent")
        exports.pack(side="right", fill="y", padx=(12, 0))

        ctk.CTkLabel(
            exports, text="EXPORT REPORT",
            font=Fonts.badge(9), text_color=Colors.text_muted,
        ).pack(anchor="w", pady=(0, 8))

        for label, command in (
            ("JSON", self.export_json),
            ("CSV", self.export_csv),
            ("HTML", self.export_html),
        ):
            ctk.CTkButton(
                exports, text=label, width=90,
                height=Spacing.BUTTON_HEIGHT,
                fg_color=Colors.neutral, hover_color=Colors.neutral_hover,
                command=command,
            ).pack(fill="x", pady=(0, 6))

    # ------------------------------------------------------------- How to Use

    def _show_how_to_use(self):
        """Show help for the Network Mapper."""
        dialog = ctk.CTkToplevel(self)
        dialog.title("How to Use | Network Mapper")
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
            outer, text="Network Mapper",
            font=Fonts.title(24), text_color=Colors.text_strong,
        ).pack(anchor="w", padx=28, pady=(6, 2))

        ctk.CTkFrame(outer, height=1, fg_color=Colors.border).pack(
            fill="x", padx=28, pady=16
        )

        help_text = (
            "Welcome to Network Mapper!\n\n"
            "1️⃣  SCAN TARGET\n"
            "•  Enter a single IP (e.g. 192.168.1.10) or a CIDR range\n"
            "   (e.g. 192.168.1.0/24, up to 1024 hosts).\n"
            "•  Click '▶ Start scan' or press Enter.\n"
            "•  Use 'Ⅱ Pause' and '■ Stop' to control the scan.\n\n"
            "2️⃣  METRICS\n"
            "•  HOSTS SCANNED: Total IPs processed so far.\n"
            "•  RESPONDED: Hosts that replied (ICMP or TCP).\n"
            "•  OPEN TCP PORTS: Total open ports found.\n"
            "•  SCAN PROGRESS: Percentage of the target list done.\n\n"
            "3️⃣  DISCOVERED ASSETS\n"
            "•  IP ADDRESS: The scanned host.\n"
            "•  STATUS: 'Responded' (green) or 'No response'.\n"
            "•  OPEN TCP PORTS: Comma-separated port numbers.\n"
            "•  SERVICE HINTS: Guessed service names (HTTP, SSH, etc.).\n\n"
            "4️⃣  TOOLS\n"
            "•  Topology: Visual overview of discovered hosts.\n"
            "•  History / Compare: View past scans and compare two.\n"
            "•  Settings: Change which TCP ports are probed.\n\n"
            "5️⃣  EXPORT\n"
            "•  JSON: Structured data for scripts.\n"
            "•  CSV: Spreadsheet-friendly table.\n"
            "•  HTML: Shareable report with styling.\n\n"
            "⚠  RESPONSIBLE USE\n"
            "Scan only networks you own or have explicit permission to assess."
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

    # ------------------------------------------------------------- scan flow

    def _parse_target(self, target: str) -> list[str]:
        if "/" in target:
            ips = cidr_to_range(target)
            if not ips:
                raise ValueError(
                    f"Invalid IPv4 CIDR or range too large. "
                    f"Limit: {MAX_HOSTS} usable hosts."
                )
            return ips
        try:
            return [str(ipaddress.IPv4Address(target))]
        except ipaddress.AddressValueError:
            raise ValueError("Enter a valid IPv4 address or an IPv4 CIDR range.")

    def start_scan(self) -> None:
        if self.scan_running:
            return

        target = self.target_entry.get().strip()
        try:
            ip_list = self._parse_target(target)
        except ValueError as exc:
            messagebox.showerror("Invalid target", str(exc), parent=self)
            return

        self.controller = ScanController()
        self.scan_running = True
        self.scan_started_at = datetime.now().astimezone().isoformat(timespec="seconds")
        self.scan_target = target
        self.results = []
        self._scan_total = len(ip_list)

        self.tree.delete(*self.tree.get_children())
        self.progress.set(0)
        self._set_scan_controls(True)
        self.status_badge.configure(
            text="●  SCANNING",
            fg_color=Colors.warning, text_color="#1A1305",
        )
        self.progress_label.configure(
            text=f"Preparing scan of {len(ip_list)} address(es)…"
        )
        self.log_panel.log(f"Scan started for {target} ({len(ip_list)} address(es)).")

        threading.Thread(
            target=self._scan_worker,
            args=(ip_list,),
            daemon=True,
        ).start()

    def _scan_worker(self, ip_list: list[str]) -> None:
        """Run the parallel network scan and stream results to the queue."""
        total = len(ip_list)
        progress = {"done": 0}

        def on_result(result) -> None:
            progress["done"] += 1
            self.scan_queue.put(("result", (progress["done"], total, result)))

        try:
            self.scanner.scan_network(ip_list, self.controller, on_result=on_result)
        except Exception as exc:
            self.scan_queue.put(("log", f"Scan loop failed: {exc}"))
        finally:
            self.scan_queue.put(("done", self.controller.stopped))

    def _poll_scan_queue(self) -> None:
        try:
            while True:
                kind, payload = self.scan_queue.get_nowait()
                if kind == "log":
                    self.log_panel.log(payload)
                elif kind == "result":
                    self._handle_result(*payload)
                elif kind == "done":
                    self._handle_done(payload)
        except queue.Empty:
            pass
        self.after(100, self._poll_scan_queue)

    def _handle_result(self, index: int, total: int, result) -> None:
        self.results.append(result)
        ports = ", ".join(map(str, result.open_ports)) or "—"
        services = ", ".join(
            f"{p}: {s}" for p, s in result.services.items()
        ) or "—"
        status = "Responded" if result.online else "No response"
        self.tree.insert(
            "", "end",
            values=(result.ip, status, ports, services),
            tags=("online" if result.online else "offline",),
        )
        self.progress.set(index / total if total else 0)
        self.progress_label.configure(text=f"Processed {index} of {total} addresses")
        self._update_metrics(index)

    def _handle_done(self, stopped: bool) -> None:
        self.scan_running = False
        self._set_scan_controls(False)
        self.status_badge.configure(
            text="●  STOPPED" if stopped else "●  COMPLETE",
            fg_color=Colors.danger if stopped else Colors.success,
            text_color=Colors.danger_text if stopped else Colors.success_text,
        )
        self.progress_label.configure(
            text=f"Scan {'stopped' if stopped else 'completed'} · "
                 f"{len(self.results)} result(s) recorded"
        )
        self.log_panel.log(
            f"Scan {'stopped' if stopped else 'completed'}; "
            f"{len(self.results)} result(s) recorded."
        )
        self._save_scan_history(stopped)

    def _update_metrics(self, count: int) -> None:
        online = sum(1 for r in self.results if r.online)
        ports = sum(len(r.open_ports) for r in self.results)
        self.metric_values["hosts"].configure(text=str(count))
        self.metric_values["online"].configure(text=str(online))
        self.metric_values["ports"].configure(text=str(ports))
        total = getattr(self, "_scan_total", 0)
        percent = int(count / total * 100) if total else 0
        self.metric_values["coverage"].configure(text=f"{percent}%")
        self.result_count.configure(text=f"{len(self.results)} records")

    def _set_scan_controls(self, active: bool) -> None:
        state = "disabled" if active else "normal"
        self.scan_button.configure(state=state)
        self.pause_button.configure(
            state="normal" if active else "disabled", text="Ⅱ  Pause"
        )
        self.stop_button.configure(state="normal" if active else "disabled")
        self.target_entry.configure(state=state)

    def toggle_pause(self) -> None:
        if not self.scan_running:
            return
        if self.controller.paused:
            self.controller.resume()
            self.pause_button.configure(text="Ⅱ  Pause")
            self.status_badge.configure(
                text="●  SCANNING",
                fg_color=Colors.warning, text_color="#1A1305",
            )
            self.log_panel.log("Scan resumed.")
        else:
            self.controller.pause()
            self.pause_button.configure(text="▶  Resume")
            self.status_badge.configure(
                text="●  PAUSED",
                fg_color=Colors.info, text_color="#062130",
            )
            self.log_panel.log(
                "Pause requested; probes already in flight will finish."
            )

    def stop_scan(self) -> None:
        self.controller.stop()
        self.log_panel.log("Stop requested…")

    # ------------------------------------------------------------- history

    def _history_path(self) -> Path:
        """Return the path to the scan-history JSON file.

        Uses the shared :func:`core.utils.paths.config_root` helper so the
        location matches the rest of the suite (Windows: %APPDATA%, Linux:
        ~/.config).
        """
        base = config_root("NetworkMapper")
        return base / "scan_history.json"

    def _save_scan_history(self, stopped: bool = False) -> None:
        """Persist compact scan summaries for later comparison."""
        session = {
            "id": datetime.now().astimezone().strftime("%Y%m%dT%H%M%S%f"),
            "started_at": (
                self.scan_started_at
                or datetime.now().astimezone().isoformat(timespec="seconds")
            ),
            "finished_at": datetime.now().astimezone().isoformat(timespec="seconds"),
            "target": self.scan_target,
            "stopped": bool(stopped),
            "hosts_scanned": len(self.results),
            "responded": sum(1 for r in self.results if r.online),
            "open_ports": sum(len(r.open_ports) for r in self.results),
            "results": [
                {
                    "ip": r.ip,
                    "online": bool(r.online),
                    "open_ports": list(r.open_ports),
                    "services": dict(r.services),
                }
                for r in self.results
            ],
        }
        try:
            path = self._history_path()
            history = json.loads(path.read_text(encoding="utf-8")) if path.exists() else []
            if not isinstance(history, list):
                history = []
            history.append(session)
            path.write_text(
                json.dumps(history[-100:], indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
            self.log_panel.log("Scan summary saved to local history.")
        except (OSError, ValueError) as exc:
            self.log_panel.log(f"Could not save scan history: {exc}")

    # ------------------------------------------------------------- dialogs

    def open_history(self) -> None:
        try:
            HistoryWindow(self, self._history_path())
        except OSError as exc:
            messagebox.showerror("History unavailable", str(exc), parent=self)

    def open_settings(self) -> None:
        SettingsWindow(self)

    def open_graph(self) -> None:
        if not self.results:
            messagebox.showinfo(
                "No results",
                "Run a scan before opening topology.",
                parent=self,
            )
            return
        try:
            GraphWindow(self, self.results)
        except ImportError as exc:
            messagebox.showerror(
                "Topology unavailable",
                f"Graph dependencies are missing: {exc}",
                parent=self,
            )

    def open_about(self) -> None:
        """Show product information and safe-use guidance."""
        if self._about_open:
            return
        self._about_open = True

        # Hide Help button on About page (grid_remove keeps position)
        self.help_btn.grid_remove()

        dialog = ctk.CTkToplevel(self)
        dialog.title("About Network Mapper")
        dialog.configure(fg_color=Colors.bg)
        dialog.resizable(False, False)
        dialog.transient(self)
        dialog.grab_set()
        dialog.geometry("620x680")

        apply_window_icon(dialog)

        def on_close():
            dialog.destroy()
            # Restore Help button at the SAME grid position
            self.help_btn.grid(row=0, column=0, padx=(0, 8), pady=0)
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
            card, text="Network Mapper",
            font=Fonts.title(22), text_color=Colors.text,
        ).pack(anchor="w", padx=26, pady=(6, 2))

        ctk.CTkLabel(
            card,
            text=f"Version {APP_VERSION}  ·  Network visibility & asset overview",
            font=Fonts.label(10), text_color=Colors.text_muted,
        ).pack(anchor="w", padx=26)

        divider = ctk.CTkFrame(card, fg_color=Colors.border, height=1)
        divider.pack(fill="x", padx=26, pady=14)

        # Runtime info
        os_name = f"{platform.system()} {platform.release()}"
        py_version = platform.python_version()
        cfg_path = config_root_quiet("NetworkMapper")

        info_frame = ctk.CTkFrame(
            card, fg_color=Colors.bg,
            corner_radius=Spacing.RADIUS_INPUT,
            border_width=1, border_color=Colors.border,
        )
        info_frame.pack(fill="x", padx=26, pady=(0, 12))

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

        description = (
            "A lightweight desktop utility for discovering responsive hosts, "
            "checking selected TCP ports, and reviewing scan results.\n\n"
            "FEATURES\n"
            "• Host discovery (ICMP + TCP)\n"
            "• Service hints from open ports\n"
            "• Pause/Stop controls between probes\n"
            "• Topology overview\n"
            "• JSON / CSV / HTML report export\n"
            "• Scan history with two-way comparison\n\n"
            "SUPPORTED PLATFORMS\n"
            "• Windows 10 / 11 / Server 2019+\n"
            "• Linux (any distribution with ping)\n"
            "• macOS is not officially supported.\n\n"
            "RESPONSIBLE USE\n"
            "Scan only networks and devices you own or have explicit "
            "permission to assess. A missing response does not prove "
            "that a host is offline."
        )
        ctk.CTkLabel(
            card, text=description,
            font=Fonts.label(11), text_color=Colors.text,
            justify="left", anchor="w",
            wraplength=540,
        ).pack(fill="x", padx=26)

        footer = ctk.CTkFrame(card, fg_color="transparent")
        footer.pack(side="bottom", fill="x", padx=26, pady=(18, 22))

        ctk.CTkButton(
            footer, text="Close",
            width=140, height=38,
            fg_color=Colors.primary, hover_color=Colors.primary_hover,
            font=Fonts.label(11, bold=True),
            command=on_close,
        ).pack(side="right")

        ctk.CTkLabel(
            footer, text="CyberOpsSuite · Network tools",
            font=Fonts.label(9), text_color=Colors.text_dim,
        ).pack(side="left")

        dialog.bind("<Escape>", lambda _e: on_close())
        dialog.bind("<Return>", lambda _e: on_close())
        dialog.update_idletasks()
        x = self.winfo_rootx() + (self.winfo_width() - dialog.winfo_width()) // 2
        y = self.winfo_rooty() + (self.winfo_height() - dialog.winfo_height()) // 2
        dialog.geometry(f"+{max(0, x)}+{max(0, y)}")

    # ------------------------------------------------------------- export

    def _export(self, exporter, extension: str) -> None:
        if not self.results:
            messagebox.showinfo(
                "No results",
                "There are no scan results to export yet.",
                parent=self,
            )
            return

        path = filedialog.asksaveasfilename(
            parent=self,
            defaultextension=extension,
            filetypes=[(extension.upper().lstrip("."), f"*{extension}")],
        )
        if not path:
            return

        try:
            exporter(self.results, path)
            messagebox.showinfo(
                "Export complete",
                f"Report saved to:\n{path}",
                parent=self,
            )
            self.log_panel.log(f"Exported report: {path}")
        except OSError as exc:
            messagebox.showerror("Export failed", str(exc), parent=self)

    def export_json(self) -> None:
        self._export(export_json, ".json")

    def export_csv(self) -> None:
        self._export(export_csv, ".csv")

    def export_html(self) -> None:
        self._export(export_html, ".html")


def main() -> None:
    app = NetworkMapperGUI()
    app.mainloop()


if __name__ == "__main__":
    main()