"""Network Logs tab (Syslog / NetFlow) for the Event Log Analyzer GUI.

Fixes compared with the code that used to live in ``gui/main.py``:

* the table is updated incrementally (new rows only) instead of being deleted
  and rebuilt four times a second - no more lag on busy networks;
* newest events are on top and "Follow newest" really follows them (it used
  to scroll to the *oldest* row);
* the details window shows the row you clicked (it used to match on
  timestamp + id + source, which is ambiguous for NetFlow);
* the allow-list is validated, port presets match the selected mode;
* Pause freezes the display while capture continues;
* live counters explain why nothing shows up (rejected / malformed /
  unsupported NetFlow version / dropped);
* "Send Test" sends a sample event to the local listener to verify the setup.
"""

from __future__ import annotations

import re
import time
import tkinter as tk
from collections import deque
from collections.abc import Callable
from tkinter import filedialog, messagebox, ttk

import customtkinter as ctk

from core.theme import Colors, Fonts, Spacing
from core.utils.icons import apply_window_icon

from event_log_analyzer.core.exporters import write_csv
from event_log_analyzer.core.levels import FILTER_LEVELS, normalize_level
from event_log_analyzer.core.listeners import (
    AllowListError,
    UdpListener,
    guess_local_ip,
    parse_allow_list,
)
from event_log_analyzer.core.netflow_events import (
    DEFAULT_NETFLOW_PORT,
    NetFlowListener,
    send_test_packet,
)
from event_log_analyzer.core.parser import LogEntry
from event_log_analyzer.core.syslog_events import (
    DEFAULT_SYSLOG_PORT,
    SyslogListener,
    send_test_message,
)

MODE_SYSLOG = "Syslog"
MODE_NETFLOW = "NetFlow"

#: Events kept in memory (oldest are discarded).
MAX_STORED_EVENTS = 20000
#: Rows drawn in the table at once.
MAX_TABLE_ROWS = 2000
#: Events moved from the listener queue to the UI per tick (keeps UI responsive).
DRAIN_BATCH = 500
DRAIN_INTERVAL_MS = 200
STATS_INTERVAL_MS = 1000

PORT_PRESETS: dict[str, dict[int, str]] = {
    MODE_SYSLOG: {
        5140: "Syslog (unprivileged, default)",
        514: "Syslog (standard, needs admin/root)",
        1514: "Syslog (alternative)",
    },
    MODE_NETFLOW: {
        2055: "NetFlow (standard)",
        9995: "NetFlow (alternative)",
        9996: "NetFlow (alternative)",
    },
}
DEFAULT_PORTS = {MODE_SYSLOG: DEFAULT_SYSLOG_PORT, MODE_NETFLOW: DEFAULT_NETFLOW_PORT}

_LEADING_DIGITS = re.compile(r"^\s*(\d+)")


def parse_port(text: str) -> int:
    """``"5140"`` or ``"5140 - Syslog"`` -> 5140. Raises ``ValueError``."""
    match = _LEADING_DIGITS.match(text or "")
    if not match:
        raise ValueError("Port must be a number between 1 and 65535.")
    port = int(match.group(1))
    if not 1 <= port <= 65535:
        raise ValueError("Port must be a number between 1 and 65535.")
    return port


def entry_matches(entry: LogEntry, level: str, needle: str) -> bool:
    """Level + case-insensitive text filter used by the live table."""
    if level != "ALL" and normalize_level(entry.level) != level:
        return False
    if needle:
        haystack = f"{entry.message} {entry.source} {entry.event_id} {entry.machine}"
        return needle in haystack.casefold()
    return True


class NetworkTab(ctk.CTkFrame):
    """Self-contained network capture tab. Embed it in a tab of the main window."""

    def __init__(
        self,
        parent,
        status_callback: Callable[[str], None] | None = None,
    ) -> None:
        super().__init__(parent, fg_color="transparent")
        self._status = status_callback or (lambda _msg: None)

        self.mode_var = tk.StringVar(value=MODE_SYSLOG)
        self.port_var = tk.StringVar(value=str(DEFAULT_SYSLOG_PORT))
        self.allow_var = tk.StringVar(value="")
        self.level_var = tk.StringVar(value="ALL")
        self.search_var = tk.StringVar(value="")
        self.follow_var = tk.BooleanVar(value=True)
        self.stats_var = tk.StringVar(value="Listener stopped.")

        self._listener: UdpListener | None = None
        self._paused = False
        self._events: deque[LogEntry] = deque(maxlen=MAX_STORED_EVENTS)
        self._pending: list[LogEntry] = []        # captured while paused
        self._row_entries: dict[str, LogEntry] = {}
        self._row_order: deque[str] = deque()     # iids, oldest -> newest
        self._next_iid = 0
        self._drain_after: str | None = None
        self._stats_after: str | None = None
        self._filter_after: str | None = None
        self._last_rate_check = (time.monotonic(), 0)
        self._rate = 0.0

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)
        self._build_controls()
        self._build_table()
        self._on_mode_changed(MODE_SYSLOG)

    # ----------------------------------------------------------------- build

    def _menu(self, parent, **kwargs):
        return ctk.CTkOptionMenu(
            parent,
            fg_color=Colors.primary, button_color=Colors.primary_hover,
            button_hover_color=Colors.primary_active,
            dropdown_fg_color=Colors.surface,
            dropdown_hover_color=Colors.primary,
            **kwargs,
        )

    def _label(self, parent, text):
        return ctk.CTkLabel(parent, text=text, font=Fonts.label(12), text_color=Colors.text)

    def _build_controls(self) -> None:
        bar = ctk.CTkFrame(
            self, corner_radius=Spacing.RADIUS_CARD, fg_color=Colors.surface,
            border_width=1, border_color=Colors.border,
        )
        bar.grid(row=0, column=0, sticky="ew", padx=8, pady=(8, 6))
        bar.grid_columnconfigure(5, weight=1)

        # ---- row 0: listener setup
        self._label(bar, "Mode").grid(row=0, column=0, padx=(12, 6), pady=(10, 5))
        self.mode_menu = self._menu(
            bar, variable=self.mode_var, values=[MODE_SYSLOG, MODE_NETFLOW],
            width=115, command=self._on_mode_changed,
        )
        self.mode_menu.grid(row=0, column=1, padx=5, pady=(10, 5))

        self._label(bar, "UDP port").grid(row=0, column=2, padx=(10, 5), pady=(10, 5))
        self.port_combo = ctk.CTkComboBox(
            bar, variable=self.port_var, values=[], width=230,
            fg_color=Colors.bg, border_color=Colors.border_light,
            text_color=Colors.text, button_color=Colors.primary,
            button_hover_color=Colors.primary_hover,
            dropdown_fg_color=Colors.surface, dropdown_hover_color=Colors.primary,
            command=self._on_port_picked,
        )
        self.port_combo.grid(row=0, column=3, padx=5, pady=(10, 5))

        self._label(bar, "Allow IPs").grid(row=0, column=4, padx=(10, 5), pady=(10, 5))
        self.allow_entry = ctk.CTkEntry(
            bar, textvariable=self.allow_var, height=Spacing.INPUT_HEIGHT,
            fg_color=Colors.bg, border_color=Colors.border_light,
            text_color=Colors.text,
            placeholder_text="empty = accept all, e.g. 192.168.1.1, 10.0.0.5",
        )
        self.allow_entry.grid(row=0, column=5, sticky="ew", padx=5, pady=(10, 5))

        self.start_btn = ctk.CTkButton(
            bar, text="Start Listener", width=125, height=Spacing.BUTTON_HEIGHT,
            fg_color=Colors.primary, hover_color=Colors.primary_hover,
            command=self.toggle_listener,
        )
        self.start_btn.grid(row=0, column=6, padx=(10, 6), pady=(10, 5))

        self.test_btn = ctk.CTkButton(
            bar, text="Send Test", width=95, height=Spacing.BUTTON_HEIGHT,
            fg_color=Colors.neutral_dark, hover_color=Colors.neutral_dark_hover,
            state="disabled", command=self.send_test,
        )
        self.test_btn.grid(row=0, column=7, padx=(0, 12), pady=(10, 5))

        # ---- row 1: filters and actions
        self._label(bar, "Level").grid(row=1, column=0, padx=(12, 6), pady=(5, 5), sticky="w")
        self._menu(
            bar, variable=self.level_var, values=list(FILTER_LEVELS), width=115,
            command=lambda _v: self._schedule_rebuild(),
        ).grid(row=1, column=1, padx=5, pady=(5, 5), sticky="w")

        self._label(bar, "Search").grid(row=1, column=2, padx=(10, 5), pady=(5, 5), sticky="e")
        self.search_entry = ctk.CTkEntry(
            bar, textvariable=self.search_var, height=Spacing.INPUT_HEIGHT,
            placeholder_text="IP, port, host or message...",
            fg_color=Colors.bg, border_color=Colors.border_light,
            text_color=Colors.text,
        )
        self.search_entry.grid(row=1, column=3, columnspan=3, sticky="ew", padx=5, pady=(5, 5))
        self.search_entry.bind("<KeyRelease>", lambda _e: self._schedule_rebuild())

        actions = ctk.CTkFrame(bar, fg_color="transparent")
        actions.grid(row=1, column=6, columnspan=2, sticky="e", padx=(0, 12), pady=(5, 5))

        self.pause_btn = ctk.CTkButton(
            actions, text="Pause", width=75, height=Spacing.BUTTON_HEIGHT,
            fg_color=Colors.neutral_dark, hover_color=Colors.neutral_dark_hover,
            command=self.toggle_pause,
        )
        self.pause_btn.pack(side="left", padx=(0, 6))
        ctk.CTkButton(
            actions, text="Clear", width=70, height=Spacing.BUTTON_HEIGHT,
            fg_color=Colors.neutral_dark, hover_color=Colors.neutral_dark_hover,
            command=self.clear_events,
        ).pack(side="left", padx=(0, 6))
        ctk.CTkButton(
            actions, text="Export CSV", width=95, height=Spacing.BUTTON_HEIGHT,
            fg_color=Colors.neutral, hover_color=Colors.neutral_hover,
            command=self.export_csv,
        ).pack(side="left")

        # ---- row 2: follow + live stats
        ctk.CTkCheckBox(
            bar, text="Follow newest", variable=self.follow_var,
            font=Fonts.label(11), text_color=Colors.text,
            fg_color=Colors.primary, hover_color=Colors.primary_hover,
            border_color=Colors.border_light,
        ).grid(row=2, column=0, columnspan=3, sticky="w", padx=12, pady=(0, 10))

        self.stats_label = ctk.CTkLabel(
            bar, textvariable=self.stats_var, anchor="e",
            font=Fonts.label(11), text_color=Colors.text_muted,
        )
        self.stats_label.grid(row=2, column=3, columnspan=5, sticky="e", padx=12, pady=(0, 10))

    def _build_table(self) -> None:
        frame = ctk.CTkFrame(
            self, corner_radius=Spacing.RADIUS_CARD, fg_color=Colors.surface,
            border_width=1, border_color=Colors.border,
        )
        frame.grid(row=1, column=0, sticky="nsew", padx=8, pady=(0, 8))
        frame.grid_rowconfigure(0, weight=1)
        frame.grid_columnconfigure(0, weight=1)

        columns = ("time", "level", "source", "event_id", "machine", "message")
        headings = {
            "time": "Timestamp", "level": "Level", "source": "Source",
            "event_id": "Event ID", "machine": "Host / Exporter", "message": "Message",
        }
        widths = {"time": 160, "level": 85, "source": 190,
                  "event_id": 120, "machine": 140, "message": 500}

        self.tree = ttk.Treeview(
            frame, columns=columns, show="headings",
            selectmode="browse", style="Cyber.Treeview",
        )
        for col in columns:
            self.tree.heading(col, text=headings[col])
            self.tree.column(col, width=widths[col], minwidth=60,
                             anchor="w", stretch=(col == "message"))
        self.tree.tag_configure("CRITICAL", foreground=Colors.danger_text)
        self.tree.tag_configure("ERROR", foreground=Colors.danger_light)
        self.tree.tag_configure("WARNING", foreground=Colors.warning_text)

        yscroll = ttk.Scrollbar(
            frame, orient="vertical", style="Vertical.TScrollbar",
            command=self.tree.yview,
        )
        self.tree.configure(yscrollcommand=yscroll.set)
        self.tree.grid(row=0, column=0, sticky="nsew", padx=(8, 0), pady=8)
        yscroll.grid(row=0, column=1, sticky="ns", pady=8, padx=(0, 8))

        self.tree.bind("<Double-1>", self._show_details)
        self.tree.bind("<Return>", self._show_details)
        self.tree.bind("<Control-c>", self._copy_selected)

        self._menu_popup = tk.Menu(self.tree, tearoff=0)
        self._menu_popup.add_command(label="Copy message", command=self._copy_selected)
        self._menu_popup.add_command(label="Details...", command=self._show_details)
        self.tree.bind("<Button-3>", self._popup_menu)

    # -------------------------------------------------------------- settings

    def _on_mode_changed(self, mode: str) -> None:
        presets = PORT_PRESETS[mode]
        self.port_combo.configure(values=[f"{p} - {name}" for p, name in presets.items()])
        self.port_var.set(str(DEFAULT_PORTS[mode]))
        self.search_entry.configure(
            placeholder_text=(
                "IP, port, host or message..." if mode == MODE_SYSLOG
                else "IP, port, protocol or service (e.g. RDP)..."
            )
        )

    def _on_port_picked(self, value: str) -> None:
        match = _LEADING_DIGITS.match(value)
        if match:
            self.port_var.set(match.group(1))

    # ------------------------------------------------------------- listener

    @property
    def running(self) -> bool:
        return self._listener is not None and self._listener.running

    def toggle_listener(self) -> None:
        if self.running:
            self.stop_listener()
        else:
            self.start_listener()

    def start_listener(self) -> None:
        mode = self.mode_var.get()
        try:
            port = parse_port(self.port_var.get())
            allow = parse_allow_list(self.allow_var.get())
        except (ValueError, AllowListError) as exc:
            messagebox.showwarning("Network listener", str(exc), parent=self)
            return

        cls = SyslogListener if mode == MODE_SYSLOG else NetFlowListener
        listener = cls(port=port, allow_ips=allow)
        try:
            listener.start()
        except RuntimeError as exc:
            messagebox.showerror("Listener error", str(exc), parent=self)
            return

        self._listener = listener
        self._set_controls_running(True)
        target = f"{guess_local_ip()}:{port}"
        who = f"only {', '.join(sorted(allow))}" if allow else "any sender"
        self._status(
            f"{mode} listener running on UDP {port} ({who}). "
            f"Point your device to {target}."
        )
        self._last_rate_check = (time.monotonic(), 0)
        self._schedule_drain()
        self._schedule_stats()

    def stop_listener(self) -> None:
        listener = self._listener
        if listener is not None:
            listener.stop()
            self._ingest(listener.drain(MAX_STORED_EVENTS))  # keep what was queued
            self._update_stats()
        self._listener = None
        for attr in ("_drain_after", "_stats_after"):
            self._cancel(attr)
        self._set_controls_running(False)
        self._update_stats()
        self._status("Network listener stopped.")

    def shutdown(self) -> None:
        """Release the socket and timers (call when the window closes)."""
        if self._listener is not None:
            self._listener.stop()
            self._listener = None
        for attr in ("_drain_after", "_stats_after", "_filter_after"):
            self._cancel(attr)

    def _set_controls_running(self, running: bool) -> None:
        if running:
            self.start_btn.configure(
                text="Stop Listener",
                fg_color=Colors.danger, hover_color=Colors.danger_text,
            )
        else:
            self.start_btn.configure(
                text="Start Listener",
                fg_color=Colors.primary, hover_color=Colors.primary_hover,
            )
        state = "disabled" if running else "normal"
        self.mode_menu.configure(state=state)
        self.port_combo.configure(state=state)
        self.allow_entry.configure(state=state)
        self.test_btn.configure(state="normal" if running else "disabled")

    def send_test(self) -> None:
        listener = self._listener
        if listener is None:
            return
        try:
            if isinstance(listener, SyslogListener):
                send_test_message(listener.port)
            else:
                send_test_packet(listener.port)
        except OSError as exc:
            messagebox.showerror("Send Test", f"Could not send the test packet: {exc}", parent=self)
            return
        if listener.allow_ips and "127.0.0.1" not in listener.allow_ips:
            self._status(
                "Test sent from 127.0.0.1, but your allow-list does not include it, "
                "so it will be rejected (see the counters)."
            )
        else:
            self._status("Test event sent to the local listener.")

    # ------------------------------------------------------------- timers

    def _cancel(self, attr: str) -> None:
        after_id = getattr(self, attr)
        if after_id is not None:
            try:
                self.after_cancel(after_id)
            except (tk.TclError, ValueError):
                pass
            setattr(self, attr, None)

    def _schedule_drain(self) -> None:
        self._drain_after = self.after(DRAIN_INTERVAL_MS, self._drain_tick)

    def _schedule_stats(self) -> None:
        self._stats_after = self.after(STATS_INTERVAL_MS, self._stats_tick)

    def _drain_tick(self) -> None:
        self._drain_after = None
        listener = self._listener
        if listener is None:
            return
        try:
            self._ingest(listener.drain(DRAIN_BATCH))
            if listener.running:
                self._schedule_drain()
        except tk.TclError:
            return  # window is being destroyed

    def _stats_tick(self) -> None:
        self._stats_after = None
        try:
            self._update_stats()
            if self.running:
                self._schedule_stats()
        except tk.TclError:
            return

    # ------------------------------------------------------------- data flow

    def _ingest(self, batch: list[LogEntry]) -> None:
        if not batch:
            return
        self._events.extend(batch)
        if self._paused:
            self._pending.extend(batch)
            if len(self._pending) > MAX_STORED_EVENTS:
                del self._pending[: len(self._pending) - MAX_STORED_EVENTS]
            return
        self._append_rows(batch)

    def _current_filter(self) -> tuple[str, str]:
        return self.level_var.get(), self.search_var.get().strip().casefold()

    def _append_rows(self, batch: list[LogEntry]) -> None:
        level, needle = self._current_filter()
        for entry in batch:
            if entry_matches(entry, level, needle):
                self._insert_row(entry)
        while len(self._row_order) > MAX_TABLE_ROWS:
            old = self._row_order.popleft()
            self._row_entries.pop(old, None)
            try:
                self.tree.delete(old)
            except tk.TclError:
                pass
        if self.follow_var.get():
            self.tree.yview_moveto(0)  # newest rows are inserted on top

    def _insert_row(self, entry: LogEntry) -> None:
        iid = str(self._next_iid)
        self._next_iid += 1
        message = " ".join(str(entry.message).split())
        if len(message) > 240:
            message = message[:237] + "..."
        level = normalize_level(entry.level)
        self.tree.insert(
            "", 0, iid=iid,
            values=(entry.timestamp, level, entry.source,
                    entry.event_id, entry.machine, message),
            tags=(level,),
        )
        self._row_entries[iid] = entry
        self._row_order.append(iid)

    def _schedule_rebuild(self) -> None:
        """Debounce: rebuild once the user stops typing."""
        self._cancel("_filter_after")
        self._filter_after = self.after(200, self._rebuild_table)

    def _rebuild_table(self) -> None:
        self._filter_after = None
        self.tree.delete(*self.tree.get_children())
        self._row_entries.clear()
        self._row_order.clear()
        level, needle = self._current_filter()
        matching = [e for e in self._events if entry_matches(e, level, needle)]
        for entry in matching[-MAX_TABLE_ROWS:]:  # oldest first -> newest ends on top
            self._insert_row(entry)
        self._pending.clear()
        self._update_stats()

    def toggle_pause(self) -> None:
        self._paused = not self._paused
        if self._paused:
            self.pause_btn.configure(text="Resume", fg_color=Colors.warning,
                                     hover_color=Colors.warning_text)
            self._status("Display paused - capture continues in the background.")
        else:
            self.pause_btn.configure(text="Pause", fg_color=Colors.neutral_dark,
                                     hover_color=Colors.neutral_dark_hover)
            pending, self._pending = self._pending, []
            self._append_rows(pending)
            self._status("Display resumed.")

    def clear_events(self) -> None:
        self._events.clear()
        self._pending.clear()
        self.level_var.set("ALL")
        self.search_var.set("")
        self._rebuild_table()
        self._status("Network events and filters cleared.")

    clear_filters = clear_events  # Ctrl+L in the main window

    def _update_stats(self) -> None:
        listener = self._listener
        if listener is None:
            self.stats_var.set(f"Stored: {len(self._events):,} events  |  listener stopped")
            return
        s = listener.stats
        now = time.monotonic()
        last_time, last_events = self._last_rate_check
        if now - last_time >= 1.0:
            self._rate = (s.events - last_events) / (now - last_time)
            self._last_rate_check = (now, s.events)
        parts = [
            f"Packets {s.packets:,}",
            f"Events {s.events:,}",
            f"{self._rate:.0f}/s",
            f"Shown {len(self._row_order):,}",
        ]
        if s.rejected:
            parts.append(f"Rejected {s.rejected:,}")
        if s.malformed:
            parts.append(f"Malformed {s.malformed:,}")
        if s.queue_dropped:
            parts.append(f"Dropped {s.queue_dropped:,}")
        if self._paused:
            parts.append(f"Paused (+{len(self._pending):,} waiting)")
        text = "  |  ".join(parts)
        if s.unsupported:
            text = f"{s.last_unsupported}  |  {text}"
        self.stats_var.set(text)
        self.stats_label.configure(
            text_color=Colors.warning_text if s.unsupported else Colors.text_muted
        )

    # ------------------------------------------------------------- row actions

    def _selected_entry(self) -> LogEntry | None:
        selection = self.tree.selection()
        if not selection:
            return None
        return self._row_entries.get(selection[0])

    def _popup_menu(self, event) -> None:
        row = self.tree.identify_row(event.y)
        if row:
            self.tree.selection_set(row)
            self._menu_popup.tk_popup(event.x_root, event.y_root)

    def _copy_selected(self, _event=None) -> str:
        entry = self._selected_entry()
        if entry is not None:
            self.clipboard_clear()
            self.clipboard_append(entry.message)
            self._status("Message copied to the clipboard.")
        return "break"

    def _show_details(self, _event=None) -> None:
        entry = self._selected_entry()
        if entry is None:
            return

        win = ctk.CTkToplevel(self)
        win.title("Network Event Details")
        win.geometry("720x520")
        win.minsize(520, 350)
        win.configure(fg_color=Colors.bg)
        win.transient(self.winfo_toplevel())
        win.grid_columnconfigure(0, weight=1)
        win.grid_rowconfigure(1, weight=1)
        apply_window_icon(win)

        ctk.CTkLabel(
            win, text=f"{entry.level}  |  {entry.event_id}",
            font=Fonts.heading(18), anchor="w", text_color=Colors.text,
        ).grid(row=0, column=0, sticky="ew", padx=18, pady=(18, 8))

        box = ctk.CTkTextbox(
            win, wrap="word", font=Fonts.label(12),
            fg_color=Colors.surface, text_color=Colors.text,
            border_color=Colors.border, border_width=1,
        )
        box.grid(row=1, column=0, sticky="nsew", padx=18, pady=(0, 12))

        lines = [
            f"Timestamp: {entry.timestamp}",
            f"Level: {entry.level}",
            f"Source: {entry.source}",
            f"Event ID: {entry.event_id}",
            f"Host / Exporter: {entry.machine}",
            "",
            "Message:",
            entry.message,
        ]
        if entry.raw:
            lines += ["", "Raw fields:"]
            lines += [f"  {key}: {value}" for key, value in entry.raw.items()]
        box.insert("1.0", "\n".join(lines))
        box.configure(state="disabled")

        ctk.CTkButton(
            win, text="Close", width=120, height=Spacing.BUTTON_HEIGHT,
            fg_color=Colors.primary, hover_color=Colors.primary_hover,
            command=win.destroy,
        ).grid(row=2, column=0, sticky="e", padx=18, pady=(0, 16))
        win.bind("<Escape>", lambda _e: win.destroy())

    # ------------------------------------------------------------------ export

    def export_csv(self) -> None:
        level, needle = self._current_filter()
        entries = [e for e in self._events if entry_matches(e, level, needle)]
        if not entries:
            messagebox.showinfo("Export", "No network events to export.", parent=self)
            return
        path = filedialog.asksaveasfilename(
            title="Export network events",
            defaultextension=".csv",
            filetypes=[("CSV file", "*.csv")],
            initialfile="network_events.csv",
        )
        if not path:
            return
        try:
            with open(path, "w", newline="", encoding="utf-8-sig") as handle:
                count = write_csv(entries, handle)
        except OSError as exc:
            messagebox.showerror("Export failed", str(exc), parent=self)
            return
        self._status(f"Exported {count:,} network events (current filter applied).")

    # ----------------------------------------------------------------- focus

    def focus_search(self) -> None:
        self.search_entry.focus_set()
        self.search_entry.select_range(0, "end")
