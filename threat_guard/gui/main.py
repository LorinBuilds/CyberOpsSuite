from __future__ import annotations

import argparse
import json
import sys
import threading
from pathlib import Path
from tkinter import filedialog, messagebox

import customtkinter as ctk
from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from PIL import Image

# Resolve the suite root in the same way as the other CyberOpsSuite modules.
PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from threat_guard.gui.theme import Colors, Fonts, Spacing, apply_window_icon, apply_dialog_icon
from threat_guard.engine.scanner import ThreatScanner
from threat_guard.engine.audit import local_security_audit

# ---- Optional subsystems ----
try:
    from threat_guard.engine.protection import ProtectionManager, full_review, make_scanner
    GUARD_AVAILABLE = True
except Exception:
    ProtectionManager = None
    full_review = None
    make_scanner = None
    GUARD_AVAILABLE = False

try:
    from threat_guard.utils.notifications import notify, set_tray_notifier
except Exception:
    def notify(title: str, message: str, timeout: int = 10) -> bool:
        return False

    def set_tray_notifier(func) -> None:
        return None

try:
    from threat_guard.utils.startup import (
        is_enabled_startup_folder,
        enable_startup_folder,
        disable_startup_folder,
    )
    STARTUP_AVAILABLE = True
except Exception:
    def is_enabled_startup_folder() -> bool: return False
    def enable_startup_folder(): return None
    def disable_startup_folder() -> bool: return False
    STARTUP_AVAILABLE = False

try:
    import pystray
    TRAY_AVAILABLE = True
except Exception:
    pystray = None
    TRAY_AVAILABLE = False


APP_NAME = "ThreatGuard"
APP_VERSION = "0.4.0"
GUARD_INTERVAL_SECONDS = 600

def _c(name: str, fallback: str) -> str:
    return getattr(Colors, name, fallback)


class ThreatGuardApp(ctk.CTk):
    def __init__(
        self,
        auto_start_guard: bool = False,
        initial_target: str | None = None,
    ) -> None:
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("dark-blue")
        super().__init__()
        self.title(f"CyberOpsSuite | {APP_NAME}")
        self.geometry("1180x850")
        self.minsize(1000, 720)
        self.configure(fg_color=Colors.bg_alt)

        # ---- State ----
        self.target = ctk.StringVar()
        self.status = ctk.StringVar(value="Ready · Read-only protection")
        self.scanned_value = ctk.StringVar(value="—")
        self.findings_value = ctk.StringVar(value="—")
        self.skipped_value = ctk.StringVar(value="—")
        self.risk_value = ctk.StringVar(value="NOT SCANNED")
        self.guard_status_var = ctk.StringVar(value="Protection: Off")
        
        self._last_report: dict | None = None
        self._busy = False
        self._cancel_event = threading.Event()
        self._dialogs: dict[str, ctk.CTkToplevel] = {}
        
        # Data for Charts
        self.scan_history: list[tuple[int, int]] = [] # (scanned, threats)
        self._guard = None
        self._guard_enabled = False
        self._tray_icon = None
        self._tray_thread = None
        self._hidden_to_tray = False

        try:
            apply_dialog_icon(self)
        except Exception:
            pass

        self._build()
        self._refresh_startup_button()
        self._refresh_guard_button()
        self._draw_charts(0, 0, 0) # Initial empty charts

        if initial_target:
            self.target.set(initial_target)

        self.protocol("WM_DELETE_WINDOW", self._on_close)

        if auto_start_guard:
            self.after(400, self._auto_start_guard)

    def _card(self, parent, title: str, value_var: ctk.StringVar, accent: str):
        card = ctk.CTkFrame(
            parent, fg_color=Colors.surface, corner_radius=Spacing.RADIUS_CARD,
            border_width=1, border_color=Colors.border,
        )
        ctk.CTkLabel(card, text=title.upper(), font=Fonts.badge(10),
                     text_color=Colors.text_muted).pack(anchor="w", padx=16, pady=(14, 4))
        ctk.CTkLabel(card, textvariable=value_var, font=Fonts.title(25),
                     text_color=accent).pack(anchor="w", padx=16, pady=(0, 14))
        return card

    # ---------- UI build ----------

    def _build(self) -> None:
        page = ctk.CTkFrame(self, fg_color="transparent")
        page.pack(fill="both", expand=True, padx=Spacing.PAGE_PADX, pady=Spacing.PAGE_PADY)

        # Header with Logo
        header = ctk.CTkFrame(page, fg_color="transparent")
        header.pack(fill="x", pady=(0, 18))
        
        logo_path = PROJECT_ROOT / "assets" / "icons" / "cyberopssuite.png"
        if logo_path.exists():
            pil_img = Image.open(logo_path)
            self.logo_img = ctk.CTkImage(light_image=pil_img, dark_image=pil_img, size=(32, 32))
            ctk.CTkLabel(header, text="", image=self.logo_img).pack(side="left", padx=(0, 12))

        title_area = ctk.CTkFrame(header, fg_color="transparent")
        title_area.pack(side="left", fill="x", expand=True)
        ctk.CTkLabel(title_area, text="THREATGUARD", font=Fonts.title(25),
                     text_color=Colors.text_strong).pack(anchor="w")
        ctk.CTkLabel(title_area,
                     text="Endpoint security · File scanning · Local security review",
                     font=Fonts.label(11), text_color=Colors.text_muted).pack(anchor="w")
        ctk.CTkLabel(header, text=f"CYBEROPSSUITE  /  v{APP_VERSION}",
                     font=Fonts.badge(10), text_color=Colors.info).pack(side="right", anchor="n")

        # Stats
        stats = ctk.CTkFrame(page, fg_color="transparent")
        stats.pack(fill="x", pady=(0, 14))
        for col in range(4):
            stats.grid_columnconfigure(col, weight=1, uniform="stats")
        self._card(stats, "Files scanned", self.scanned_value, Colors.info).grid(
            row=0, column=0, sticky="ew", padx=(0, 7))
        self._card(stats, "Detections", self.findings_value, Colors.danger_text).grid(
            row=0, column=1, sticky="ew", padx=7)
        self._card(stats, "Skipped", self.skipped_value, Colors.warning_text).grid(
            row=0, column=2, sticky="ew", padx=7)
        self._card(stats, "Assessment", self.risk_value, Colors.success_text).grid(
            row=0, column=3, sticky="ew", padx=(7, 0))

        # Primary controls
        controls = ctk.CTkFrame(page, fg_color="transparent")
        controls.pack(fill="x", pady=(0, 8))
        self.scan_btn = ctk.CTkButton(
            controls, text="Scan now", height=Spacing.BUTTON_HEIGHT, width=150,
            fg_color=Colors.primary, hover_color=Colors.primary_hover,
            corner_radius=Spacing.RADIUS_BUTTON, font=Fonts.label(11, bold=True),
            command=self._scan,
        )
        self.scan_btn.pack(side="left", padx=(0, 8))
        self.stop_btn = ctk.CTkButton(
            controls, text="Stop", height=Spacing.BUTTON_HEIGHT, width=80,
            fg_color=Colors.surface_alt, hover_color=Colors.neutral_hover,
            text_color=Colors.text, corner_radius=Spacing.RADIUS_BUTTON,
            font=Fonts.label(11), command=self._stop_scan, state="disabled",
        )
        self.stop_btn.pack(side="left", padx=(0, 8))
        self.audit_btn = ctk.CTkButton(
            controls, text="Local security audit", height=Spacing.BUTTON_HEIGHT,
            fg_color=Colors.surface_alt, hover_color=Colors.neutral_hover,
            text_color=Colors.text, corner_radius=Spacing.RADIUS_BUTTON,
            font=Fonts.label(11), command=self._audit,
        )
        self.audit_btn.pack(side="left")
        self.export_btn = ctk.CTkButton(
            controls, text="Export report", height=Spacing.BUTTON_HEIGHT,
            fg_color=Colors.surface_alt, hover_color=Colors.neutral_hover,
            text_color=Colors.text, corner_radius=Spacing.RADIUS_BUTTON,
            font=Fonts.label(11), command=self._export,
        )
        self.export_btn.pack(side="right")

        # Guard controls
        guard_row = ctk.CTkFrame(page, fg_color="transparent")
        guard_row.pack(fill="x", pady=(0, 4))
        self.guard_btn = ctk.CTkButton(
            guard_row, text="Activate", height=Spacing.BUTTON_HEIGHT,
            width=150, fg_color=_c("success", Colors.success_text),
            hover_color=_c("success_hover", Colors.success_text),
            text_color=_c("bg", "#0b1220"),
            corner_radius=Spacing.RADIUS_BUTTON, font=Fonts.label(11, bold=True),
            command=self._start_guard,
        )
        self.guard_btn.pack(side="left", padx=(0, 8))
        self.deactivate_btn = ctk.CTkButton(
            guard_row, text="Deactivate", height=Spacing.BUTTON_HEIGHT,
            width=150, fg_color=_c("danger", Colors.danger_text),
            hover_color=_c("danger_hover", Colors.danger_text),
            text_color="#ffffff",
            corner_radius=Spacing.RADIUS_BUTTON, font=Fonts.label(11, bold=True),
            command=self._stop_guard, state="disabled",
        )
        self.deactivate_btn.pack(side="left", padx=(0, 8))
        self.startup_btn = ctk.CTkButton(
            guard_row, text="Run at startup", height=Spacing.BUTTON_HEIGHT,
            width=150, fg_color=Colors.surface_alt, hover_color=Colors.neutral_hover,
            text_color=Colors.text, corner_radius=Spacing.RADIUS_BUTTON,
            font=Fonts.label(11), command=self._toggle_startup,
        )
        self.startup_btn.pack(side="left", padx=(0, 8))
        ctk.CTkLabel(
            guard_row, textvariable=self.guard_status_var,
            font=Fonts.label(10), text_color=Colors.text_muted,
        ).pack(side="right")

        # Status + progress
        status_panel = ctk.CTkFrame(page, fg_color="transparent")
        status_panel.pack(fill="x", pady=(2, 8))
        ctk.CTkLabel(status_panel, textvariable=self.status,
                     font=Fonts.label(10), text_color=Colors.text_soft).pack(side="left")
        self.progress = ctk.CTkProgressBar(
            status_panel, width=150, height=7, mode="indeterminate",
            fg_color=Colors.surface_alt, progress_color=Colors.info,
        )
        self.progress.set(0)
        self.progress.pack(side="right")

        # Results Split (Left: Charts, Right: Text Summary)
        results_frame = ctk.CTkFrame(page, fg_color="transparent")
        results_frame.pack(fill="both", expand=True, pady=(0, 10))
        results_frame.grid_columnconfigure(0, weight=1)
        results_frame.grid_columnconfigure(1, weight=1)
        results_frame.grid_rowconfigure(0, weight=1)

        # Charts Panel
        chart_panel = ctk.CTkFrame(results_frame, fg_color=Colors.surface,
                                   corner_radius=Spacing.RADIUS_CARD,
                                   border_width=1, border_color=Colors.border)
        chart_panel.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        
        ctk.CTkLabel(chart_panel, text="SECURITY POSTURE (Double-click for raw data)",
                     font=Fonts.badge(10), text_color=Colors.text_muted).pack(anchor="w", padx=16, pady=(12, 0))
        
        self.chart_container = ctk.CTkFrame(chart_panel, fg_color="transparent")
        self.chart_container.pack(fill="both", expand=True, padx=10, pady=10)

        # Text Panel
        text_panel = ctk.CTkFrame(results_frame, fg_color=Colors.surface,
                                  corner_radius=Spacing.RADIUS_CARD,
                                  border_width=1, border_color=Colors.border)
        text_panel.grid(row=0, column=1, sticky="nsew", padx=(8, 0))
        
        ctk.CTkLabel(text_panel, text="DETAILED FINDINGS",
                     font=Fonts.badge(10), text_color=Colors.text_muted).pack(anchor="w", padx=16, pady=(12, 4))
        
        self.output = ctk.CTkTextbox(
            text_panel, wrap="word", corner_radius=Spacing.RADIUS_INPUT,
            fg_color=Colors.bg, border_width=1, border_color=Colors.border,
            text_color=Colors.text_soft, font=Fonts.mono(11),
        )
        self.output.pack(fill="both", expand=True, padx=12, pady=(4, 12))

        # --- Footer (About & How to Use) ---
        footer = ctk.CTkFrame(page, fg_color="transparent")
        footer.pack(fill="x", side="bottom", pady=(0, 0))

        self.about_btn = ctk.CTkButton(
            footer, text="About", width=90, height=32,
            fg_color=Colors.surface_alt, hover_color=Colors.neutral_hover,
            text_color=Colors.info, font=Fonts.label(11, bold=True),
            corner_radius=16, command=self._show_about
        )
        self.about_btn.pack(side="right", padx=(8, 0))

        self.howto_btn = ctk.CTkButton(
            footer, text="How to Use", width=110, height=32,
            fg_color=Colors.surface_alt, hover_color=Colors.neutral_hover,
            text_color=Colors.info, font=Fonts.label(11, bold=True),
            corner_radius=16, command=self._show_howto
        )
        self.howto_btn.pack(side="right")

        self._write_output("ThreatGuard is ready.\nPress Activate to protect the whole computer.")

    # ---------- Charts Engine ----------

    def _draw_charts(self, clean: int, threats: int, skipped: int) -> None:
        for widget in self.chart_container.winfo_children():
            widget.destroy()

        bg = _c("surface", "#1e1e2e")       # same colour as the card around the chart
        grid = _c("border", "#334155")
        muted = _c("text_muted", "#94a3b8")
        strong = _c("text_strong", "#e2e8f0")

        # A plain Figure (not pyplot): nothing is leaked when charts are redrawn.
        # The figure is opaque and dark; a transparent figure shows the Tk
        # canvas' default *white* background around the axes.
        fig = Figure(figsize=(8, 3), facecolor=bg)
        ax_pie, ax_line = fig.subplots(1, 2)
        fig.patch.set_facecolor(bg)

        # --- Pie Chart ---
        ax_pie.set_facecolor(bg)
        if clean == 0 and threats == 0 and skipped == 0:
            ax_pie.pie([1], colors=[grid], startangle=90, wedgeprops=dict(width=0.3, edgecolor=bg))
            ax_pie.text(0, 0, "No Data", ha='center', va='center', color=muted, fontsize=10, fontweight='bold')
        else:
            labels, sizes, colors = [], [], []
            if clean > 0:
                labels.append("Clean"); sizes.append(clean); colors.append('#10b981')
            if threats > 0:
                labels.append("Threats"); sizes.append(threats); colors.append('#ef4444')
            if skipped > 0:
                labels.append("Skipped"); sizes.append(skipped); colors.append('#f59e0b')

            ax_pie.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%',
                       startangle=90, textprops={'color': strong, 'fontsize': 9},
                       wedgeprops=dict(width=0.4, edgecolor=bg))
            ax_pie.text(0, 0, f"{clean+threats+skipped}\nFiles", ha='center', va='center', color=strong, fontsize=10, fontweight='bold')

        ax_pie.set_title("Scan Distribution", color=strong, fontsize=11, fontweight='bold')

        # --- Line Chart ---
        ax_line.set_facecolor(bg)
        if not self.scan_history:
            ax_line.text(0.5, 0.5, "History will appear here", ha='center', va='center',
                         color=muted, fontsize=10, transform=ax_line.transAxes)
        else:
            x = list(range(1, len(self.scan_history) + 1))
            y = [h[1] for h in self.scan_history]
            ax_line.plot(x, y, color='#ef4444', marker='o', linestyle='-', linewidth=2, markersize=5)
            ax_line.fill_between(x, y, color='#ef4444', alpha=0.2)

        ax_line.set_title("Threats Over Time", color=strong, fontsize=11, fontweight='bold')
        ax_line.tick_params(colors=muted, labelsize=8)
        for spine in ax_line.spines.values():
            spine.set_color(grid)
        ax_line.grid(color=grid, linestyle='--', linewidth=0.5, alpha=0.7)

        fig.tight_layout()

        canvas = FigureCanvasTkAgg(fig, master=self.chart_container)
        widget = canvas.get_tk_widget()
        widget.configure(bg=bg, highlightthickness=0, bd=0)
        canvas.draw()
        widget.pack(fill="both", expand=True)

        canvas.mpl_connect("button_press_event", self._on_chart_double_click)

    def _on_chart_double_click(self, event):
        if event.dblclick:
            self._show_raw_json()

    def _show_raw_json(self):
        if not self._last_report:
            return
        dialog = self._open_dialog("raw", "Raw JSON Data", 640, 520)
        if dialog is None:
            return
        textbox = ctk.CTkTextbox(
            dialog, wrap="none", fg_color=Colors.surface, text_color=Colors.text_soft,
            border_width=1, border_color=Colors.border, font=Fonts.mono(11),
        )
        textbox.pack(fill="both", expand=True, padx=16, pady=16)
        textbox.insert("end", json.dumps(self._last_report, indent=2, ensure_ascii=False))
        textbox.configure(state="disabled")

    # ---------- Output Formatting ----------

    def _write_output(self, content: str) -> None:
        self.output.configure(state="normal")
        self.output.delete("1.0", "end")
        self.output.insert("end", content)
        
        # راه‌حل ارور Scaling: استفاده از cnf برای دور زدن محدودیت CustomTkinter
        self.output.tag_config("bold", cnf={"font": Fonts.mono(11, bold=True)})
        self.output.tag_config("danger", foreground="#ef4444")
        self.output.tag_config("warn", foreground="#f59e0b")
        self.output.tag_config("success", foreground="#10b981")
        
        self.output.configure(state="disabled")

    def _generate_summary_text(self, payload: dict) -> str:
        scanned = payload.get("scanned_files", 0)
        skipped = payload.get("skipped_files", 0)
        findings = payload.get("findings", [])
        
        if "audit_checks" in payload:
            warns = [c for c in payload["audit_checks"] if c.get("status") == "WARN"]
            text = f"=== LOCAL SECURITY AUDIT ===\n\n"
            text += f"Warnings found: {len(warns)}\n"
            for w in warns:
                text += f"[WARN] {w['check']}\n  Details: {w['details']}\n"
            if not warns:
                text += "No warnings found. System looks good.\n"
            return text

        text = "=== SCAN STOPPED (partial result) ===\n\n" if payload.get("cancelled") else "=== SCAN COMPLETE ===\n\n"
        text += f"Files Scanned: {scanned}\n"
        text += f"Skipped:       {skipped}\n"
        text += f"Detections:    {len(findings)}\n\n"
        
        if not findings:
            text += "✅ NO THREATS FOUND\nSystem appears clean.\n"
        else:
            text += "🚨 FINDINGS TO REVIEW 🚨\n\n"
            for f in findings[:200]:
                sev = f.get("severity", "high").upper()
                text += f"[{sev}] {f.get('title')}\n"
                text += f"Engine: {f.get('engine')}\n"
                text += f"Path: {f.get('path')}\n"
                text += f"Details: {f.get('details')}\n\n"
            if len(findings) > 200:
                text += f"… and {len(findings) - 200} more. Use Export report to see all of them.\n"
        errors = payload.get("errors") or []
        notes = [e for e in errors if "Administrator" in e or "psutil" in e or "skipped" in e]
        if notes:
            text += "\nNotes\n" + "\n".join(f"• {n}" for n in notes[:5]) + "\n"
        return text

    # ---------- Logic Actions ----------

    def _set_busy(self, busy: bool, message: str) -> None:
        self._busy = busy
        self.status.set(message)
        state = "disabled" if busy else "normal"
        self.scan_btn.configure(state=state)
        self.audit_btn.configure(state=state)
        self.stop_btn.configure(state="normal" if busy else "disabled")
        if busy:
            self.progress.start()
        else:
            self.progress.stop()
            self.progress.set(0)

    def _scan(self) -> None:
        path = self.target.get().strip()
        everything = not path
        if not everything and not Path(path).expanduser().exists():
            messagebox.showwarning(APP_NAME, "That path does not exist.")
            return
        if everything and not GUARD_AVAILABLE:
            messagebox.showinfo(APP_NAME, "Select a file or folder first.")
            return
        self._cancel_event.clear()
        self._set_busy(True, "Reviewing the whole computer…" if everything else "Scanning selected path…")
        self.risk_value.set("SCANNING")
        self._write_output("Scan started. Everything is inspected in read-only mode…\n")

        def on_progress(scanned: int, skipped: int, current: str) -> None:
            # called from the worker threads: hand over to the Tk thread
            name = Path(current).name if current else ""
            self.after(0, lambda: self._show_progress(scanned, skipped, name))

        def worker() -> None:
            try:
                if everything:
                    payload = full_review(
                        None, make_scanner(), cancel=self._cancel_event, progress=on_progress,
                        status=lambda msg: self._ui(lambda: self.status.set(msg)),
                    )
                else:
                    report = ThreatScanner().scan(
                        path, progress=on_progress, cancel=self._cancel_event,
                    )
                    payload = report.to_dict()
                self.after(0, lambda: self._show_scan_result(payload))
            except Exception as exc:
                self.after(0, lambda error=str(exc): self._show_error(error))

        threading.Thread(target=worker, daemon=True).start()

    def _show_progress(self, scanned: int, skipped: int, name: str) -> None:
        if not self._busy:
            return
        tail = f" · {name}" if name else ""
        self.status.set(f"Scanning… {scanned:,} files · {skipped:,} skipped{tail}")

    def _stop_scan(self) -> None:
        if self._busy:
            self._cancel_event.set()
            self.status.set("Stopping scan…")
            self.stop_btn.configure(state="disabled")

    def _show_scan_result(self, payload: dict) -> None:
        self._last_report = payload
        findings = len(payload.get("findings", []))
        scanned = payload.get("scanned_files", 0)
        skipped = payload.get("skipped_files", 0)
        
        self.scanned_value.set(str(scanned))
        self.findings_value.set(str(findings))
        self.skipped_value.set(str(skipped))
        self.risk_value.set("REVIEW" if findings else "NO FINDINGS")
        
        clean = max(0, scanned - findings)
        self.scan_history.append((scanned, findings))
        self._draw_charts(clean, findings, skipped)
        
        summary = self._generate_summary_text(payload)
        self._write_output(summary)
        
        if payload.get("cancelled"):
            self.risk_value.set("STOPPED")
            self._set_busy(False, f"Scan stopped · {scanned} files checked · {findings} detections · partial result")
        else:
            self._set_busy(False, f"Scan complete · {scanned} files · {findings} detections · {skipped} skipped")

    def _show_error(self, message: str) -> None:
        self.risk_value.set("ERROR")
        self._write_output(f"Operation failed:\n{message}")
        self._set_busy(False, "Operation failed · See results for details")

    def _audit(self) -> None:
        try:
            checks = local_security_audit()
            payload = {"audit_checks": checks}
            self._last_report = payload
            warns = sum(1 for item in checks if item.get("status") == "WARN")
            self.findings_value.set(str(warns))
            self.risk_value.set("REVIEW" if warns else "AUDIT DONE")
            
            summary = self._generate_summary_text(payload)
            self._write_output(summary)
            self.status.set("Local security audit complete · Review MANUAL checks")
        except Exception as exc:
            self._show_error(str(exc))

    def _export(self) -> None:
        if not self._last_report:
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".json", filetypes=[("JSON report", "*.json")],
            title="Save ThreatGuard report",
        )
        if path:
            try:
                Path(path).write_text(json.dumps(self._last_report, indent=2, ensure_ascii=False), encoding="utf-8")
                self.status.set(f"Report exported · {Path(path).name}")
            except OSError as exc:
                messagebox.showerror(APP_NAME, f"Could not save report:\n{exc}")

    # ---------- Protection (the one-button mode) ----------
    def _ui(self, func) -> None:
        """Run ``func`` on the Tk thread; safe to call from worker threads."""
        try:
            self.after(0, func)
        except Exception:
            pass

    def _refresh_guard_button(self) -> None:
        if not GUARD_AVAILABLE:
            self.guard_btn.configure(text="Unavailable", state="disabled")
            self.deactivate_btn.configure(state="disabled")
            self.guard_status_var.set("Protection: unavailable")
            return
        if self._guard_enabled:
            self.guard_btn.configure(state="disabled")
            self.deactivate_btn.configure(state="normal")
            self.guard_status_var.set("Protection: ACTIVE")
        else:
            self.guard_btn.configure(state="normal")
            self.deactivate_btn.configure(state="disabled")
            self.guard_status_var.set("Protection: Off")

    def _start_guard(self) -> bool:
        """Activate protection: scans every drive on the computer, no folder needed."""
        if self._guard_enabled or not GUARD_AVAILABLE:
            return False
        raw = self.target.get().strip()  # only set by the --target command-line flag
        targets = None
        if raw:
            target_path = Path(raw).expanduser()
            if not target_path.exists():
                messagebox.showwarning(APP_NAME, "That path does not exist.")
                return False
            targets = [target_path]

        self._ensure_tray()  # first, so notifications can use the tray balloon
        self._guard = ProtectionManager(
            targets=targets,
            interval_seconds=GUARD_INTERVAL_SECONDS,
            notify=notify,
            on_report=lambda report: self._ui(lambda: self._apply_protection_report(report)),
            on_status=lambda msg: self._ui(lambda: self._set_guard_status(msg)),
            on_error=lambda msg: self._ui(lambda: self.status.set(msg[:200])),
        )
        self._guard.start()
        self._guard_enabled = True
        self._refresh_guard_button()
        self.status.set("Protection enabled · first full review is running…")
        self.risk_value.set("SCANNING")
        return True

    def _stop_guard(self) -> None:
        if not self._guard_enabled:
            return
        guard, self._guard = self._guard, None
        self._guard_enabled = False
        if guard:
            guard.stop()          # also sends the "Protection DISABLED" notification
        self._refresh_guard_button()
        self.status.set("Protection disabled")
        self._tear_down_tray()

    def _stop_guard_from_tray(self) -> None:
        self._stop_guard()
        self._restore_window()    # never leave the app running with no window and no tray

    def _auto_start_guard(self) -> None:
        """Used by --guard / Run at startup: start silently in the tray."""
        if self._guard_enabled:
            return
        if self._start_guard() and TRAY_AVAILABLE:
            self.withdraw()
            self._hidden_to_tray = True

    def _set_guard_status(self, message: str) -> None:
        if not self._busy and self._guard_enabled:
            self.status.set(message)

    def _apply_protection_report(self, report: dict) -> None:
        if not self._guard_enabled:
            return
        self._last_report = report
        findings = len(report.get("findings", []))
        scanned = report.get("scanned_files", 0)
        skipped = report.get("skipped_files", 0)
        self.scan_history.append((scanned, findings))
        self.scan_history = self.scan_history[-50:]
        if self._busy:
            return
        self.scanned_value.set(f"{scanned:,}")
        self.findings_value.set(str(findings))
        self.skipped_value.set(f"{skipped:,}")
        self.risk_value.set("REVIEW" if findings else "NO FINDINGS")
        self._write_output(self._generate_summary_text(report))
        if not self._hidden_to_tray:
            self._draw_charts(max(0, scanned - findings), findings, skipped)

    # ---------- Tray & Startup ----------
    def _ensure_tray(self) -> None:
        if self._tray_icon or not TRAY_AVAILABLE: return
        image = Image.open(PROJECT_ROOT / "assets" / "icons" / "cyberopssuite.png").convert("RGBA") if (PROJECT_ROOT / "assets" / "icons" / "cyberopssuite.png").exists() else Image.new("RGBA", (64, 64), (16, 185, 129, 255))
        menu = pystray.Menu(
            pystray.MenuItem("Show ThreatGuard", lambda *_: self.after(0, self._restore_window), default=True),
            pystray.MenuItem("Deactivate Protection", lambda *_: self.after(0, self._stop_guard_from_tray)),
            pystray.MenuItem("Exit", lambda *_: self.after(0, self._quit_app))
        )
        self._tray_icon = pystray.Icon("ThreatGuard", image, "ThreatGuard · Protection active", menu)
        self._tray_thread = threading.Thread(target=self._tray_icon.run, daemon=True)
        self._tray_thread.start()
        set_tray_notifier(self._tray_notify)

    def _tray_notify(self, title: str, message: str) -> bool:
        icon = self._tray_icon
        if icon is None or not getattr(icon, "visible", False):
            return False
        icon.notify(message, title)
        return True

    def _tear_down_tray(self) -> None:
        set_tray_notifier(None)
        if self._tray_icon:
            try: self._tray_icon.stop()
            except: pass
            self._tray_icon = None

    def _restore_window(self) -> None:
        self.deiconify()
        self.lift()
        self.focus_force()
        self._hidden_to_tray = False

    def _refresh_startup_button(self) -> None:
        if not STARTUP_AVAILABLE:
            self.startup_btn.configure(text="Startup unavailable", state="disabled")
            return
        try: enabled = is_enabled_startup_folder()
        except: enabled = False
        self.startup_btn.configure(text="Remove from startup" if enabled else "Run at startup")

    def _toggle_startup(self) -> None:
        if not STARTUP_AVAILABLE: return
        try:
            if is_enabled_startup_folder():
                disable_startup_folder()
                self.status.set("Removed from Windows startup")
            else:
                enable_startup_folder()
                self.status.set("Added to Windows startup")
        except OSError as exc:
            messagebox.showerror(APP_NAME, f"Could not update startup:\n{exc}")
        self._refresh_startup_button()

    def _on_close(self) -> None:
        if self._guard_enabled and TRAY_AVAILABLE:
            self._hidden_to_tray = True
            self.withdraw()
            self._ensure_tray()
            return
        if self._guard_enabled:
            # No tray icon available: do not silently switch protection off.
            if not messagebox.askyesno(
                APP_NAME,
                "Protection is active.\n\nQuit and stop protection?\n"
                "(Choose No to keep it running minimised.)",
            ):
                self.iconify()
                return
        self._quit_app()

    def _quit_app(self) -> None:
        try: self._stop_guard()
        finally:
            self._tear_down_tray()
            self.destroy()

    # ---------- Modals ----------

    def _open_dialog(self, key: str, title: str, width: int, height: int):
        """Create (or raise) a themed dialog that carries the app's own icon."""
        existing = self._dialogs.get(key)
        if existing is not None:
            try:
                if existing.winfo_exists():
                    existing.lift()
                    existing.focus_force()
                    return None
            except Exception:
                pass

        dialog = ctk.CTkToplevel(self)
        self._dialogs[key] = dialog
        dialog.title(title)
        dialog.geometry(f"{width}x{height}")
        dialog.minsize(min(width, 420), min(height, 360))
        dialog.configure(fg_color=Colors.bg_alt)
        dialog.transient(self)
        apply_dialog_icon(dialog)          # app icon, not the CustomTkinter one

        dialog.update_idletasks()
        x = self.winfo_rootx() + (self.winfo_width() - width) // 2
        y = self.winfo_rooty() + (self.winfo_height() - height) // 2
        dialog.geometry(f"{width}x{height}+{max(0, x)}+{max(0, y)}")

        def close() -> None:
            self._dialogs.pop(key, None)
            try:
                dialog.grab_release()
            except Exception:
                pass
            dialog.destroy()

        dialog.protocol("WM_DELETE_WINDOW", close)
        dialog.bind("<Escape>", lambda _e: close())
        dialog.after(80, lambda: dialog.winfo_exists() and dialog.grab_set())
        dialog.close = close  # type: ignore[attr-defined]
        return dialog

    def _dialog_header(self, dialog, badge: str, title: str, subtitle: str) -> None:
        head = ctk.CTkFrame(dialog, fg_color="transparent")
        head.pack(fill="x", padx=24, pady=(22, 0))
        if getattr(self, "logo_img", None) is not None:
            ctk.CTkLabel(head, text="", image=self.logo_img).pack(side="left", padx=(0, 12))
        box = ctk.CTkFrame(head, fg_color="transparent")
        box.pack(side="left", fill="x", expand=True)
        ctk.CTkLabel(box, text=badge, font=Fonts.badge(10), text_color=Colors.info,
                     anchor="w").pack(fill="x")
        ctk.CTkLabel(box, text=title, font=Fonts.title(22), text_color=Colors.text_strong,
                     anchor="w").pack(fill="x")
        if subtitle:
            ctk.CTkLabel(box, text=subtitle, font=Fonts.label(11), text_color=Colors.text_muted,
                         anchor="w").pack(fill="x")

    def _dialog_body(self, dialog, text: str, button_text: str) -> None:
        tb = ctk.CTkTextbox(
            dialog, wrap="word", fg_color=Colors.surface, text_color=Colors.text_soft,
            border_width=1, border_color=Colors.border, font=Fonts.label(11),
        )
        tb.pack(fill="both", expand=True, padx=24, pady=16)
        tb.insert("end", text)
        tb.configure(state="disabled")
        ctk.CTkButton(
            dialog, text=button_text, width=130, height=36,
            fg_color=Colors.primary, hover_color=Colors.primary_hover,
            corner_radius=Spacing.RADIUS_BUTTON, font=Fonts.label(11, bold=True),
            command=dialog.close,
        ).pack(anchor="e", padx=24, pady=(0, 20))

    def _show_about(self) -> None:
        dialog = self._open_dialog("about", "About ThreatGuard", 520, 520)
        if dialog is None:
            return
        self._dialog_header(dialog, "CYBEROPSSUITE", "ThreatGuard", f"Version {APP_VERSION}  ·  Endpoint security")
        self._dialog_body(
            dialog,
            "ThreatGuard is a defensive scanning module integrated into CyberOpsSuite.\n\n"
            "What it does\n"
            "• Scans files and folders (SHA-256 reputation, built-in signatures, optional YARA and ClamAV).\n"
            "• Activate Protection reviews the whole computer (all drives, event logs, autostart entries, processes, network) and repeats it in the background.\n"
            "• Local security audit and JSON report export.\n\n"
            "Safety defaults\n"
            "• Read-only. No file deletion, quarantine, or system changes.\n"
            "• You must be authorized to scan the selected targets.\n"
            "• A scan with no findings does not guarantee a clean system.",
            "Close",
        )

    def _show_howto(self) -> None:
        dialog = self._open_dialog("howto", "How to Use | ThreatGuard", 560, 600)
        if dialog is None:
            return
        self._dialog_header(dialog, "HOW TO USE", "ThreatGuard", "Scan, monitor and review")
        self._dialog_body(
            dialog,
            "1. Manual scan\n"
            "   • Scan now checks the whole computer once: all drives, logs, autostart, processes, network.\n"
            "   • Live progress is shown below the buttons. Stop ends the scan and keeps the partial result.\n"
            "   • Charts summarise the result; double-click a chart for the raw JSON.\n\n"
            "2. Activate / Deactivate\n"
            "   • No folder needed: Activate covers every fixed and USB drive on its own.\n"
            "   • Deactivate stops all scanning and reporting.\n"
            "   • It reviews event logs, autostart entries, processes and network, then scans files.\n"
            "   • Repeats every few minutes; unchanged files are skipped, so later rounds are fast.\n"
            "   • A Windows notification appears when protection is enabled, disabled, and for new findings.\n"
            "   • New USB / external drives are scanned the moment they are plugged in.\n"
            "   • For the Security event log, run the app as Administrator.\n"
            "   • Closing the window sends it to the tray. Run at startup starts it with Windows.\n\n"
            "3. Local security audit\n"
            "   • Quick, advisory checks of this machine. MANUAL items need your review.\n\n"
            "4. Exporting\n"
            "   • Export report saves the last result as JSON.\n\n"
            "Optional engines\n"
            "   • ClamAV: install it and make sure 'clamscan' is on PATH (it is run once per scan).\n"
            "   • YARA: pip install yara-python.",
            "Got it",
        )


def main() -> None:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--guard", "--protect", dest="guard", action="store_true")
    parser.add_argument("--target", default=None)
    args, _ = parser.parse_known_args()

    app = ThreatGuardApp(auto_start_guard=args.guard, initial_target=args.target)
    app.mainloop()

if __name__ == "__main__":
    main()