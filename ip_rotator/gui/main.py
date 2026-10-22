"""IP Rotator GUI for CyberOpsSuite."""

from __future__ import annotations

import os
import sys
import tkinter as tk
import threading
from pathlib import Path

import customtkinter as ctk
from tkinter import messagebox

# Always resolve imports from the project root
PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core.theme import Colors, Fonts, Spacing
from core.utils.icons import apply_window_icon
from ip_rotator.core.tor_controller import TorController
from ip_rotator.core.ip_logger import IPLogger


APP_NAME = "IP Rotator"
APP_VERSION = "1.2.1"
APP_SUITE = "CyberOpsSuite"


class IPRotatorApp(ctk.CTk):
    """Main window for the IP Rotator module."""

    def __init__(self) -> None:
        super().__init__()

        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("dark-blue")

        self.title(f"{APP_SUITE} | {APP_NAME}")
        self.geometry("800x720")
        self.minsize(700, 680)
        self.configure(fg_color=Colors.bg)

        apply_window_icon(self)

        self.tor = TorController()
        self.ip_logger = IPLogger()
        self._auto_rotate_after_id: str | None = None
        self.current_page = "main"
        self._about_open = False

        self._build_ui()

    def _build_ui(self) -> None:
        # --- Header ---
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.pack(fill="x", padx=20, pady=(20, 10))
        header.columnconfigure(0, weight=1)

        title_frame = ctk.CTkFrame(header, fg_color="transparent")
        title_frame.grid(row=0, column=0, sticky="w")

        ctk.CTkLabel(
            title_frame, text="IP Rotator",
            font=Fonts.title(24), text_color=Colors.text_strong,
        ).pack(anchor="w")

        ctk.CTkLabel(
            title_frame, text="Change your public IP via the Tor network.",
            font=Fonts.label(11), text_color=Colors.text_muted,
        ).pack(anchor="w", pady=(3, 0))

        # Actions container using grid with fixed columns
        actions = ctk.CTkFrame(header, fg_color="transparent")
        actions.grid(row=0, column=1, sticky="e", pady=4)
        # Fixed column layout: col 0 = Help, col 1 = About
        actions.grid_columnconfigure(0, weight=0)
        actions.grid_columnconfigure(1, weight=0)

        # Help button (column 0) - will be grid_remove()'d on About page
        self.help_btn = ctk.CTkButton(
            actions, text="❓ How to Use", width=110, height=34,
            corner_radius=Spacing.RADIUS_BUTTON,
            fg_color=Colors.info_bg, hover_color=Colors.info,
            text_color=Colors.info_light, font=Fonts.label(11, bold=True),
            command=self._show_how_to_use,
        )
        self.help_btn.grid(row=0, column=0, padx=(0, 8))

        # About button (column 1) - always visible
        ctk.CTkButton(
            actions, text="About", width=90, height=34,
            corner_radius=Spacing.RADIUS_BUTTON,
            fg_color=Colors.surface_alt, hover_color=Colors.primary,
            text_color=Colors.text, font=Fonts.label(11, bold=True),
            command=self._show_about,
        ).grid(row=0, column=1)

        # --- Warning Banner ---
        warning = ctk.CTkFrame(
            self, fg_color="#2A1D17", corner_radius=8,
            border_width=1, border_color="#7C2D12",
        )
        warning.pack(fill="x", padx=20, pady=(10, 15))

        ctk.CTkLabel(
            warning, text="⚠  IMPORTANT",
            font=Fonts.badge(11), text_color="#FDBA74", anchor="w",
        ).pack(fill="x", padx=15, pady=(10, 2))

        ctk.CTkLabel(
            warning,
            text="This tool routes your browser's traffic through Tor to change your IP.\n"
                 "You MUST configure your browser to use SOCKS5 proxy: 127.0.0.1:9050\n"
                 "Ensure the Tor service is running and the 'stem' library is installed.",
            font=Fonts.label(11), text_color="#FED7AA",
            justify="left", anchor="w", wraplength=700,
        ).pack(fill="x", padx=15, pady=(0, 12))

        # --- IP Display Card ---
        ip_card = ctk.CTkFrame(
            self, fg_color=Colors.surface, corner_radius=Spacing.RADIUS_CARD,
            border_width=1, border_color=Colors.border,
        )
        ip_card.pack(fill="x", padx=20, pady=(0, 15))

        ip_inner = ctk.CTkFrame(ip_card, fg_color="transparent")
        ip_inner.pack(fill="x", padx=15, pady=12)
        ip_inner.grid_columnconfigure((0, 1), weight=1)

        # Real IP
        ctk.CTkLabel(
            ip_inner, text="REAL SYSTEM IP", font=Fonts.badge(9),
            text_color=Colors.text_dim,
        ).grid(row=0, column=0, sticky="w")
        self.real_ip_label = ctk.CTkLabel(
            ip_inner, text="Checking...", font=Fonts.mono(12, bold=True),
            text_color=Colors.warning_text,
        )
        self.real_ip_label.grid(row=1, column=0, sticky="w", pady=(2, 0))

        # Tor Exit IP
        ctk.CTkLabel(
            ip_inner, text="TOR EXIT IP", font=Fonts.badge(9),
            text_color=Colors.text_dim,
        ).grid(row=0, column=1, sticky="e")
        self.tor_ip_label = ctk.CTkLabel(
            ip_inner, text="Checking...", font=Fonts.mono(12, bold=True),
            text_color=Colors.success_text,
        )
        self.tor_ip_label.grid(row=1, column=1, sticky="e", pady=(2, 0))

        # Refresh button
        ctk.CTkButton(
            ip_inner, text="↻ Refresh IPs", width=100, height=28,
            fg_color=Colors.neutral_dark, hover_color=Colors.neutral_dark_hover,
            command=self._update_ip_display,
        ).grid(row=0, column=2, rowspan=2, padx=(15, 0))

        # Initial refresh
        self.after(500, self._update_ip_display)

        # --- Controls Card ---
        card = ctk.CTkFrame(
            self, fg_color=Colors.surface, corner_radius=Spacing.RADIUS_CARD,
            border_width=1, border_color=Colors.border,
        )
        card.pack(fill="both", expand=True, padx=20, pady=(0, 20))

        # Manual Change Button
        self.manual_btn = ctk.CTkButton(
            card, text="🔄  Change IP Now (Manual)",
            height=45, font=Fonts.label(13, bold=True),
            fg_color=Colors.primary, hover_color=Colors.primary_hover,
            command=self._manual_change_ip,
        )
        self.manual_btn.pack(pady=(20, 15), padx=20, fill="x")

        # Auto Rotate Frame
        auto_frame = ctk.CTkFrame(card, fg_color=Colors.bg, corner_radius=6)
        auto_frame.pack(fill="x", padx=20, pady=(0, 15))

        ctk.CTkLabel(
            auto_frame, text="Auto-Rotate:", font=Fonts.label(12, bold=True), text_color=Colors.text,
        ).pack(side="left", padx=(10, 8), pady=10)

        self.auto_var = tk.BooleanVar(value=False)
        self.auto_switch = ctk.CTkSwitch(
            auto_frame, text="Enable", variable=self.auto_var,
            command=self._toggle_auto, progress_color=Colors.success,
        )
        self.auto_switch.pack(side="left", padx=(0, 15))

        ctk.CTkLabel(
            auto_frame, text="Interval:", font=Fonts.label(12, bold=True), text_color=Colors.text,
        ).pack(side="left", padx=(0, 8))

        self.timer_var = ctk.StringVar(value="5 min")
        self.timer_menu = ctk.CTkOptionMenu(
            auto_frame, values=["1 min", "5 min", "10 min", "20 min"],
            variable=self.timer_var, width=100,
            command=self._change_interval,
            fg_color=Colors.surface_alt, button_color=Colors.surface_alt,
        )
        self.timer_menu.pack(side="left")

        # --- Status Log ---
        self.log_text = ctk.CTkTextbox(
            card, height=120, fg_color=Colors.bg, text_color=Colors.text_muted,
            border_width=1, border_color=Colors.border, font=Fonts.mono(10),
        )
        self.log_text.pack(fill="both", expand=True, padx=20, pady=(0, 15))
        self._log("Ready.")
        self._log("Ensure Tor is running and 'stem' is installed.")

        # --- Bottom Buttons (CSV) ---
        btn_frame = ctk.CTkFrame(card, fg_color="transparent")
        btn_frame.pack(pady=(0, 20), padx=20, fill="x")

        ctk.CTkButton(
            btn_frame, text="📁  Open History (CSV)", width=160,
            fg_color=Colors.neutral_dark, hover_color=Colors.neutral_dark_hover,
            command=self._open_csv,
        ).pack(side="left")

    def _update_ip_display(self) -> None:
        """Fetch and update both real and Tor IPs in the background."""
        self.real_ip_label.configure(text="Checking...")
        self.tor_ip_label.configure(text="Checking...")

        def worker():
            real = self.ip_logger.get_real_ip()
            tor = self.ip_logger.get_current_ip()
            self.after(0, lambda: self._apply_ip_display(real, tor))

        threading.Thread(target=worker, daemon=True).start()

    def _apply_ip_display(self, real: str, tor: str) -> None:
        self.real_ip_label.configure(text=real)
        self.tor_ip_label.configure(text=tor)

    def _log(self, message: str) -> None:
        if not hasattr(self, "log_text"):
            return
        self.log_text.configure(state="normal")
        self.log_text.insert("end", f"{message}\n")
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    def _manual_change_ip(self) -> None:
        self._log("Requesting new Tor identity...")
        success, msg = self.tor.change_identity()
        self._log(msg)
        
        if success:
            self.after(2000, self._capture_new_ip)

    def _capture_new_ip(self) -> None:
        """Fetch and log the new IP."""
        self._log("Fetching new IP address...")
        new_ip = self.ip_logger.log_current_ip()
        
        if new_ip.startswith("Error"):
            self._log(f"Failed to get IP: {new_ip}")
        else:
            self._log(f"✅ New IP Logged: {new_ip}")
            self.tor_ip_label.configure(text=new_ip)
            messagebox.showinfo(
                "Success",
                f"New IP: {new_ip}\nSaved to history.",
                parent=self,
            )

    def _open_csv(self) -> None:
        path = self.ip_logger.get_log_path()
        if not os.path.exists(path):
            messagebox.showinfo("No History", "No IP history file found yet.", parent=self)
            return
            
        if os.name == "nt":
            os.startfile(path)
        else:
            import subprocess
            subprocess.Popen(["xdg-open", path])

    def _toggle_auto(self) -> None:
        if self.auto_var.get():
            self._schedule_auto()
            self._log(f"Auto-Rotate enabled (every {self.timer_var.get()}).")
        else:
            if self._auto_rotate_after_id:
                self.after_cancel(self._auto_rotate_after_id)
                self._auto_rotate_after_id = None
            self._log("Auto-Rotate disabled.")

    def _change_interval(self, choice: str) -> None:
        if self.auto_var.get():
            if self._auto_rotate_after_id:
                self.after_cancel(self._auto_rotate_after_id)
            self._schedule_auto()
            self._log(f"Interval changed to {choice}.")

    def _schedule_auto(self) -> None:
        mapping = {"1 min": 60, "5 min": 300, "10 min": 600, "20 min": 1200}
        seconds = mapping.get(self.timer_var.get(), 300)
        self._auto_rotate_after_id = self.after(seconds * 1000, self._do_auto_change)

    def _do_auto_change(self) -> None:
        if not self.auto_var.get():
            return
        self._log(f"Auto-Rotate triggered ({self.timer_var.get()}).")
        self._manual_change_ip()
        self._schedule_auto()

    # ------------------------------------------------------------- How to Use

    def _show_how_to_use(self):
        """Show help for the IP Rotator."""
        dialog = ctk.CTkToplevel(self)
        dialog.title("How to Use | IP Rotator")
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
            outer, text="IP Rotator",
            font=Fonts.title(24), text_color=Colors.text_strong,
        ).pack(anchor="w", padx=28, pady=(6, 2))

        ctk.CTkFrame(outer, height=1, fg_color=Colors.border).pack(
            fill="x", padx=28, pady=16
        )

        help_text = (
            "Welcome to IP Rotator!\n\n"
            "1️⃣  REQUIREMENTS\n"
            "•  Tor must be installed and running.\n"
            "•  ControlPort must be enabled (9151 for Tor Browser, 9051 for Tor Expert Bundle).\n"
            "•  The 'stem' library must be installed:\n"
            "   pip install stem\n\n"
            "2️⃣  BROWSER & NETWORK CONFIGURATION\n"
            "•  Configure your browser to use SOCKS5 proxy: 127.0.0.1:9050\n"
            "•  This is required for your browser traffic to go through Tor.\n"
            "•  VPN may be required: In some regions, Tor is blocked by ISPs.\n"
            "   If you cannot connect, try using a VPN first.\n\n"
            "3️⃣  MANUAL CHANGE\n"
            "•  Click '🔄 Change IP Now (Manual)' to request a new Tor identity.\n"
            "•  The tool sends a NEWNYM signal to Tor.\n"
            "•  The new IP will be logged to CSV history.\n\n"
            "4️⃣  AUTO-ROTATE\n"
            "•  Enable the switch and choose an interval (1, 5, 10, 20 min).\n"
            "•  The tool will automatically change your IP at the chosen interval.\n\n"
            "5️⃣  HISTORY\n"
            "•  Click '📁 Open History (CSV)' to view all logged IPs.\n\n"
            "⚠  WARNING: Changing IP too frequently may trigger CAPTCHAs on some websites."
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

    # ------------------------------------------------------------- About

    def _show_about(self) -> None:
        if self._about_open:
            return
        self._about_open = True

        # Hide Help button on About page (grid_remove keeps its grid position)
        self.help_btn.grid_remove()

        dialog = ctk.CTkToplevel(self)
        dialog.title("About IP Rotator")
        dialog.geometry("700x700")
        dialog.configure(fg_color=Colors.bg)
        dialog.transient(self)
        dialog.grab_set()

        apply_window_icon(dialog)

        # Restore Help button whether the dialog is closed via button, Esc or X
        def on_close():
            dialog.destroy()
            self.help_btn.grid()  # Restores the button at the SAME grid position
            self._about_open = False

        dialog.protocol("WM_DELETE_WINDOW", on_close)

        outer = ctk.CTkScrollableFrame(
            dialog, fg_color=Colors.surface, corner_radius=Spacing.RADIUS_CARD,
            scrollbar_button_color=Colors.surface_alt,
        )
        outer.pack(fill="both", expand=True, padx=18, pady=18)

        ctk.CTkLabel(
            outer, text="◈  CYBEROPSSUITE",
            font=Fonts.badge(11), text_color=Colors.primary,
        ).pack(anchor="w", padx=24, pady=(20, 0))

        ctk.CTkLabel(
            outer, text="IP Rotator",
            font=Fonts.title(22), text_color=Colors.text_strong,
        ).pack(anchor="w", padx=24, pady=(4, 0))

        ctk.CTkLabel(
            outer, text=f"Version {APP_VERSION}  •  Privacy Tool",
            font=Fonts.label(10), text_color=Colors.text_muted,
        ).pack(anchor="w", padx=24)

        ctk.CTkFrame(outer, height=1, fg_color=Colors.border).pack(
            fill="x", padx=24, pady=14
        )

        def add_section(title: str, body: str, color: str = Colors.info) -> None:
            ctk.CTkLabel(
                outer, text=title, font=Fonts.badge(11), text_color=color,
            ).pack(anchor="w", padx=24, pady=(6, 4))
            ctk.CTkLabel(
                outer, text=body, font=Fonts.label(11), text_color=Colors.text,
                justify="left", anchor="w", wraplength=600,
            ).pack(fill="x", padx=24, pady=(0, 10))

        add_section(
            "OVERVIEW",
            "A simple utility to change your public IP address by routing "
            "traffic through the Tor network. It can rotate automatically on a timer.",
            Colors.info_soft,
        )

        add_section(
            "FEATURES",
            "• Displays your real system IP and current Tor exit IP\n"
            "• Change IP manually with one click\n"
            "• Auto-rotate every 1, 5, 10, or 20 minutes\n"
            "• Sends NEWNYM signal to Tor for a fresh circuit\n"
            "• Logs all actions in real-time and saves to CSV",
            Colors.success_text,
        )

        add_section(
            "HOW TO USE",
            "1. Install and run Tor (or Tor Browser).\n"
            "2. Ensure Tor is running with ControlPort enabled\n"
            "   (9151 for Tor Browser, 9051 for Tor Expert Bundle).\n"
            "3. Install the required library:\n"
            "   Windows: pip install stem\n"
            "   Linux:   sudo apt install python3-stem\n"
            "4. Configure your browser's SOCKS5 proxy to 127.0.0.1:9050.\n"
            "5. If Tor is blocked in your region, try using a VPN first.\n"
            "6. Use this tool to request new IPs.",
            Colors.info,
        )

        add_section(
            "PLATFORMS",
            "• Windows 10 / 11\n"
            "• Linux (Debian, Ubuntu, etc.)",
            Colors.warning_text,
        )

        warning = ctk.CTkFrame(
            outer, fg_color="#2A1D17", corner_radius=Spacing.RADIUS_CARD,
            border_width=1, border_color="#7C2D12",
        )
        warning.pack(fill="x", padx=24, pady=(10, 14))

        ctk.CTkLabel(
            warning, text="⚠  RESPONSIBLE USE",
            font=Fonts.badge(11), text_color="#FDBA74",
        ).pack(anchor="w", padx=14, pady=(10, 2))

        ctk.CTkLabel(
            warning,
            text="Use this tool responsibly. Changing your IP too frequently "
                 "may trigger CAPTCHAs on some websites. Always respect the "
                 "terms of service of the websites you visit.",
            wraplength=600, justify="left",
            text_color="#FED7AA", font=Fonts.label(11), anchor="w",
        ).pack(fill="x", padx=14, pady=(0, 12))

        ctk.CTkButton(
            outer, text="Close", width=150, height=38,
            fg_color=Colors.primary, hover_color=Colors.primary_hover,
            command=on_close,
        ).pack(anchor="e", padx=24, pady=(0, 16))

        dialog.bind("<Escape>", lambda _e: on_close())
        dialog.update_idletasks()
        x = self.winfo_rootx() + (self.winfo_width() - dialog.winfo_width()) // 2
        y = self.winfo_rooty() + (self.winfo_height() - dialog.winfo_height()) // 2
        dialog.geometry(f"+{max(0, x)}+{max(0, y)}")


def main() -> None:
    app = IPRotatorApp()
    app.mainloop()


if __name__ == "__main__":
    main()