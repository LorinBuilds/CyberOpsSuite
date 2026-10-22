"""Settings dialog for the Server Monitor.

Two ways to choose services:

* **Preset** — pick a ready-made list (Domain Controller, File Server,
  Web Server, DHCP Server, Core Windows).
* **Browse** — tick individual services from a searchable list of
  everything installed on this machine.

The choice is written to the config store on Save.
"""

from __future__ import annotations

import threading
from tkinter import messagebox

import customtkinter as ctk

from server_monitor.core.config_store import (
    PRESETS,
    ServiceConfig,
    save_config,
)
from server_monitor.core.service_checker import list_all_services

from core.theme import Colors, Fonts, Spacing
from core.utils.icons import apply_window_icon


class SettingsDialog(ctk.CTkToplevel):
    """Modal dialog for editing the monitored service list."""

    def __init__(self, parent, on_saved=None) -> None:
        super().__init__(parent)

        self._parent = parent
        self._on_saved = on_saved
        self._config: ServiceConfig = parent._config

        # Cached full service list.
        self._all_services: list = []
        self._loading_services = False
        self._service_checks: dict = {}

        self.title("Settings | Server Monitor")
        self.geometry("720x640")
        self.minsize(640, 540)
        self.configure(fg_color=Colors.bg)
        self.transient(parent)
        self.grab_set()

        # Window icon (matches the main app).
        apply_window_icon(self)

        # Observable variables.
        self.preset_var = ctk.StringVar(value=self._config.active_preset)
        self.search_var = ctk.StringVar()
        self.selected_count_var = ctk.StringVar(value="Selected: 0")
        self.tab_var = ctk.StringVar(value="Preset")

        self._build_ui()

    # ------------------------------------------------------------------ UI

    def _build_ui(self) -> None:
        outer = ctk.CTkFrame(self, fg_color="transparent")
        outer.pack(fill="both", expand=True, padx=20, pady=20)
        outer.rowconfigure(2, weight=1)
        outer.columnconfigure(0, weight=1)

        self._build_header(outer)

        # Segmented tab selector.
        self.tab_selector = ctk.CTkSegmentedButton(
            outer,
            values=["Preset", "Browse all"],
            command=self._on_tab_changed,
            font=Fonts.label(11),
            fg_color=Colors.surface_alt,
            selected_color=Colors.primary,
            selected_hover_color=Colors.primary_hover,
            unselected_color=Colors.surface_alt,
            unselected_hover_color=Colors.border_light,
            text_color=Colors.text,
            height=Spacing.INPUT_HEIGHT,
        )
        self.tab_selector.set("Preset")
        self.tab_selector.grid(row=1, column=0, sticky="ew", pady=(0, 12))

        # Container for both tab frames.
        self.tab_container = ctk.CTkFrame(outer, fg_color="transparent")
        self.tab_container.grid(row=2, column=0, sticky="nsew", pady=(0, 12))
        self.tab_container.rowconfigure(0, weight=1)
        self.tab_container.columnconfigure(0, weight=1)

        self.preset_frame = ctk.CTkFrame(self.tab_container, fg_color="transparent")
        self.browse_frame = ctk.CTkFrame(self.tab_container, fg_color="transparent")

        self._build_preset_tab(self.preset_frame)
        self._build_browse_tab(self.browse_frame)

        self._show_tab("Preset")

        self._build_footer(outer)

    def _on_tab_changed(self, value: str) -> None:
        self._show_tab(value)

    def _show_tab(self, name: str) -> None:
        self.preset_frame.grid_forget()
        self.browse_frame.grid_forget()
        if name == "Preset":
            self.preset_frame.grid(row=0, column=0, sticky="nsew")
        else:
            self.browse_frame.grid(row=0, column=0, sticky="nsew")

    def _build_header(self, parent: ctk.CTkFrame) -> None:
        header = ctk.CTkFrame(parent, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", pady=(0, 16))

        ctk.CTkLabel(
            header, text="Monitored services",
            font=Fonts.title(20), text_color=Colors.text_strong,
        ).pack(anchor="w")

        ctk.CTkLabel(
            header,
            text="Choose a preset or browse the full list of installed services.",
            font=Fonts.label(11), text_color=Colors.text_muted,
        ).pack(anchor="w", pady=(4, 0))

    # ------------------------------------------------------------- preset

    def _build_preset_tab(self, parent: ctk.CTkFrame) -> None:
        parent.rowconfigure(0, weight=1)
        parent.columnconfigure(0, weight=1)

        card = ctk.CTkFrame(
            parent, fg_color=Colors.surface,
            corner_radius=Spacing.RADIUS_CARD,
            border_width=1, border_color=Colors.border,
        )
        card.grid(row=0, column=0, sticky="nsew", pady=10)
        card.rowconfigure(2, weight=1)
        card.columnconfigure(0, weight=1)

        ctk.CTkLabel(
            card, text="CHOOSE A PRESET",
            font=Fonts.badge(10), text_color=Colors.text_muted,
        ).grid(row=0, column=0, sticky="w", padx=16, pady=(14, 6))

        self.preset_menu = ctk.CTkOptionMenu(
            card,
            variable=self.preset_var,
            values=list(PRESETS.keys()),
            width=280, height=Spacing.INPUT_HEIGHT,
            fg_color=Colors.primary, button_color=Colors.primary_hover,
            button_hover_color=Colors.primary_active,
            dropdown_fg_color=Colors.surface,
            dropdown_hover_color=Colors.primary,
            font=Fonts.label(11),
            command=self._on_preset_changed,
        )
        self.preset_menu.grid(row=1, column=0, sticky="w", padx=16, pady=(0, 12))

        self.preset_list = ctk.CTkTextbox(
            card, height=220,
            fg_color=Colors.bg, text_color=Colors.text,
            border_color=Colors.border, border_width=1,
            font=Fonts.mono(11),
        )
        self.preset_list.grid(row=2, column=0, sticky="nsew", padx=16, pady=(0, 8))

        self.preset_hint = ctk.CTkLabel(
            card, text="",
            font=Fonts.label(10), text_color=Colors.text_muted,
            justify="left", wraplength=600,
        )
        self.preset_hint.grid(row=3, column=0, sticky="w", padx=16, pady=(0, 14))

        self._refresh_preset_list()

    def _on_preset_changed(self, value: str) -> None:
        """Called when the user picks a different preset.

        When switching to a real preset (not Custom), clear the custom
        checkboxes so the Browse tab does not silently override the
        chosen preset on Save.
        """
        self._refresh_preset_list()

        # If the user picked a real preset, uncheck every browse checkbox
        # so the next Save honours the preset instead of "Custom".
        if value != "Custom" and self._service_checks:
            for var in self._service_checks.values():
                try:
                    var.set(False)
                except Exception:
                    pass
            self._update_selected_count()

    def _refresh_preset_list(self) -> None:
        preset = self.preset_var.get()

        if preset == "Custom":
            services = list(self._config.custom_services)
            hint = (
                "Custom list — add or remove services in the 'Browse all' tab."
                if services else
                "No custom services yet. Use the 'Browse all' tab to pick services."
            )
        else:
            services = list(PRESETS.get(preset, ()))
            hint = f"{len(services)} service(s) in this preset."

        if services:
            text = "\n".join(f"  • {s}" for s in services)
        else:
            text = "  (no services)"

        self.preset_list.configure(state="normal")
        self.preset_list.delete("1.0", "end")
        self.preset_list.insert("1.0", text)
        self.preset_list.configure(state="disabled")

        self.preset_hint.configure(text=hint)

    # ------------------------------------------------------------- browse

    def _build_browse_tab(self, parent: ctk.CTkFrame) -> None:
        parent.rowconfigure(0, weight=1)
        parent.columnconfigure(0, weight=1)

        card = ctk.CTkFrame(
            parent, fg_color=Colors.surface,
            corner_radius=Spacing.RADIUS_CARD,
            border_width=1, border_color=Colors.border,
        )
        card.grid(row=0, column=0, sticky="nsew", pady=10)
        card.rowconfigure(2, weight=1)
        card.columnconfigure(0, weight=1)

        ctk.CTkLabel(
            card, text="BROWSE INSTALLED SERVICES",
            font=Fonts.badge(10), text_color=Colors.text_muted,
        ).grid(row=0, column=0, sticky="w", padx=16, pady=(14, 6))

        search_bar = ctk.CTkFrame(card, fg_color="transparent")
        search_bar.grid(row=1, column=0, sticky="ew", padx=16, pady=(0, 8))
        search_bar.columnconfigure(0, weight=1)

        self.search_entry = ctk.CTkEntry(
            search_bar, textvariable=self.search_var,
            placeholder_text="Search by name or display name…",
            height=Spacing.INPUT_HEIGHT,
            fg_color=Colors.surface_alt, text_color=Colors.text,
            border_color=Colors.border_light,
            font=Fonts.label(11),
        )
        self.search_entry.grid(row=0, column=0, sticky="ew", padx=(0, 8))
        self.search_var.trace_add("write", lambda *_: self._render_service_list())

        ctk.CTkButton(
            search_bar, text="↻ Reload",
            width=100, height=Spacing.INPUT_HEIGHT,
            fg_color=Colors.neutral_dark,
            hover_color=Colors.neutral_dark_hover,
            font=Fonts.label(10),
            command=self._reload_services,
        ).grid(row=0, column=1)

        self.services_scroll = ctk.CTkScrollableFrame(
            card, fg_color=Colors.bg,
            corner_radius=Spacing.RADIUS_INPUT,
            border_width=1, border_color=Colors.border,
            scrollbar_button_color=Colors.surface_alt,
            scrollbar_button_hover_color=Colors.border_light,
        )
        self.services_scroll.grid(row=2, column=0, sticky="nsew", padx=16, pady=(0, 8))
        self.services_scroll.columnconfigure(0, weight=1)

        ctk.CTkLabel(
            card, textvariable=self.selected_count_var,
            font=Fonts.label(10), text_color=Colors.text_muted,
        ).grid(row=3, column=0, sticky="w", padx=16, pady=(0, 14))

        self.after(100, self._reload_services)

    def _reload_services(self) -> None:
        if self._loading_services:
            return
        self._loading_services = True

        for child in self.services_scroll.winfo_children():
            child.destroy()
        ctk.CTkLabel(
            self.services_scroll,
            text="Loading services…",
            font=Fonts.label(10), text_color=Colors.text_muted,
        ).pack(pady=20)

        def worker():
            try:
                services = list_all_services()
            except Exception:
                services = []
            self.after(0, lambda: self._apply_services(services))

        threading.Thread(target=worker, daemon=True).start()

    def _apply_services(self, services: list) -> None:
        self._all_services = services
        self._loading_services = False
        self._render_service_list()

    def _render_service_list(self) -> None:
        for child in self.services_scroll.winfo_children():
            child.destroy()

        query = self.search_var.get().strip().casefold()
        selected_names = set(self._config.custom_services)

        self._service_checks.clear()

        visible = 0
        for svc in self._all_services:
            haystack = f"{svc.name} {svc.display_name}".casefold()
            if query and query not in haystack:
                continue

            row = ctk.CTkFrame(self.services_scroll, fg_color="transparent")
            row.pack(fill="x", padx=4, pady=2)

            var = ctk.BooleanVar(value=(svc.name in selected_names))
            var.trace_add("write", lambda *_: self._update_selected_count())

            ctk.CTkCheckBox(
                row, text=svc.name,
                variable=var,
                font=Fonts.mono(10), text_color=Colors.text,
                fg_color=Colors.primary, hover_color=Colors.primary_hover,
                border_color=Colors.border_light,
                width=200,
            ).pack(side="left", padx=(4, 8))

            ctk.CTkLabel(
                row, text=svc.display_name or "—",
                font=Fonts.label(10), text_color=Colors.text_muted,
                anchor="w",
            ).pack(side="left", fill="x", expand=True, padx=(0, 8))

            status = svc.status or "—"
            status_color = (
                Colors.success_text if status == "Running"
                else Colors.danger_text if status == "Stopped"
                else Colors.text_dim
            )
            ctk.CTkLabel(
                row, text=status, width=80,
                font=Fonts.label(10), text_color=status_color,
                anchor="w",
            ).pack(side="right", padx=(0, 4))

            self._service_checks[svc.name] = var
            visible += 1

        if visible == 0:
            ctk.CTkLabel(
                self.services_scroll,
                text="No services match your search." if query
                     else "No services found.",
                font=Fonts.label(10), text_color=Colors.text_muted,
            ).pack(pady=20)

        self._update_selected_count()

    def _update_selected_count(self) -> None:
        count = sum(1 for v in self._service_checks.values() if v.get())
        self.selected_count_var.set(f"Selected: {count}")

    # ------------------------------------------------------------- footer

    def _build_footer(self, parent: ctk.CTkFrame) -> None:
        footer = ctk.CTkFrame(parent, fg_color="transparent")
        footer.grid(row=3, column=0, sticky="ew", pady=(0, 0))

        ctk.CTkButton(
            footer, text="Save",
            width=130, height=Spacing.BUTTON_HEIGHT,
            fg_color=Colors.primary, hover_color=Colors.primary_hover,
            font=Fonts.label(11, bold=True),
            command=self._save,
        ).pack(side="right", padx=(8, 0))

        ctk.CTkButton(
            footer, text="Cancel",
            width=110, height=Spacing.BUTTON_HEIGHT,
            fg_color=Colors.neutral_dark,
            hover_color=Colors.neutral_dark_hover,
            font=Fonts.label(11),
            command=self.destroy,
        ).pack(side="right")

    # -------------------------------------------------------------- save

    def _save(self) -> None:
        """Persist the user's choice.

        Rules:
        * If a real preset is selected (not "Custom"), that preset wins.
          Any checkboxes in Browse are ignored for the active preset, but
          kept as the custom list for later use.
        * If "Custom" is selected and at least one service is checked,
          the custom list becomes active.
        * If nothing is checked and the preset is "Custom", keep the
          previous custom list untouched.
        """
        preset_choice = self.preset_var.get()
        chosen_custom = [
            name for name, var in self._service_checks.items()
            if var.get()
        ]

        if preset_choice and preset_choice != "Custom":
            # A real preset is active — it wins.
            self._config.active_preset = preset_choice
            if chosen_custom:
                # Remember what the user ticked for later, without
                # switching to it.
                self._config.custom_services = chosen_custom

        elif chosen_custom:
            # Custom mode explicitly chosen with at least one service.
            self._config.custom_services = chosen_custom
            self._config.active_preset = "Custom"

        else:
            # No explicit choice — fall back to whatever was already set.
            if not self._config.active_preset:
                self._config.active_preset = "Core Windows"

        try:
            save_config(self._config)
        except OSError as exc:
            messagebox.showerror(
                "Save failed",
                f"Could not save settings:\n\n{exc}",
                parent=self,
            )
            return

        if self._on_saved is not None:
            try:
                self._on_saved(self._config)
            except Exception:
                pass

        self.destroy()