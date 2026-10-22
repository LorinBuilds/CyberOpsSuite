"""Persistent storage for the Server Monitor service list.

The user's chosen services are stored in a small JSON file under the
platform's standard config directory:

* Windows: ``%APPDATA%\\CyberOpsSuite\\ServerMonitor\\services.json``
* Linux:   ``~/.config/CyberOpsSuite/ServerMonitor/services.json``

The file has a simple structure::

    {
      "active_preset": "Domain Controller",
      "custom_services": ["CustomService1", "CustomService2"]
    }

Presets themselves live in this module as immutable constants so they can
be updated with the code. The user can switch between presets or build a
custom list.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path

from core.utils.paths import config_root


#: Module name used for the per-user config directory.
APP_DIR_NAME = "ServerMonitor"


#: Built-in service presets. Keys are user-visible preset names, values
#: are the service names to monitor for that preset.
PRESETS: dict[str, tuple[str, ...]] = {
    "Domain Controller": (
        "NTDS",
        "DNS",
        "KDC",
        "Netlogon",
        "W32Time",
        "DFS Replication",
    ),
    "File Server": (
        "LanmanServer",
        "LanmanWorkstation",
        "Spooler",
        "W32Time",
    ),
    "Web Server (IIS)": (
        "W3SVC",
        "WAS",
        "IISADMIN",
        "HTTP",
    ),
    "DHCP Server": (
        "DHCPServer",
        "Dnscache",
        "W32Time",
    ),
    "Core Windows": (
        "RpcSs",
        "DcomLaunch",
        "Winmgmt",
        "EventLog",
        "Schedule",
    ),
    "Custom": (),  # populated by the user
}


DEFAULT_PRESET = "Core Windows"


@dataclass
class ServiceConfig:
    """In-memory representation of the persisted configuration."""

    active_preset: str = DEFAULT_PRESET
    custom_services: list[str] = field(default_factory=list)

    def services(self) -> list[str]:
        """Return the effective list of services to monitor.

        For non-custom presets, the list comes from :data:`PRESETS`.
        For the ``"Custom"`` preset, the user's list is returned.
        """
        if self.active_preset == "Custom":
            return list(self.custom_services)
        return list(PRESETS.get(self.active_preset, ()))

    def set_preset(self, name: str) -> None:
        """Switch to *name*, or raise ``ValueError`` if unknown."""
        if name not in PRESETS:
            raise ValueError(f"Unknown preset: {name!r}")
        self.active_preset = name

    def add_custom(self, service: str) -> bool:
        """Add *service* to the custom list. Return ``True`` if added."""
        service = (service or "").strip()
        if not service or service in self.custom_services:
            return False
        self.custom_services.append(service)
        self.active_preset = "Custom"
        return True

    def remove_custom(self, service: str) -> bool:
        """Remove *service* from the custom list. Return ``True`` if removed."""
        if service in self.custom_services:
            self.custom_services.remove(service)
            return True
        return False


# ------------------------------------------------------------- path helpers

def config_path() -> Path:
    """Return the full path to the services JSON file.

    The parent directory is created on demand by
    :func:`core.utils.paths.config_root`.
    """
    return config_root(APP_DIR_NAME) / "services.json"


# ------------------------------------------------------------- load / save

def load_config() -> ServiceConfig:
    """Load configuration from disk, or return defaults if missing.

    Corrupt files are silently replaced with the default configuration;
    a broken config should never prevent the app from starting.
    """
    path = config_path()
    if not path.is_file():
        return ServiceConfig()

    try:
        with path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return ServiceConfig()

    if not isinstance(data, dict):
        return ServiceConfig()

    preset = str(data.get("active_preset") or DEFAULT_PRESET)
    if preset not in PRESETS:
        preset = DEFAULT_PRESET

    raw_custom = data.get("custom_services") or []
    if not isinstance(raw_custom, list):
        raw_custom = []
    custom = [str(s).strip() for s in raw_custom if str(s).strip()]

    return ServiceConfig(active_preset=preset, custom_services=custom)


def save_config(cfg: ServiceConfig) -> None:
    """Persist *cfg* to disk. Creates the directory if needed."""
    path = config_path()
    path.parent.mkdir(parents=True, exist_ok=True)

    payload = {
        "active_preset": cfg.active_preset,
        "custom_services": list(cfg.custom_services),
    }

    # Atomic write: write to a temp file, then replace.
    tmp = path.with_suffix(".tmp")
    with tmp.open("w", encoding="utf-8", newline="\n") as handle:
        json.dump(payload, handle, indent=2, ensure_ascii=False)
        handle.write("\n")
    os.replace(tmp, path)