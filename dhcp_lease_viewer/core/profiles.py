"""Server profiles storage for remote DHCP connections.

Saves connection details (server, username, backend) but NEVER passwords.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

from core.utils.paths import config_root


APP_DIR_NAME = "DHCPLeaseViewer"


def profiles_path() -> Path:
    """Return the path to the saved server profiles."""
    return config_root(APP_DIR_NAME) / "server_profiles.json"


def load_profiles() -> list[dict]:
    """Load saved profiles from disk."""
    path = profiles_path()
    if not path.exists():
        return []
    try:
        with path.open("r", encoding="utf-8-sig") as f:
            data = json.load(f)
            return data if isinstance(data, list) else []
    except (OSError, json.JSONDecodeError):
        return []


def save_profiles(profiles: list[dict]) -> None:
    """Save profiles atomically to disk."""
    path = profiles_path()
    path.parent.mkdir(parents=True, exist_ok=True)

    fd, temp_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent,
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
            json.dump(profiles, f, indent=4, ensure_ascii=False)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp_name, path)
    finally:
        if os.path.exists(temp_name):
            os.unlink(temp_name)


def add_profile(server: str, username: str, backend: str, key_path: str = "") -> dict:
    """Add or update a server profile (never stores passwords)."""
    profiles = load_profiles()
    for p in profiles:
        if p.get("server") == server:
            p["username"] = username
            p["backend"] = backend
            p["key_path"] = key_path
            save_profiles(profiles)
            return p

    profile = {
        "server": server,
        "username": username,
        "backend": backend,
        "key_path": key_path,
    }
    profiles.append(profile)
    save_profiles(profiles)
    return profile
