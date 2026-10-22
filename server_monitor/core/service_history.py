"""Track when each service's status last changed (in-memory only)."""

from __future__ import annotations

import time


class ServiceHistory:
    """Stores the last change time for each service."""

    def __init__(self) -> None:
        self._last_status: dict[str, str] = {}
        self._changed_at: dict[str, float] = {}

    def update(self, name: str, status: str) -> None:
        """Record *status* for *name*. Updates change time on transition."""
        previous = self._last_status.get(name)
        if previous is None:
            self._last_status[name] = status
            self._changed_at[name] = time.time()
            return
        if previous != status:
            self._last_status[name] = status
            self._changed_at[name] = time.time()

    def uptime_seconds(self, name: str, status: str) -> int:
        """Return seconds since the service last changed."""
        if name not in self._changed_at:
            return 0
        return int(time.time() - self._changed_at[name])

    def format_change(self, name: str, status: str) -> str:
        """Return a human-readable 'last change' string."""
        seconds = self.uptime_seconds(name, status)
        if seconds < 60:
            return "just now"
        minutes = seconds // 60
        if minutes < 60:
            return f"{minutes}m ago"
        hours = minutes // 60
        if hours < 24:
            return f"{hours}h ago"
        days = hours // 24
        return f"{days}d ago"