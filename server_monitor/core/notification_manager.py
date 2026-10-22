"""Notification and alert manager for Server Monitor."""

from __future__ import annotations

import logging
import platform

logger = logging.getLogger(__name__)

# Try to import notification libraries with fallback
try:
    from plyer import notification as plyer_notification
    HAS_PLYER = True
except ImportError:
    HAS_PLYER = False
    logger.warning("plyer not installed - notifications disabled")


class NotificationManager:
    """Manages system notifications and alert state."""

    def __init__(self) -> None:
        self._last_states: dict[str, str] = {}
        self._alerted_services: set[str] = set()

    def notify(self, title: str, message: str) -> bool:
        """Send a system notification."""
        if not HAS_PLYER:
            return False
        try:
            plyer_notification.notify(
                title=title,
                message=message,
                app_name="CyberOpsSuite Server Monitor",
                timeout=8,
            )
            return True
        except Exception as exc:
            logger.warning(f"Notification failed: {exc}")
            return False

    def check_transitions(
        self,
        current: dict[str, str],
        critical_services: list[str],
    ) -> list[tuple[str, str, str]]:
        """Return list of (service, old_status, new_status) for critical services."""
        alerts: list[tuple[str, str, str]] = []

        for service in critical_services:
            new_status = current.get(service, "Unknown")
            old_status = self._last_states.get(service)

            # Alert when a critical service goes from Running to Stopped
            if (old_status == "Running" and new_status == "Stopped"
                    and service not in self._alerted_services):
                alerts.append((service, old_status, new_status))
                self._alerted_services.add(service)
            # Clear the alert flag once the service is back to Running
            elif new_status == "Running":
                self._alerted_services.discard(service)

        self._last_states = dict(current)
        return alerts