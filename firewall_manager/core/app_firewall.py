"""Apply per-app network policies.

Windows: ``netsh advfirewall`` with ``program=`` (inbound + outbound rules).
Linux:   not available yet (needs cgroup v2 / nft integration).

Fixes over the first version:
* Old rules were deleted with the wrong name (``name=X`` while the rules were
  created as ``X_in`` / ``X_out``), so nothing was ever removed.  Switching an
  app from Block to Allow left the old *Block* rule active (and in Windows
  Firewall Block always wins).  Both rules are now deleted by their real names.
* ``netsh`` failures now raise an error that contains netsh's own message
  instead of a bare ``CalledProcessError``.
* Administrator rights are checked up front with a clear message.
* If the outbound rule fails, the inbound one is rolled back.
"""

from __future__ import annotations

import os
import platform
import subprocess

from core.utils.subprocess_utils import get_no_window_kwargs
from firewall_manager.core.app_discovery import AppEntry


RULE_NAME = "CyberOpsApp_{app_id}"


def is_admin() -> bool:
    """True when the process has the rights needed to edit firewall rules."""
    if os.name == "nt":
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    return hasattr(os, "geteuid") and os.geteuid() == 0


class AppFirewall:
    def __init__(self) -> None:
        self.system = platform.system().lower()

    @property
    def supported(self) -> bool:
        return self.system == "windows"

    # ---------------------------------------------------- public

    def apply(self, app: AppEntry) -> str:
        if self.system == "windows":
            return self._apply_windows(app)
        if self.system == "linux":
            return self._apply_linux(app)
        raise RuntimeError(f"Unsupported OS: {self.system}")

    def clear(self, app: AppEntry) -> None:
        if self.system == "windows":
            if not is_admin():
                raise PermissionError(self._admin_message())
            self._delete_rules(RULE_NAME.format(app_id=app.app_id))
        elif self.system == "linux":
            self._clear_linux(app)

    # ---------------------------------------------------- Windows

    @staticmethod
    def _admin_message() -> str:
        return (
            "Administrator rights are required to change firewall rules.\n"
            "Close the app and start it again with 'Run as administrator'."
        )

    def _apply_windows(self, app: AppEntry) -> str:
        if not is_admin():
            raise PermissionError(self._admin_message())

        base = RULE_NAME.format(app_id=app.app_id)

        # Always remove the previous rules first (both directions).
        self._delete_rules(base)

        if app.policy == "default":
            return "cleared"

        exe = app.executable.replace("/", "\\")
        if any(ch in exe for ch in "\r\n\0"):
            raise RuntimeError("Invalid executable path.")
        if not os.path.isfile(exe):
            raise RuntimeError(f"Executable not found:\n{exe}")

        action = "allow" if app.policy == "allow" else "block"
        enable = "yes" if app.enabled else "no"

        try:
            for direction in ("in", "out"):
                self._netsh_checked([
                    "advfirewall", "firewall", "add", "rule",
                    f"name={base}_{direction}",
                    f"dir={direction}",
                    f"action={action}",
                    f"program={exe}",
                    f"enable={enable}",
                    "profile=any",
                ])
        except Exception:
            self._delete_rules(base)          # roll back a half-applied pair
            raise
        return "applied"

    def _delete_rules(self, base: str) -> None:
        # "base" alone is the legacy name used by the very first version.
        for name in (f"{base}_in", f"{base}_out", base):
            self._netsh(["advfirewall", "firewall", "delete", "rule", f"name={name}"])

    def _netsh(self, args: list[str]) -> subprocess.CompletedProcess:
        """Run netsh; never raises on a non-zero exit code."""
        try:
            return subprocess.run(
                ["netsh", *args],
                capture_output=True, text=True, errors="replace",
                shell=False, timeout=20, check=False,
                **get_no_window_kwargs(),
            )
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError("netsh timed out.") from exc
        except OSError as exc:
            raise RuntimeError(f"Could not run netsh: {exc}") from exc

    def _netsh_checked(self, args: list[str]) -> None:
        result = self._netsh(args)
        if result.returncode != 0:
            detail = (result.stdout or result.stderr or "").strip()
            raise RuntimeError(detail or f"netsh failed (exit {result.returncode}).")

    # ---------------------------------------------------- Linux

    def _apply_linux(self, app: AppEntry) -> str:
        raise RuntimeError(
            "Per-app blocking on Linux requires cgroup v2 integration "
            "and is not yet available in this build."
        )

    def _clear_linux(self, app: AppEntry) -> None:
        pass
