"""Desktop notifications that really show up on Windows 10/11.

Why the old version failed
--------------------------
* The PowerShell toast used an unregistered app id ("ThreatGuard"); Windows
  silently drops toasts from unknown ids.
* It returned True even when PowerShell failed.
* win10toast is unmaintained and breaks on new Python versions.

Order used now
--------------
1. The tray icon's own balloon (pystray) when the tray icon is running.
2. A PowerShell toast using PowerShell's registered app id (always allowed).
3. plyer (if installed).
4. notify-send on Linux.
"""
from __future__ import annotations

import platform
import subprocess
import threading
from typing import Callable

_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)
# App id of Windows PowerShell: registered by Windows, so its toasts are displayed.
_POWERSHELL_APP_ID = r"{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe"

_tray_notifier: Callable[[str, str], bool] | None = None


def set_tray_notifier(func: Callable[[str, str], bool] | None) -> None:
    """The GUI registers the tray icon's notify function here (None to unregister)."""
    global _tray_notifier
    _tray_notifier = func


def notify(title: str, message: str, timeout: int = 10) -> bool:
    """Show a notification. Returns True if some backend accepted it."""
    title = (title or "ThreatGuard")[:100]
    message = (message or "")[:250]

    if _tray_notifier is not None:
        try:
            if _tray_notifier(title, message):
                return True
        except Exception:
            pass

    system = platform.system()
    if system == "Windows":
        if _powershell_toast(title, message):
            return True
    elif system == "Linux":
        if _notify_send(title, message, timeout):
            return True
    return _plyer(title, message, timeout)


def _run_bounded(target: Callable[[], bool], wait: float = 8.0) -> bool:
    """Run a slow backend in a helper thread and wait for it only briefly."""
    result: list[bool] = []

    def runner() -> None:
        try:
            result.append(bool(target()))
        except Exception:
            result.append(False)

    thread = threading.Thread(target=runner, daemon=True)
    thread.start()
    thread.join(timeout=wait)
    return bool(result and result[0])


def _ps_escape(text: str) -> str:
    return text.replace("'", "''").replace("\r", " ").replace("\n", " | ")


def _powershell_toast(title: str, message: str) -> bool:
    script = (
        "$ErrorActionPreference='Stop';"
        "[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, "
        "ContentType = WindowsRuntime] | Out-Null;"
        "$t=[Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent(5);"  # ToastText02
        "$n=$t.GetElementsByTagName('text');"
        f"$n.Item(0).AppendChild($t.CreateTextNode('{_ps_escape(title)}')) | Out-Null;"
        f"$n.Item(1).AppendChild($t.CreateTextNode('{_ps_escape(message)}')) | Out-Null;"
        "$toast=[Windows.UI.Notifications.ToastNotification]::new($t);"
        f"[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('{_POWERSHELL_APP_ID}')"
        ".Show($toast)"
    )

    def run() -> bool:
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True, timeout=15, check=False, creationflags=_NO_WINDOW,
        )
        return proc.returncode == 0

    return _run_bounded(run)


def _notify_send(title: str, message: str, timeout: int) -> bool:
    def run() -> bool:
        proc = subprocess.run(
            ["notify-send", "-t", str(int(timeout) * 1000), title, message],
            capture_output=True, timeout=10, check=False,
        )
        return proc.returncode == 0

    return _run_bounded(run)


def _plyer(title: str, message: str, timeout: int) -> bool:
    try:
        from plyer import notification
        notification.notify(title=title, message=message, timeout=timeout, app_name="ThreatGuard")
        return True
    except Exception:
        return False
