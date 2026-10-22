"""Shared subprocess helpers for all CyberOpsSuite modules.

The single purpose of this module is to hide console windows that
would otherwise flash on screen for every system command executed
from a GUI application built with PyInstaller's ``--windowed`` mode.
"""

from __future__ import annotations

import subprocess
import sys


def get_no_window_kwargs() -> dict:
    """Return kwargs for subprocess calls that suppress the console window.

    Usage::

        from core.utils.subprocess_utils import run_hidden
        result = run_hidden(["ping", "8.8.8.8"])

    Or::

        from core.utils.subprocess_utils import get_no_window_kwargs
        subprocess.run(["ping", "8.8.8.8"], **get_no_window_kwargs())
    """
    if sys.platform == "win32":
        return {
            "creationflags": subprocess.CREATE_NO_WINDOW,
        }
    return {}


def run_hidden(args, **kwargs) -> subprocess.CompletedProcess:
    """Run a command with the console window suppressed on Windows.

    All extra ``kwargs`` are forwarded to :func:`subprocess.run`.
    """
    kwargs.setdefault("capture_output", True)
    kwargs.setdefault("text", True)
    kwargs.setdefault("shell", False)
    
    no_window = get_no_window_kwargs()
    for key, value in no_window.items():
        kwargs.setdefault(key, value)
        
    return subprocess.run(args, **kwargs)


def popen_hidden(args, **kwargs) -> subprocess.Popen:
    """Spawn a background process without a console window on Windows."""
    
    no_window = get_no_window_kwargs()
    for key, value in no_window.items():
        kwargs.setdefault(key, value)
        
    return subprocess.Popen(args, **kwargs)