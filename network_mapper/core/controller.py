"""Scan control primitives shared by scanners and the GUI.

The controller is a tiny thread-safe state machine built on
:class:`threading.Event`. It exposes three conceptual states:

* **running** — the default. ``wait_if_paused`` returns immediately and
  ``stopped`` is ``False``.
* **paused** — worker threads block inside ``wait_if_paused`` until either
  :meth:`resume` or :meth:`stop` is called.
* **stopped** — no further work should be scheduled. Any thread currently
  blocked in ``wait_if_paused`` is released so it can observe ``stopped``.

The controller is deliberately free of any GUI or scanner imports so it can
be reused by every module in CyberOpsSuite.
"""

from __future__ import annotations

import threading


class ScanController:
    """Thread-safe pause / stop signals for a running scan."""

    def __init__(self) -> None:
        # ``set`` means "not paused" so a fresh controller starts running.
        self._pause_event = threading.Event()
        self._pause_event.set()
        self._stop_event = threading.Event()

    # ------------------------------------------------------------- state

    @property
    def paused(self) -> bool:
        """``True`` while the scan is paused (and not stopped)."""
        return not self._pause_event.is_set()

    @property
    def stopped(self) -> bool:
        """``True`` once :meth:`stop` has been called."""
        return self._stop_event.is_set()

    # ----------------------------------------------------------- control

    def pause(self) -> None:
        """Request a pause. Threads blocked in :meth:`wait_if_paused` hold."""
        self._pause_event.clear()

    def resume(self) -> None:
        """Release threads blocked in :meth:`wait_if_paused`."""
        self._pause_event.set()

    def stop(self) -> None:
        """Request a stop and release anything waiting on the pause gate."""
        self._stop_event.set()
        self._pause_event.set()

    # ------------------------------------------------------------ checks

    def wait_if_paused(self) -> None:
        """Block while paused. Returns immediately if running or stopped.

        Intended to be called at the top of each unit of work (a host probe,
        a port probe, a batch iteration) so the GUI can pause without
        interrupting a probe that is already in flight.
        """
        self._pause_event.wait()

    def can_continue(self) -> bool:
        """Block while paused, then report whether work should continue.

        Equivalent to::

            controller.wait_if_paused()
            if controller.stopped:
                return False
            return True
        """
        self._pause_event.wait()
        return not self.stopped