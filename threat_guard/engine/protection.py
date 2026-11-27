"""One-button protection: review everything, repeat on a schedule, notify.

What "activate" does
--------------------
1. Reviews the system (event logs, autostart entries, processes, network,
   rootkit indicators, hardening) and reports immediately.
2. Scans files: risky folders first (Downloads, Temp, AppData, Startup), then
   every fixed and removable drive. Later cycles only re-check changed files.
3. Watches for newly connected USB / external drives and scans them at once.
4. Sends a Windows notification when protection is enabled, disabled, when
   a scan finishes the first time, and whenever *new* findings appear.

Read-only by design: nothing is deleted, quarantined or modified.
"""
from __future__ import annotations

import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from threat_guard.engine.scanner import Finding, ScanReport, ThreatScanner
from threat_guard.engine import system_review as sr

_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

Notify = Callable[[str, str], object]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def finding_key(item: dict) -> tuple:
    """Identity of a finding, so the same one is announced only once."""
    return (item.get("engine"), item.get("path"), item.get("title"),
            str(item.get("details", ""))[:160])


def sort_findings(findings: list[dict]) -> list[dict]:
    return sorted(findings, key=lambda f: (_SEVERITY_RANK.get(str(f.get("severity")).lower(), 9),
                                           str(f.get("engine")), str(f.get("path"))))


def make_scanner(use_clamav: bool = False, workers: int | None = None) -> ThreatScanner:
    return ThreatScanner(
        use_clamav=use_clamav,
        workers=workers,
        use_cache=True,
        exclude_dirs=sr.default_exclusions(),
    )


def full_review(
    targets: list[Path] | None,
    scanner: ThreatScanner,
    cancel: threading.Event | None = None,
    progress: Callable[[int, int, str], None] | None = None,
    status: Callable[[str], None] | None = None,
    include_system: bool = True,
) -> dict:
    """Run the whole review once and return a report dict (GUI/JSON friendly).

    ``targets=None`` means: all fixed and removable drives.
    """
    started = _now()
    say = status or (lambda _msg: None)
    findings: list[Finding] = []
    checks: list[dict] = []
    errors: list[str] = []
    scanned = skipped = 0
    cancelled = False

    if include_system:
        say("Reviewing event logs, autostart entries, processes and network…")
        sys_findings, checks, sys_errors = sr.run_system_review(cancel=cancel)
        findings.extend(sys_findings)
        errors.extend(sys_errors)

    if targets is None:
        roots = [path for path, _kind in sr.list_drives()]
        ordered: list[Path] = list(sr.quick_locations()) + roots
    else:
        ordered = list(targets)

    total_done = [0, 0]  # files scanned / skipped in finished roots

    for root in ordered:
        if cancel is not None and cancel.is_set():
            cancelled = True
            break
        say(f"Scanning {root} …")

        def on_progress(s: int, k: int, current: str, _root=root) -> None:
            if progress is not None:
                progress(total_done[0] + s, total_done[1] + k, current)

        try:
            report: ScanReport = scanner.scan(root, progress=on_progress, cancel=cancel)
        except (OSError, ValueError) as exc:
            errors.append(f"{root}: {exc}")
            continue
        total_done[0] += report.scanned_files
        total_done[1] += report.skipped_files
        findings.extend(report.findings)
        errors.extend(report.errors)
        if report.cancelled:
            cancelled = True
            break
    scanned, skipped = total_done

    # The same file can be reached twice (quick folder + whole drive): keep one.
    unique: dict[tuple, dict] = {}
    for item in findings:
        row = item.__dict__.copy() if isinstance(item, Finding) else dict(item)
        unique.setdefault(finding_key(row), row)

    return {
        "started_at": started,
        "finished_at": _now(),
        "scanned_files": scanned,
        "skipped_files": skipped,
        "findings": sort_findings(list(unique.values())),
        "errors": errors[:500],
        "cancelled": cancelled,
        "checks": checks,
        "mode": "full-review",
    }


class ProtectionManager:
    """Background protection. ``start()`` / ``stop()`` are the two buttons."""

    def __init__(
        self,
        targets: list[Path] | None = None,
        interval_seconds: int = 600,
        notify: Notify | None = None,
        on_report: Callable[[dict], None] | None = None,
        on_status: Callable[[str], None] | None = None,
        on_error: Callable[[str], None] | None = None,
        watch_drives: bool = True,
    ) -> None:
        self.targets = targets
        self.interval = max(60, int(interval_seconds))
        self._notify_fn = notify
        self._on_report = on_report
        self._on_status = on_status
        self._on_error = on_error
        self.watch_drives = watch_drives and targets is None

        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []
        self._scanner: ThreatScanner | None = None
        self._seen: set[tuple] = set()
        self._cycles = 0
        self._last_report: dict | None = None

    # ------------------------------------------------------------ lifecycle

    @property
    def is_running(self) -> bool:
        return any(t.is_alive() for t in self._threads)

    @property
    def cycles(self) -> int:
        return self._cycles

    @property
    def last_report(self) -> dict | None:
        return self._last_report

    def start(self) -> None:
        if self.is_running:
            return
        self._stop.clear()
        self._scanner = make_scanner()
        self._threads = [threading.Thread(target=self._loop, name="TG-Protection", daemon=True)]
        if self.watch_drives:
            self._threads.append(threading.Thread(target=self._drive_watcher,
                                                  name="TG-DriveWatch", daemon=True))
        for thread in self._threads:
            thread.start()
        where = "all drives" if self.targets is None else ", ".join(str(t) for t in self.targets)
        self._notify("ThreatGuard — Protection ENABLED", f"Monitoring {where}.")

    def stop(self, timeout: float = 5.0) -> None:
        was_running = self.is_running
        self._stop.set()
        for thread in self._threads:
            if thread.is_alive() and thread is not threading.current_thread():
                thread.join(timeout=timeout)
        self._threads = []
        if was_running:
            self._notify("ThreatGuard — Protection DISABLED",
                         "Your computer is no longer being monitored by ThreatGuard.")

    # ------------------------------------------------------------- internals

    def _notify(self, title: str, message: str) -> None:
        if self._notify_fn:
            try:
                self._notify_fn(title, message)
            except Exception:
                pass

    def _status(self, message: str) -> None:
        if self._on_status:
            try:
                self._on_status(message)
            except Exception:
                pass

    def _loop(self) -> None:
        first = True
        while not self._stop.is_set():
            self._one_cycle(first)
            first = False
            if self._stop.wait(self.interval):
                break

    def _one_cycle(self, first: bool) -> None:
        try:
            assert self._scanner is not None
            report = full_review(
                self.targets, self._scanner, cancel=self._stop,
                progress=lambda s, k, cur: self._status(
                    f"Protection active · scanning… {s:,} files · {Path(cur).name if cur else ''}"),
                status=self._status,
            )
            if self._stop.is_set():
                return
            self._cycles += 1
            self._last_report = report
            new = [f for f in report["findings"] if finding_key(f) not in self._seen]
            for item in new:
                self._seen.add(finding_key(item))

            if self._on_report:
                self._on_report(report)
            self._status(
                f"Protection active · cycle {self._cycles} · {report['scanned_files']:,} files · "
                f"{len(report['findings'])} findings · next check in {self.interval // 60} min")

            if new:
                self._announce_findings(new)
            elif first:
                self._notify("ThreatGuard — Scan complete",
                             f"{report['scanned_files']:,} files checked. No threats found.")
        except Exception as exc:  # the guard must survive anything
            if self._on_error:
                self._on_error(f"Protection cycle failed: {exc}")

    def _announce_findings(self, new: list[dict]) -> None:
        ordered = sort_findings(new)
        worst = str(ordered[0].get("severity", "")).upper()
        lines = [f"• [{str(f.get('severity')).upper()}] {f.get('title')}" for f in ordered[:4]]
        if len(ordered) > 4:
            lines.append(f"… and {len(ordered) - 4} more")
        self._notify(f"ThreatGuard — {len(ordered)} new finding(s) ({worst})", "\n".join(lines))

    def _drive_watcher(self) -> None:
        """Scan USB / external drives the moment they are connected."""
        known = {str(path) for path, _kind in sr.list_drives()}
        usb_scanner = ThreatScanner(use_clamav=False, workers=2, exclude_dirs=sr.default_exclusions())
        while not self._stop.wait(5):
            try:
                current = {str(path): (path, kind) for path, kind in sr.list_drives()}
            except Exception:
                continue
            for key, (path, kind) in current.items():
                if key in known:
                    continue
                known.add(key)
                label = "USB / external drive" if kind == "removable" else "Drive"
                self._notify(f"ThreatGuard — {label} connected", f"Scanning {path} …")
                try:
                    report = usb_scanner.scan(path, cancel=self._stop)
                except Exception as exc:
                    if self._on_error:
                        self._on_error(f"Drive scan failed ({path}): {exc}")
                    continue
                rows = [f.__dict__ for f in report.findings]
                new = [r for r in rows if finding_key(r) not in self._seen]
                for row in new:
                    self._seen.add(finding_key(row))
                if new:
                    self._announce_findings(new)
                else:
                    self._notify(f"ThreatGuard — {path} is clean",
                                 f"{report.scanned_files:,} files checked, no threats found.")
            known = set(current)  # a drive that was unplugged is scanned again when re-inserted
