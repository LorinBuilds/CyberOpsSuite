"""Continuous read-only guard. Runs in a background thread."""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from threat_guard.engine.scanner import ThreatScanner, ScanReport


@dataclass
class GuardConfig:
    targets: list[Path] = field(default_factory=list)
    interval_seconds: int = 300          # هر ۵ دقیقه
    scan_on_start: bool = True
    max_file_size: int = 100 * 1024 * 1024
    workers: int = 2                     # keep the background guard light on CPU/disk
    use_cache: bool = True               # only re-check files that changed since last cycle
    use_clamav: bool = True
    hash_db: Path | None = None
    yara_rules: Path | None = None
    signature_db: Path | None = None


class ContinuousGuard:
    """
    Read-only periodic scanner.

    - Never deletes/modifies/quarantines.
    - Emits only *new* findings to the callback (deduplicated by path+sha256+engine+title).
    - Stops cleanly via stop().
    """

    def __init__(
        self,
        config: GuardConfig,
        on_new_finding: Callable[[dict, ScanReport], None] | None = None,
        on_cycle_complete: Callable[[ScanReport], None] | None = None,
        on_error: Callable[[str], None] | None = None,
    ) -> None:
        self.config = config
        self._on_new = on_new_finding
        self._on_cycle = on_cycle_complete
        self._on_error = on_error

        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._seen: set[tuple] = set()
        self._scanner: ThreatScanner | None = None
        self._last_report: ScanReport | None = None
        self._cycles = 0

    # ---------- lifecycle ----------

    def start(self) -> None:
        if self.is_running:
            return
        self._stop_event.clear()
        self._scanner = None  # rebuilt (and rules reloaded) on every start
        self._thread = threading.Thread(target=self._run, name="ThreatGuard-Guard", daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=timeout)
        self._thread = None

    @property
    def is_running(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    @property
    def last_report(self) -> ScanReport | None:
        return self._last_report

    @property
    def cycles(self) -> int:
        return self._cycles

    # ---------- internals ----------

    def _run(self) -> None:
        if self.config.scan_on_start:
            self._one_cycle()

        while not self._stop_event.wait(self.config.interval_seconds):
            self._one_cycle()

    def _one_cycle(self) -> None:
        try:
            # One scanner for the guard's whole lifetime: signatures / YARA rules
            # are loaded once and the file cache survives between cycles.
            if self._scanner is None:
                self._scanner = ThreatScanner(
                    hash_db=self.config.hash_db,
                    yara_rules=self.config.yara_rules,
                    use_clamav=self.config.use_clamav,
                    max_file_size=self.config.max_file_size,
                    signature_db=self.config.signature_db,
                    workers=self.config.workers,
                    use_cache=self.config.use_cache,
                )
            scanner = self._scanner
            combined_findings = []
            combined_errors = []
            scanned = skipped = 0
            started = datetime.now(timezone.utc).isoformat()

            for target in self.config.targets:
                try:
                    report = scanner.scan(target, cancel=self._stop_event)
                    combined_findings.extend(report.findings)
                    combined_errors.extend(report.errors)
                    scanned += report.scanned_files
                    skipped += report.skipped_files
                except (OSError, ValueError) as exc:
                    combined_errors.append(f"{target}: {exc}")

            full_report = ScanReport(
                started_at=started,
                finished_at=datetime.now(timezone.utc).isoformat(),
                scanned_files=scanned,
                skipped_files=skipped,
                findings=combined_findings,
                errors=combined_errors,
            )
            if self._stop_event.is_set():
                return  # stopped mid-scan: discard the partial result
            self._last_report = full_report
            self._cycles += 1

            new_findings = []
            for finding in full_report.findings:
                key = (finding.path, finding.sha256, finding.engine, finding.title)
                if key not in self._seen:
                    self._seen.add(key)
                    new_findings.append(finding)

            if new_findings and self._on_new:
                self._on_new(
                    {"new_findings": [f.__dict__ for f in new_findings]},
                    full_report,
                )
            if self._on_cycle:
                self._on_cycle(full_report)

        except Exception as exc:  # keep the guard alive no matter what
            if self._on_error:
                self._on_error(f"Guard cycle failed: {exc}")