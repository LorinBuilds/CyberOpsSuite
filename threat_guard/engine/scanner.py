from __future__ import annotations
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import threading
import time
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable, Iterator

from threat_guard.engine.signature import SignatureMatcher, load_signatures

CHUNK_SIZE = 1024 * 1024
DEFAULT_MAX_FILE_SIZE = 100 * 1024 * 1024
MAX_ERRORS = 500            # keep reports (and memory) bounded on huge trees
CACHE_LIMIT = 250_000       # max remembered files when use_cache=True
CLAM_TIMEOUT = 3600         # seconds for the single batched clamscan run

# progress(scanned_files, skipped_files, current_path)
ProgressCallback = Callable[[int, int, str], None]


@dataclass
class Finding:
    path: str
    engine: str
    severity: str
    title: str
    details: str
    sha256: str = ""


@dataclass
class ScanReport:
    started_at: str
    finished_at: str
    scanned_files: int
    skipped_files: int
    findings: list[Finding]
    errors: list[str]
    cancelled: bool = False

    def to_dict(self) -> dict:
        return {
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "scanned_files": self.scanned_files,
            "skipped_files": self.skipped_files,
            "findings": [asdict(item) for item in self.findings],
            "errors": self.errors,
            "cancelled": self.cancelled,
        }


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(CHUNK_SIZE), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_hash_database(path: Path | None) -> dict[str, str]:
    """Load a JSON object mapping SHA-256 hex digests to labels."""
    if not path:
        return {}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    if not isinstance(raw, dict):
        raise ValueError("Hash database must be a JSON object.")
    clean = {}
    for digest, label in raw.items():
        key = str(digest).lower().strip()
        if len(key) == 64 and all(c in "0123456789abcdef" for c in key):
            clean[key] = str(label)[:200]
    return clean


def iter_files(target: Path) -> Iterable[Path]:
    """Yield regular files below ``target`` (symlinks / junctions are not followed)."""
    for path, _stat in _walk(Path(target), lambda _msg: None, None):
        yield Path(path)


def _is_junction(entry: os.DirEntry) -> bool:
    check = getattr(entry, "is_junction", None)  # Python 3.12+
    try:
        return bool(check()) if check else False
    except OSError:
        return False


def _walk(
    root: Path,
    on_error: Callable[[str], None],
    cancel: threading.Event | None,
    exclude: tuple[str, ...] = (),
) -> Iterator[tuple[str, os.stat_result]]:
    """Fast directory walk: one scandir per folder, stat comes from the DirEntry cache."""
    if root.is_file():
        try:
            yield str(root), root.stat()
        except OSError as exc:
            on_error(f"{root}: {exc}")
        return

    stack = [str(root)]
    while stack:
        if cancel is not None and cancel.is_set():
            return
        current = stack.pop()
        try:
            iterator = os.scandir(current)
        except OSError as exc:
            on_error(f"{current}: {exc}")
            continue
        with iterator:
            while True:
                try:
                    entry = next(iterator)
                except StopIteration:
                    break
                except OSError as exc:
                    on_error(f"{current}: {exc}")
                    break
                try:
                    if entry.is_symlink() or _is_junction(entry):
                        continue
                    if entry.is_dir(follow_symlinks=False):
                        if exclude and (os.path.normcase(entry.path) + os.sep).startswith(exclude):
                            continue
                        stack.append(entry.path)
                    elif entry.is_file(follow_symlinks=False):
                        yield entry.path, entry.stat(follow_symlinks=False)
                except OSError as exc:
                    on_error(f"{entry.path}: {exc}")


class ThreatScanner:
    """Read-only scanner. It never deletes, modifies, or quarantines files.

    Performance notes
    -----------------
    * every file is read **once**: SHA-256 and the signature check share the
      same chunked read (flat memory use, no whole-file reads);
    * files are processed by a small thread pool (hashing and disk I/O release
      the GIL);
    * ClamAV is started **once per scan** on the whole batch instead of once per
      file (loading its database takes seconds);
    * ``use_cache=True`` skips files whose size and modification time did not
      change since the previous scan by the same scanner object (used by Guard
      Mode so each cycle only re-checks what changed).
    """

    def __init__(
        self,
        hash_db: Path | None = None,
        yara_rules: Path | None = None,
        use_clamav: bool = True,
        max_file_size: int = DEFAULT_MAX_FILE_SIZE,
        signature_db: Path | None = None,
        workers: int | None = None,
        use_cache: bool = False,
        chunk_size: int = CHUNK_SIZE,
        exclude_dirs: Iterable[str | Path] | None = None,
    ):
        self.hashes = load_hash_database(hash_db)
        self.yara_rules_path = yara_rules
        self.use_clamav = use_clamav
        self.max_file_size = max_file_size
        self.signature_db = signature_db
        self.signatures = load_signatures(signature_db)
        self.workers = workers or max(2, min(8, os.cpu_count() or 2))
        self.use_cache = use_cache
        self.chunk_size = max(4096, int(chunk_size))
        # Exceptions list: whole folders that are never walked (normalised prefixes).
        self.exclude = tuple(
            os.path.normcase(str(Path(item))).rstrip("\\/") + os.sep
            for item in (exclude_dirs or [])
        )

        # Only threat signatures matter to the scanner; file-type headers are
        # informational and were always discarded, so don't spend time on them.
        self._matcher = SignatureMatcher(self.signatures, threats_only=True)
        self._clam_binary = shutil.which("clamscan") if use_clamav else None
        self._cache: dict[str, tuple[int, int, str, list[Finding]]] = {}

        self._yara = None
        self._yara_error = None
        self._yara_lock = threading.Lock()
        if yara_rules and yara_rules.exists():
            try:
                import yara
                self._yara = yara.compile(filepath=str(yara_rules))
            except Exception as exc:
                self._yara_error = f"YARA unavailable or rules invalid: {exc}"

    # ------------------------------------------------------------------ API

    def clear_cache(self) -> None:
        self._cache.clear()

    def scan(
        self,
        target: str | Path,
        progress: ProgressCallback | None = None,
        cancel: threading.Event | None = None,
    ) -> ScanReport:
        start = datetime.now(timezone.utc).isoformat()
        findings: list[Finding] = []
        errors: list[str] = []
        dropped_errors = 0
        scanned = skipped = 0
        root = Path(target).expanduser().resolve()
        if not root.exists():
            raise FileNotFoundError(root)

        def add_error(message: str) -> None:
            nonlocal dropped_errors
            if len(errors) < MAX_ERRORS:
                errors.append(message)
            else:
                dropped_errors += 1

        if self._yara_error:
            add_error(self._yara_error)

        fresh_paths: list[str] = []
        last_tick = 0.0

        def handle(result: tuple[str, str, list[Finding], list[str], bool]) -> None:
            nonlocal scanned, skipped, last_tick
            path, status, found, errs, fresh = result
            if status == "scanned":
                scanned += 1
                if fresh:
                    fresh_paths.append(path)
            else:
                skipped += 1
            findings.extend(found)
            for message in errs:
                add_error(message)
            if progress is not None:
                now = time.monotonic()
                if now - last_tick >= 0.1:
                    last_tick = now
                    progress(scanned, skipped, path)

        cancelled = False
        with ThreadPoolExecutor(max_workers=self.workers, thread_name_prefix="tg-scan") as pool:
            pending: set = set()
            limit = self.workers * 8

            def drain(block: bool) -> None:
                done, _ = wait(pending, timeout=None if block else 0, return_when=FIRST_COMPLETED)
                for future in done:
                    pending.discard(future)
                    handle(future.result())

            for path, st in _walk(root, add_error, cancel, self.exclude):
                if cancel is not None and cancel.is_set():
                    cancelled = True
                    break
                pending.add(pool.submit(self._scan_one, path, st))
                if len(pending) >= limit:
                    drain(True)
                elif pending:
                    drain(False)
            while pending:
                drain(True)

        if cancel is not None and cancel.is_set():
            cancelled = True

        # ClamAV: one process for the whole batch (optional, only if installed).
        if self._clam_binary and fresh_paths and not cancelled:
            clam_findings, clam_errors = self._clamav_batch(fresh_paths, cancel)
            for message in clam_errors:
                add_error(message)
            for item in clam_findings:
                findings.append(item)
                entry = self._cache.get(item.path)
                if entry is not None:
                    entry[3].append(item)
            if cancel is not None and cancel.is_set():
                cancelled = True

        if dropped_errors:
            errors.append(f"... {dropped_errors} more errors not shown")
        if progress is not None:
            progress(scanned, skipped, "")

        findings.sort(key=lambda item: (item.path, item.engine, item.title))
        return ScanReport(
            start, datetime.now(timezone.utc).isoformat(),
            scanned, skipped, findings, errors, cancelled,
        )

    # ------------------------------------------------------------ internals

    def _scan_one(
        self, path: str, st: os.stat_result
    ) -> tuple[str, str, list[Finding], list[str], bool]:
        """Scan one file -> (path, 'scanned'|'skipped', findings, errors, fresh)."""
        size = st.st_size
        if size > self.max_file_size:
            return path, "skipped", [], [], False

        if self.use_cache:
            hit = self._cache.get(path)
            if hit is not None and hit[0] == st.st_mtime_ns and hit[1] == size:
                return path, "scanned", list(hit[3]), [], False

        digest = hashlib.sha256()
        state = self._matcher.start() if self._matcher else None
        try:
            with open(path, "rb") as stream:
                while True:
                    chunk = stream.read(self.chunk_size)
                    if not chunk:
                        break
                    digest.update(chunk)
                    if state is not None:
                        state.feed(chunk)
        except (PermissionError, OSError) as exc:
            return path, "skipped", [], [f"{path}: {exc}"], False
        hexdigest = digest.hexdigest()

        found: list[Finding] = []
        errs: list[str] = []

        # 1) Hash reputation
        if hexdigest in self.hashes:
            found.append(Finding(
                path, "sha256-reputation", "critical",
                "Known hash match", self.hashes[hexdigest], hexdigest,
            ))

        # 2) Built-in / custom signatures (collected during the hashing pass)
        if state is not None:
            for sig in state.hits:
                found.append(Finding(
                    path, "signature", sig.severity,
                    f"Signature match: {sig.name}",
                    f"Category: {sig.category}", hexdigest,
                ))

        # 3) YARA
        if self._yara is not None:
            try:
                with self._yara_lock:
                    matches = self._yara.match(path)
                for match in matches:
                    found.append(Finding(
                        path, "yara", "high",
                        f"YARA rule: {match.rule}",
                        "Matched a locally configured YARA rule.", hexdigest,
                    ))
            except Exception as exc:
                errs.append(f"{path}: YARA scan failed: {exc}")

        if self.use_cache:
            if len(self._cache) >= CACHE_LIMIT:
                self._cache.clear()
            self._cache[path] = (st.st_mtime_ns, size, hexdigest, found)
            found = list(found)

        return path, "scanned", found, errs, True

    def _clamav_batch(
        self, paths: list[str], cancel: threading.Event | None
    ) -> tuple[list[Finding], list[str]]:
        """Run clamscan once over ``paths`` (scan-only mode, never removes anything)."""
        findings: list[Finding] = []
        errors: list[str] = []
        fd, list_file = tempfile.mkstemp(prefix="threatguard_", suffix=".lst")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write("\n".join(paths) + "\n")
            command = [
                self._clam_binary, "--no-summary", "--infected",
                f"--file-list={list_file}",
            ]
            try:
                proc = subprocess.Popen(
                    command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    text=True, encoding="utf-8", errors="replace",
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
            except OSError as exc:
                return findings, [f"ClamAV could not start: {exc}"]

            deadline = time.monotonic() + CLAM_TIMEOUT
            while True:
                try:
                    out, err = proc.communicate(timeout=1)
                    break
                except subprocess.TimeoutExpired:
                    stop = cancel is not None and cancel.is_set()
                    if stop or time.monotonic() > deadline:
                        proc.kill()
                        proc.communicate()
                        if not stop:
                            errors.append("ClamAV timed out")
                        return findings, errors
        finally:
            try:
                os.remove(list_file)
            except OSError:
                pass

        for line in (out or "").splitlines():
            line = line.strip()
            if not line.endswith(" FOUND"):
                continue
            path, _sep, _sig = line[:-len(" FOUND")].rpartition(": ")
            if not path:
                continue
            try:
                digest = sha256_file(Path(path))
            except OSError:
                digest = ""
            findings.append(Finding(
                path, "clamav", "high", "ClamAV detection", line[:1000], digest,
            ))
        if proc.returncode not in (0, 1):
            errors.append(f"clamscan exit {proc.returncode}: {(err or '').strip()[:300]}")
        return findings, errors
