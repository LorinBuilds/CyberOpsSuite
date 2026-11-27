"""Signature-based detection using magic bytes and known marker strings.

Read-only. This is NOT a replacement for a full AV engine - it matches
a small set of built-in signatures plus an optional user-provided JSON.

Matching is streaming: files are read in chunks (with an overlap so a marker
split across two chunks is still found), so memory use stays flat no matter how
large the file is.
"""
from __future__ import annotations
import json
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Signature:
    name: str
    magic: bytes
    category: str
    severity: str
    is_threat: bool
    # True  -> magic must be at the very start of the file (file-type headers)
    # False -> marker may appear anywhere in the file (EICAR, ransom notes...)
    anchored: bool = False


# Built-in signatures. Only EICAR and ransomware markers are treated as
# threats; the rest are informational file-type detection.
# (name, magic, category, severity, is_threat, anchored)
_BUILTIN: list[tuple[str, str | bytes, str, str, bool, bool]] = [
    # EICAR antivirus test string (harmless, industry standard)
    ("EICAR_ANTIVIRUS_TEST",
     "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
     "malware-test", "high", True, False),
    # Ransomware note markers
    ("RANSOMWARE_NOTE_EN_1", "Your files have been encrypted", "ransomware-note", "critical", True, False),
    ("RANSOMWARE_NOTE_EN_2", "all your files are encrypted", "ransomware-note", "critical", True, False),
    ("RANSOMWARE_NOTE_EN_3", "All your important files are encrypted", "ransomware-note", "critical", True, False),
    # File type detection (informational, not threats) - header only
    ("ELF_Executable", b"\x7fELF", "binary", "info", False, True),
    ("PE_Executable", "MZ", "binary", "info", False, True),
    ("PDF_Document", "%PDF", "document", "info", False, True),
    ("ZIP_Archive", "PK\x03\x04", "archive", "info", False, True),
    ("RAR_Archive", "Rar!\x1a\x07", "archive", "info", False, True),
    ("GZIP_Stream", b"\x1f\x8b", "archive", "info", False, True),
]

DEFAULT_READ_LIMIT = 4 * 1024 * 1024  # kept for backwards compatibility
CHUNK_SIZE = 1024 * 1024


def _as_bytes(magic: str | bytes) -> bytes:
    return magic.encode("latin-1") if isinstance(magic, str) else magic


def load_signatures(extra_path: Path | None = None) -> list[Signature]:
    """Load built-in signatures plus optional extra entries from JSON.

    Extra file format:
        [{"name": "...", "magic_ascii": "...", "category": "...",
          "severity": "...", "is_threat": true}]
    or with "magic_hex": "deadbeef". Add ``"anchored": true`` to require the
    magic at the start of the file.
    """
    sigs = [
        Signature(name, _as_bytes(magic), category, severity, is_threat, anchored)
        for name, magic, category, severity, is_threat, anchored in _BUILTIN
    ]
    if extra_path and Path(extra_path).exists():
        try:
            raw = json.loads(Path(extra_path).read_text(encoding="utf-8"))
            for item in raw if isinstance(raw, list) else []:
                try:
                    magic = (
                        bytes.fromhex(item["magic_hex"])
                        if "magic_hex" in item
                        else str(item["magic_ascii"]).encode("latin-1")
                    )
                    sigs.append(Signature(
                        str(item["name"]), magic,
                        str(item.get("category", "custom")),
                        str(item.get("severity", "medium")),
                        bool(item.get("is_threat", True)),
                        bool(item.get("anchored", False)),
                    ))
                except (KeyError, ValueError):
                    continue
        except (OSError, ValueError):
            pass
    return sigs


class SignatureMatcher:
    """Reusable, thread-safe description of what to look for.

    Create one per scanner, then call :meth:`start` once per file to get a
    cheap stateful object that is fed the file's chunks one by one.
    """

    def __init__(self, signatures: list[Signature], threats_only: bool = False) -> None:
        usable = [s for s in signatures if s.magic and (s.is_threat or not threats_only)]
        self.anchored = [s for s in usable if s.anchored]
        self.floating = [s for s in usable if not s.anchored]
        longest = max((len(s.magic) for s in self.floating), default=1)
        self.overlap = max(0, longest - 1)

    def __bool__(self) -> bool:
        return bool(self.anchored or self.floating)

    def start(self) -> "_MatchState":
        return _MatchState(self)


class _MatchState:
    __slots__ = ("_m", "_tail", "_first", "_open", "hits")

    def __init__(self, matcher: SignatureMatcher) -> None:
        self._m = matcher
        self._tail = b""
        self._first = True
        self._open = list(matcher.floating)  # floating sigs not matched yet
        self.hits: list[Signature] = []

    def feed(self, chunk: bytes) -> None:
        if not chunk:
            return
        if self._first:
            self._first = False
            for sig in self._m.anchored:
                if chunk.startswith(sig.magic):
                    self.hits.append(sig)
        if self._open:
            window = self._tail + chunk if self._tail else chunk
            still_open = []
            for sig in self._open:
                if sig.magic in window:
                    self.hits.append(sig)
                else:
                    still_open.append(sig)
            self._open = still_open
            overlap = self._m.overlap
            self._tail = window[-overlap:] if overlap else b""


def scan_file_for_signatures(
    path: Path, signatures: list[Signature], read_limit: int = DEFAULT_READ_LIMIT
) -> list[dict]:
    """Return metadata for every signature matching the file.

    ``read_limit`` is accepted for backwards compatibility; the whole file is
    streamed in chunks, so large files no longer need to fit in memory.
    """
    matcher = SignatureMatcher(signatures)
    if not matcher:
        return []
    state = matcher.start()
    try:
        with Path(path).open("rb") as stream:
            for chunk in iter(lambda: stream.read(CHUNK_SIZE), b""):
                state.feed(chunk)
    except OSError:
        return []
    return [
        {
            "signature": sig.name,
            "category": sig.category,
            "severity": sig.severity,
            "is_threat": sig.is_threat,
        }
        for sig in state.hits
    ]
