"""Bookmark manager for Event Log Analyzer."""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import uuid
from datetime import datetime
from pathlib import Path

from core.utils.paths import config_root, project_root


APP_DIR_NAME = "EventLogAnalyzer"


def bookmarks_path() -> Path:
    """Return the canonical bookmarks JSON file path."""
    return config_root(APP_DIR_NAME) / "bookmarks.json"


def load_bookmarks() -> list[dict]:
    """Load bookmarks from AppData. If not found, try the seed file in data/."""
    path = bookmarks_path()
    
    if not path.exists():
        seed = project_root() / "data" / "bookmarks.json"
        if seed.is_file():
            try:
                path.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(seed, path)
            except OSError:
                pass
    
    if not path.exists():
        return []
    
    try:
        with path.open("r", encoding="utf-8-sig") as stream:
            data = json.load(stream)
            return data if isinstance(data, list) else []
    except (OSError, json.JSONDecodeError):
        return []


def save_bookmarks(bookmarks: list[dict]) -> None:
    """Save bookmarks to AppData (atomic write)."""
    path = bookmarks_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    
    fd, temp_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent,
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(bookmarks, stream, indent=4, ensure_ascii=False)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_name, path)
    finally:
        if os.path.exists(temp_name):
            os.unlink(temp_name)


def add_bookmark(entry: dict) -> dict:
    """Add a log entry to bookmarks if not already present."""
    bookmarks = load_bookmarks()
    
    
    for bm in bookmarks:
        if (bm.get("timestamp") == entry.get("timestamp") and 
            bm.get("event_id") == entry.get("event_id") and
            bm.get("source") == entry.get("source") and
            bm.get("message") == entry.get("message")):
            return bm
    
    bm = {
        "id": str(uuid.uuid4()),
        "timestamp": entry.get("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
        "level": entry.get("level", "INFO"),
        "source": entry.get("source", ""),
        "event_id": entry.get("event_id", ""),
        "message": entry.get("message", ""),
    }
    bookmarks.append(bm)
    save_bookmarks(bookmarks)
    return bm


def remove_bookmark(bookmark_id: str) -> None:
    """Remove a bookmark by its ID."""
    bookmarks = load_bookmarks()
    bookmarks = [bm for bm in bookmarks if bm.get("id") != bookmark_id]
    save_bookmarks(bookmarks)


def remove_bookmark_by_timestamp(timestamp: str, event_id: str, source: str, message: str) -> None:
    """Remove a bookmark based on its identifying fields."""
    if not timestamp:
        return
    bookmarks = load_bookmarks()
    

    bookmarks = [
        bm for bm in bookmarks
        if not (
            bm.get("timestamp") == timestamp and 
            bm.get("event_id") == event_id and
            bm.get("source") == source and
            bm.get("message") == message
        )
    ]
    save_bookmarks(bookmarks)