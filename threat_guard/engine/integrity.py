from __future__ import annotations
import json
from pathlib import Path
from .scanner import iter_files, sha256_file

def create_baseline(target: str | Path, output: str | Path) -> dict:
    """Create a SHA-256 baseline for regular files under a chosen directory."""
    root = Path(target).expanduser().resolve()
    if not root.is_dir():
        raise ValueError("Baseline target must be a directory.")
    entries = {}
    for file in iter_files(root):
        try:
            entries[str(file.relative_to(root))] = sha256_file(file)
        except (OSError, PermissionError):
            continue
    payload = {"root": str(root), "algorithm": "sha256", "files": entries}
    out = Path(output).expanduser()
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return payload

def compare_baseline(target: str | Path, baseline: str | Path) -> dict:
    root = Path(target).expanduser().resolve()
    saved = json.loads(Path(baseline).read_text(encoding="utf-8"))
    if Path(saved["root"]).resolve() != root:
        raise ValueError("Baseline root does not match the selected directory.")
    current = {}
    for file in iter_files(root):
        try:
            current[str(file.relative_to(root))] = sha256_file(file)
        except (OSError, PermissionError):
            pass
    old = saved.get("files", {})
    return {
        "added": sorted(set(current) - set(old)),
        "removed": sorted(set(old) - set(current)),
        "changed": sorted(k for k in set(old) & set(current) if old[k] != current[k]),
        "unchanged": sum(1 for k in set(old) & set(current) if old[k] == current[k]),
    }
