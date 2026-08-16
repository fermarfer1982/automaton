from __future__ import annotations

from pathlib import Path


def precreated_audit_path(path: Path) -> Path:
    """Model the elevated bootstrap without changing production behavior."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.touch(exist_ok=True)
    return path
