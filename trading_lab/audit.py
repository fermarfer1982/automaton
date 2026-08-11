from __future__ import annotations

import hashlib
import json
import os
import threading
from dataclasses import asdict, dataclass, is_dataclass
from datetime import UTC, datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any


_REDACTED_KEYS = {
    "password", "passwd", "credential", "credentials", "api_key", "apikey",
    "token", "secret", "private_key", "authorization",
}


@dataclass(frozen=True)
class AuditVerification:
    valid: bool
    records: int
    error: str | None = None


def _sanitize(value: Any) -> Any:
    if is_dataclass(value) and not isinstance(value, type):
        return _sanitize(asdict(value))
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        return {
            str(key): "[REDACTED]" if str(key).lower() in _REDACTED_KEYS else _sanitize(child)
            for key, child in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [_sanitize(child) for child in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


class HashChainAuditLog:
    """Append-only JSONL audit with a SHA-256 link between every record."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._lock = threading.Lock()

    def _last_hash(self) -> str:
        if not self.path.exists() or self.path.stat().st_size == 0:
            return "0" * 64
        last = ""
        with self.path.open("r", encoding="utf-8") as handle:
            for line in handle:
                if line.strip():
                    last = line
        if not last:
            return "0" * 64
        return str(json.loads(last)["record_hash"])

    def append(self, event: str, payload: dict[str, Any]) -> dict[str, Any]:
        if not event or not isinstance(event, str):
            raise ValueError("audit event must be a non-empty string")
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            previous_hash = self._last_hash()
            unsigned = {
                "schema_version": 1,
                "timestamp": datetime.now(UTC).isoformat(),
                "event": event,
                "payload": _sanitize(payload),
                "previous_hash": previous_hash,
            }
            record_hash = hashlib.sha256(_canonical(unsigned).encode("utf-8")).hexdigest()
            record = {**unsigned, "record_hash": record_hash}
            with self.path.open("a", encoding="utf-8", newline="\n") as handle:
                handle.write(_canonical(record) + "\n")
                handle.flush()
                os.fsync(handle.fileno())
            return record

    def verify(self) -> AuditVerification:
        with self._lock:
            return self._verify_unlocked()

    def _verify_unlocked(self) -> AuditVerification:
        previous_hash = "0" * 64
        records = 0
        if not self.path.exists():
            return AuditVerification(valid=True, records=0)
        try:
            with self.path.open("r", encoding="utf-8") as handle:
                for line_number, line in enumerate(handle, start=1):
                    if not line.strip():
                        continue
                    record = json.loads(line)
                    claimed_hash = record.pop("record_hash")
                    if record.get("previous_hash") != previous_hash:
                        return AuditVerification(False, records, f"broken link at line {line_number}")
                    calculated = hashlib.sha256(_canonical(record).encode("utf-8")).hexdigest()
                    if calculated != claimed_hash:
                        return AuditVerification(False, records, f"hash mismatch at line {line_number}")
                    previous_hash = claimed_hash
                    records += 1
        except (OSError, ValueError, KeyError, TypeError) as exc:
            return AuditVerification(False, records, str(exc))
        return AuditVerification(True, records)

    def has_recent_fingerprint(self, fingerprint: str, window_seconds: int) -> bool:
        with self._lock:
            cutoff = datetime.now(UTC) - timedelta(seconds=window_seconds)
            if not self.path.exists():
                return False
            try:
                with self.path.open("r", encoding="utf-8") as handle:
                    for line in handle:
                        if not line.strip():
                            continue
                        record = json.loads(line)
                        payload = record.get("payload", {})
                        if payload.get("fingerprint") != fingerprint:
                            continue
                        timestamp = datetime.fromisoformat(record["timestamp"])
                        accepted_outcome = (
                            record.get("event") == "proposal_outcome"
                            and payload.get("status") in {"OBSERVED", "PAPER_ACCEPTED", "EXECUTED"}
                        )
                        possible_execution = record.get("event") == "order_send_authorized"
                        if timestamp >= cutoff and (accepted_outcome or possible_execution):
                            return True
            except (OSError, ValueError, TypeError):
                return True
            return False
