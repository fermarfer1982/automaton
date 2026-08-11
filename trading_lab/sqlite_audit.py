from __future__ import annotations

import json
import sqlite3
import threading
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .audit import AuditVerification, HashChainAuditLog, _canonical


_SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA synchronous=FULL;
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS audit_schema (
  version INTEGER PRIMARY KEY,
  applied_at_utc TEXT NOT NULL
);
INSERT OR IGNORE INTO audit_schema(version, applied_at_utc)
VALUES (1, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'));
CREATE TABLE IF NOT EXISTS audit_events (
  sequence INTEGER PRIMARY KEY,
  schema_version INTEGER NOT NULL,
  timestamp_utc TEXT NOT NULL,
  event TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  previous_hash TEXT NOT NULL,
  record_hash TEXT NOT NULL UNIQUE
);
CREATE TRIGGER IF NOT EXISTS audit_events_no_update
BEFORE UPDATE ON audit_events
BEGIN SELECT RAISE(ABORT, 'audit events are append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_events_no_delete
BEFORE DELETE ON audit_events
BEGIN SELECT RAISE(ABORT, 'audit events are append-only'); END;
"""

_PROJECTION_TABLES = (
    "audit_decisions",
    "audit_proposals",
    "audit_gates",
    "audit_execution_attempts",
    "audit_orders",
    "audit_positions",
    "audit_trade_events",
    "audit_reviews",
    "audit_hypotheses",
    "audit_strategy_versions",
    "audit_denials",
)


def _projections_for(event: str, payload: dict[str, Any]) -> tuple[str, ...]:
    tables: list[str] = []
    if event == "agent_decision_recorded":
        tables.append("audit_decisions")
    if event.startswith("semantic_proposal") or event.startswith("proposal_"):
        tables.extend(("audit_proposals", "audit_strategy_versions"))
    if (
        "guard" in event
        or ("risk" in event and "decision" in event)
        or event == "execution_authorization_decision"
    ):
        tables.append("audit_gates")
    if "order_check" in event or "order_send" in event or "pre_send_guard" in event:
        tables.append("audit_execution_attempts")
    if "order_send" in event or event in {"paper_position_opened", "paper_position_open_authorized"}:
        tables.append("audit_orders")
    if "position" in event:
        tables.append("audit_positions")
    if event in {"paper_position_closed", "position_management_outcome"}:
        tables.append("audit_trade_events")
    if event == "trade_review_saved":
        tables.append("audit_reviews")
    if event == "hypothesis_saved":
        tables.append("audit_hypotheses")
    status = str(payload.get("status", ""))
    if (
        "rejected" in event
        or "error" in event
        or status in {"REJECTED", "EXECUTION_UNCERTAIN", "FAILED"}
    ):
        tables.append("audit_denials")
    return tuple(dict.fromkeys(tables))


@dataclass(frozen=True)
class SQLiteAuditVerification:
    valid: bool
    records: int
    last_hash: str
    error: str | None = None


class SQLiteAuditStore:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        with closing(self._connect()) as connection:
            connection.executescript(_SCHEMA)
            projection_migration = connection.execute(
                "SELECT 1 FROM audit_schema WHERE version = 2"
            ).fetchone() is None
            for table in _PROJECTION_TABLES:
                connection.execute(
                    f"""
                    CREATE TABLE IF NOT EXISTS {table} (
                      sequence INTEGER PRIMARY KEY REFERENCES audit_events(sequence),
                      timestamp_utc TEXT NOT NULL,
                      event TEXT NOT NULL,
                      payload_json TEXT NOT NULL
                    )
                    """
                )
                connection.execute(
                    f"""
                    CREATE TRIGGER IF NOT EXISTS {table}_no_update
                    BEFORE UPDATE ON {table}
                    BEGIN SELECT RAISE(ABORT, 'audit projections are append-only'); END
                    """
                )
                connection.execute(
                    f"""
                    CREATE TRIGGER IF NOT EXISTS {table}_no_delete
                    BEFORE DELETE ON {table}
                    BEGIN SELECT RAISE(ABORT, 'audit projections are append-only'); END
                    """
                )
            if projection_migration:
                existing = connection.execute(
                    "SELECT sequence, timestamp_utc, event, payload_json FROM audit_events ORDER BY sequence"
                ).fetchall()
                for sequence, timestamp, event, payload_json in existing:
                    payload = json.loads(str(payload_json))
                    for table in _projections_for(str(event), payload):
                        connection.execute(
                            f"INSERT INTO {table}(sequence, timestamp_utc, event, payload_json) "
                            "VALUES (?, ?, ?, ?)",
                            (int(sequence), str(timestamp), str(event), str(payload_json)),
                        )
                connection.execute(
                    "INSERT INTO audit_schema(version, applied_at_utc) "
                    "VALUES (2, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))"
                )
            connection.commit()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=5.0)
        connection.execute("PRAGMA busy_timeout=5000")
        return connection

    def append_record(self, record: dict[str, Any]) -> None:
        required = {
            "schema_version", "timestamp", "event", "payload",
            "previous_hash", "record_hash",
        }
        if set(record) != required:
            raise ValueError("SQLite audit mirror received an invalid record schema")
        with self._lock, closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT sequence, record_hash FROM audit_events ORDER BY sequence DESC LIMIT 1"
            ).fetchone()
            sequence = 1 if row is None else int(row[0]) + 1
            expected_previous = "0" * 64 if row is None else str(row[1])
            if record["previous_hash"] != expected_previous:
                raise RuntimeError("SQLite audit mirror diverged from JSON audit chain")
            connection.execute(
                """
                INSERT INTO audit_events(
                  sequence, schema_version, timestamp_utc, event, payload_json,
                  previous_hash, record_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    sequence,
                    int(record["schema_version"]),
                    str(record["timestamp"]),
                    str(record["event"]),
                    _canonical(record["payload"]),
                    str(record["previous_hash"]),
                    str(record["record_hash"]),
                ),
            )
            payload_json = _canonical(record["payload"])
            for table in _projections_for(str(record["event"]), record["payload"]):
                connection.execute(
                    f"INSERT INTO {table}(sequence, timestamp_utc, event, payload_json) "
                    "VALUES (?, ?, ?, ?)",
                    (sequence, str(record["timestamp"]), str(record["event"]), payload_json),
                )
            connection.commit()

    def verify(self) -> SQLiteAuditVerification:
        previous_hash = "0" * 64
        records = 0
        try:
            with self._lock, closing(self._connect()) as connection:
                rows = connection.execute(
                    """
                    SELECT sequence, schema_version, timestamp_utc, event,
                           payload_json, previous_hash, record_hash
                    FROM audit_events ORDER BY sequence
                    """
                ).fetchall()
                for expected_sequence, row in enumerate(rows, start=1):
                    sequence, schema_version, timestamp, event, payload_json, claimed_previous, claimed_hash = row
                    if int(sequence) != expected_sequence or claimed_previous != previous_hash:
                        return SQLiteAuditVerification(
                            False, records, previous_hash, "SQLite audit sequence or link is broken"
                        )
                    unsigned = {
                        "schema_version": int(schema_version),
                        "timestamp": str(timestamp),
                        "event": str(event),
                        "payload": json.loads(str(payload_json)),
                        "previous_hash": str(claimed_previous),
                    }
                    import hashlib
                    calculated = hashlib.sha256(_canonical(unsigned).encode("utf-8")).hexdigest()
                    if calculated != claimed_hash:
                        return SQLiteAuditVerification(
                            False, records, previous_hash, "SQLite audit hash mismatch"
                        )
                    previous_hash = str(claimed_hash)
                    records += 1
                expected: dict[str, list[tuple[int, str, str]]] = {
                    table: [] for table in _PROJECTION_TABLES
                }
                for row in rows:
                    sequence, _, timestamp, event, payload_json, _, _ = row
                    payload = json.loads(str(payload_json))
                    for table in _projections_for(str(event), payload):
                        expected[table].append((int(sequence), str(event), str(payload_json)))
                for table, expected_rows in expected.items():
                    actual_rows = connection.execute(
                        f"SELECT sequence, event, payload_json FROM {table} ORDER BY sequence"
                    ).fetchall()
                    actual = [
                        (int(item[0]), str(item[1]), str(item[2])) for item in actual_rows
                    ]
                    if actual != expected_rows:
                        return SQLiteAuditVerification(
                            False, records, previous_hash,
                            f"SQLite audit projection diverged: {table}",
                        )
        except (OSError, sqlite3.Error, ValueError, TypeError) as exc:
            return SQLiteAuditVerification(False, records, previous_hash, str(exc))
        return SQLiteAuditVerification(True, records, previous_hash)


class DualAuditLog:
    """Writes every event to JSON and SQLite; disagreement locks the lab."""

    def __init__(self, json_path: str | Path, sqlite_path: str | Path) -> None:
        self._json = HashChainAuditLog(json_path)
        self._sqlite = SQLiteAuditStore(sqlite_path)
        self._lock = threading.Lock()

    def append(self, event: str, payload: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            if not self.verify().valid:
                raise RuntimeError("Dual audit is already divergent")
            record = self._json.append(event, payload)
            self._sqlite.append_record(record)
            return record

    def verify(self) -> AuditVerification:
        json_check = self._json.verify()
        sqlite_check = self._sqlite.verify()
        if not json_check.valid:
            return json_check
        if not sqlite_check.valid:
            return AuditVerification(False, sqlite_check.records, sqlite_check.error)
        if json_check.records != sqlite_check.records:
            return AuditVerification(False, min(json_check.records, sqlite_check.records), "audit stores diverged")
        if json_check.records:
            try:
                last = ""
                with self._json.path.open("r", encoding="utf-8") as handle:
                    for line in handle:
                        if line.strip():
                            last = line
                json_last_hash = str(json.loads(last)["record_hash"])
            except (OSError, ValueError, KeyError, TypeError) as exc:
                return AuditVerification(False, json_check.records, str(exc))
            if json_last_hash != sqlite_check.last_hash:
                return AuditVerification(False, json_check.records, "audit tail hashes differ")
        return AuditVerification(True, json_check.records)

    def has_recent_fingerprint(self, fingerprint: str, window_seconds: int) -> bool:
        if not self.verify().valid:
            return True
        return self._json.has_recent_fingerprint(fingerprint, window_seconds)

    def has_unreconciled_execution(self, fingerprint: str) -> bool:
        if not self.verify().valid:
            return True
        return self._json.has_unreconciled_execution(fingerprint)

    def has_recent_entry(self, window_seconds: int) -> bool:
        if not self.verify().valid:
            return True
        return self._json.has_recent_entry(window_seconds)
