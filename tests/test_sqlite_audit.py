from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from trading_lab.sqlite_audit import DualAuditLog


class DualAuditTests(unittest.TestCase):
    def test_mirrors_and_verifies_both_append_only_stores(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            audit = DualAuditLog(root / "audit.jsonl", root / "audit.db")
            audit.append("decision", {"action": "HOLD"})
            audit.append("proposal", {"proposal_id": "p1"})
            result = audit.verify()
            self.assertTrue(result.valid, result.error)
            self.assertEqual(2, result.records)
            with closing(sqlite3.connect(root / "audit.db")) as connection:
                with self.assertRaises(sqlite3.DatabaseError):
                    connection.execute("UPDATE audit_events SET event = 'tampered'")

    def test_detects_missing_sqlite_mirror_tail(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            audit = DualAuditLog(root / "audit.jsonl", root / "audit.db")
            audit.append("decision", {"action": "HOLD"})
            (root / "audit.db").unlink()
            rebuilt = DualAuditLog(root / "audit.jsonl", root / "audit.db")
            self.assertFalse(rebuilt.verify().valid)

    def test_uses_same_redacted_record_in_both_stores(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            audit = DualAuditLog(root / "audit.jsonl", root / "audit.db")
            audit.append("secret_test", {"api_key": "never-store-this"})
            self.assertNotIn("never-store-this", (root / "audit.jsonl").read_text(encoding="utf-8"))
            with closing(sqlite3.connect(root / "audit.db")) as connection:
                payload = connection.execute("SELECT payload_json FROM audit_events").fetchone()[0]
            self.assertEqual("[REDACTED]", json.loads(payload)["api_key"])


if __name__ == "__main__":
    unittest.main()
