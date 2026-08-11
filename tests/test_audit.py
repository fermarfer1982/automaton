from __future__ import annotations

import json
import inspect
import tempfile
import unittest
from dataclasses import dataclass
from pathlib import Path

from trading_lab.audit import HashChainAuditLog


class AuditLogTests(unittest.TestCase):
    def test_writer_uses_append_mode_without_truncate_replace_or_delete(self) -> None:
        source = inspect.getsource(HashChainAuditLog.append)
        self.assertIn('self.path.open("a"', source)
        for forbidden in ("write_text(", ".replace(", ".unlink(", 'open("w"'):
            self.assertNotIn(forbidden, source)

    def test_serializes_dataclasses_as_structured_payloads(self) -> None:
        @dataclass(frozen=True)
        class Example:
            code: str
            passed: bool

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            audit = HashChainAuditLog(path)
            audit.append("check", {"checks": (Example("SAFE", True),)})
            record = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual({"code": "SAFE", "passed": True}, record["payload"]["checks"][0])

    def test_records_and_verifies_append_only_hash_chain(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            audit = HashChainAuditLog(path)
            audit.append("proposal_received", {"proposal_id": "p1"})
            audit.append("proposal_outcome", {"proposal_id": "p1", "status": "OBSERVED"})
            self.assertTrue(audit.verify().valid)
            self.assertEqual(2, audit.verify().records)

    def test_detects_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            audit = HashChainAuditLog(path)
            audit.append("proposal_received", {"proposal_id": "p1"})
            record = json.loads(path.read_text(encoding="utf-8"))
            record["payload"]["proposal_id"] = "tampered"
            path.write_text(json.dumps(record) + "\n", encoding="utf-8")
            self.assertFalse(audit.verify().valid)

    def test_never_serializes_fields_named_like_credentials(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            audit = HashChainAuditLog(path)
            audit.append(
                "redaction_test",
                {"password": "secret", "api_key": "secret", "safe": "visible"},
            )
            text = path.read_text(encoding="utf-8")
            self.assertNotIn("secret", text)
            self.assertIn("[REDACTED]", text)


if __name__ == "__main__":
    unittest.main()
