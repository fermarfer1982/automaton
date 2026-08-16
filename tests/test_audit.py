from __future__ import annotations

import json
import inspect
import tempfile
import unittest
from dataclasses import dataclass
from pathlib import Path
from unittest import mock

from tests.audit_helpers import precreated_audit_path
from trading_lab.audit import HashChainAuditLog, _canonical
from trading_lab.windows_append_log import WindowsAppendOnlyFile


class AuditLogTests(unittest.TestCase):
    def test_writer_uses_shared_win32_primitive_without_conventional_append(self) -> None:
        source = inspect.getsource(HashChainAuditLog.append)
        self.assertIn("WindowsAppendOnlyFile(self.path)", source)
        for forbidden in (
            'self.path.open("a"', 'open("a"', "write_text(", ".replace(",
            ".unlink(", 'open("w"', ".seek(", ".truncate(", "rename(",
        ):
            self.assertNotIn(forbidden, source)

    def test_serializes_dataclasses_as_structured_payloads(self) -> None:
        @dataclass(frozen=True)
        class Example:
            code: str
            passed: bool

        with tempfile.TemporaryDirectory() as directory:
            path = precreated_audit_path(Path(directory) / "audit.jsonl")
            audit = HashChainAuditLog(path)
            audit.append("check", {"checks": (Example("SAFE", True),)})
            record = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual({"code": "SAFE", "passed": True}, record["payload"]["checks"][0])

    def test_records_and_verifies_append_only_hash_chain(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = precreated_audit_path(Path(directory) / "audit.jsonl")
            audit = HashChainAuditLog(path)
            audit.append("proposal_received", {"proposal_id": "p1"})
            audit.append("proposal_outcome", {"proposal_id": "p1", "status": "OBSERVED"})
            self.assertTrue(audit.verify().valid)
            self.assertEqual(2, audit.verify().records)

    def test_detects_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = precreated_audit_path(Path(directory) / "audit.jsonl")
            audit = HashChainAuditLog(path)
            audit.append("proposal_received", {"proposal_id": "p1"})
            record = json.loads(path.read_text(encoding="utf-8"))
            record["payload"]["proposal_id"] = "tampered"
            path.write_text(json.dumps(record) + "\n", encoding="utf-8")
            self.assertFalse(audit.verify().valid)

    def test_never_serializes_fields_named_like_credentials(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = precreated_audit_path(Path(directory) / "audit.jsonl")
            audit = HashChainAuditLog(path)
            audit.append(
                "redaction_test",
                {"password": "secret", "api_key": "secret", "safe": "visible"},
            )
            text = path.read_text(encoding="utf-8")
            self.assertNotIn("secret", text)
            self.assertIn("[REDACTED]", text)

    def test_serialized_record_bytes_remain_canonical_utf8_with_one_newline(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = precreated_audit_path(Path(directory) / "audit.jsonl")
            audit = HashChainAuditLog(path)
            record = audit.append("unicode", {"value": "España"})
            self.assertEqual(
                (_canonical(record) + "\n").encode("utf-8"),
                path.read_bytes(),
            )

    def test_two_appends_preserve_hash_chain_and_exact_line_boundaries(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = precreated_audit_path(Path(directory) / "audit.jsonl")
            audit = HashChainAuditLog(path)
            first = audit.append("first", {"sequence": 1})
            second = audit.append("second", {"sequence": 2})
            self.assertEqual(first["record_hash"], second["previous_hash"])
            self.assertEqual(2, len(path.read_bytes().splitlines()))
            self.assertTrue(path.read_bytes().endswith(b"\n"))
            self.assertTrue(audit.verify().valid)

    def test_missing_journal_fails_closed_without_creating_it(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            audit = HashChainAuditLog(path)
            verification = audit.verify()
            self.assertFalse(verification.valid)
            self.assertIn("missing", verification.error or "")
            with self.assertRaises(FileNotFoundError):
                audit.append("missing", {})
            self.assertFalse(path.exists())

    def test_reparse_journal_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = precreated_audit_path(Path(directory) / "audit.jsonl")
            with mock.patch(
                "trading_lab.windows_append_log._is_reparse_point",
                side_effect=lambda candidate: candidate == path,
            ):
                verification = HashChainAuditLog(path).verify()
                self.assertFalse(verification.valid)
                self.assertIn("reparse point", verification.error or "")
                with self.assertRaisesRegex(OSError, "reparse point"):
                    HashChainAuditLog(path).append("reparse", {})
            self.assertEqual(b"", path.read_bytes())

    def test_writefile_error_propagates_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = precreated_audit_path(Path(directory) / "audit.jsonl")
            writer = mock.MagicMock()
            writer.__enter__.return_value = writer
            writer.append.side_effect = OSError("append denied")
            with mock.patch(
                "trading_lab.audit.WindowsAppendOnlyFile",
                return_value=writer,
            ):
                with self.assertRaisesRegex(OSError, "append denied"):
                    HashChainAuditLog(path).append("failure", {})
            writer.append.assert_called_once()
            self.assertEqual(b"", path.read_bytes())

    def test_audit_uses_shared_primitive_class(self) -> None:
        self.assertIsNotNone(WindowsAppendOnlyFile)


if __name__ == "__main__":
    unittest.main()
