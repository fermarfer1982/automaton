from __future__ import annotations

import json
import tempfile
import unittest
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

from tests.test_readiness import security_config
from trading_lab.mt5_read_only_controls import (
    AUTHORIZATION_LIFETIME,
    AUTHORIZATION_PURPOSE,
    KillSwitchState,
    MT5ReadOnlyControlError,
    authorization_path,
    parse_authorization,
    probe_kill_switch,
    read_authorization_file,
    render_authorization,
    validate_authorization,
)


RUN_ID = "11111111-2222-4333-8444-555555555555"
AUTHORIZATION_ID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
GATEWAY_SID = "S-1-5-21-1-2-3-1007"
MAINTENANCE_SID = "S-1-5-21-1-2-3-1008"
ISSUED = datetime(2026, 8, 17, 12, 0, tzinfo=UTC)
WORKSPACE = Path(__file__).resolve().parents[1]


class MT5ReadOnlyControlTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.config_path = self.root / "trading.yaml"
        self.config_path.write_text("trading_mode: OBSERVE_ONLY\n", encoding="utf-8")
        self.config = replace(
            security_config(self.root),
            mt5_access_enabled=False,
            demo_authorization_path=(
                self.root / "control" / "demo-authorization" / "authorization.json"
            ),
            kill_switch_path=self.root / "control" / "STOP_TRADING",
        )
        self.payload = render_authorization(
            config=self.config,
            config_path=self.config_path,
            workspace=WORKSPACE,
            run_id=RUN_ID,
            authorization_id=AUTHORIZATION_ID,
            issuer_sid=MAINTENANCE_SID,
            gateway_sid=GATEWAY_SID,
            issued_at=ISSUED,
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_authorization_format_is_exact_bounded_and_secret_free(self) -> None:
        self.assertEqual(AUTHORIZATION_PURPOSE, self.payload["purpose"])
        self.assertEqual(RUN_ID, self.payload["run_id"])
        self.assertEqual("OBSERVE_ONLY", self.payload["trading_mode"])
        self.assertIs(self.payload["gateway_mt5_access_required"], False)
        self.assertEqual(timedelta(minutes=15), AUTHORIZATION_LIFETIME)
        self.assertEqual(
            ISSUED + timedelta(minutes=15),
            datetime.fromisoformat(self.payload["expires_at_utc"].replace("Z", "+00:00")),
        )
        serialized = json.dumps(self.payload).casefold()
        for forbidden in ("password", "api_key", "ipc_key", "token", "credential"):
            self.assertNotIn(forbidden, serialized)

    def test_authorization_path_is_derived_only_from_canonical_run_id(self) -> None:
        expected = (
            self.config.demo_authorization_path.parent
            / f"mt5-read-only-authorization-{RUN_ID}.json"
        )
        self.assertEqual(expected, authorization_path(self.config, RUN_ID))
        for invalid in ("../escape", "NOT-A-UUID", AUTHORIZATION_ID.upper()):
            with self.subTest(invalid=invalid), self.assertRaises(MT5ReadOnlyControlError):
                authorization_path(self.config, invalid)

    def test_authorization_reader_rejects_missing_directory_and_reparse(self) -> None:
        artifact = authorization_path(self.config, RUN_ID)
        with self.assertRaises(MT5ReadOnlyControlError) as missing:
            read_authorization_file(artifact)
        self.assertEqual("MT5_READ_ONLY_AUTHORIZATION_MISSING", missing.exception.code)
        artifact.parent.mkdir(parents=True)
        target = artifact.parent / "other.json"
        target.write_text("{}", encoding="utf-8")
        try:
            artifact.symlink_to(target)
        except OSError:
            self.skipTest("symlink creation is unavailable")
        with self.assertRaises(MT5ReadOnlyControlError) as reparse:
            read_authorization_file(artifact)
        self.assertEqual("MT5_READ_ONLY_AUTHORIZATION_UNREADABLE", reparse.exception.code)

    def test_kill_switch_probe_maps_only_file_not_found_to_absent(self) -> None:
        self.assertIs(KillSwitchState.ABSENT, probe_kill_switch(self.config.kill_switch_path))
        for error in (PermissionError("denied"), OSError("unexpected I/O")):
            with self.subTest(error=type(error).__name__), patch.object(
                Path, "lstat", side_effect=error
            ):
                with self.assertRaises(MT5ReadOnlyControlError) as raised:
                    probe_kill_switch(self.config.kill_switch_path)
                self.assertEqual("KILL_SWITCH_UNREADABLE", raised.exception.code)

    def test_authorization_exact_payload_validates_all_hashes(self) -> None:
        authorization = parse_authorization(json.dumps(self.payload).encode("utf-8"))
        evidence = validate_authorization(
            authorization,
            config=self.config,
            config_path=self.config_path,
            workspace=WORKSPACE,
            run_id=RUN_ID,
            issuer_sid=MAINTENANCE_SID,
            gateway_sid=GATEWAY_SID,
            now=ISSUED + timedelta(minutes=1),
        )
        self.assertTrue(all(evidence.values()))

    def test_schema_rejects_unknown_missing_and_wrong_type_fields(self) -> None:
        payloads = []
        unknown = dict(self.payload)
        unknown["password"] = "forbidden"
        payloads.append(unknown)
        missing = dict(self.payload)
        del missing["purpose"]
        payloads.append(missing)
        wrong_type = dict(self.payload)
        wrong_type["authorized_account"] = str(wrong_type["authorized_account"])
        payloads.append(wrong_type)
        for payload in payloads:
            with self.subTest(keys=sorted(payload)), self.assertRaises(
                MT5ReadOnlyControlError
            ):
                parse_authorization(json.dumps(payload).encode("utf-8"))


if __name__ == "__main__":
    unittest.main()
