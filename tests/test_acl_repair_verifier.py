from __future__ import annotations

import io
import json
import sys
import unittest
from contextlib import redirect_stdout
from types import SimpleNamespace
from unittest.mock import patch

from trading_lab.acl_repair_verifier import main, verify_repaired_acl
from trading_lab.domain import TradingMode
from trading_lab.windows_acl import AclVerification


def config(*, mode: TradingMode = TradingMode.OBSERVE_ONLY, mt5: bool = False):
    return SimpleNamespace(trading_mode=mode, mt5_access_enabled=mt5)


class AclRepairVerifierTests(unittest.TestCase):
    @patch("trading_lab.acl_repair_verifier.verify_windows_acl")
    @patch("trading_lab.acl_repair_verifier.load_mt5_security_config")
    def test_both_canonical_verifier_scopes_must_pass(self, load_config, verify) -> None:
        load_config.return_value = config()
        verify.side_effect = [AclVerification(True, "partial"), AclVerification(True, "full")]
        result = verify_repaired_acl()
        self.assertEqual("PASS", result["status"])
        self.assertEqual(
            [False, True],
            [call.kwargs["include_automaton_state"] for call in verify.call_args_list],
        )
        self.assertTrue(result["without_automaton_state"]["passed"])
        self.assertTrue(result["with_automaton_state"]["passed"])

    @patch("trading_lab.acl_repair_verifier.verify_windows_acl")
    @patch("trading_lab.acl_repair_verifier.load_mt5_security_config")
    def test_any_failed_scope_is_fail_closed(self, load_config, verify) -> None:
        load_config.return_value = config()
        verify.side_effect = [AclVerification(True, "partial"), AclVerification(False, "drift")]
        self.assertEqual("FAIL_CLOSED", verify_repaired_acl()["status"])

    @patch("trading_lab.acl_repair_verifier.load_mt5_security_config")
    def test_non_observe_or_mt5_enabled_config_is_rejected(self, load_config) -> None:
        for candidate in (config(mode=TradingMode.PAPER), config(mt5=True)):
            load_config.return_value = candidate
            with self.assertRaises(RuntimeError):
                verify_repaired_acl()

    @patch("trading_lab.acl_repair_verifier.verify_windows_acl")
    @patch("trading_lab.acl_repair_verifier.load_mt5_security_config")
    def test_loaded_mt5_module_is_fail_closed(self, load_config, verify) -> None:
        load_config.return_value = config()
        verify.return_value = AclVerification(True, "ok")
        with patch.dict(sys.modules, {"MetaTrader5": object()}):
            result = verify_repaired_acl()
        self.assertEqual("FAIL_CLOSED", result["status"])
        self.assertTrue(result["mt5_imported"])

    @patch("trading_lab.acl_repair_verifier.verify_repaired_acl")
    def test_main_emits_structured_fail_closed_json(self, verify) -> None:
        verify.side_effect = RuntimeError("synthetic verifier failure")
        output = io.StringIO()
        with redirect_stdout(output):
            exit_code = main()
        self.assertEqual(1, exit_code)
        payload = json.loads(output.getvalue())
        self.assertEqual("FAIL_CLOSED", payload["status"])
        self.assertEqual("RuntimeError", payload["error_type"])
        self.assertFalse(payload["mt5_accessed"])
