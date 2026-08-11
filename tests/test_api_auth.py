from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from trading_lab.api_auth import ApiKeyError, ApiKeyVerifier


class ApiKeyTests(unittest.TestCase):
    def test_compares_external_key_without_exposing_it(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "automaton.key"
            key = "A" * 43
            path.write_text(key, encoding="ascii")
            verifier = ApiKeyVerifier(path)
            self.assertTrue(verifier.verify(key))
            self.assertFalse(verifier.verify("B" * 43))
            self.assertNotIn(key, repr(verifier))

    def test_rejects_whitespace_short_or_missing_keys(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "automaton.key"
            for value in ("short", "A" * 43 + "\n"):
                path.write_text(value, encoding="ascii")
                with self.assertRaises(ApiKeyError):
                    ApiKeyVerifier(path)


if __name__ == "__main__":
    unittest.main()
