from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from tests.fakes import FakeMT5Adapter
from tests.test_readiness import security_config
from trading_lab.factory import build_application


class FactoryTests(unittest.TestCase):
    def test_runtime_identity_proof_reaches_health_response(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            app = build_application(
                security_config(Path(directory)),
                FakeMT5Adapter(),
                runtime_identity_verified=True,
            )
            health = app.health()
            self.assertTrue(health["runtime_identity_verified"])
            self.assertTrue(health["healthy"])


if __name__ == "__main__":
    unittest.main()
