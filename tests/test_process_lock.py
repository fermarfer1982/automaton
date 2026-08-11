from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from trading_lab.process_lock import GatewayAlreadyRunningError, GatewayProcessLock


class ProcessLockTests(unittest.TestCase):
    def test_prevents_two_gateway_instances_and_releases_cleanly(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "gateway.lock"
            first = GatewayProcessLock(path)
            second = GatewayProcessLock(path)
            first.acquire()
            try:
                with self.assertRaises(GatewayAlreadyRunningError):
                    second.acquire()
            finally:
                first.release()
            second.acquire()
            second.release()


if __name__ == "__main__":
    unittest.main()
