from __future__ import annotations

import logging
import tempfile
import unittest
from logging.handlers import TimedRotatingFileHandler
from pathlib import Path

from trading_lab.logging_config import configure_gateway_logging


class GatewayLoggingAclCompatibilityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.loggers = [
            logging.getLogger("automaton.gateway"),
            logging.getLogger("automaton.trading"),
            logging.getLogger("automaton.security"),
        ]
        self._clear_handlers()

    def tearDown(self) -> None:
        self._clear_handlers()

    def _clear_handlers(self) -> None:
        for logger in self.loggers:
            for handler in logger.handlers[:]:
                handler.close()
                logger.removeHandler(handler)

    def test_security_log_is_separate_append_only_pattern_without_rotation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            gateway_dir = root / "logs" / "gateway"
            security_dir = root / "logs" / "security"
            try:
                configure_gateway_logging(gateway_dir, security_dir)

                gateway_handlers = logging.getLogger("automaton.gateway").handlers
                trading_handlers = logging.getLogger("automaton.trading").handlers
                security_handlers = logging.getLogger("automaton.security").handlers
                self.assertIsInstance(gateway_handlers[0], TimedRotatingFileHandler)
                self.assertIsInstance(trading_handlers[0], TimedRotatingFileHandler)
                self.assertNotIsInstance(security_handlers[0], TimedRotatingFileHandler)
                self.assertEqual("a", security_handlers[0].mode)  # type: ignore[attr-defined]
                self.assertEqual(
                    security_dir / "security.log",
                    Path(security_handlers[0].baseFilename),  # type: ignore[attr-defined]
                )
            finally:
                self._clear_handlers()


if __name__ == "__main__":
    unittest.main()
