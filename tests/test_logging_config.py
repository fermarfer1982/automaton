from __future__ import annotations

import logging
import os
import tempfile
import unittest
from logging.handlers import TimedRotatingFileHandler
from pathlib import Path
from unittest import mock

from trading_lab.logging_config import configure_gateway_logging
from trading_lab.windows_append_log import (
    APPEND_ONLY_DESIRED_ACCESS,
    APPEND_ONLY_SHARE_MODE,
    FILE_APPEND_DATA,
    FILE_ATTRIBUTE_NORMAL,
    FILE_SHARE_DELETE,
    FILE_SHARE_READ,
    FILE_SHARE_WRITE,
    INVALID_HANDLE_VALUE,
    OPEN_EXISTING,
    SECURITY_LOG_DESIRED_ACCESS,
    SECURITY_LOG_SHARE_MODE,
    SYNCHRONIZE,
    WindowsAppendOnlyFile,
    WindowsAppendOnlyFileHandler,
    _Win32AppendApi,
)


class FakeAppendApi:
    def __init__(self) -> None:
        self.handle = object()
        self.opened: list[Path] = []
        self.writes: list[bytes] = []
        self.closed: list[object] = []
        self.open_error: OSError | None = None
        self.write_error: OSError | None = None

    def open_existing_append(self, path: Path) -> object:
        self.opened.append(path)
        if self.open_error is not None:
            raise self.open_error
        return self.handle

    def write(self, handle: object, payload: bytes) -> None:
        if self.write_error is not None:
            raise self.write_error
        if handle is not self.handle:
            raise AssertionError("unexpected handle")
        self.writes.append(payload)

    def close(self, handle: object) -> None:
        self.closed.append(handle)


class RecordingHandler(logging.Handler):
    def __init__(self, filename: Path) -> None:
        super().__init__()
        self.baseFilename = str(filename)

    def emit(self, record: logging.LogRecord) -> None:
        del record


class WindowsAppendOnlyFileHandlerTests(unittest.TestCase):
    def _fixture(
        self,
    ) -> tuple[tempfile.TemporaryDirectory[str], Path, FakeAppendApi]:
        temporary = tempfile.TemporaryDirectory()
        path = Path(temporary.name) / "security" / "security.log"
        path.parent.mkdir()
        path.touch()
        return temporary, path, FakeAppendApi()

    def _handler(
        self, path: Path, api: FakeAppendApi
    ) -> WindowsAppendOnlyFileHandler:
        with mock.patch(
            "trading_lab.windows_append_log.SECURITY_LOG_PATH", path
        ), mock.patch(
            "trading_lab.windows_append_log._FIXED_SECURITY_LOG_PATH", path
        ):
            return WindowsAppendOnlyFileHandler(_api=api)

    def _writer(self, path: Path, api: FakeAppendApi) -> WindowsAppendOnlyFile:
        return WindowsAppendOnlyFile(path, _api=api)

    def test_createfilew_uses_exact_append_only_contract(self) -> None:
        api = _Win32AppendApi.__new__(_Win32AppendApi)
        create_file = mock.Mock(return_value=123)
        api._create_file = create_file

        handle = api.open_existing_append(Path(r"C:\exact\security.log"))

        self.assertEqual(123, handle)
        create_file.assert_called_once_with(
            r"C:\exact\security.log",
            FILE_APPEND_DATA | SYNCHRONIZE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
        self.assertEqual(FILE_APPEND_DATA | SYNCHRONIZE, SECURITY_LOG_DESIRED_ACCESS)
        self.assertEqual(FILE_APPEND_DATA | SYNCHRONIZE, APPEND_ONLY_DESIRED_ACCESS)
        self.assertEqual(
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            SECURITY_LOG_SHARE_MODE,
        )
        self.assertEqual(SECURITY_LOG_SHARE_MODE, APPEND_ONLY_SHARE_MODE)
        self.assertEqual(0, SECURITY_LOG_DESIRED_ACCESS & 0x0002)
        self.assertEqual(0, SECURITY_LOG_DESIRED_ACCESS & 0x40000000)

    @unittest.skipUnless(os.name == "nt", "Win32 handler smoke test")
    def test_real_win32_handler_appends_to_precreated_temporary_file(self) -> None:
        temporary, path, _ = self._fixture()
        with temporary, mock.patch(
            "trading_lab.windows_append_log.SECURITY_LOG_PATH", path
        ), mock.patch(
            "trading_lab.windows_append_log._FIXED_SECURITY_LOG_PATH", path
        ):
            handler = WindowsAppendOnlyFileHandler()
            try:
                handler.setFormatter(logging.Formatter("%(message)s"))
                handler.emit(
                    logging.LogRecord("test", 20, "", 0, "win32-smoke", (), None)
                )
            finally:
                handler.close()
            self.assertEqual(b"win32-smoke\n", path.read_bytes())

    @unittest.skipUnless(os.name == "nt", "Win32 primitive smoke test")
    def test_real_shared_primitive_appends_to_precreated_temporary_file(self) -> None:
        temporary, path, _ = self._fixture()
        with temporary:
            writer = WindowsAppendOnlyFile(path)
            try:
                writer.append("audit-España\n".encode("utf-8"))
            finally:
                writer.close()
            self.assertEqual("audit-España\n".encode("utf-8"), path.read_bytes())

    def test_invalid_handle_fails_closed_with_winerror(self) -> None:
        api = _Win32AppendApi.__new__(_Win32AppendApi)
        api._create_file = mock.Mock(return_value=INVALID_HANDLE_VALUE)
        with mock.patch.object(api, "_raise_last_error", side_effect=OSError("denied")):
            with self.assertRaisesRegex(OSError, "denied"):
                api.open_existing_append(Path(r"C:\exact\security.log"))

    def test_missing_file_fails_before_open(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "security" / "security.log"
            path.parent.mkdir()
            api = FakeAppendApi()
            with self.assertRaises(FileNotFoundError):
                self._handler(path, api)
            self.assertEqual([], api.opened)

    def test_shared_writer_missing_file_fails_before_open(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            api = FakeAppendApi()
            with self.assertRaises(FileNotFoundError):
                self._writer(path, api)
            self.assertEqual([], api.opened)

    def test_missing_directory_fails_before_open(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "missing" / "security.log"
            api = FakeAppendApi()
            with self.assertRaises(FileNotFoundError):
                self._handler(path, api)
            self.assertEqual([], api.opened)

    def test_handler_rejects_any_changed_security_path(self) -> None:
        temporary, path, api = self._fixture()
        with temporary:
            other = path.parent / "other.log"
            other.touch()
            with mock.patch(
                "trading_lab.windows_append_log.SECURITY_LOG_PATH", other
            ), self.assertRaises(ValueError):
                WindowsAppendOnlyFileHandler(_api=api)
            self.assertEqual([], api.opened)

    def test_reparse_file_fails_before_open(self) -> None:
        temporary, path, api = self._fixture()
        with temporary, mock.patch(
            "trading_lab.windows_append_log._is_reparse_point",
            side_effect=lambda candidate: candidate == path,
        ):
            with self.assertRaisesRegex(OSError, "reparse point"):
                self._handler(path, api)
            self.assertEqual([], api.opened)

    def test_shared_writer_reparse_file_fails_before_open(self) -> None:
        temporary, path, api = self._fixture()
        with temporary, mock.patch(
            "trading_lab.windows_append_log._is_reparse_point",
            side_effect=lambda candidate: candidate == path,
        ):
            with self.assertRaisesRegex(OSError, "reparse point"):
                self._writer(path, api)
            self.assertEqual([], api.opened)

    def test_reparse_directory_fails_before_open(self) -> None:
        temporary, path, api = self._fixture()
        with temporary, mock.patch(
            "trading_lab.windows_append_log._is_reparse_point",
            side_effect=lambda candidate: candidate == path.parent,
        ):
            with self.assertRaisesRegex(OSError, "reparse point"):
                self._handler(path, api)
            self.assertEqual([], api.opened)

    def test_writefile_receives_utf8_and_exactly_one_newline(self) -> None:
        temporary, path, api = self._fixture()
        with temporary:
            handler = self._handler(path, api)
            try:
                handler.setFormatter(logging.Formatter("%(message)s"))
                handler.emit(logging.LogRecord("test", 20, "", 0, "España\n", (), None))
                self.assertEqual(["España\n".encode("utf-8")], api.writes)
            finally:
                handler.close()

    def test_two_emits_append_two_complete_records(self) -> None:
        temporary, path, api = self._fixture()
        with temporary:
            handler = self._handler(path, api)
            try:
                handler.setFormatter(logging.Formatter("%(message)s"))
                for message in ("first", "second"):
                    handler.emit(
                        logging.LogRecord("test", 20, "", 0, message, (), None)
                    )
                self.assertEqual(b"first\nsecond\n", b"".join(api.writes))
                self.assertEqual([path], api.opened)
            finally:
                handler.close()

    def test_shared_writer_uses_one_handle_and_one_write_per_append(self) -> None:
        temporary, path, api = self._fixture()
        with temporary:
            writer = self._writer(path, api)
            writer.append(b"first\n")
            writer.append(b"second\n")
            writer.close()
            writer.close()
            self.assertEqual([path], api.opened)
            self.assertEqual([b"first\n", b"second\n"], api.writes)
            self.assertEqual([api.handle], api.closed)

    def test_write_error_propagates_fail_closed(self) -> None:
        temporary, path, api = self._fixture()
        with temporary:
            api.write_error = OSError("write denied")
            handler = self._handler(path, api)
            try:
                with self.assertRaisesRegex(OSError, "write denied"):
                    handler.emit(
                        logging.LogRecord("test", 20, "", 0, "record", (), None)
                    )
            finally:
                handler.close()

    def test_open_error_propagates_fail_closed(self) -> None:
        temporary, path, api = self._fixture()
        with temporary:
            api.open_error = OSError("open denied")
            with self.assertRaisesRegex(OSError, "open denied"):
                self._handler(path, api)

    def test_closehandle_runs_once_and_close_is_idempotent(self) -> None:
        temporary, path, api = self._fixture()
        with temporary:
            handler = self._handler(path, api)
            handler.close()
            handler.close()
            self.assertEqual([api.handle], api.closed)

    def test_source_has_no_forbidden_mutation_or_mt5_fallback(self) -> None:
        source = (
            Path(__file__).parents[1] / "trading_lab" / "windows_append_log.py"
        ).read_text(encoding="utf-8")
        for forbidden in (
            "GENERIC_WRITE",
            "FILE_WRITE_DATA",
            "FILE_WRITE_ATTRIBUTES",
            "FILE_WRITE_EA",
            "WRITE_DAC",
            "WRITE_OWNER",
            "FlushFileBuffers",
            "MetaTrader5",
            "logging.FileHandler(",
            ".seek(",
            ".truncate(",
            "os.rename(",
            "TemporaryFile",
        ):
            self.assertNotIn(forbidden, source)


class GatewayLoggingIntegrationTests(unittest.TestCase):
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

    def test_security_uses_new_handler_and_operational_logs_still_rotate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            gateway_dir = root / "logs" / "gateway"
            security_dir = root / "logs" / "security"
            security_dir.mkdir(parents=True)
            security_file = security_dir / "security.log"
            security_file.touch()
            replacement = RecordingHandler(security_file)
            try:
                with mock.patch(
                    "trading_lab.logging_config.SECURITY_LOG_DIRECTORY",
                    security_dir,
                ), mock.patch(
                    "trading_lab.logging_config.WindowsAppendOnlyFileHandler",
                    return_value=replacement,
                ) as factory:
                    configure_gateway_logging(gateway_dir, security_dir)

                factory.assert_called_once_with()
                gateway_handlers = logging.getLogger("automaton.gateway").handlers
                trading_handlers = logging.getLogger("automaton.trading").handlers
                security_handlers = logging.getLogger("automaton.security").handlers
                self.assertIsInstance(gateway_handlers[0], TimedRotatingFileHandler)
                self.assertIsInstance(trading_handlers[0], TimedRotatingFileHandler)
                self.assertIs(security_handlers[0], replacement)
                self.assertNotIsInstance(
                    security_handlers[0], TimedRotatingFileHandler
                )
            finally:
                self._clear_handlers()

    def test_missing_security_directory_is_not_created(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            security_dir = root / "missing-security"
            with mock.patch(
                "trading_lab.logging_config.SECURITY_LOG_DIRECTORY",
                security_dir,
            ), self.assertRaisesRegex(RuntimeError, "Pre-created"):
                configure_gateway_logging(root / "gateway", security_dir)
            self.assertFalse(security_dir.exists())

    def test_nonexact_security_directory_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            security_dir = root / "security"
            security_dir.mkdir()
            with self.assertRaisesRegex(RuntimeError, "exact protected path"):
                configure_gateway_logging(root / "gateway", security_dir)


if __name__ == "__main__":
    unittest.main()
