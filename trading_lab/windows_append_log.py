from __future__ import annotations

import ctypes
import logging
import os
from ctypes import wintypes
from pathlib import Path
from typing import Protocol


SECURITY_LOG_DIRECTORY = Path(
    r"C:\ProgramData\AutomatonMT5Lab\logs\security"
)
_FIXED_SECURITY_LOG_PATH = Path(
    r"C:\ProgramData\AutomatonMT5Lab\logs\security\security.log"
)
SECURITY_LOG_PATH = _FIXED_SECURITY_LOG_PATH

FILE_APPEND_DATA = 0x0004
SYNCHRONIZE = 0x00100000
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
FILE_SHARE_DELETE = 0x00000004
OPEN_EXISTING = 3
FILE_ATTRIBUTE_NORMAL = 0x00000080
FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

APPEND_ONLY_DESIRED_ACCESS = FILE_APPEND_DATA | SYNCHRONIZE
APPEND_ONLY_SHARE_MODE = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE
# Compatibility names for callers that previously consumed the security-specific
# constants. Both aliases retain the shared primitive as the single source of truth.
SECURITY_LOG_DESIRED_ACCESS = APPEND_ONLY_DESIRED_ACCESS
SECURITY_LOG_SHARE_MODE = APPEND_ONLY_SHARE_MODE


class _AppendApi(Protocol):
    def open_existing_append(self, path: Path) -> object: ...

    def write(self, handle: object, payload: bytes) -> None: ...

    def close(self, handle: object) -> None: ...


class _Win32AppendApi:
    def __init__(self) -> None:
        if os.name != "nt":
            raise OSError("The append-only security handler requires Windows")

        self._kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self._create_file = self._kernel32.CreateFileW
        self._create_file.argtypes = (
            wintypes.LPCWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.LPVOID,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.HANDLE,
        )
        self._create_file.restype = wintypes.HANDLE

        self._write_file = self._kernel32.WriteFile
        self._write_file.argtypes = (
            wintypes.HANDLE,
            wintypes.LPCVOID,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
            wintypes.LPVOID,
        )
        self._write_file.restype = wintypes.BOOL

        self._close_handle = self._kernel32.CloseHandle
        self._close_handle.argtypes = (wintypes.HANDLE,)
        self._close_handle.restype = wintypes.BOOL

    @staticmethod
    def _raise_last_error(operation: str) -> None:
        error_code = ctypes.get_last_error()
        raise ctypes.WinError(error_code, operation)

    def open_existing_append(self, path: Path) -> object:
        handle = self._create_file(
            str(path),
            APPEND_ONLY_DESIRED_ACCESS,
            APPEND_ONLY_SHARE_MODE,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
        handle_value = (
            handle if isinstance(handle, int) else ctypes.cast(handle, ctypes.c_void_p).value
        )
        if handle_value == INVALID_HANDLE_VALUE:
            self._raise_last_error("CreateFileW append-only open failed")
        return handle

    def write(self, handle: object, payload: bytes) -> None:
        buffer = ctypes.create_string_buffer(payload)
        bytes_written = wintypes.DWORD(0)
        if not self._write_file(
            handle,
            buffer,
            len(payload),
            ctypes.byref(bytes_written),
            None,
        ):
            self._raise_last_error("WriteFile append-only write failed")
        if bytes_written.value != len(payload):
            raise OSError(
                "WriteFile append-only write was incomplete: "
                f"{bytes_written.value}/{len(payload)} bytes"
            )

    def close(self, handle: object) -> None:
        if not self._close_handle(handle):
            self._raise_last_error("CloseHandle append-only file failed")


def _normalized_absolute(path: Path) -> str:
    return os.path.normcase(os.path.abspath(os.fspath(path)))


def _is_reparse_point(path: Path) -> bool:
    attributes = getattr(os.lstat(path), "st_file_attributes", 0)
    return bool(attributes & FILE_ATTRIBUTE_REPARSE_POINT)


def validate_existing_append_only_file(path: str | os.PathLike[str]) -> Path:
    candidate = Path(path)
    parent = candidate.parent
    if not parent.exists() or not parent.is_dir():
        raise FileNotFoundError(f"append-only directory is missing: {parent}")
    if parent.is_symlink() or _is_reparse_point(parent):
        raise OSError("append-only directory must not be a reparse point")
    if not candidate.exists() or not candidate.is_file():
        raise FileNotFoundError(
            f"pre-created append-only file is missing: {candidate}"
        )
    if candidate.is_symlink() or _is_reparse_point(candidate):
        raise OSError("append-only file must not be a reparse point")
    return candidate


class WindowsAppendOnlyFile:
    """Write bytes to one existing, non-reparse Windows file with append rights."""

    def __init__(
        self,
        path: str | os.PathLike[str],
        *,
        _api: _AppendApi | None = None,
    ) -> None:
        self.path = Path(path)
        self._handle: object | None = None
        self._api = _api if _api is not None else _Win32AppendApi()
        self.path = validate_existing_append_only_file(self.path)
        self._handle = self._api.open_existing_append(self.path)

    def append(self, payload: bytes) -> None:
        if not isinstance(payload, bytes):
            raise TypeError("append-only payload must be bytes")
        if self._handle is None:
            raise OSError("append-only file handle is closed")
        self._api.write(self._handle, payload)

    def close(self) -> None:
        handle = self._handle
        self._handle = None
        if handle is not None:
            self._api.close(handle)

    def __enter__(self) -> WindowsAppendOnlyFile:
        return self

    def __exit__(self, *_exc_info: object) -> None:
        self.close()


class WindowsAppendOnlyFileHandler(logging.Handler):
    """Append UTF-8 records to the pre-created security journal on Windows."""

    terminator = "\n"

    def __init__(
        self,
        *,
        _api: _AppendApi | None = None,
    ) -> None:
        super().__init__()
        self._handle: object | None = None
        self._api = _api if _api is not None else _Win32AppendApi()
        candidate = SECURITY_LOG_PATH
        if _normalized_absolute(candidate) != _normalized_absolute(
            _FIXED_SECURITY_LOG_PATH
        ):
            raise ValueError("security log path is not the exact protected path")

        self.baseFilename = str(candidate)
        self.mode = "append-only-win32"
        self.encoding = "utf-8"
        self.errors = "strict"
        self._writer: WindowsAppendOnlyFile | None = WindowsAppendOnlyFile(
            candidate,
            _api=self._api,
        )

    def emit(self, record: logging.LogRecord) -> None:
        if self._writer is None:
            raise OSError("security log handle is closed")
        message = self.format(record).rstrip("\r\n") + self.terminator
        self._writer.append(message.encode(self.encoding, self.errors))

    def close(self) -> None:
        close_error: BaseException | None = None
        self.acquire()
        try:
            writer = getattr(self, "_writer", None)
            self._writer = None
            if writer is not None:
                try:
                    writer.close()
                except BaseException as exc:  # preserve WinError after local cleanup
                    close_error = exc
        finally:
            self.release()
            super().close()
        if close_error is not None:
            raise close_error


__all__ = [
    "APPEND_ONLY_DESIRED_ACCESS",
    "APPEND_ONLY_SHARE_MODE",
    "FILE_APPEND_DATA",
    "FILE_ATTRIBUTE_NORMAL",
    "FILE_SHARE_DELETE",
    "FILE_SHARE_READ",
    "FILE_SHARE_WRITE",
    "OPEN_EXISTING",
    "SECURITY_LOG_DESIRED_ACCESS",
    "SECURITY_LOG_DIRECTORY",
    "SECURITY_LOG_PATH",
    "SECURITY_LOG_SHARE_MODE",
    "SYNCHRONIZE",
    "WindowsAppendOnlyFile",
    "WindowsAppendOnlyFileHandler",
    "validate_existing_append_only_file",
]
