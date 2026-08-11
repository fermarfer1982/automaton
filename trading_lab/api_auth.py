from __future__ import annotations

import hmac
import re
from pathlib import Path


_KEY_PATTERN = re.compile(r"^[A-Za-z0-9_-]{43,128}$")


class ApiKeyError(RuntimeError):
    pass


class ApiKeyVerifier:
    """Loads one external IPC secret; its value is never exposed by this API."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        try:
            if self.path.is_symlink():
                raise ApiKeyError("API key path cannot be a symlink")
            value = self.path.read_text(encoding="ascii")
        except (OSError, UnicodeError) as exc:
            raise ApiKeyError("Cannot read protected gateway API key") from exc
        if value != value.strip() or not _KEY_PATTERN.fullmatch(value):
            raise ApiKeyError("Protected gateway API key has invalid format")
        self._key = value

    def verify(self, candidate: str | None) -> bool:
        if not isinstance(candidate, str) or not _KEY_PATTERN.fullmatch(candidate):
            return False
        return hmac.compare_digest(self._key, candidate)
