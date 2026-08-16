from __future__ import annotations


class MT5AccessDisabled(RuntimeError):
    code = "MT5_ACCESS_DISABLED"

    def __init__(self) -> None:
        super().__init__(self.code)
