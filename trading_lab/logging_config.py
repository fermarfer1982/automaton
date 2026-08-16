from __future__ import annotations

import logging
from logging.handlers import TimedRotatingFileHandler
from pathlib import Path

from trading_lab.windows_append_log import (
    SECURITY_LOG_DIRECTORY,
    WindowsAppendOnlyFileHandler,
)


def configure_gateway_logging(log_dir: Path | None, security_log_dir: Path | None) -> None:
    if log_dir is None or security_log_dir is None:
        raise RuntimeError("Separated external gateway and security log directories are required")
    if log_dir.is_symlink() or security_log_dir.is_symlink():
        raise RuntimeError("Gateway log directories cannot be symlinks")
    if security_log_dir.absolute() != SECURITY_LOG_DIRECTORY:
        raise RuntimeError("Security log directory is not the exact protected path")
    log_dir.mkdir(parents=True, exist_ok=True)
    if not security_log_dir.exists() or not security_log_dir.is_dir():
        raise RuntimeError("Pre-created security log directory is required")
    formatter = logging.Formatter(
        "%(asctime)sZ %(levelname)s %(name)s %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )
    formatter.converter = __import__("time").gmtime
    for name, filename in (
        ("automaton.gateway", "gateway.log"),
        ("automaton.trading", "trading.log"),
    ):
        logger = logging.getLogger(name)
        logger.setLevel(logging.INFO)
        logger.propagate = False
        if logger.handlers:
            continue
        handler = TimedRotatingFileHandler(
            log_dir / filename,
            when="midnight",
            interval=1,
            backupCount=30,
            encoding="utf-8",
            utc=True,
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    security_logger = logging.getLogger("automaton.security")
    security_logger.setLevel(logging.INFO)
    security_logger.propagate = False
    if not security_logger.handlers:
        security_handler = WindowsAppendOnlyFileHandler()
        security_handler.setFormatter(formatter)
        security_logger.addHandler(security_handler)
