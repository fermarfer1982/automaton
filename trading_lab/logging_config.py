from __future__ import annotations

import logging
from logging.handlers import TimedRotatingFileHandler
from pathlib import Path


def configure_gateway_logging(log_dir: Path | None) -> None:
    if log_dir is None:
        raise RuntimeError("External gateway log directory is required")
    if log_dir.is_symlink():
        raise RuntimeError("Gateway log directory cannot be a symlink")
    log_dir.mkdir(parents=True, exist_ok=True)
    formatter = logging.Formatter(
        "%(asctime)sZ %(levelname)s %(name)s %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )
    formatter.converter = __import__("time").gmtime
    for name, filename in (
        ("automaton.gateway", "gateway.log"),
        ("automaton.security", "security.log"),
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
