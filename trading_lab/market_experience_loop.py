from __future__ import annotations

import logging
import threading
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Callable

from .market_experience_collector import (
    CollectorResult,
    MarketExperienceCollector,
)


_LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True)
class CollectorLoopSnapshot:
    cycles: int
    experiences_created: int
    outcomes_created: int
    consecutive_errors: int
    last_bar_time_utc: str | None
    last_success_at_utc: str | None
    last_error_at_utc: str | None
    last_error: str | None


class MarketExperienceLoop:
    """Retrying loop around the idempotent closed-M1 collector."""

    def __init__(
        self,
        collector: MarketExperienceCollector,
        *,
        interval_seconds: float = 10.0,
        now_provider: Callable[[], datetime] = (
            lambda: datetime.now(UTC)
        ),
    ) -> None:
        if not 1.0 <= interval_seconds <= 60.0:
            raise ValueError(
                "Collector interval must be between 1 and 60 seconds"
            )
        self._collector = collector
        self._interval_seconds = float(interval_seconds)
        self._now_provider = now_provider
        self._stop_event = threading.Event()
        self._state_lock = threading.Lock()
        self._snapshot = CollectorLoopSnapshot(
            cycles=0,
            experiences_created=0,
            outcomes_created=0,
            consecutive_errors=0,
            last_bar_time_utc=None,
            last_success_at_utc=None,
            last_error_at_utc=None,
            last_error=None,
        )

    def snapshot(self) -> CollectorLoopSnapshot:
        with self._state_lock:
            return self._snapshot

    def stop(self) -> None:
        self._stop_event.set()

    def run_cycle(self) -> CollectorResult | None:
        now = self._now_provider().astimezone(UTC)

        try:
            result = self._collector.collect_once(now=now)
        except Exception as exc:
            with self._state_lock:
                current = self._snapshot
                self._snapshot = CollectorLoopSnapshot(
                    cycles=current.cycles + 1,
                    experiences_created=current.experiences_created,
                    outcomes_created=current.outcomes_created,
                    consecutive_errors=current.consecutive_errors + 1,
                    last_bar_time_utc=current.last_bar_time_utc,
                    last_success_at_utc=current.last_success_at_utc,
                    last_error_at_utc=now.isoformat(),
                    last_error=f"{type(exc).__name__}: {exc}",
                )

            _LOGGER.exception(
                "Market experience collection cycle failed"
            )
            return None

        with self._state_lock:
            current = self._snapshot
            self._snapshot = CollectorLoopSnapshot(
                cycles=current.cycles + 1,
                experiences_created=(
                    current.experiences_created
                    + int(result.experience_created)
                ),
                outcomes_created=(
                    current.outcomes_created
                    + result.outcomes_created
                ),
                consecutive_errors=0,
                last_bar_time_utc=result.bar_time_utc,
                last_success_at_utc=now.isoformat(),
                last_error_at_utc=current.last_error_at_utc,
                last_error=None,
            )

        if result.experience_created or result.outcomes_created:
            _LOGGER.info(
                "Market experience evidence persisted: "
                "bar=%s experience_created=%s outcomes_created=%s",
                result.bar_time_utc,
                result.experience_created,
                result.outcomes_created,
            )

        return result

    def run(self) -> None:
        while not self._stop_event.is_set():
            self.run_cycle()
            self._stop_event.wait(self._interval_seconds)
