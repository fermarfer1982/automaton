from __future__ import annotations

import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from trading_lab.research_store import ResearchStore


class ResearchLifecycleTests(unittest.TestCase):
    def test_idempotency_replays_result_and_rejects_hash_conflict(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = ResearchStore(Path(directory) / "research.db")
            state, proposal_id, response = store.reserve_idempotency("key-1", "hash-a", "p1")
            self.assertEqual(("NEW", "p1", None), (state, proposal_id, response))
            store.complete_idempotency("key-1", {"status": "OBSERVED", "proposal_id": "p1"})
            state, proposal_id, response = store.reserve_idempotency("key-1", "hash-a", "ignored")
            self.assertEqual("EXISTING", state)
            self.assertEqual("p1", proposal_id)
            self.assertEqual("OBSERVED", response["status"])
            state, _, _ = store.reserve_idempotency("key-1", "hash-b", "ignored")
            self.assertEqual("CONFLICT", state)

    def test_lifecycle_and_decisions_are_append_only(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "research.db"
            store = ResearchStore(path)
            store.append_lifecycle("e1", "p1", "PROPOSED")
            store.record_agent_decision(
                decision_id="d1", action="HOLD", symbol="XAUUSD", timeframe="M1",
                bar_time_utc="2026-08-11T12:00:00+00:00", reason="No valid setup",
                hypothesis_id=None,
            )
            with closing(sqlite3.connect(path)) as connection:
                with self.assertRaises(sqlite3.DatabaseError):
                    connection.execute("DELETE FROM lifecycle_events")
                with self.assertRaises(sqlite3.DatabaseError):
                    connection.execute("UPDATE agent_decisions SET action='PROPOSE'")


if __name__ == "__main__":
    unittest.main()
